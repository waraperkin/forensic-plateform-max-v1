#!/usr/bin/env python3
"""
Forensic Platform — Ingest Worker
MinIO → Parse (EVTX/CSV/text) → OpenSearch → Timesketch (pipeline unifié)
"""
from __future__ import annotations

import json
import hashlib
import logging
import os
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import boto3
import redis
from opensearchpy import OpenSearch, helpers

from parsers.evtx_parser import parse_evtx
from parsers.text_parser import detect_index, parse_text_content
from ti_enrichment import enrich_events
from timesketch_pipeline import import_to_timesketch

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ingest-worker] %(levelname)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("ingest-worker")

# P-04 : aucun secret codé en dur. Les credentials viennent de l'environnement
# (docker-compose injecte MINIO_ROOT_USER/PASSWORD et REDIS_URL depuis .env).
# En l'absence de valeur, le worker échoue explicitement plutôt que d'utiliser
# un mot de passe par défaut.
def _required(name: str) -> str:
    v = os.environ.get(name, "")
    if not v:
        log.error("Variable d'environnement obligatoire absente : %s", name)
        raise SystemExit(f"Configuration incomplète : {name} manquant (voir .env.example)")
    return v

REDIS_URL = _required("REDIS_URL")
QUEUE_KEY = os.environ.get("INGEST_QUEUE_KEY", "fp:ingest:queue")
TIMESKETCH_IMPORT_TIMEOUT_SEC = int(os.environ.get("TIMESKETCH_IMPORT_TIMEOUT_SEC", "120"))
TIMESKETCH_BACKOFF_SEC = int(os.environ.get("TIMESKETCH_BACKOFF_SEC", "300"))
TIMESKETCH_IMPORT_WORKERS = int(os.environ.get("TIMESKETCH_IMPORT_WORKERS", "2"))
MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "minio:9000")
MINIO_ACCESS_KEY = _required("MINIO_ACCESS_KEY")
MINIO_SECRET_KEY = _required("MINIO_SECRET_KEY")
OS_URL = os.environ.get("OPENSEARCH_URL", "http://opensearch-node1:9200")
LOGSTASH_HOST = os.environ.get("LOGSTASH_HOST", "logstash")
LOGSTASH_PORT = int(os.environ.get("LOGSTASH_PORT", "5045"))
BULK_CHUNK = int(os.environ.get("INGEST_BULK_CHUNK", "500"))
MAX_EV_TX = int(os.environ.get("INGEST_MAX_EVTX_EVENTS", "200000"))
MINIO_SCAN_INTERVAL_SEC = int(os.environ.get("MINIO_SCAN_INTERVAL_SEC", "30"))
MINIO_SCAN_MAX_KEYS = int(os.environ.get("MINIO_SCAN_MAX_KEYS", "200"))
MINIO_SCAN_BUCKETS = [b.strip() for b in os.environ.get("MINIO_SCAN_BUCKETS", "").split(",") if b.strip()]
MINIO_DIRECT_SKIP_PREFIXES = tuple(
    p.strip() for p in os.environ.get("MINIO_DIRECT_SKIP_PREFIXES", "cert/,it/").split(",") if p.strip()
)

TS_EXTENSIONS = {"evtx", "evt", "plaso", "dump", "csv", "jsonl", "db"}
DIRECT_MINIO_EXTENSIONS = {
    "evtx", "evt", "log", "txt", "syslog", "csv", "tsv", "json", "jsonl", "xml",
    "plaso", "dump", "pcap", "pcapng", "cap", "gz",
}
HEALTH_PORT = int(os.environ.get("INGEST_HEALTH_PORT", "8090"))
timesketch_executor = ThreadPoolExecutor(max_workers=max(1, TIMESKETCH_IMPORT_WORKERS))
timesketch_disabled_until = 0.0


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path in ("/health", "/"):
            body = b'{"status":"ok","service":"ingest-worker"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *_args) -> None:
        return


def start_health_server() -> None:
    server = HTTPServer(("0.0.0.0", HEALTH_PORT), _HealthHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log.info("Health endpoint listening on :%s/health", HEALTH_PORT)


def s3_client():
    return boto3.client(
        "s3",
        endpoint_url=f"http://{MINIO_ENDPOINT}",
        aws_access_key_id=MINIO_ACCESS_KEY,
        aws_secret_access_key=MINIO_SECRET_KEY,
        region_name="us-east-1",
    )


def os_client() -> OpenSearch:
    return OpenSearch(
        hosts=[OS_URL],
        use_ssl=False,
        verify_certs=False,
        timeout=120,
    )


def download_object(bucket: str, key: str) -> bytes:
    s3 = s3_client()
    resp = s3.get_object(Bucket=bucket, Key=key)
    return resp["Body"].read()


def event_base(job: dict) -> dict[str, Any]:
    return {
        "upload_id": job.get("upload_id"),
        "case_id": job.get("case_id"),
        "analyst": job.get("analyst", "unknown"),
        "os_type": job.get("os_type", "unknown"),
        "portal": job.get("portal", "unknown"),
        "source_file": job.get("filename"),
        "tags": ["file-content", "ingest-worker", job.get("portal", "unknown")],
        "event": {"module": "file-upload", "category": "file", "action": "parsed"},
    }


def parse_file(data: bytes, job: dict) -> tuple[list[dict], str]:
    filename = job.get("filename", "unknown")
    ext = (filename.rsplit(".", 1)[-1] if "." in filename else "").lower()
    os_type = job.get("os_type", "unknown")
    base = event_base(job)
    index_prefix = detect_index(filename, os_type)
    events: list[dict] = []

    if ext in ("evtx", "evt"):
        for ev in parse_evtx(data, base, max_events=MAX_EV_TX):
            events.append(ev)
        index_prefix = "forensic-windows"
    else:
        try:
            content = data.decode("utf-8", errors="replace")
        except Exception:
            content = ""
        for ev in parse_text_content(content, filename, base):
            events.append(ev)

    return events, index_prefix


def bulk_index(client: OpenSearch, index_prefix: str, events: list[dict]) -> int:
    if not events:
        return 0
    events = enrich_events(events, client)
    date_suffix = datetime.now(timezone.utc).strftime("%Y.%m.%d")
    index_name = f"{index_prefix}-{date_suffix}"
    use_pipeline = not index_prefix.startswith("forensic-ti")

    def gen():
        for ev in events:
            action: dict = {"_index": index_name, "_source": ev}
            if use_pipeline:
                action["pipeline"] = "fp-ti-match"
            yield action

    ok, errors = helpers.bulk(client, gen(), chunk_size=BULK_CHUNK, raise_on_error=False)
    if errors:
        log.warning("Bulk had %d errors", len(errors))
    return ok


def send_to_logstash(events: list[dict], index_prefix: str) -> None:
    import socket

    tag = index_prefix.replace("forensic-", "")
    for ev in events[:2000]:
        payload = {
            **ev,
            "tags": list(set((ev.get("tags") or []) + ["json", tag])),
            "[@metadata][pipeline]": tag,
        }
        try:
            with socket.create_connection((LOGSTASH_HOST, LOGSTASH_PORT), timeout=5) as sock:
                sock.sendall((json.dumps(payload, default=str) + "\n").encode())
        except OSError:
            break


def update_upload_doc(client: OpenSearch, job: dict, status: str, extra: dict) -> None:
    upload_id = job.get("upload_id")
    if not upload_id:
        return
    body = {
        "doc": {
            "ingest_status": status,
            "ingest_completed_at": datetime.now(timezone.utc).isoformat(),
            **extra,
        }
    }
    try:
        client.update(index="forensic-uploads", id=upload_id, body=body, refresh=True)
    except Exception:
        try:
            client.update_by_query(
                index="forensic-uploads*",
                body={
                    "script": {
                        "source": "ctx._source.ingest_status=params.status",
                        "lang": "painless",
                        "params": {"status": status},
                    },
                    "query": {"term": {"upload_id": upload_id}},
                },
            )
        except Exception as e:
            log.warning("Could not update upload doc %s: %s", upload_id, e)


def direct_minio_upload_id(bucket: str, key: str, etag: str = "") -> str:
    raw = f"{bucket}\n{key}\n{etag}".encode("utf-8", "replace")
    return "minio-" + hashlib.sha256(raw).hexdigest()[:32]


def should_scan_minio_object(key: str) -> bool:
    if not key or key.endswith("/") or key.startswith(MINIO_DIRECT_SKIP_PREFIXES):
        return False
    ext = (key.rsplit(".", 1)[-1] if "." in key else "").lower()
    return ext in DIRECT_MINIO_EXTENSIONS


def scan_direct_minio_once(r: redis.Redis) -> None:
    if MINIO_SCAN_INTERVAL_SEC <= 0:
        return
    s3 = s3_client()
    client = os_client()
    buckets = MINIO_SCAN_BUCKETS
    if not buckets:
        buckets = [b["Name"] for b in s3.list_buckets().get("Buckets", [])]

    for bucket in buckets:
        token = None
        scanned = 0
        while True:
            kwargs: dict[str, Any] = {"Bucket": bucket, "MaxKeys": min(MINIO_SCAN_MAX_KEYS, 1000)}
            if token:
                kwargs["ContinuationToken"] = token
            resp = s3.list_objects_v2(**kwargs)
            for obj in resp.get("Contents", []):
                key = obj.get("Key", "")
                if not should_scan_minio_object(key):
                    continue
                etag = str(obj.get("ETag", "")).strip('"')
                upload_id = direct_minio_upload_id(bucket, key, etag)
                seen_key = f"fp:minio:direct:seen:{upload_id}"
                if not r.set(seen_key, "processing", nx=True, ex=90 * 24 * 3600):
                    continue
                try:
                    if client.exists(index="forensic-uploads", id=upload_id):
                        r.set(seen_key, "indexed", ex=90 * 24 * 3600)
                        continue
                except Exception:
                    pass

                head = s3.head_object(Bucket=bucket, Key=key)
                meta = head.get("Metadata") or {}
                filename = os.path.basename(key) or key
                job = {
                    "upload_id": upload_id,
                    "case_id": meta.get("case-id") or meta.get("case_id") or "MINIO-DIRECT",
                    "analyst": meta.get("analyst") or meta.get("submitter") or "minio-console",
                    "os_type": meta.get("os-type") or meta.get("os_type") or "unknown",
                    "portal": meta.get("portal") or "minio",
                    "bucket": bucket,
                    "key": key,
                    "filename": filename,
                    "size": int(obj.get("Size") or 0),
                }
                upload_doc = {
                    "@timestamp": datetime.now(timezone.utc).isoformat(),
                    "upload_id": upload_id,
                    "case_id": job["case_id"],
                    "analyst": job["analyst"],
                    "os_type": job["os_type"],
                    "portal": "minio",
                    "file": {"name": filename, "size": job["size"]},
                    "storage": {"bucket": bucket, "key": key},
                    "event": {"module": "minio-direct-upload", "category": "file", "action": "discovered"},
                    "tags": ["minio-direct", "pending-cert-review"],
                }
                client.index(index="forensic-uploads", id=upload_id, body=upload_doc, refresh=True)
                log.info("Direct MinIO object discovered: s3://%s/%s -> %s", bucket, key, upload_id)
                process_job(job)
                r.set(seen_key, "indexed", ex=90 * 24 * 3600)

            scanned += len(resp.get("Contents", []))
            if scanned >= MINIO_SCAN_MAX_KEYS or not resp.get("IsTruncated"):
                break
            token = resp.get("NextContinuationToken")


def start_direct_minio_scanner(r: redis.Redis) -> None:
    if MINIO_SCAN_INTERVAL_SEC <= 0:
        log.info("Direct MinIO scanner disabled")
        return

    def loop() -> None:
        log.info("Direct MinIO scanner enabled every %ss", MINIO_SCAN_INTERVAL_SEC)
        while True:
            try:
                scan_direct_minio_once(r)
            except Exception as e:
                log.warning("Direct MinIO scan failed: %s", e)
            time.sleep(MINIO_SCAN_INTERVAL_SEC)

    threading.Thread(target=loop, daemon=True).start()


def import_to_timesketch_guarded(events: list[dict], job: dict, raw_data: bytes) -> dict[str, Any]:
    global timesketch_disabled_until
    if TIMESKETCH_IMPORT_TIMEOUT_SEC <= 0:
        return {"ok": False, "skipped": True, "reason": "disabled"}
    if time.time() < timesketch_disabled_until:
        return {"ok": False, "skipped": True, "reason": "temporary_backoff"}
    future = timesketch_executor.submit(import_to_timesketch, events, job, raw_data)
    try:
        return future.result(timeout=TIMESKETCH_IMPORT_TIMEOUT_SEC)
    except TimeoutError:
        future.cancel()
        timesketch_disabled_until = time.time() + TIMESKETCH_BACKOFF_SEC
        filename = job.get("filename", "?")
        log.warning(
            "Timesketch import timeout after %ss for %s; continuing ingest pipeline and backing off %ss",
            TIMESKETCH_IMPORT_TIMEOUT_SEC,
            filename,
            TIMESKETCH_BACKOFF_SEC,
        )
        return {
            "ok": False,
            "error": "timeout",
            "timeout_sec": TIMESKETCH_IMPORT_TIMEOUT_SEC,
            "continued": True,
        }


def process_job(job: dict) -> None:
    upload_id = job.get("upload_id", "?")
    filename = job.get("filename", "?")
    log.info("Processing %s (%s)", filename, upload_id)

    client = os_client()
    update_upload_doc(client, job, "processing", {})

    try:
        data = download_object(job["bucket"], job["key"])
        log.info("Downloaded %s bytes from s3://%s/%s", len(data), job["bucket"], job["key"])

        events, index_prefix = parse_file(data, job)
        log.info("Parsed %d events -> index %s", len(events), index_prefix)

        indexed = bulk_index(client, index_prefix, events)
        log.info("Indexed %d events to %s", indexed, index_prefix)

        if events:
            send_to_logstash(events, index_prefix)

        ts_result = None
        ext = (filename.rsplit(".", 1)[-1] if "." in filename else "").lower()
        if ext in TS_EXTENSIONS or job.get("os_type") in ("windows", "linux") or events:
            ts_result = import_to_timesketch_guarded(events, job, data)
            log.info("Timesketch: %s", ts_result)

        update_upload_doc(
            client,
            job,
            "completed",
            {
                "content_indexed": {
                    "events_parsed": len(events),
                    "events_indexed": indexed,
                    "index": index_prefix,
                },
                "timesketch": ts_result,
            },
        )
        log.info("Completed %s", filename)

    except Exception as e:
        log.exception("Failed job %s: %s", upload_id, e)
        update_upload_doc(client, job, "failed", {"ingest_error": str(e)})


def main() -> None:
    log.info("Ingest worker starting — queue=%s", QUEUE_KEY)
    start_health_server()
    r = redis.from_url(REDIS_URL, decode_responses=True)
    start_direct_minio_scanner(r)
    while True:
        try:
            item = r.brpop(QUEUE_KEY, timeout=5)
            if not item:
                continue
            _, raw = item
            job = json.loads(raw)
            process_job(job)
        except redis.ConnectionError as e:
            log.error("Redis connection error: %s - retry in 5s", e)
            time.sleep(5)
        except json.JSONDecodeError as e:
            log.error("Invalid job JSON: %s", e)
        except KeyboardInterrupt:
            log.info("Shutting down")
            break
        except Exception as e:
            log.exception("Loop error: %s", e)
            time.sleep(2)


if __name__ == "__main__":
    main()
