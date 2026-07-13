#!/usr/bin/env python3
"""Génère des fixtures réalistes pour les tests E2E forensic (style Wara)."""
from __future__ import annotations

import json
import os
import struct
import zlib
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"


def write(name: str, content: str | bytes) -> Path:
    FIX.mkdir(parents=True, exist_ok=True)
    p = FIX / name
    if isinstance(content, str):
        p.write_text(content, encoding="utf-8")
    else:
        p.write_bytes(content)
    return p


def gen_windows_csv() -> None:
    rows = [
        "datetime,message,source,timestamp_desc",
        "2024-03-15T08:12:01Z,Successful logon user=jdoe src=10.0.5.22,Microsoft-Windows-Security-Auditing,Event log",
        "2024-03-15T08:12:05Z,Failed logon user=admin src=203.0.113.44,Microsoft-Windows-Security-Auditing,Event log",
        "2024-03-15T08:13:00Z,Process Create cmdline=powershell.exe -enc ...,Microsoft-Windows-Sysmon,Event log",
        "2024-03-15T08:14:22Z,Network connection dest=203.0.113.66:443,Microsoft-Windows-Sysmon,Event log",
        "2024-03-15T08:15:01Z,Service installed name=RemoteAccess,Microsoft-Windows-Security-Auditing,Event log",
    ]
    write("wara-windows-events.csv", "\n".join(rows) + "\n")


def gen_linux_auth() -> None:
    lines = [
        "Mar 15 08:00:01 wara-linux-test sshd[1234]: Accepted publickey for analyst from 10.0.1.5 port 22",
        "Mar 15 08:00:02 wara-linux-test sudo: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/bin/bash",
        "Mar 15 08:01:11 wara-linux-test sshd[1240]: Failed password for invalid user root from 198.51.100.7 port 48922",
        "Mar 15 08:02:33 wara-linux-test kernel: [UFW BLOCK] IN=eth0 OUT= MAC= SRC=198.51.100.7 DST=10.0.1.10",
        "Mar 15 08:05:00 wara-linux-test CRON[1300]: (root) CMD (/usr/local/bin/backup.sh)",
    ]
    write("wara-linux-auth.log", "\n".join(lines) + "\n")


def gen_web_access() -> None:
    lines = [
        '10.0.2.15 - - [15/Mar/2024:09:10:01 +0000] "GET /admin/login HTTP/1.1" 404 512 "-" "curl/7.88.1"',
        '203.0.113.50 - - [15/Mar/2024:09:10:05 +0000] "POST /api/upload HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
        '10.0.2.20 - - [15/Mar/2024:09:11:00 +0000] "GET /wp-login.php HTTP/1.1" 403 256 "-" "sqlmap/1.7"',
        '203.0.113.66 - - [15/Mar/2024:09:12:44 +0000] "GET /.env HTTP/1.1" 404 128 "-" "nikto/2.5"',
    ]
    write("wara-nginx-access.log", "\n".join(lines) + "\n")


def gen_stix_bundle() -> None:
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    bundle = {
        "type": "bundle",
        "id": "bundle--fp-wara-test",
        "objects": [
            {
                "type": "indicator",
                "id": "indicator--fp-wara-1",
                "created": now,
                "pattern": "[ipv4-addr:value = '203.0.113.50']",
                "pattern_type": "stix",
                "valid_from": now,
                "labels": ["malicious-activity"],
            },
            {
                "type": "malware",
                "id": "malware--fp-wara-1",
                "created": now,
                "name": "WaraTestMalware",
                "is_family": True,
            },
        ],
    }
    write("wara-iocs.stix.json", json.dumps(bundle, indent=2))


def gen_minimal_pcap() -> None:
    """PCAP global header + un paquet UDP minimal (valide pour Wireshark)."""
    gh = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    # Ethernet(14) + IPv4(20) + UDP(8) + payload
    eth = b"\x00" * 12 + b"\x08\x00"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 1, 0, 64, 17, 0,
                     bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]))
    udp = struct.pack("!HHHH", 12345, 53, 16, 0)
    payload = b"wara-dns-test"
    pkt = eth + ip + udp + payload
    incl = struct.pack("<IIII", 0, 0, len(pkt), len(pkt))
    write("wara-network.pcap", gh + incl + pkt)


def gen_evtx_placeholder() -> None:
    """Copie le CSV windows comme EVTX fallback si pas de vrai EVTX — le worker attend .evtx."""
    # Télécharger un petit EVTX public si absent
    evtx_path = FIX / "wara-security-mini.evtx"
    if evtx_path.exists() and evtx_path.stat().st_size > 1000:
        return
    import urllib.request

    urls = [
        "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/raw/master/EVTX/to-upload/Powershell_4104_01.evtx",
        "https://github.com/omerbenyaev/EVTX-ATTACK-SAMPLES/raw/master/EVTX/Powershell/Powershell_4104.evtx",
    ]
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "forensic-platform/2.1"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
            if len(data) > 4096:
                evtx_path.write_bytes(data)
                return
        except Exception:
            continue
    # Fallback: fichier vide marqué (tests utiliseront CSV pour Windows si EVTX indisponible)
    write("wara-security-mini.evtx.readme", "EVTX auto-download failed; use wara-windows-events.csv for Windows E2E\n")


def main() -> None:
    gen_windows_csv()
    gen_linux_auth()
    gen_web_access()
    gen_stix_bundle()
    gen_minimal_pcap()
    gen_evtx_placeholder()
    print(f"[fixtures] OK → {FIX}")


if __name__ == "__main__":
    main()
