FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends bash curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN pip install --no-cache-dir requests pyyaml
COPY scripts/ti_platform_interconnect.py scripts/ti_platform_interconnect_verify.py scripts/opensearch_ioc_common.py scripts/opensearch_ioc_opencti_sync.py scripts/opensearch_ioc_misp_sync.py scripts/opensearch_ti_enrich_logs.py scripts/opensearch_ti_setup.sh scripts/cti_enrich.py scripts/fp_runtime_env.py scripts/fp_http_lib.py /app/scripts/
COPY scripts/opensearch_pipeline_ti_match.json /app/scripts/
COPY config/opensearch/index-templates /app/config/opensearch/index-templates
COPY parsers/ingest-pipelines /app/parsers/ingest-pipelines
ENV TI_SYNC_INTERVAL_SEC=300
ENV PYTHONPATH=/app/scripts
CMD ["python", "/app/scripts/ti_platform_interconnect.py", "--loop"]
