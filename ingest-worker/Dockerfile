FROM python:3.11-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    libxml2 \
    libyaml-dev \
    libssl-dev \
    && (apt-get install -y --no-install-recommends plaso-tools 2>/dev/null || true) \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY worker.py csv_validator.py timesketch_io.py timesketch_compatible.py \
    timesketch_plaso.py timesketch_pipeline.py timesketch_normalizer.py \
    ti_enrichment.py ioc_common.py .
COPY parsers/ ./parsers/

ENV PYTHONUNBUFFERED=1
CMD ["python", "-u", "worker.py"]
