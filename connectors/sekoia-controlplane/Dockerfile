FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SECRETS_PATH=/data/sekoia-secrets.enc \
    CONTROLPLANE_PORT=8901

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd -r cp && useradd -r -g cp -d /app cp \
    && mkdir -p /data && chown cp:cp /data

COPY app.py analytics.py sol.py .
USER cp

EXPOSE 8901
HEALTHCHECK --interval=30s --timeout=6s --retries=5 --start-period=15s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8901/health',timeout=4).status==200 else 1)"

CMD ["python", "-u", "app.py"]
