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

# Tout module importé par app.py DOIT figurer ici : un COPY oublié met le
# control-plane en crash-loop au démarrage (précédent : sol.py, commit e02b3c8).
COPY app.py analytics.py sol.py volumetry.py alerting.py mailnotify.py bulkops.py dashboards.py inventory.py storage.py gateway.py telemetry.py assets.py graph.py hostwatch.py hostprofile.py satisfiability.py valuation.py backtest.py schemadrift.py sagf.py sagql.py analyst.py feedback.py conflicts.py dac.py economics.py efficacy.py harness.py insurance.py adversary.py twin.py dataplane.py sep.py sep_catalog.py sep_signals.py sep_groups.py sep_crawl.py .
USER cp

EXPOSE 8901
HEALTHCHECK --interval=30s --timeout=6s --retries=5 --start-period=15s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8901/health',timeout=4).status==200 else 1)"

CMD ["python", "-u", "app.py"]
