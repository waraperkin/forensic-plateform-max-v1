FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MONITOR_PORT=8903

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd -r mon && useradd -r -g mon -d /app mon

COPY monitor.py .
USER mon

EXPOSE 8903
HEALTHCHECK --interval=30s --timeout=6s --retries=5 --start-period=20s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8903/health',timeout=4).status==200 else 1)"

CMD ["python", "-u", "monitor.py"]
