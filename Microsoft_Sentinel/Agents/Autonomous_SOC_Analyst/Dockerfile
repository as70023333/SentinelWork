FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SOC_HOST=0.0.0.0 \
    SOC_PORT=8080

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY soc_agent ./soc_agent
COPY config ./config
COPY demo_data ./demo_data

# Run as an unprivileged user; /app/data holds the SQLite incident store.
RUN useradd --system --uid 10001 soc && mkdir -p /app/data && chown soc /app/data
USER soc

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=3)" || exit 1

CMD ["python", "-m", "soc_agent", "serve"]
