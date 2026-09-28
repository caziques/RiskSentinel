FROM python:3.12-slim

WORKDIR /app

# System deps (sqlite3 CLI for healthcheck + debug)
RUN apt-get update && apt-get install -y --no-install-recommends \
        sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Ensure persistent-data directories exist and are writable
RUN mkdir -p instance uploads static \
    && adduser --disabled-password --gecos '' appuser \
    && chown -R appuser:appuser /app

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

USER appuser

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/login')" || exit 1

ENTRYPOINT ["/entrypoint.sh"]
