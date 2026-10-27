# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN addgroup --system app && adduser --system --ingroup app app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --upgrade pip && pip install ".[postgres]"

COPY config ./config
COPY scripts ./scripts

# Bake the SQLite demo database into the image so it runs with zero configuration.
RUN python scripts/seed_demo.py --database-url sqlite:////app/data/demo.db \
    && mkdir -p /app/logs \
    && chown -R app:app /app/data /app/logs

ENV DATABASE_URL=sqlite:////app/data/demo.db \
    POLICY_PATH=/app/config/policy.yaml \
    AUDIT_LOG_PATH=/app/logs/audit.jsonl \
    MCP_HOST=0.0.0.0 \
    MCP_PORT=8765

USER app
EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD python -c "import os,urllib.request,sys; port=os.environ.get('PORT') or os.environ.get('MCP_PORT','8765'); sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{port}/health').status == 200 else 1)"

CMD ["mcp-pg-analyst", "serve", "--transport", "http"]
