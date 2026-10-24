#!/usr/bin/env bash
# Codespaces start hook: run the MCP server over Streamable HTTP against the SQLite demo database.
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p logs
[ -f data/demo.db ] || python scripts/seed_demo.py

# Accept the forwarded *.app.github.dev host as well as localhost (DNS-rebinding protection).
if [ -n "${CODESPACE_NAME:-}" ]; then
  export MCP_ALLOWED_HOSTS="${CODESPACE_NAME}-8765.${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN:-app.github.dev}"
fi

pkill -f "mcp-pg-analyst serve" 2>/dev/null || true
nohup mcp-pg-analyst serve --transport http --port 8765 > logs/server.log 2>&1 &

for _ in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:8765/health >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

cat <<'MSG'

mcp-postgres-analyst is running (SQLite demo shop, policy in config/policy.yaml).
  MCP endpoint:   http://127.0.0.1:8765/mcp   (forwarded port 8765)
  Try a client:   python examples/client.py --url http://127.0.0.1:8765/mcp
  Inspector UI:   npx -y @modelcontextprotocol/inspector   -> open forwarded port 6274,
                  transport "Streamable HTTP", URL http://127.0.0.1:8765/mcp
  Guard dry-run:  mcp-pg-analyst check "select email, count(*) from customers group by 1"
  Audit log:      tail -f logs/audit.jsonl
MSG
