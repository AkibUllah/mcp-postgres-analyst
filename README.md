<!-- topics: mcp, model-context-protocol, postgresql, sqlite, sql, sqlglot, data-masking, llm-tools, python, ai-safety -->
# MCP Postgres Analyst

A Model Context Protocol server that lets AI assistants explore and query a PostgreSQL or SQLite database read-only, behind a SQL allow-list, automatic row limits, timeouts, column masking, rate limits and a JSONL audit log.

[![CI](https://github.com/AkibUllah/mcp-postgres-analyst/actions/workflows/ci.yml/badge.svg)](https://github.com/AkibUllah/mcp-postgres-analyst/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11-blue)
![MCP SDK](https://img.shields.io/badge/mcp%20SDK-2.x-6e56cf)
![License](https://img.shields.io/badge/license-MIT-green)

## Try it live

| | |
|---|---|
| Run in your browser | [![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/AkibUllah/mcp-postgres-analyst?quickstart=1) — installs the package, seeds the SQLite demo shop and starts the server over Streamable HTTP on port 8765. Run `python examples/client.py --url http://127.0.0.1:8765/mcp` in the terminal, or `npx -y @modelcontextprotocol/inspector` and open forwarded port 6274 to click through tools, resources and prompts. |
| One-click deploy | [![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/AkibUllah/mcp-postgres-analyst) — `render.yaml` runs the Docker image with the demo database baked in; `MCP_HTTP_TOKEN` is generated, send it as `Authorization: Bearer <token>` to `https://<service>.onrender.com/mcp`. |
| Local | `pip install -e ".[dev]" && python scripts/seed_demo.py && python examples/client.py` (no database server needed), or `docker compose up` for PostgreSQL |

There is no GitHub Pages site for this repo: an MCP server has no browser UI, and the Codespace gives you the real thing.

## Why this exists

Every team that connects an assistant to its database ends up with the same question from security: what stops it from running `DELETE`, reading password hashes, or pulling a whole customer table with phone numbers into a chat log? In payment and e-commerce systems I have worked on, the answer cannot be "the prompt says please". This server puts the controls in code: queries are parsed and validated before they reach the database, the database session itself is read-only, personal data is masked on the way out, and every call is written to an audit log that compliance can read.

## Features

- Seven MCP tools: `list_schemas`, `describe_table`, `sample_rows`, `run_query`, `explain_query`, `find_columns` (by name or comment) and `run_saved_query`, all with JSON schemas, structured output and read-only annotations
- Resources: `schema://overview` (Markdown data dictionary) and `queries://saved` / `queries://saved/{name}`; prompts: `analyse_table` and `write_report`
- SQL guard built on sqlglot: one statement only, `SELECT`/`WITH` only, no data-modifying CTEs, `SELECT INTO`, `FOR UPDATE`, `COPY`, `SET`, `PRAGMA`; blocked functions (`pg_sleep`, `dblink*`, `lo_*`, `pg_read_file`, `set_config`, `load_extension`, ...) and system tables (`pg_authid`, `pg_stat_activity`, ...)
- The database only ever receives SQL re-rendered from the validated AST, never the caller's raw text
- Automatic `LIMIT` injection and clamping (also replaces `LIMIT ALL`, sub-query limits and `FETCH FIRST`), plus row and byte caps on the result
- Statement timeout: `statement_timeout` on PostgreSQL, a progress-handler interrupt on SQLite
- Column masking from a YAML policy (`email`, `phone`, `last4`, `hash`, `redact`) that follows aliases, expressions, CTEs and derived tables; blocked columns disappear even from `SELECT *`; whole-row tricks like `row_to_json(c)` are rejected
- Per-tool token-bucket rate limits and an append-only JSONL audit log of every call (ok, rejected, timeout, rate limited)
- Both transports: stdio for desktop clients, Streamable HTTP with optional bearer token, DNS-rebinding protection and a `/health` endpoint
- Deterministic demo database (fictional Bangladeshi online shop: customers, products, orders, bKash/Nagad/card/COD payments) seeded identically into SQLite or PostgreSQL

## Architecture

```mermaid
flowchart LR
    subgraph Clients
        CD[Claude Desktop / Cursor / VS Code<br/>stdio]
        HC[Remote MCP client<br/>Streamable HTTP + bearer token]
    end
    CD --> S[MCPServer<br/>tools · resources · prompts]
    HC --> AUTH[BearerTokenMiddleware<br/>/health is public] --> S
    S --> SVC[AnalystService]
    SVC --> RL[ToolRateLimiter<br/>token bucket per tool]
    SVC --> G[SqlGuard<br/>sqlglot AST checks<br/>LIMIT rewrite · lineage]
    G --> DB[(Database adapter)]
    DB --> PG[(PostgreSQL<br/>READ ONLY txn<br/>statement_timeout)]
    DB --> SQ[(SQLite<br/>mode=ro · authorizer<br/>progress interrupt)]
    DB --> M[Masking<br/>name + lineage rules]
    M --> SVC
    SVC --> A[[audit.jsonl]]
    P[policy.yaml] -.-> G
    P -.-> M
    P -.-> RL
```

Key decisions:

- **Parse, validate, re-render.** The guard parses with the target dialect and executes `ast.sql()`, so comment tricks, stacked statements and dollar-quoted payloads cannot smuggle anything past the checks: what was validated is byte-for-byte what runs.
- **Defence in depth, not one wall.** Even if a query slipped through the guard, PostgreSQL runs it in a `READ ONLY` transaction under a `SELECT`-only role (compose creates `analyst_ro`, and the seed revokes payroll access at the database level too); SQLite opens the file `mode=ro` with an authorizer that denies anything but reads.
- **Masking follows lineage, not just column names.** `compute_taint` walks every projection to a fixed point, so `WITH x AS (SELECT email AS contact ...) SELECT upper(contact) AS shout FROM x` still masks `shout`. `count(...)` is exempt because it reveals a number, not the value.
- **One extra row.** When the guard writes the LIMIT it asks for `limit + 1` rows, so the result can say `truncated: row_limit` honestly instead of guessing.
- **Transport-agnostic core.** `AnalystService` is synchronous and knows nothing about MCP; the server runs it in a worker thread. Tests exercise it directly, through the SDK's in-process client, over real HTTP and over a stdio subprocess.

## Safety model

| Layer | What it stops | Where |
| --- | --- | --- |
| Statement allow-list | anything but one `SELECT` / `WITH ... SELECT`; DML inside CTEs; `SELECT INTO`; row locks | `guard.py` |
| Function / table block lists | sleeps, file access, remote connections, dynamic SQL, session changes; credential and activity catalogs; policy-listed tables | `guard.py`, `policy.yaml` |
| Column rules | explicit references to blocked columns; whole-row references; masked values in results | `guard.py`, `masking.py` |
| Result caps | runaway result sets (`MAX_ROWS`, `MAX_RESULT_BYTES`) | `guard.py`, `service.py` |
| Timeouts | long-running queries (`STATEMENT_TIMEOUT_MS`) | `db.py` |
| Read-only session | writes, DDL, `nextval` side effects, even if the guard were bypassed | `db.py`, `docker/initdb` |
| Rate limits | an agent loop hammering the database | `ratelimit.py` |
| Audit log | "what did it run?" questions afterwards | `audit.py` |

Known limits, stated plainly: masking hides values in results but a determined caller can still learn about a masked column through filters (`WHERE email LIKE 'a%'` changes the row count). Treat masking as protection against accidental exposure in transcripts, and keep truly secret columns in `blocked_columns` or out of the role's grants. Lineage is name-based across the query, so it can over-mask a same-named column from another table; it errs on the safe side.

## Tech Stack

| Area | Choice |
| --- | --- |
| Protocol | Official `mcp` Python SDK 2.x (`MCPServer`, `Client`, stdio + Streamable HTTP) |
| SQL analysis | sqlglot (PostgreSQL and SQLite dialects) |
| Databases | PostgreSQL 16 via psycopg 3; SQLite via the standard library |
| Config | pydantic-settings (env vars / `.env`), YAML policy validated with pydantic |
| HTTP | Starlette app from the SDK, uvicorn |
| Tests | pytest, anyio, httpx; PostgreSQL job in CI with a service container |
| Tooling | ruff, Docker, docker compose, GitHub Actions, Render blueprint, Codespaces |

## Quick Start

### Local, SQLite demo (no database server)

```bash
git clone https://github.com/AkibUllah/mcp-postgres-analyst.git
cd mcp-postgres-analyst
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
python scripts/seed_demo.py              # -> data/demo.db (300 customers, 2,000 orders)
python examples/client.py                # spawns the server over stdio and calls a few tools
mcp-pg-analyst serve --transport http    # or serve over Streamable HTTP on :8765/mcp
```

### Docker compose, PostgreSQL

```bash
cp .env.example .env                     # optional: set MCP_HTTP_TOKEN
docker compose up --build                # postgres + seed job + server on :8765
python examples/client.py --url http://127.0.0.1:8765/mcp --token "$MCP_HTTP_TOKEN"
```

The server connects as `analyst_ro`, a login role with `default_transaction_read_only = on` and `SELECT` grants only.

### Dry-run the guard

```console
$ mcp-pg-analyst check "WITH x AS (SELECT email AS contact FROM customers) SELECT upper(contact) AS shout FROM x LIMIT 5000"
ALLOWED
WITH x AS (
  SELECT
    email AS contact
  FROM customers
)
SELECT
  UPPER(contact) AS shout
FROM x
LIMIT 101
-- tables: customers; limit: 100 (rewritten; one extra row is fetched to detect truncation)
-- masked derived columns: contact (email), shout (email)

$ mcp-pg-analyst check "WITH gone AS (DELETE FROM orders RETURNING *) SELECT count(*) FROM gone"
REJECTED forbidden_statement: DELETE is not allowed
```

## Connecting clients

All stdio clients launch the same command. Use absolute paths; the server reads its settings from `env`.

**Claude Desktop** (`claude_desktop_config.json`) and **Cursor** (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "shop-analyst": {
      "command": "/home/you/mcp-postgres-analyst/.venv/bin/mcp-pg-analyst",
      "args": ["serve", "--transport", "stdio"],
      "env": {
        "DATABASE_URL": "sqlite:////home/you/mcp-postgres-analyst/data/demo.db",
        "POLICY_PATH": "/home/you/mcp-postgres-analyst/config/policy.yaml",
        "AUDIT_LOG_PATH": "/home/you/mcp-postgres-analyst/logs/audit.jsonl"
      }
    }
  }
}
```

**VS Code** (`.vscode/mcp.json`), stdio or HTTP:

```json
{
  "inputs": [{ "id": "token", "type": "promptString", "description": "MCP_HTTP_TOKEN", "password": true }],
  "servers": {
    "shop-analyst": {
      "type": "stdio",
      "command": "${workspaceFolder}/.venv/bin/mcp-pg-analyst",
      "args": ["serve"],
      "env": { "DATABASE_URL": "sqlite:///${workspaceFolder}/data/demo.db" }
    },
    "shop-analyst-http": {
      "type": "http",
      "url": "http://127.0.0.1:8765/mcp",
      "headers": { "Authorization": "Bearer ${input:token}" }
    }
  }
}
```

**HTTP mode** for remote clients: `MCP_HOST=0.0.0.0 MCP_HTTP_TOKEN=... mcp-pg-analyst serve --transport http`. Cursor takes `{"url": "...", "headers": {...}}` in place of `command`; any SDK client can connect as in [`examples/client.py`](examples/client.py). For a public hostname, also set `MCP_ALLOWED_HOSTS` so DNS-rebinding protection accepts it.

**MCP Inspector**: `make run-http` in one terminal, `npx -y @modelcontextprotocol/inspector` in another, then connect with transport "Streamable HTTP" to `http://127.0.0.1:8765/mcp`.

## API

### Tools

| Tool | Arguments | Returns |
| --- | --- | --- |
| `list_schemas` | – | schemas, tables, row estimates, table comments (blocked tables hidden) |
| `describe_table` | `table` (optionally `schema.table`) | columns with type, nullability, default, PK, comment and masking strategy; foreign keys; indexes |
| `sample_rows` | `table`, `n` (1–50, default 5) | first `n` rows, masked |
| `run_query` | `sql`, `limit` (optional, capped by `MAX_ROWS`) | `sql` actually executed, `columns`, `rows`, `row_count`, `truncated`/`truncated_reason`, `masked_columns`, `hidden_columns`, `elapsed_ms` |
| `explain_query` | `sql` | the database's plan (`EXPLAIN` / `EXPLAIN QUERY PLAN`), without executing |
| `find_columns` | `query` | columns whose name or comment contains the text |
| `run_saved_query` | `name` | result of a vetted query from the policy file |

Failures come back as tool errors with a stable code prefix, e.g. `not_select: ...`, `blocked_function: ...`, `timeout: ...`, `rate_limited: ...`, `unknown_table: ...`.

Example `run_query` result on the demo data (delivered revenue by customer city):

```json
{
  "sql": "SELECT c.city, COUNT(*) AS orders, ROUND(SUM(o.total_bdt), 2) AS revenue_bdt FROM orders AS o JOIN customers AS c ON c.id = o.customer_id WHERE o.status = 'delivered' GROUP BY c.city ORDER BY revenue_bdt DESC LIMIT 101",
  "columns": ["city", "orders", "revenue_bdt"],
  "rows": [["Dhaka", 482, 4112160.8], ["Chattogram", 188, 1624927.2], ["Sylhet", 109, 845776.5], ["Khulna", 100, 796680.5]],
  "row_count": 7, "truncated": false, "limit": 100, "limit_rewritten": true, "masked_columns": []
}
```

and with personal data involved:

```json
{
  "sql": "SELECT full_name, email, phone FROM customers WHERE city = 'Sylhet' ORDER BY id LIMIT 4",
  "rows": [["Rafiq Uddin", "r***@outlook.com", "+**********654"], ["Nusrat Rahman", "n***@gmail.com", "+**********103"]],
  "truncated": true, "truncated_reason": "row_limit", "masked_columns": ["email", "phone"]
}
```

### Resources and prompts

| URI / name | Content |
| --- | --- |
| `schema://overview` | Markdown data dictionary: every visible table, columns, keys, comments, masking notes |
| `queries://saved` | JSON list of saved queries (name, description, SQL) |
| `queries://saved/{name}` | SQL of one saved query |
| prompt `analyse_table(table)` | step-by-step profiling plan using the tools, aggregates only |
| prompt `write_report(question, audience)` | report structure with findings, caveats and an SQL appendix |

### Audit log

One JSON object per line in `AUDIT_LOG_PATH`; `mcp-pg-analyst audit -n 20` prints the tail.

```json
{"ts": "2026-10-24T18:07:11.722+00:00", "tool": "sample_rows", "status": "ok", "duration_ms": 2.15, "args": {"table": "customers", "n": 3}, "sql": "SELECT * FROM \"main\".\"customers\" LIMIT 4", "rows": 3, "masked": ["email", "phone", "nid", "address_line"]}
{"ts": "2026-10-24T18:07:11.743+00:00", "tool": "run_query", "status": "rejected", "duration_ms": 0.61, "args": {"sql": "DELETE FROM orders", "limit": null}, "code": "not_select", "reason": "only SELECT / WITH queries are allowed, got DELETE"}
```

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `DATABASE_URL` | `sqlite:///data/demo.db` | `sqlite:///relative.db`, `sqlite:////absolute.db` or `postgresql://user:pass@host/db` (`postgres://` accepted) |
| `ALLOWED_SCHEMAS` | `public` | PostgreSQL schemas exposed (comma separated) |
| `POLICY_PATH` | `config/policy.yaml` | masking, blocked tables/columns/functions, rate limits, saved queries; empty disables |
| `DEFAULT_LIMIT` / `MAX_ROWS` | `100` / `1000` | injected limit / hard cap per query |
| `MAX_RESULT_BYTES` | `262144` | result payload budget; rows beyond it are dropped and flagged |
| `STATEMENT_TIMEOUT_MS` | `5000` | per-statement timeout |
| `AUDIT_LOG_PATH` | `logs/audit.jsonl` | JSONL audit file; empty disables |
| `MCP_HOST` / `MCP_PORT` (or `PORT`) | `127.0.0.1` / `8765` | HTTP bind |
| `MCP_HTTP_TOKEN` | – | bearer token required on `/mcp` |
| `MCP_ALLOWED_HOSTS` | – | extra Host values for DNS-rebinding protection |

The policy file is documented inline in [`config/policy.yaml`](config/policy.yaml).

## Project Structure

```
mcp-postgres-analyst/
├── src/pg_analyst/
│   ├── server.py        # MCPServer: tools, resources, prompts, /health
│   ├── http.py          # Streamable HTTP app, bearer auth, DNS-rebinding settings
│   ├── service.py       # rate limit -> guard -> execute -> mask -> audit
│   ├── guard.py         # sqlglot validation, LIMIT rewrite, lineage for masking
│   ├── masking.py       # email / phone / last4 / hash / redact
│   ├── policy.py        # YAML policy models
│   ├── db.py            # SQLite and PostgreSQL adapters (read-only, timeouts, introspection)
│   ├── ratelimit.py     # token buckets per tool
│   ├── audit.py         # JSONL audit log
│   ├── demo.py          # deterministic demo shop data
│   └── cli.py           # serve | check | seed | audit
├── config/policy.yaml
├── scripts/seed_demo.py
├── examples/client.py   # SDK client over stdio or HTTP
├── docker/initdb/       # read-only role for PostgreSQL
├── tests/               # guard, masking, policy, service, MCP protocol, transports, PostgreSQL
├── Dockerfile · docker-compose.yml · render.yaml · .devcontainer/
└── Makefile · pyproject.toml
```

## Testing

```bash
make test        # 164 tests, no database server needed (~9 s)
make test-pg     # 4 more against PostgreSQL: docker compose up -d postgres first
make lint
```

Coverage by area:

- **Guard** (100+ cases across both dialects): stacked statements, DML/DDL, data-modifying CTEs, `SELECT INTO`, `FOR UPDATE`, `COPY`/`SET`/`PRAGMA`/`ATTACH`, comment and dollar-quote smuggling, blocked functions in every position (schema-qualified, quoted, upper-case, nested in CTEs and sub-queries), system and policy tables, blocked columns, whole-row references, LIMIT injection/clamping/`LIMIT ALL`/`FETCH FIRST`/unions/offsets, lineage through aliases and CTEs
- **Masking and policy**: every strategy, glob rules, taint-based masking, rate-limit parsing, token-bucket refill with a fake clock
- **Service**: masking of direct and derived columns, `SELECT *` hiding, row and byte caps, timeout cancellation, audit entries for ok/rejected/rate-limited calls, introspection, saved queries
- **Protocol**: tools, schemas and annotations, structured content, tool errors, resources, templates and prompts through the SDK's in-process `Client`
- **Transports**: Streamable HTTP through uvicorn on a free port (health, 401s, authenticated round trip) and stdio through a spawned subprocess
- **PostgreSQL** (CI service container): catalog comments, FK introspection, saved queries, `statement_timeout`, read-only transaction rejects DDL

## Roadmap

- Per-session rate limits and audit attribution in HTTP mode (session id / OAuth subject instead of one bucket per tool)
- OAuth 2.1 resource-server mode using the SDK's `TokenVerifier`, so HTTP deployments can drop the shared token
- Optional result sampling (`TABLESAMPLE`) for `sample_rows` on very large tables
- MySQL adapter (sqlglot already speaks the dialect; the adapter needs read-only session handling)
- Policy hot-reload on file change

## License

MIT, see [LICENSE](LICENSE).
