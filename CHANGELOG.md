# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- CodeQL analysis for Python and GitHub Actions on pushes and pull requests to `main` and on a weekly schedule.
- Dependabot version updates for pip, Docker and GitHub Actions, with minor and patch updates grouped per ecosystem.
- README screenshots: SQL guard dry runs and an example client session.
- Roadmap items tracked as GitHub issues under the v0.2.0 milestone.

### Changed

- CI workflow runs with a read-only `GITHUB_TOKEN`.

## [0.1.0] - 2026-10-25

First public release of MCP Postgres Analyst.

### Added

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

[Unreleased]: https://github.com/AkibUllah/mcp-postgres-analyst/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/AkibUllah/mcp-postgres-analyst/releases/tag/v0.1.0
