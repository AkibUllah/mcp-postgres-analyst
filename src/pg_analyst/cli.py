"""Command line: ``mcp-pg-analyst serve | check | seed | audit``."""

from __future__ import annotations

import argparse
import json
import logging
import sys

from pg_analyst import __version__
from pg_analyst.config import Settings


def _configure_logging(level: str) -> None:
    # stdout belongs to the stdio transport; logs always go to stderr.
    logging.basicConfig(
        level=level,
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def cmd_serve(args: argparse.Namespace, settings: Settings) -> int:
    from pg_analyst.server import create_server

    server, service = create_server(settings)
    logging.getLogger("pg_analyst").info(
        "serving %s over %s (policy=%s, audit=%s)",
        service.db.display_name,
        args.transport,
        settings.policy_path,
        settings.audit_log_path,
    )
    if args.transport == "stdio":
        server.run("stdio")
        return 0

    import uvicorn

    from pg_analyst.http import create_http_app

    host = args.host or settings.mcp_host
    port = args.port or settings.mcp_port
    settings = settings.model_copy(update={"mcp_host": host, "mcp_port": port})
    if host not in ("127.0.0.1", "localhost", "::1") and not settings.mcp_http_token:
        logging.getLogger("pg_analyst").warning(
            "binding %s without MCP_HTTP_TOKEN: anyone who can reach this port can query", host
        )
    app = create_http_app(server, settings)
    uvicorn.run(app, host=host, port=port, log_level=settings.log_level.lower())
    return 0


def cmd_check(args: argparse.Namespace, settings: Settings) -> int:
    from pg_analyst.guard import QueryRejected
    from pg_analyst.service import AnalystService, format_sql

    service = AnalystService(settings.model_copy(update={"audit_log_path": None}))
    try:
        guarded = service.check_sql(args.sql, limit=args.limit)
    except QueryRejected as exc:
        print(f"REJECTED {exc.code}: {exc.message}")
        return 1
    print("ALLOWED")
    print(format_sql(guarded.sql, service.db.dialect))
    note = " (rewritten; one extra row is fetched to detect truncation)"
    print(
        f"-- tables: {', '.join(guarded.tables) or '-'}; limit: {guarded.limit}"
        f"{note if guarded.limit_rewritten else ''}"
    )
    if guarded.tainted_outputs:
        derived = ", ".join(
            f"{k} ({v.strategy})" for k, v in sorted(guarded.tainted_outputs.items())
        )
        print(f"-- masked derived columns: {derived}")
    return 0


def cmd_seed(args: argparse.Namespace, settings: Settings) -> int:
    from pathlib import Path

    from pg_analyst.db import sqlite_path_from_url
    from pg_analyst.demo import seed_postgres, seed_sqlite

    url = args.database_url or settings.database_url
    if url.startswith("sqlite:"):
        path = Path(sqlite_path_from_url(url))
        if path.exists() and not args.force:
            print(f"{path} already exists (use --force to rebuild)")
            return 0
        counts = seed_sqlite(path, force=args.force)
    else:
        counts = seed_postgres(url)
    print("seeded: " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    return 0


def cmd_audit(args: argparse.Namespace, settings: Settings) -> int:
    from pg_analyst.audit import AuditLog

    for entry in AuditLog(settings.audit_log_path).tail(args.n):
        print(json.dumps(entry, ensure_ascii=False))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcp-pg-analyst", description=__doc__)
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the MCP server")
    serve.add_argument("--transport", choices=("stdio", "http"), default="stdio")
    serve.add_argument("--host", default=None, help="HTTP bind address (default MCP_HOST)")
    serve.add_argument("--port", type=int, default=None, help="HTTP port (default MCP_PORT)")
    serve.set_defaults(func=cmd_serve)

    check = sub.add_parser("check", help="dry-run the SQL guard on a statement")
    check.add_argument("sql")
    check.add_argument("--limit", type=int, default=None)
    check.set_defaults(func=cmd_check)

    seed = sub.add_parser("seed", help="create the demo shop database")
    seed.add_argument("--database-url", default=None)
    seed.add_argument("--force", action="store_true")
    seed.set_defaults(func=cmd_seed)

    audit = sub.add_parser("audit", help="print the last audit log entries")
    audit.add_argument("-n", type=int, default=20)
    audit.set_defaults(func=cmd_audit)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = Settings()
    _configure_logging(settings.log_level)
    return int(args.func(args, settings))


if __name__ == "__main__":
    sys.exit(main())
