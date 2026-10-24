"""Database backends: SQLite (stdlib) and PostgreSQL (psycopg 3), both strictly read-only.

Read-only is enforced here independently of the SQL guard:

* SQLite opens the file with ``mode=ro``, sets ``PRAGMA query_only`` and installs an authorizer
  that only permits reads and function calls.
* PostgreSQL runs every statement in a ``READ ONLY`` transaction with ``statement_timeout`` set
  and rolls back afterwards. Pair it with a role that only has ``SELECT`` grants.
"""

from __future__ import annotations

import logging
import re
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from pg_analyst.guard import is_function_blocked

logger = logging.getLogger(__name__)


class DatabaseError(Exception):
    """The database refused or failed to run a statement."""


class QueryTimeout(DatabaseError):
    """The statement exceeded the configured timeout and was cancelled."""


@dataclass(frozen=True)
class ColumnInfo:
    name: str
    type: str
    nullable: bool
    default: str | None = None
    primary_key: bool = False
    comment: str | None = None


@dataclass(frozen=True)
class ForeignKey:
    column: str
    references_table: str
    references_column: str


@dataclass(frozen=True)
class TableSummary:
    schema: str
    name: str
    row_estimate: int | None = None
    comment: str | None = None


@dataclass(frozen=True)
class TableInfo:
    schema: str
    name: str
    columns: list[ColumnInfo]
    foreign_keys: list[ForeignKey] = field(default_factory=list)
    indexes: list[str] = field(default_factory=list)
    row_estimate: int | None = None
    comment: str | None = None


@dataclass
class QueryOutput:
    columns: list[str]
    rows: list[list[Any]]
    has_more: bool


class Database(Protocol):
    dialect: str
    display_name: str

    def ping(self) -> bool: ...

    def list_tables(self) -> list[TableSummary]: ...

    def describe(self, schema: str, table: str) -> TableInfo | None: ...

    def execute(self, sql: str, *, max_rows: int, timeout_ms: int) -> QueryOutput: ...

    def explain(self, sql: str, *, timeout_ms: int) -> str: ...


# ---------------------------------------------------------------------------------------------
# SQLite
# ---------------------------------------------------------------------------------------------

_SQLITE_ALLOWED_ACTIONS = {
    sqlite3.SQLITE_SELECT,
    sqlite3.SQLITE_READ,
    sqlite3.SQLITE_FUNCTION,
    getattr(sqlite3, "SQLITE_RECURSIVE", 33),
}
_COLUMN_COMMENT_RE = re.compile(r'^\s*"?(?P<name>[A-Za-z_][A-Za-z0-9_]*)"?\s+[^-]*?--\s*(?P<c>.+)$')
_TABLE_COMMENT_RE = re.compile(r"create\s+table[^(]*\(\s*--\s*(?P<c>.+)$", re.I)


def _sqlite_authorizer(action: int, arg1: Any, arg2: Any, *_: Any) -> int:
    if action not in _SQLITE_ALLOWED_ACTIONS:
        return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_FUNCTION and is_function_blocked(str(arg2 or "")):
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def parse_sqlite_comments(ddl: str) -> tuple[str | None, dict[str, str]]:
    """Read ``-- comments`` from a CREATE TABLE statement (SQLite keeps the original text)."""
    table_comment: str | None = None
    columns: dict[str, str] = {}
    for index, line in enumerate(ddl.splitlines()):
        if index == 0:
            match = _TABLE_COMMENT_RE.search(line)
            if match:
                table_comment = match.group("c").strip()
            continue
        match = _COLUMN_COMMENT_RE.match(line)
        if match:
            columns[match.group("name").lower()] = match.group("c").strip()
    return table_comment, columns


class SQLiteDatabase:
    dialect = "sqlite"

    def __init__(self, path: Path) -> None:
        self.path = path
        self.display_name = f"SQLite ({path.name})"

    def _connect(self, *, guarded: bool) -> sqlite3.Connection:
        if not self.path.exists():
            raise DatabaseError(
                f"SQLite file {self.path} does not exist; run `python scripts/seed_demo.py` first"
            )
        conn = sqlite3.connect(
            f"file:{self.path.resolve()}?mode=ro", uri=True, check_same_thread=False
        )
        conn.execute("PRAGMA query_only = ON")
        if guarded:
            conn.set_authorizer(_sqlite_authorizer)
        return conn

    def ping(self) -> bool:
        try:
            with _closing(self._connect(guarded=False)) as conn:
                conn.execute("SELECT 1").fetchone()
            return True
        except (sqlite3.Error, DatabaseError):
            return False

    def list_tables(self) -> list[TableSummary]:
        with _closing(self._connect(guarded=False)) as conn:
            rows = conn.execute(
                "SELECT name, type, sql FROM sqlite_master "
                "WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' ORDER BY name"
            ).fetchall()
            result = []
            for name, _kind, ddl in rows:
                count = conn.execute(f'SELECT count(*) FROM "{name}"').fetchone()[0]
                comment, _ = parse_sqlite_comments(ddl or "")
                result.append(TableSummary("main", name, int(count), comment))
            return result

    def describe(self, schema: str, table: str) -> TableInfo | None:
        with _closing(self._connect(guarded=False)) as conn:
            found = conn.execute(
                "SELECT name, sql FROM sqlite_master WHERE type IN ('table','view') "
                "AND lower(name) = lower(?)",
                (table,),
            ).fetchone()
            if not found:
                return None
            name, ddl = found
            table_comment, comments = parse_sqlite_comments(ddl or "")
            quoted = name.replace('"', '""')
            columns = [
                ColumnInfo(
                    name=row[1],
                    type=row[2] or "",
                    nullable=not row[3] and not row[5],
                    default=row[4],
                    primary_key=bool(row[5]),
                    comment=comments.get(row[1].lower()),
                )
                for row in conn.execute(f'PRAGMA table_info("{quoted}")')
            ]
            fks = [
                ForeignKey(column=row[3], references_table=row[2], references_column=row[4])
                for row in conn.execute(f'PRAGMA foreign_key_list("{quoted}")')
            ]
            indexes = [
                row[1]
                for row in conn.execute(f'PRAGMA index_list("{quoted}")')
                if not str(row[1]).startswith("sqlite_autoindex")
            ]
            count = conn.execute(f'SELECT count(*) FROM "{quoted}"').fetchone()[0]
            return TableInfo("main", name, columns, fks, indexes, int(count), table_comment)

    def _run(self, sql: str, timeout_ms: int, fetch: int | None) -> tuple[list[str], list, bool]:
        conn = self._connect(guarded=True)
        deadline = time.monotonic() + timeout_ms / 1000
        conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 5_000)
        try:
            cursor = conn.execute(sql)
            columns = [d[0] for d in cursor.description or []]
            rows = cursor.fetchmany(fetch + 1) if fetch is not None else cursor.fetchall()
        except sqlite3.OperationalError as exc:
            if "interrupted" in str(exc).lower():
                raise QueryTimeout(f"query exceeded {timeout_ms} ms and was cancelled") from exc
            raise DatabaseError(str(exc)) from exc
        except sqlite3.DatabaseError as exc:
            raise DatabaseError(str(exc)) from exc
        finally:
            conn.close()
        has_more = fetch is not None and len(rows) > fetch
        if fetch is not None:
            rows = rows[:fetch]
        return columns, [list(r) for r in rows], has_more

    def execute(self, sql: str, *, max_rows: int, timeout_ms: int) -> QueryOutput:
        columns, rows, has_more = self._run(sql, timeout_ms, max_rows)
        return QueryOutput(columns, rows, has_more)

    def explain(self, sql: str, *, timeout_ms: int) -> str:
        _, rows, _ = self._run(f"EXPLAIN QUERY PLAN {sql}", timeout_ms, None)
        depth: dict[int, int] = {0: 0}
        lines = []
        for node_id, parent, _unused, detail in rows:
            level = depth.get(parent, 0) + 1
            depth[node_id] = level
            lines.append("  " * (level - 1) + f"-> {detail}")
        return "\n".join(lines)


class _closing:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def __enter__(self) -> sqlite3.Connection:
        return self.conn

    def __exit__(self, *_: object) -> None:
        self.conn.close()


# ---------------------------------------------------------------------------------------------
# PostgreSQL
# ---------------------------------------------------------------------------------------------

_PG_TABLES = """
SELECT n.nspname, c.relname, c.reltuples::bigint, obj_description(c.oid, 'pg_class')
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'v', 'm', 'p') AND n.nspname = ANY(%s)
ORDER BY 1, 2
"""

_PG_COLUMNS = """
SELECT a.attname,
       format_type(a.atttypid, a.atttypmod),
       NOT a.attnotnull,
       pg_get_expr(d.adbin, d.adrelid),
       EXISTS (SELECT 1 FROM pg_index i
               WHERE i.indrelid = c.oid AND i.indisprimary AND a.attnum = ANY(i.indkey)),
       col_description(c.oid, a.attnum),
       c.reltuples::bigint,
       obj_description(c.oid, 'pg_class'),
       c.relname
FROM pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_attrdef d ON d.adrelid = c.oid AND d.adnum = a.attnum
WHERE n.nspname = %s AND lower(c.relname) = lower(%s) AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY a.attnum
"""

_PG_FKS = """
SELECT a.attname, cf.relname, af.attname
FROM pg_constraint con
JOIN pg_class c ON c.oid = con.conrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_class cf ON cf.oid = con.confrelid
CROSS JOIN LATERAL unnest(con.conkey, con.confkey) AS k(attnum, fattnum)
JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum
JOIN pg_attribute af ON af.attrelid = cf.oid AND af.attnum = k.fattnum
WHERE con.contype = 'f' AND n.nspname = %s AND c.relname = %s
ORDER BY 1
"""

_PG_INDEXES = "SELECT indexname FROM pg_indexes WHERE schemaname = %s AND tablename = %s ORDER BY 1"


class PostgresDatabase:
    dialect = "postgres"

    def __init__(self, url: str, schemas: list[str]) -> None:
        try:
            import psycopg  # noqa: F401
        except ImportError as exc:  # pragma: no cover - depends on install extras
            raise DatabaseError(
                "PostgreSQL support needs psycopg: pip install 'mcp-postgres-analyst[postgres]'"
            ) from exc
        self.url = url
        self.schemas = schemas or ["public"]
        self.display_name = "PostgreSQL"

    def _connect(self, timeout_ms: int):  # type: ignore[no-untyped-def]
        import psycopg

        try:
            conn = psycopg.connect(
                self.url,
                connect_timeout=5,
                options=(
                    f"-c statement_timeout={int(timeout_ms)} "
                    "-c default_transaction_read_only=on "
                    "-c idle_in_transaction_session_timeout=30000"
                ),
            )
        except psycopg.Error as exc:
            raise DatabaseError(f"could not connect to PostgreSQL: {exc}") from exc
        conn.read_only = True
        return conn

    def _query(
        self, sql: str, params: tuple | None, timeout_ms: int, fetch: int | None
    ) -> tuple[list[str], list[list[Any]], bool]:
        import psycopg
        from psycopg import errors

        conn = self._connect(timeout_ms)
        try:
            with conn.cursor() as cur:
                cur.execute(sql, params)  # type: ignore[arg-type]
                columns = [d.name for d in cur.description or []]
                rows = cur.fetchmany(fetch + 1) if fetch is not None else cur.fetchall()
            conn.rollback()
        except errors.QueryCanceled as exc:
            raise QueryTimeout(f"query exceeded {timeout_ms} ms and was cancelled") from exc
        except psycopg.Error as exc:
            message = (exc.diag.message_primary if exc.diag else None) or str(exc)
            raise DatabaseError(message) from exc
        finally:
            conn.close()
        has_more = fetch is not None and len(rows) > fetch
        if fetch is not None:
            rows = rows[:fetch]
        return columns, [list(r) for r in rows], has_more

    def ping(self) -> bool:
        try:
            self._query("SELECT 1", None, 2000, 1)
            return True
        except DatabaseError:
            return False

    def list_tables(self) -> list[TableSummary]:
        _, rows, _ = self._query(_PG_TABLES, (self.schemas,), 10_000, None)
        return [
            TableSummary(schema, name, int(est) if est is not None and est >= 0 else None, comment)
            for schema, name, est, comment in rows
        ]

    def describe(self, schema: str, table: str) -> TableInfo | None:
        if schema not in self.schemas:
            return None
        _, rows, _ = self._query(_PG_COLUMNS, (schema, table), 10_000, None)
        if not rows:
            return None
        relname = rows[0][8]
        columns = [
            ColumnInfo(
                name=r[0], type=r[1], nullable=r[2], default=r[3], primary_key=r[4], comment=r[5]
            )
            for r in rows
        ]
        _, fk_rows, _ = self._query(_PG_FKS, (schema, relname), 10_000, None)
        _, idx_rows, _ = self._query(_PG_INDEXES, (schema, relname), 10_000, None)
        estimate = rows[0][6]
        return TableInfo(
            schema=schema,
            name=relname,
            columns=columns,
            foreign_keys=[ForeignKey(*r) for r in fk_rows],
            indexes=[r[0] for r in idx_rows],
            row_estimate=int(estimate) if estimate is not None and estimate >= 0 else None,
            comment=rows[0][7],
        )

    def execute(self, sql: str, *, max_rows: int, timeout_ms: int) -> QueryOutput:
        columns, rows, has_more = self._query(sql, None, timeout_ms, max_rows)
        return QueryOutput(columns, rows, has_more)

    def explain(self, sql: str, *, timeout_ms: int) -> str:
        _, rows, _ = self._query(f"EXPLAIN {sql}", None, timeout_ms, None)
        return "\n".join(str(r[0]) for r in rows)


# ---------------------------------------------------------------------------------------------


def sqlite_path_from_url(url: str) -> Path:
    """``sqlite:///data/demo.db`` -> ``data/demo.db``; ``sqlite:////abs/x.db`` -> ``/abs/x.db``."""
    rest = url[len("sqlite:///") :] if url.startswith("sqlite:///") else url[len("sqlite:") :]
    if not rest:
        raise ValueError(f"invalid SQLite URL {url!r}")
    return Path(rest)


def connect(url: str, schemas: list[str] | None = None) -> Database:
    if url.startswith("sqlite:"):
        return SQLiteDatabase(sqlite_path_from_url(url))
    if url.startswith(("postgresql://", "postgres://", "postgresql+psycopg://")):
        return PostgresDatabase(
            url.replace("postgresql+psycopg://", "postgresql://"), schemas or []
        )
    raise ValueError(f"unsupported DATABASE_URL scheme: {url.split(':', 1)[0]}")
