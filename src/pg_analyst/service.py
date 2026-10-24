"""The analyst service: every tool goes through rate limiting, the guard, masking and the audit log.

This layer is transport-agnostic and synchronous; the MCP server wraps it and runs calls in a
worker thread so the event loop never blocks on the database.
"""

from __future__ import annotations

import base64
import datetime as dt
import decimal
import json
import logging
import threading
import time
import uuid
from collections.abc import Callable
from typing import Any, TypeVar

import sqlglot
from sqlglot import exp

from pg_analyst.audit import AuditLog
from pg_analyst.config import Settings
from pg_analyst.db import Database, DatabaseError, QueryTimeout, TableInfo, TableSummary, connect
from pg_analyst.guard import GuardedQuery, QueryRejected, SqlGuard
from pg_analyst.masking import apply_masks, plan_masks
from pg_analyst.models import (
    ColumnEntry,
    ColumnMatch,
    ColumnSearchResult,
    ExplainResult,
    ForeignKeyEntry,
    QueryResult,
    SchemaEntry,
    SchemaListing,
    TableDescription,
    TableEntry,
)
from pg_analyst.policy import Policy, SavedQuery, load_policy
from pg_analyst.ratelimit import RateLimited, ToolRateLimiter

logger = logging.getLogger(__name__)

T = TypeVar("T")

MAX_SAMPLE_ROWS = 50
CATALOG_TTL_SECONDS = 300.0


class AnalystError(Exception):
    """A failure reported back to the MCP client as a tool error (``code: message``)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def to_json_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, decimal.Decimal):
        # numeric(12,2) money becomes a plain JSON number; huge or special values stay exact.
        return float(value) if value.is_finite() and abs(value) < 10**15 else str(value)
    if isinstance(value, (dt.datetime, dt.date, dt.time)):
        return value.isoformat()
    if isinstance(value, dt.timedelta):
        return str(value)
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if len(raw) <= 32:
            return "base64:" + base64.b64encode(raw).decode()
        return f"<{len(raw)} bytes>"
    if isinstance(value, (list, tuple)):
        return [to_json_value(v) for v in value]
    if isinstance(value, dict):
        return {str(k): to_json_value(v) for k, v in value.items()}
    return str(value)


class AnalystService:
    def __init__(
        self,
        settings: Settings,
        *,
        database: Database | None = None,
        policy: Policy | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.settings = settings
        self.db = database or connect(settings.database_url, settings.schemas)
        self.policy = policy if policy is not None else load_policy(settings.policy_path)
        self.guard = SqlGuard(
            self.db.dialect,
            self.policy,
            default_limit=settings.effective_default_limit,
            max_rows=settings.max_rows,
        )
        self.limiter = ToolRateLimiter(self.policy, clock)
        self.audit = AuditLog(settings.audit_log_path)
        self._clock = clock
        self._catalog_lock = threading.Lock()
        self._catalog: dict[str, TableInfo] | None = None
        self._catalog_at = 0.0

    # -- plumbing ---------------------------------------------------------------------------

    def _call(self, tool: str, audit_args: dict[str, Any], fn: Callable[[], T]) -> T:
        started = time.perf_counter()
        status, extra = "ok", {}
        try:
            self.limiter.check(tool)
            result = fn()
            if isinstance(result, QueryResult):
                extra = {
                    "sql": result.sql,
                    "rows": result.row_count,
                    "truncated": result.truncated_reason,
                    "masked": result.masked_columns or None,
                }
            return result
        except RateLimited as exc:
            status, extra = "rate_limited", {"reason": str(exc)}
            raise AnalystError("rate_limited", str(exc)) from exc
        except QueryRejected as exc:
            status, extra = "rejected", {"code": exc.code, "reason": exc.message}
            raise AnalystError(exc.code, exc.message) from exc
        except QueryTimeout as exc:
            status, extra = "timeout", {"reason": str(exc)}
            raise AnalystError("timeout", str(exc)) from exc
        except DatabaseError as exc:
            status, extra = "error", {"reason": str(exc)}
            raise AnalystError("database_error", str(exc)) from exc
        except AnalystError as exc:
            status, extra = "rejected", {"code": exc.code, "reason": exc.message}
            raise
        finally:
            elapsed = round((time.perf_counter() - started) * 1000, 2)
            self.audit.record(tool, status, duration_ms=elapsed, args=audit_args, **extra)

    def _visible(self, schema: str, table: str) -> bool:
        return not self.guard.table_blocked(table.lower(), schema.lower())

    def _tables(self) -> list[TableSummary]:
        return [t for t in self.db.list_tables() if self._visible(t.schema, t.name)]

    def catalog(self, *, refresh: bool = False) -> dict[str, TableInfo]:
        """Visible tables keyed by ``schema.table`` (lower case), cached for a few minutes."""
        with self._catalog_lock:
            stale = self._clock() - self._catalog_at > CATALOG_TTL_SECONDS
            if self._catalog is None or stale or refresh:
                catalog: dict[str, TableInfo] = {}
                for summary in self._tables():
                    info = self.db.describe(summary.schema, summary.name)
                    if info is not None:
                        catalog[f"{info.schema}.{info.name}".lower()] = info
                self._catalog = catalog
                self._catalog_at = self._clock()
            return self._catalog

    def _guard_catalog(self) -> dict[str, set[str]]:
        columns: dict[str, set[str]] = {}
        for info in self.catalog().values():
            columns.setdefault(info.name.lower(), set()).update(
                c.name.lower() for c in info.columns
            )
        return columns

    def resolve_table(self, name: str) -> TableInfo:
        name = name.strip().strip('"')
        schema, _, table = name.rpartition(".")
        catalog = self.catalog()
        if schema:
            info = catalog.get(f"{schema}.{table}".lower())
        else:
            matches = [i for i in catalog.values() if i.name.lower() == table.lower()]
            if len(matches) > 1:
                options = ", ".join(f"{i.schema}.{i.name}" for i in matches)
                raise AnalystError(
                    "ambiguous_table", f"{table!r} exists in several schemas: {options}"
                )
            info = matches[0] if matches else None
        if info is None:
            raise AnalystError(
                "unknown_table", f"table {name!r} does not exist or is not accessible"
            )
        return info

    def _mask_name(self, column: str) -> str | None:
        rule = self.policy.mask_rule_for(column)
        return rule.strategy if rule else None

    def _hidden_names(self) -> set[str]:
        return {column for _, column in self.policy.blocked_column_pairs()}

    def _run_guarded(self, guarded: GuardedQuery) -> QueryResult:
        started = time.perf_counter()
        output = self.db.execute(
            guarded.sql, max_rows=guarded.limit, timeout_ms=self.settings.statement_timeout_ms
        )
        keep = [
            i for i, name in enumerate(output.columns) if name.lower() not in guarded.hidden_outputs
        ]
        hidden = [output.columns[i] for i in range(len(output.columns)) if i not in keep]
        columns = [output.columns[i] for i in keep]
        rows = [[row[i] for i in keep] for row in output.rows]

        plan = plan_masks(columns, self.policy, guarded.tainted_outputs)
        rows = apply_masks(rows, plan)
        rows = [[to_json_value(v) for v in row] for row in rows]

        truncated_reason = "row_limit" if output.has_more else None
        budget = self.settings.max_result_bytes
        used = 0
        for index, row in enumerate(rows):
            used += len(json.dumps(row, ensure_ascii=False, default=str)) + 1
            if used > budget:
                rows = rows[:index]
                truncated_reason = "max_result_bytes"
                break

        return QueryResult(
            sql=guarded.sql,
            columns=columns,
            rows=rows,
            row_count=len(rows),
            truncated=truncated_reason is not None,
            truncated_reason=truncated_reason,
            limit=guarded.limit,
            limit_rewritten=guarded.limit_rewritten,
            masked_columns=[columns[i] for i in sorted(plan)],
            hidden_columns=hidden,
            elapsed_ms=round((time.perf_counter() - started) * 1000, 2),
        )

    # -- tools ------------------------------------------------------------------------------

    def list_schemas(self) -> SchemaListing:
        def run() -> SchemaListing:
            grouped: dict[str, list[TableEntry]] = {}
            for t in self._tables():
                grouped.setdefault(t.schema, []).append(
                    TableEntry(name=t.name, row_estimate=t.row_estimate, comment=t.comment)
                )
            return SchemaListing(
                database=self.db.display_name,
                dialect=self.db.dialect,
                schemas=[SchemaEntry(name=s, tables=ts) for s, ts in grouped.items()],
            )

        return self._call("list_schemas", {}, run)

    def describe_table(self, table: str) -> TableDescription:
        def run() -> TableDescription:
            info = self.resolve_table(table)
            hidden = {
                c for t, c in self.policy.blocked_column_pairs() if t in ("*", info.name.lower())
            }
            return TableDescription(
                schema_name=info.schema,
                table=info.name,
                comment=info.comment,
                row_estimate=info.row_estimate,
                columns=[
                    ColumnEntry(
                        name=c.name,
                        type=c.type,
                        nullable=c.nullable,
                        default=c.default,
                        primary_key=c.primary_key,
                        comment=c.comment,
                        masking=self._mask_name(c.name),
                    )
                    for c in info.columns
                    if c.name.lower() not in hidden
                ],
                foreign_keys=[
                    ForeignKeyEntry(
                        column=fk.column, references=f"{fk.references_table}.{fk.references_column}"
                    )
                    for fk in info.foreign_keys
                ],
                indexes=info.indexes,
            )

        return self._call("describe_table", {"table": table}, run)

    def run_query(self, sql: str, limit: int | None = None) -> QueryResult:
        def run() -> QueryResult:
            guarded = self.guard.check(sql, limit=limit, catalog=self._guard_catalog())
            return self._run_guarded(guarded)

        return self._call("run_query", {"sql": sql, "limit": limit}, run)

    def sample_rows(self, table: str, n: int = 5) -> QueryResult:
        def run() -> QueryResult:
            if n < 1 or n > MAX_SAMPLE_ROWS:
                raise AnalystError("bad_limit", f"n must be between 1 and {MAX_SAMPLE_ROWS}")
            info = self.resolve_table(table)
            target = exp.table_(info.name, db=info.schema, quoted=True)
            sql = exp.select("*").from_(target).sql(dialect=self.db.dialect)
            guarded = self.guard.check(sql, limit=n, catalog=self._guard_catalog())
            return self._run_guarded(guarded)

        return self._call("sample_rows", {"table": table, "n": n}, run)

    def explain_query(self, sql: str) -> ExplainResult:
        def run() -> ExplainResult:
            guarded = self.guard.check(sql, catalog=self._guard_catalog())
            plan = self.db.explain(guarded.sql, timeout_ms=self.settings.statement_timeout_ms)
            return ExplainResult(sql=guarded.sql, plan=plan)

        return self._call("explain_query", {"sql": sql}, run)

    def find_columns(self, query: str, limit: int = 50) -> ColumnSearchResult:
        def run() -> ColumnSearchResult:
            needle = query.strip().lower()
            if len(needle) < 2:
                raise AnalystError("bad_query", "search text must be at least 2 characters")
            hidden = self._hidden_names()
            matches: list[ColumnMatch] = []
            for info in self.catalog().values():
                for column in info.columns:
                    if column.name.lower() in hidden:
                        continue
                    haystack = f"{column.name} {column.comment or ''}".lower()
                    if needle in haystack:
                        matches.append(
                            ColumnMatch(
                                schema_name=info.schema,
                                table=info.name,
                                column=column.name,
                                type=column.type,
                                comment=column.comment,
                                masking=self._mask_name(column.name),
                            )
                        )
            return ColumnSearchResult(query=query, matches=matches[: max(1, min(limit, 200))])

        return self._call("find_columns", {"query": query}, run)

    def run_saved_query(self, name: str) -> QueryResult:
        def run() -> QueryResult:
            saved = self.policy.saved_query(name)
            if saved is None:
                known = ", ".join(q.name for q in self.policy.saved_queries) or "none"
                raise AnalystError("unknown_query", f"no saved query {name!r} (available: {known})")
            guarded = self.guard.check(saved.sql, catalog=self._guard_catalog())
            return self._run_guarded(guarded)

        return self._call("run_saved_query", {"name": name}, run)

    # -- resources --------------------------------------------------------------------------

    def schema_overview_markdown(self) -> str:
        lines = [f"# Schema overview ({self.db.display_name})", ""]
        hidden = self._hidden_names()
        for key, info in sorted(self.catalog().items()):
            title = f"## {key}"
            if info.row_estimate is not None:
                title += f" (~{info.row_estimate:,} rows)"
            lines.append(title)
            if info.comment:
                lines.append(info.comment)
            lines.append("")
            lines.append("| column | type | notes |")
            lines.append("| --- | --- | --- |")
            fks = {
                fk.column: f"{fk.references_table}.{fk.references_column}"
                for fk in info.foreign_keys
            }
            for c in info.columns:
                if c.name.lower() in hidden:
                    continue
                notes = []
                if c.primary_key:
                    notes.append("PK")
                if c.name in fks:
                    notes.append(f"FK -> {fks[c.name]}")
                if (strategy := self._mask_name(c.name)) is not None:
                    notes.append(f"masked ({strategy})")
                if c.comment:
                    notes.append(c.comment)
                lines.append(f"| {c.name} | {c.type} | {'; '.join(notes)} |")
            lines.append("")
        return "\n".join(lines).rstrip() + "\n"

    def saved_queries(self) -> list[SavedQuery]:
        return list(self.policy.saved_queries)

    def check_sql(self, sql: str, limit: int | None = None) -> GuardedQuery:
        """Dry-run the guard (CLI ``check``); no execution, no audit entry."""
        return self.guard.check(sql, limit=limit, catalog=self._guard_catalog())


def format_sql(sql: str, dialect: str) -> str:
    return sqlglot.transpile(sql, read=dialect, write=dialect, pretty=True)[0]
