"""Static SQL guard: parse with sqlglot, allow a single read-only SELECT, rewrite its LIMIT.

The guard never forwards the caller's text to the database. It parses the text into an AST,
validates that AST, applies the row cap, and renders SQL *from the validated AST*. Whatever
the database executes is therefore exactly what was checked here.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError, TokenError

from pg_analyst.policy import MaskRule, Policy

# sqlglot logs a warning when it falls back to an opaque Command node; we reject those anyway.
logging.getLogger("sqlglot").setLevel(logging.ERROR)

MAX_SQL_LENGTH = 20_000

DEFAULT_BLOCKED_FUNCTIONS = frozenset(
    {
        # sleeping / locking / resource abuse
        "pg_sleep",
        "pg_sleep_for",
        "pg_sleep_until",
        "sleep",
        "randomblob",
        "zeroblob",
        # server-side file and large-object access
        "pg_read_file",
        "pg_read_binary_file",
        "pg_ls_dir",
        "pg_stat_file",
        "lo_import",
        "lo_export",
        "lo_get",
        "lo_put",
        "lo_from_bytea",
        "readfile",
        "writefile",
        "edit",
        "load_extension",
        # remote connections and dynamic SQL
        "dblink",
        "dblink_exec",
        "dblink_connect",
        "dblink_send_query",
        "query_to_xml",
        "query_to_xml_and_xmlschema",
        "table_to_xml",
        "cursor_to_xml",
        "database_to_xml",
        "schema_to_xml",
        # session / server state changes
        "set_config",
        "pg_terminate_backend",
        "pg_cancel_backend",
        "pg_reload_conf",
        "pg_rotate_logfile",
        "pg_promote",
        "pg_switch_wal",
        "nextval",
        "setval",
        "txid_current",
        "pg_current_xact_id",
        "pg_notify",
        "copy",
    }
)

# Whole families that have no business in an analyst query.
BLOCKED_FUNCTION_PREFIXES = (
    "dblink",
    "lo_",
    "pg_advisory",
    "pg_try_advisory",
    "pg_read_",
    "pg_ls_",
    "pg_file_",
    "pg_create_",
    "pg_drop_",
    "pg_replication_",
    "pg_logical_",
    "pg_import_",
)

DEFAULT_BLOCKED_TABLES = (
    "pg_catalog.pg_authid",
    "pg_authid",
    "pg_shadow",
    "pg_user_mapping",
    "pg_user_mappings",
    "pg_largeobject",
    "pg_file_settings",
    "pg_hba_file_rules",
    "pg_ident_file_mappings",
    "pg_stat_activity",
    "pg_settings",
)

_FORBIDDEN_NODE_NAMES = (
    "Insert",
    "Update",
    "Delete",
    "Merge",
    "Create",
    "Drop",
    "Alter",
    "TruncateTable",
    "Command",
    "Copy",
    "Set",
    "Pragma",
    "Transaction",
    "Commit",
    "Rollback",
    "Into",
    "Lock",
    "Grant",
    "Revoke",
    "Use",
    "Attach",
    "Detach",
    "Analyze",
    "Kill",
    "Show",
    "Cache",
    "Uncache",
    "LoadData",
    "Refresh",
    "Declare",
    "Execute",
    "Comment",
    "Describe",
)
FORBIDDEN_NODES: tuple[type[exp.Expression], ...] = tuple(
    getattr(exp, name) for name in _FORBIDDEN_NODE_NAMES if hasattr(exp, name)
)

ALLOWED_ROOTS: tuple[type[exp.Expression], ...] = (exp.Select, exp.SetOperation, exp.Subquery)


class QueryRejected(Exception):
    """The query failed a guard check. ``code`` is stable for clients and the audit log."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class GuardedQuery:
    original: str
    sql: str
    tables: tuple[str, ...]
    limit: int
    limit_rewritten: bool
    tainted_outputs: Mapping[str, MaskRule] = field(default_factory=dict)
    hidden_outputs: frozenset[str] = frozenset()


def _function_name(node: exp.Func) -> str:
    if isinstance(node, exp.Anonymous):
        return str(node.name).lower()
    return node.sql_name().lower()


def is_function_blocked(name: str, extra: Iterable[str] = ()) -> bool:
    name = name.lower()
    if name in DEFAULT_BLOCKED_FUNCTIONS or name in set(extra):
        return True
    return name.startswith(BLOCKED_FUNCTION_PREFIXES)


def _is_count(node: exp.Expression) -> bool:
    inner = node.this if isinstance(node, exp.Alias) else node
    return isinstance(inner, exp.Count)


def compute_taint(root: exp.Expression, rules: list[MaskRule]) -> dict[str, MaskRule]:
    """Map output/intermediate column names to the mask rule they inherit.

    A projection is tainted when it references a column that matches a mask rule, or a column
    produced by another tainted projection (CTEs, derived tables). Iterates to a fixed point so
    ``WITH x AS (SELECT email AS e ...) SELECT upper(e) AS shout FROM x`` taints ``shout``.
    ``count(...)`` is exempt because it returns a number, not the value.
    """
    if not rules:
        return {}

    def direct(name: str) -> MaskRule | None:
        return next((r for r in rules if r.matches(name)), None)

    tainted: dict[str, MaskRule] = {}
    changed = True
    while changed:
        changed = False
        for select in root.find_all(exp.Select):
            for projection in select.expressions:
                if isinstance(projection, exp.Star) or _is_count(projection):
                    continue
                output = projection.alias_or_name.lower()
                if not output or output in tainted or direct(output):
                    continue
                for column in projection.find_all(exp.Column):
                    name = column.name.lower()
                    rule = direct(name) or tainted.get(name)
                    if rule is not None:
                        tainted[output] = rule
                        changed = True
                        break
    return tainted


class SqlGuard:
    def __init__(
        self,
        dialect: str,
        policy: Policy,
        *,
        default_limit: int,
        max_rows: int,
    ) -> None:
        self.dialect = dialect
        self.policy = policy
        self.default_limit = min(default_limit, max_rows)
        self.max_rows = max_rows
        self._blocked_tables = tuple(policy.blocked_tables) + DEFAULT_BLOCKED_TABLES

    # -- public -----------------------------------------------------------------------------

    def check(
        self,
        sql: str,
        *,
        limit: int | None = None,
        catalog: Mapping[str, set[str]] | None = None,
    ) -> GuardedQuery:
        """Validate ``sql`` and return the rewritten statement, or raise ``QueryRejected``.

        ``catalog`` maps lower-case table names to their column names; when given, whole-row
        references (``row_to_json(c)``) are detected precisely instead of heuristically.
        """
        root = self._parse(sql)
        self._check_root(root)
        self._check_nodes(root)
        tables = self._check_tables(root)
        hidden = self._check_columns(root, catalog or {})
        target = self._target_limit(limit)
        rewritten, final_limit = self._apply_limit(root, target)
        return GuardedQuery(
            original=sql,
            sql=root.sql(dialect=self.dialect),
            tables=tuple(sorted(tables)),
            limit=final_limit,
            limit_rewritten=rewritten,
            tainted_outputs=compute_taint(root, self.policy.masking),
            hidden_outputs=frozenset(hidden),
        )

    # -- steps ------------------------------------------------------------------------------

    def _parse(self, sql: str) -> exp.Expression:
        if not sql or not sql.strip():
            raise QueryRejected("empty", "query is empty")
        if len(sql) > MAX_SQL_LENGTH:
            raise QueryRejected("too_long", f"query exceeds {MAX_SQL_LENGTH} characters")
        try:
            statements = [s for s in sqlglot.parse(sql, read=self.dialect) if s is not None]
        except (ParseError, TokenError) as exc:
            first = str(exc).splitlines()[0][:200]
            raise QueryRejected("parse_error", f"could not parse SQL: {first}") from exc
        if not statements:
            raise QueryRejected("empty", "query contains no statement")
        if len(statements) > 1:
            raise QueryRejected(
                "multiple_statements", f"exactly one statement allowed, got {len(statements)}"
            )
        return statements[0]

    def _check_root(self, root: exp.Expression) -> None:
        if not isinstance(root, ALLOWED_ROOTS):
            kind = type(root).__name__.upper()
            raise QueryRejected("not_select", f"only SELECT / WITH queries are allowed, got {kind}")
        if isinstance(root, exp.Subquery) and not isinstance(root.unnest(), exp.Query):
            raise QueryRejected("not_select", "only SELECT / WITH queries are allowed")

    def _check_nodes(self, root: exp.Expression) -> None:
        for node in root.walk():
            if isinstance(node, FORBIDDEN_NODES):
                label = type(node).__name__.upper()
                if isinstance(node, exp.Into):
                    label = "SELECT INTO"
                elif isinstance(node, exp.Lock):
                    label = "row locking (FOR UPDATE/SHARE)"
                raise QueryRejected("forbidden_statement", f"{label} is not allowed")
            if isinstance(node, exp.Func):
                name = _function_name(node)
                if is_function_blocked(name, self.policy.blocked_functions):
                    raise QueryRejected("blocked_function", f"function {name}() is not allowed")

    def _cte_names(self, root: exp.Expression) -> set[str]:
        return {cte.alias_or_name.lower() for cte in root.find_all(exp.CTE)}

    def _check_tables(self, root: exp.Expression) -> set[str]:
        ctes = self._cte_names(root)
        tables: set[str] = set()
        for table in root.find_all(exp.Table):
            name = table.name.lower()
            if not name:
                continue  # table-valued function, already checked as a function
            schema = table.db.lower() if table.db else None
            if schema is None and name in ctes:
                continue
            qualified = f"{schema}.{name}" if schema else name
            if self.table_blocked(name, schema):
                raise QueryRejected("blocked_table", f"table {qualified} is not accessible")
            tables.add(qualified)
        return tables

    def table_blocked(self, name: str, schema: str | None) -> bool:
        if self.policy.is_table_blocked(name, schema):
            return True
        candidates = {name} | ({f"{schema}.{name}"} if schema else set())
        return any(c in self._blocked_tables for c in candidates)

    def _check_columns(self, root: exp.Expression, catalog: Mapping[str, set[str]]) -> set[str]:
        """Reject blocked columns and whole-row references; return output names to hide."""
        aliases: dict[str, str] = {}
        for table in root.find_all(exp.Table):
            if table.name:
                aliases[table.alias_or_name.lower()] = table.name.lower()
        query_tables = set(aliases.values())
        pairs = self.policy.blocked_column_pairs()

        known_columns: set[str] = set()
        for table in query_tables:
            known_columns |= {c.lower() for c in catalog.get(table, set())}
        projected = {
            p.alias_or_name.lower()
            for select in root.find_all(exp.Select)
            for p in select.expressions
            if not isinstance(p, exp.Star)
        }

        for column in root.find_all(exp.Column):
            name = column.name.lower()
            qualifier = column.table.lower() if column.table else ""
            sources = {aliases.get(qualifier, qualifier)} if qualifier else query_tables
            for table, blocked in pairs:
                if name == blocked and (table == "*" or table in sources):
                    raise QueryRejected("blocked_column", f"column {blocked} is not accessible")
            if (
                not qualifier
                and name in aliases
                and name not in known_columns
                and not (
                    name in projected
                    and column.find_ancestor(exp.Order, exp.Group, exp.Having) is not None
                )
            ):
                raise QueryRejected(
                    "whole_row_reference",
                    f"whole-row reference to {name!r} is not allowed (it bypasses column masking)",
                )

        hidden = set()
        for table, blocked in pairs:
            if table == "*" or table in query_tables:
                hidden.add(blocked)
        return hidden

    def _target_limit(self, requested: int | None) -> int:
        if requested is None:
            return self.default_limit
        if requested < 1:
            raise QueryRejected("bad_limit", "limit must be a positive integer")
        return min(requested, self.max_rows)

    def _apply_limit(self, root: exp.Expression, target: int) -> tuple[bool, int]:
        node = root.args.get("limit")
        current: int | None = None
        if isinstance(node, exp.Limit):
            current = _int_literal(node.expression)
        elif isinstance(node, exp.Fetch):
            current = _int_literal(node.args.get("count"))
        if node is not None and current is not None and current <= target:
            return False, current
        # Ask for one extra row so the executor can tell "exactly N rows" from "truncated at N".
        root.set("limit", None)
        root.limit(target + 1, dialect=self.dialect, copy=False)  # type: ignore[attr-defined]
        return True, target


def _int_literal(node: exp.Expression | None) -> int | None:
    if isinstance(node, exp.Literal) and node.is_int:
        return int(node.name)
    return None
