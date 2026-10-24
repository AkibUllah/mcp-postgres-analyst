from __future__ import annotations

import pytest

from pg_analyst.guard import QueryRejected, SqlGuard, compute_taint
from pg_analyst.policy import MaskRule, Policy

CATALOG = {
    "customers": {"id", "full_name", "email", "phone", "nid", "city", "password_hash"},
    "orders": {"id", "customer_id", "status", "total_bdt", "created_at"},
}


@pytest.fixture(params=["postgres", "sqlite"])
def guard(request: pytest.FixtureRequest, policy: Policy) -> SqlGuard:
    return SqlGuard(request.param, policy, default_limit=100, max_rows=500)


@pytest.fixture
def pg(policy: Policy) -> SqlGuard:
    return SqlGuard("postgres", policy, default_limit=100, max_rows=500)


def rejected(guard: SqlGuard, sql: str) -> str:
    with pytest.raises(QueryRejected) as info:
        guard.check(sql, catalog=CATALOG)
    return info.value.code


# -- accepted shapes -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT id, status FROM orders",
        "select count(*) from orders where status = 'paid'",
        "WITH paid AS (SELECT * FROM orders WHERE status = 'paid') SELECT count(*) FROM paid",
        "SELECT city FROM customers UNION SELECT status FROM orders",
        "SELECT o.id FROM orders o JOIN customers c ON c.id = o.customer_id WHERE c.city = 'Dhaka'",
        "SELECT * FROM (SELECT id FROM orders) AS t",
        "SELECT 'DROP TABLE orders; --' AS harmless_text",
        "SELECT id FROM orders -- trailing comment; DELETE FROM orders",
        "/* leading */ SELECT 1",
        "SELECT 1;",
    ],
)
def test_allows_read_only_selects(guard: SqlGuard, sql: str) -> None:
    result = guard.check(sql, catalog=CATALOG)
    assert result.sql.upper().startswith(("SELECT", "WITH", "(", "/*"))


def test_executed_sql_is_rendered_from_the_ast(pg: SqlGuard) -> None:
    result = pg.check("SELECT id FROM orders -- ; DELETE FROM orders", catalog=CATALOG)
    assert "DELETE" not in result.sql.upper().replace("/* ; DELETE FROM ORDERS */", "")
    assert result.tables == ("orders",)


# -- rejected statements -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("sql", "code"),
    [
        ("", "empty"),
        ("   ", "empty"),
        ("SELECT 1; SELECT 2", "multiple_statements"),
        ("SELECT * FROM orders; DROP TABLE orders", "multiple_statements"),
        ("DELETE FROM orders", "not_select"),
        ("UPDATE orders SET status = 'paid'", "not_select"),
        ("INSERT INTO orders (id) VALUES (1)", "not_select"),
        ("DROP TABLE orders", "not_select"),
        ("TRUNCATE orders", "not_select"),
        ("CREATE TABLE x AS SELECT * FROM orders", "not_select"),
        ("ALTER TABLE orders ADD COLUMN x int", "not_select"),
        ("GRANT ALL ON orders TO public", "not_select"),
        ("VALUES (1)", "not_select"),
        ("SELEC * FROM orders", "not_select"),
    ],
)
def test_rejects_non_select(guard: SqlGuard, sql: str, code: str) -> None:
    assert rejected(guard, sql) in {code, "parse_error"}


@pytest.mark.parametrize(
    "sql",
    [
        "COPY orders TO '/tmp/orders.csv'",
        "SET statement_timeout = 0",
        "BEGIN",
        "EXPLAIN ANALYZE DELETE FROM orders",
        "SHOW ALL",
        "LOCK TABLE orders",
    ],
)
def test_rejects_postgres_commands(pg: SqlGuard, sql: str) -> None:
    assert rejected(pg, sql) in {"not_select", "parse_error"}


def test_rejects_sqlite_pragma_and_attach(policy: Policy) -> None:
    guard = SqlGuard("sqlite", policy, default_limit=10, max_rows=10)
    assert rejected(guard, "PRAGMA writable_schema = 1") == "not_select"
    assert rejected(guard, "ATTACH DATABASE '/tmp/x.db' AS x") in {"not_select", "parse_error"}


def test_rejects_data_modifying_cte(pg: SqlGuard) -> None:
    sql = "WITH gone AS (DELETE FROM orders RETURNING *) SELECT count(*) FROM gone"
    assert rejected(pg, sql) == "forbidden_statement"


def test_rejects_select_into_and_row_locks(pg: SqlGuard) -> None:
    assert rejected(pg, "SELECT * INTO backup FROM orders") == "forbidden_statement"
    assert rejected(pg, "SELECT * FROM orders FOR UPDATE") == "forbidden_statement"


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT pg_sleep(10)",
        "SELECT PG_SLEEP(10)",
        'SELECT "pg_sleep"(10)',
        "SELECT pg_catalog.pg_sleep(1)",
        "SELECT id FROM orders WHERE pg_sleep(1) IS NOT NULL",
        "SELECT * FROM dblink('host=evil', 'select 1') AS t(a int)",
        "SELECT pg_read_file('/etc/passwd')",
        "SELECT * FROM pg_ls_dir('.')",
        "SELECT lo_import('/etc/passwd')",
        "SELECT set_config('statement_timeout', '0', false)",
        "SELECT pg_terminate_backend(123)",
        "SELECT pg_advisory_lock(1)",
        "SELECT query_to_xml('delete from orders', true, true, '')",
        "SELECT nextval('orders_id_seq')",
        "WITH x AS (SELECT pg_sleep(5)) SELECT * FROM x",
        "SELECT (SELECT pg_sleep(5))",
        "SELECT load_extension('/tmp/evil.so')",
    ],
)
def test_blocks_dangerous_functions(pg: SqlGuard, sql: str) -> None:
    assert rejected(pg, sql) == "blocked_function"


def test_policy_can_block_extra_functions(policy: Policy) -> None:
    guard = SqlGuard("postgres", policy, default_limit=10, max_rows=10)
    assert rejected(guard, "SELECT pg_stat_get_activity(NULL)") == "blocked_function"


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM pg_authid",
        "SELECT rolpassword FROM pg_catalog.pg_authid",
        "SELECT * FROM pg_shadow",
        "SELECT query FROM pg_stat_activity",
        "SELECT * FROM staff_payroll",
        "SELECT * FROM public.staff_payroll",
        "SELECT * FROM audit_events",
        "SELECT o.id FROM orders o WHERE o.id IN (SELECT id FROM staff_payroll)",
    ],
)
def test_blocks_sensitive_tables(pg: SqlGuard, sql: str) -> None:
    assert rejected(pg, sql) == "blocked_table"


def test_cte_named_like_blocked_table_is_not_a_table(pg: SqlGuard) -> None:
    result = pg.check("WITH staff_payroll AS (SELECT 1 AS x) SELECT x FROM staff_payroll")
    assert result.tables == ()


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT password_hash FROM customers",
        "SELECT c.password_hash FROM customers c",
        "SELECT id FROM customers WHERE password_hash LIKE '$2b$%'",
        "SELECT md5(password_hash) FROM customers",
    ],
)
def test_blocks_sensitive_columns(pg: SqlGuard, sql: str) -> None:
    assert rejected(pg, sql) == "blocked_column"


def test_star_hides_blocked_columns(pg: SqlGuard) -> None:
    assert "password_hash" in pg.check("SELECT * FROM customers", catalog=CATALOG).hidden_outputs
    assert "password_hash" not in pg.check("SELECT * FROM orders", catalog=CATALOG).hidden_outputs


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT row_to_json(c) FROM customers c",
        "SELECT to_jsonb(customers) FROM customers",
        "SELECT CAST(c AS TEXT) FROM customers AS c",
    ],
)
def test_rejects_whole_row_references(pg: SqlGuard, sql: str) -> None:
    assert rejected(pg, sql) == "whole_row_reference"


def test_column_named_like_its_table_is_not_whole_row(policy: Policy) -> None:
    guard = SqlGuard("postgres", policy, default_limit=10, max_rows=10)
    result = guard.check("SELECT status FROM status", catalog={"status": {"status"}})
    assert result.tables == ("status",)


def test_too_long_query_rejected(pg: SqlGuard) -> None:
    sql = "SELECT " + ", ".join(["1"] * 8000)
    assert rejected(pg, sql) == "too_long"


def test_parse_errors_are_reported(pg: SqlGuard) -> None:
    assert rejected(pg, "SELECT (1") == "parse_error"


# -- LIMIT handling ------------------------------------------------------------------------


def test_injects_default_limit(guard: SqlGuard) -> None:
    result = guard.check("SELECT id FROM orders", catalog=CATALOG)
    assert result.limit == 100 and result.limit_rewritten
    assert result.sql.endswith("LIMIT 101")


def test_keeps_smaller_limit(guard: SqlGuard) -> None:
    result = guard.check("SELECT id FROM orders LIMIT 7", catalog=CATALOG)
    assert result.limit == 7 and not result.limit_rewritten


def test_clamps_larger_limit(guard: SqlGuard) -> None:
    result = guard.check("SELECT id FROM orders LIMIT 100000", catalog=CATALOG)
    assert result.limit == 100 and "100000" not in result.sql


def test_requested_limit_is_capped_by_max_rows(guard: SqlGuard) -> None:
    assert guard.check("SELECT 1", limit=10_000).limit == 500
    assert guard.check("SELECT 1", limit=3).limit == 3
    with pytest.raises(QueryRejected):
        guard.check("SELECT 1", limit=0)


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT id FROM orders LIMIT ALL",
        "SELECT id FROM orders LIMIT (SELECT 1000000)",
        "SELECT id FROM orders FETCH FIRST 5000 ROWS ONLY",
    ],
)
def test_replaces_non_literal_or_large_limits(pg: SqlGuard, sql: str) -> None:
    result = pg.check(sql, catalog=CATALOG)
    assert result.limit == 100
    assert result.sql.endswith("LIMIT 101")


def test_limit_applies_to_whole_union(pg: SqlGuard) -> None:
    result = pg.check("SELECT city FROM customers UNION ALL SELECT status FROM orders")
    assert result.sql.endswith("LIMIT 101")


def test_limit_keeps_offset(pg: SqlGuard) -> None:
    result = pg.check("SELECT id FROM orders ORDER BY id LIMIT 10 OFFSET 20")
    assert "OFFSET 20" in result.sql and result.limit == 10


# -- lineage for masking -------------------------------------------------------------------


def test_taint_follows_aliases_expressions_and_ctes(pg: SqlGuard) -> None:
    sql = (
        "WITH x AS (SELECT email AS contact, phone FROM customers) "
        "SELECT upper(contact) AS shout, phone AS p, count(*) AS n FROM x GROUP BY 1, 2"
    )
    taint = pg.check(sql, catalog=CATALOG).tainted_outputs
    assert taint["contact"].strategy == "email"
    assert taint["shout"].strategy == "email"
    assert taint["p"].strategy == "phone"
    assert "n" not in taint


def test_taint_ignores_unrelated_columns() -> None:
    import sqlglot

    rules = [MaskRule(column="email", strategy="email")]
    tree = sqlglot.parse_one("SELECT city AS c, count(email) AS emails FROM customers")
    assert compute_taint(tree, rules) == {}
