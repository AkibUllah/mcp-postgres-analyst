from __future__ import annotations

import json
from pathlib import Path

import pytest

from pg_analyst.config import Settings
from pg_analyst.policy import Policy
from pg_analyst.service import AnalystError, AnalystService, to_json_value


def audit_lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_list_schemas_hides_blocked_tables(service: AnalystService) -> None:
    listing = service.list_schemas()
    names = {t.name for s in listing.schemas for t in s.tables}
    assert {"customers", "orders", "payments", "products", "order_items"} <= names
    assert "staff_payroll" not in names


def test_describe_table_marks_masking_and_hides_blocked_columns(service: AnalystService) -> None:
    info = service.describe_table("customers")
    columns = {c.name: c for c in info.columns}
    assert columns["email"].masking == "email"
    assert columns["nid"].masking == "last4"
    assert columns["id"].primary_key and not columns["id"].nullable
    assert "password_hash" not in columns
    assert info.comment == "Registered shoppers"
    orders = service.describe_table("main.orders")
    assert any(fk.references == "customers.id" for fk in orders.foreign_keys)
    assert "idx_orders_created" in orders.indexes


def test_unknown_and_blocked_tables_are_not_found(service: AnalystService) -> None:
    for name in ("nope", "staff_payroll"):
        with pytest.raises(AnalystError) as info:
            service.describe_table(name)
        assert info.value.code == "unknown_table"


def test_run_query_masks_direct_and_derived_columns(service: AnalystService) -> None:
    result = service.run_query(
        "SELECT id, email, lower(email) AS e2, city FROM customers ORDER BY id LIMIT 2"
    )
    assert result.columns == ["id", "email", "e2", "city"]
    assert result.masked_columns == ["email", "e2"]
    assert all("***@" in row[1] and "***@" in row[2] for row in result.rows)


def test_select_star_drops_blocked_columns(service: AnalystService) -> None:
    result = service.run_query("SELECT * FROM customers LIMIT 1")
    assert "password_hash" not in result.columns
    assert result.hidden_columns == ["password_hash"]


def test_aggregates_are_not_masked(service: AnalystService) -> None:
    result = service.run_query("SELECT count(DISTINCT email) AS emails FROM customers")
    assert result.rows == [[300]] and result.masked_columns == []


def test_limit_injection_reaches_the_database(service: AnalystService) -> None:
    result = service.run_query("SELECT id FROM orders")
    assert result.row_count == 100 and result.limit_rewritten and result.truncated
    assert result.truncated_reason == "row_limit"
    explicit = service.run_query("SELECT id FROM orders", limit=5)
    assert explicit.row_count == 5


def test_byte_budget_truncates_rows(settings: Settings) -> None:
    small = AnalystService(settings.model_copy(update={"max_result_bytes": 2048}))
    result = small.run_query("SELECT id, full_name, city, area FROM customers", limit=200)
    assert result.truncated_reason == "max_result_bytes"
    assert 0 < result.row_count < 200


def test_statement_timeout_cancels_runaway_query(settings: Settings) -> None:
    fast = AnalystService(settings.model_copy(update={"statement_timeout_ms": 200}))
    with pytest.raises(AnalystError) as info:
        fast.run_query(
            "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r) SELECT count(*) FROM r"
        )
    assert info.value.code == "timeout"


def test_rejections_are_audited(service: AnalystService, settings: Settings) -> None:
    with pytest.raises(AnalystError):
        service.run_query("DROP TABLE orders")
    service.run_query("SELECT count(*) FROM orders")
    entries = audit_lines(settings.audit_log_path)
    assert entries[-2]["status"] == "rejected" and entries[-2]["code"] == "not_select"
    assert entries[-1]["status"] == "ok" and entries[-1]["rows"] == 1
    assert entries[-1]["sql"].endswith("LIMIT 101")
    assert {"ts", "tool", "duration_ms", "args"} <= entries[-1].keys()


def test_rate_limit_is_enforced_and_audited(settings: Settings) -> None:
    policy = Policy.model_validate({"rate_limits": {"run_query": "2/minute"}})
    limited = AnalystService(settings, policy=policy, clock=lambda: 0.0)
    limited.run_query("SELECT 1")
    limited.run_query("SELECT 1")
    with pytest.raises(AnalystError) as info:
        limited.run_query("SELECT 1")
    assert info.value.code == "rate_limited"
    assert audit_lines(settings.audit_log_path)[-1]["status"] == "rate_limited"


def test_sample_rows_validates_and_masks(service: AnalystService) -> None:
    result = service.sample_rows("payments", 3)
    assert result.row_count == 3
    assert "trx_id" in result.masked_columns and "payer_phone" in result.masked_columns
    with pytest.raises(AnalystError):
        service.sample_rows("payments", 500)
    with pytest.raises(AnalystError):
        service.sample_rows('orders"; DROP TABLE orders; --')


def test_explain_query(service: AnalystService) -> None:
    result = service.explain_query(
        "SELECT * FROM orders o JOIN customers c ON c.id = o.customer_id WHERE o.customer_id = 5"
    )
    assert "idx_orders_customer" in result.plan
    with pytest.raises(AnalystError):
        service.explain_query("DELETE FROM orders")


def test_find_columns_searches_names_and_comments(service: AnalystService) -> None:
    by_name = service.find_columns("phone")
    assert {(m.table, m.column) for m in by_name.matches} == {
        ("customers", "phone"),
        ("payments", "payer_phone"),
    }
    by_comment = service.find_columns("bangladeshi taka")
    assert [m.column for m in by_comment.matches] == ["price_bdt"]
    assert service.find_columns("password").matches == []
    with pytest.raises(AnalystError):
        service.find_columns("x")


def test_saved_queries_run_on_sqlite(service: AnalystService) -> None:
    for saved in service.saved_queries():
        result = service.run_saved_query(saved.name)
        assert result.row_count > 0, saved.name
    with pytest.raises(AnalystError) as info:
        service.run_saved_query("missing")
    assert info.value.code == "unknown_query"


def test_schema_overview_markdown(service: AnalystService) -> None:
    text = service.schema_overview_markdown()
    assert "## main.customers" in text
    assert "| email | TEXT | masked (email)" in text
    assert "password_hash" not in text and "staff_payroll" not in text


def test_json_conversion_of_driver_types() -> None:
    import datetime as dt
    import decimal
    import uuid

    assert to_json_value(decimal.Decimal("1250.50")) == 1250.5
    assert to_json_value(dt.date(2026, 3, 26)) == "2026-03-26"
    assert to_json_value(uuid.UUID(int=1)) == "00000000-0000-0000-0000-000000000001"
    assert to_json_value(b"\x00" * 64) == "<64 bytes>"
    assert to_json_value({"a": [decimal.Decimal("1")]}) == {"a": [1.0]}


def test_postgres_scheme_is_normalised() -> None:
    settings = Settings(_env_file=None, database_url="postgres://u:p@h:5432/db")
    assert settings.database_url == "postgresql://u:p@h:5432/db"
