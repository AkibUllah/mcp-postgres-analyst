"""PostgreSQL integration tests. Run with a disposable database:

docker compose up -d postgres
TEST_DATABASE_URL=postgresql://shop:shop@localhost:5432/shop pytest -m postgres
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from pg_analyst.config import Settings
from pg_analyst.db import DatabaseError, PostgresDatabase
from pg_analyst.service import AnalystError, AnalystService

URL = os.environ.get("TEST_DATABASE_URL")
pytestmark = [
    pytest.mark.postgres,
    pytest.mark.skipif(not URL, reason="TEST_DATABASE_URL is not set"),
]
POLICY = Path(__file__).resolve().parents[1] / "config" / "policy.yaml"


@pytest.fixture(scope="module")
def pg_service(tmp_path_factory: pytest.TempPathFactory) -> AnalystService:
    from pg_analyst.demo import seed_postgres

    assert URL
    seed_postgres(URL)
    settings = Settings(
        _env_file=None,
        database_url=URL,
        policy_path=POLICY,
        audit_log_path=tmp_path_factory.mktemp("audit") / "audit.jsonl",
        statement_timeout_ms=300,
    )
    return AnalystService(settings)


def test_introspection_uses_catalog_comments(pg_service: AnalystService) -> None:
    names = {t.name for s in pg_service.list_schemas().schemas for t in s.tables}
    assert "orders" in names and "staff_payroll" not in names
    info = pg_service.describe_table("public.customers")
    columns = {c.name: c for c in info.columns}
    assert columns["phone"].comment.startswith("Mobile number")
    assert "password_hash" not in columns
    orders = pg_service.describe_table("orders")
    assert any(fk.references == "customers.id" for fk in orders.foreign_keys)


def test_queries_masking_and_saved_queries(pg_service: AnalystService) -> None:
    result = pg_service.run_query(
        "SELECT c.id, email, total_bdt FROM customers c JOIN orders o "
        "ON o.customer_id = c.id ORDER BY o.id LIMIT 3"
    )
    assert result.masked_columns == ["email"] and isinstance(result.rows[0][2], float)
    for saved in pg_service.saved_queries():
        assert pg_service.run_saved_query(saved.name).row_count > 0


def test_timeout_and_read_only_transaction(pg_service: AnalystService) -> None:
    with pytest.raises(AnalystError) as info:
        pg_service.run_query("SELECT count(*) FROM generate_series(1, 500000000)")
    assert info.value.code == "timeout"
    db = pg_service.db
    assert isinstance(db, PostgresDatabase)
    with pytest.raises(DatabaseError, match="read-only"):
        db.execute("CREATE TABLE nope (id int)", max_rows=1, timeout_ms=1000)


def test_explain_on_postgres(pg_service: AnalystService) -> None:
    plan = pg_service.explain_query("SELECT * FROM orders WHERE customer_id = 7").plan
    assert "Scan" in plan
