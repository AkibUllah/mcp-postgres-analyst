from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from pg_analyst.db import SQLiteDatabase, parse_sqlite_comments, sqlite_path_from_url
from pg_analyst.demo import SCHEMA, ddl, generate, seed_sqlite


def test_generator_is_deterministic() -> None:
    assert generate(7, customers=20, orders=50) == generate(7, customers=20, orders=50)
    assert generate(7, customers=20, orders=50) != generate(8, customers=20, orders=50)


def test_seeded_database_is_consistent(demo_db: Path) -> None:
    conn = sqlite3.connect(demo_db)
    orphans = conn.execute(
        "SELECT count(*) FROM orders o LEFT JOIN customers c ON c.id = o.customer_id "
        "WHERE c.id IS NULL"
    ).fetchone()[0]
    methods = {r[0] for r in conn.execute("SELECT DISTINCT method FROM payments")}
    conn.close()
    assert orphans == 0
    assert methods == {"bkash", "nagad", "card", "cod"}


def test_seed_refuses_to_overwrite(demo_db: Path) -> None:
    with pytest.raises(FileExistsError):
        seed_sqlite(demo_db)


def test_sqlite_comments_round_trip() -> None:
    customers = next(t for t in SCHEMA if t.name == "customers")
    table_comment, columns = parse_sqlite_comments(ddl(customers, with_comments=True))
    assert table_comment == "Registered shoppers"
    assert columns["phone"].startswith("Mobile number")
    assert len(columns) == len(customers.columns)


def test_sqlite_url_parsing() -> None:
    assert sqlite_path_from_url("sqlite:///data/demo.db") == Path("data/demo.db")
    assert sqlite_path_from_url("sqlite:////abs/demo.db") == Path("/abs/demo.db")


def test_sqlite_connection_is_read_only(demo_db: Path) -> None:
    from pg_analyst.db import DatabaseError

    db = SQLiteDatabase(demo_db)
    with pytest.raises(DatabaseError):
        db.execute("DELETE FROM orders", max_rows=1, timeout_ms=1000)
    with pytest.raises(DatabaseError):
        db.execute("SELECT load_extension('x')", max_rows=1, timeout_ms=1000)
    assert db.execute("SELECT count(*) FROM orders", max_rows=1, timeout_ms=1000).rows == [[2000]]
