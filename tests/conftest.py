from __future__ import annotations

from pathlib import Path

import pytest

from pg_analyst.config import Settings
from pg_analyst.demo import seed_sqlite
from pg_analyst.policy import Policy, load_policy
from pg_analyst.server import build_server
from pg_analyst.service import AnalystService

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config" / "policy.yaml"


@pytest.fixture(scope="session")
def demo_db(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path = tmp_path_factory.mktemp("db") / "demo.db"
    seed_sqlite(path)
    return path


@pytest.fixture(scope="session")
def policy() -> Policy:
    return load_policy(POLICY_PATH)


@pytest.fixture
def settings(demo_db: Path, tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        database_url=f"sqlite:///{demo_db}",
        policy_path=POLICY_PATH,
        audit_log_path=tmp_path / "audit.jsonl",
        default_limit=100,
        max_rows=500,
        statement_timeout_ms=2000,
    )


@pytest.fixture
def service(settings: Settings) -> AnalystService:
    return AnalystService(settings)


@pytest.fixture
def server(service: AnalystService):
    return build_server(service)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
