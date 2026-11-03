"""Real transports: Streamable HTTP via uvicorn on a free port, and stdio via a subprocess."""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import httpx
import httpx2
import pytest
import uvicorn
from mcp import Client, StdioServerParameters
from mcp.client.streamable_http import streamable_http_client

from pg_analyst.config import Settings
from pg_analyst.http import create_http_app, transport_security
from pg_analyst.policy import Policy
from pg_analyst.server import build_server
from pg_analyst.service import AnalystService

TOKEN = "test-token-123"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextmanager
def _serve(settings: Settings, service: AnalystService | None = None) -> Iterator[str]:
    port = _free_port()
    settings = settings.model_copy(update={"mcp_http_token": TOKEN, "mcp_port": port})
    service = service or AnalystService(settings)
    app = create_http_app(build_server(service), settings)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)


@pytest.fixture
def http_url(settings: Settings) -> Iterator[str]:
    with _serve(settings) as url:
        yield url


def _http_client(url: str, mode: str = "auto") -> Client:
    http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {TOKEN}"}, timeout=30)
    return Client(streamable_http_client(f"{url}/mcp", http_client=http), mode=mode)


def test_health_is_public_and_mcp_needs_token(http_url: str) -> None:
    health = httpx.get(f"{http_url}/health")
    assert health.status_code == 200 and health.json()["reachable"] is True
    denied = httpx.post(f"{http_url}/mcp", json={})
    assert denied.status_code == 401
    wrong = httpx.post(f"{http_url}/mcp", json={}, headers={"Authorization": "Bearer nope"})
    assert wrong.status_code == 401


@pytest.mark.anyio
async def test_streamable_http_round_trip(http_url: str) -> None:
    async with _http_client(http_url) as client:
        result = await client.call_tool("run_query", {"sql": "SELECT count(*) AS n FROM products"})
    assert result.structured_content["rows"] == [[38]]


@pytest.mark.anyio
async def test_http_sessions_have_independent_rate_limits(settings: Settings) -> None:
    policy = Policy.model_validate({"rate_limits": {"run_query": "2/minute"}})
    service = AnalystService(settings, policy=policy, clock=lambda: 0.0)
    sql = {"sql": "SELECT 1 AS one"}
    with _serve(settings, service) as url:
        async with _http_client(url, "legacy") as first, _http_client(url, "legacy") as second:
            used_up = [(await first.call_tool("run_query", sql)).is_error for _ in range(3)]
            fresh = [(await second.call_tool("run_query", sql)).is_error for _ in range(2)]
            again = await first.call_tool("run_query", sql)
    assert used_up == [False, False, True]
    assert fresh == [False, False]
    assert again.is_error and "retry after 30.0s" in again.content[0].text

    entries = service.audit.tail(10)
    sessions = [e["session"] for e in entries]
    assert len(set(sessions)) == 2 and all(len(s) == 32 for s in sessions)
    assert sessions[:3] == [sessions[0]] * 3 and sessions[3:5] == [sessions[3]] * 2
    assert sessions[5] == sessions[0]
    assert [e["status"] for e in entries] == [
        "ok",
        "ok",
        "rate_limited",
        "ok",
        "ok",
        "rate_limited",
    ]
    assert all(e["remote"] == "127.0.0.1" and e["client"] for e in entries)
    assert service.limiter.tracked == 2


@pytest.mark.anyio
async def test_sessionless_http_requests_are_keyed_by_remote_address(settings: Settings) -> None:
    service = AnalystService(settings)
    with _serve(settings, service) as url:
        async with _http_client(url) as client:
            await client.call_tool("list_schemas", {})
    (entry,) = service.audit.tail(1)
    assert "session" not in entry
    assert entry["remote"] == "127.0.0.1"
    assert service.limiter.tracked == 1  # one bucket set for the address, default policy limit


def test_transport_security_settings(settings: Settings) -> None:
    assert transport_security(settings) is None
    custom = settings.model_copy(update={"mcp_allowed_hosts": "analyst.example.com"})
    security = transport_security(custom)
    assert security is not None
    assert security.allowed_hosts[-1] == "analyst.example.com"
    assert security.allowed_origins[-2:] == [
        "https://analyst.example.com",
        "http://analyst.example.com",
    ]


@pytest.mark.anyio
async def test_stdio_round_trip(demo_db: Path, tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "pg_analyst", "serve", "--transport", "stdio"],
        env={
            "DATABASE_URL": f"sqlite:///{demo_db}",
            "POLICY_PATH": str(root / "config" / "policy.yaml"),
            "AUDIT_LOG_PATH": str(tmp_path / "audit.jsonl"),
            "LOG_LEVEL": "WARNING",
            "PYTHONPATH": os.pathsep.join(sys.path),
        },
        cwd=str(tmp_path),
    )
    async with Client(params) as client:
        tools = await client.list_tools()
        result = await client.call_tool("describe_table", {"table": "orders"})
    assert len(tools.tools) == 7
    assert result.structured_content["table"] == "orders"
    assert (tmp_path / "audit.jsonl").read_text().count("describe_table") == 1
