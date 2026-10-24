"""Real transports: Streamable HTTP via uvicorn on a free port, and stdio via a subprocess."""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

import httpx
import httpx2
import pytest
import uvicorn
from mcp import Client, StdioServerParameters
from mcp.client.streamable_http import streamable_http_client

from pg_analyst.config import Settings
from pg_analyst.http import create_http_app, transport_security
from pg_analyst.server import build_server
from pg_analyst.service import AnalystService

TOKEN = "test-token-123"


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def http_url(settings: Settings) -> Iterator[str]:
    port = _free_port()
    settings = settings.model_copy(update={"mcp_http_token": TOKEN, "mcp_port": port})
    app = create_http_app(build_server(AnalystService(settings)), settings)
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=10)


def test_health_is_public_and_mcp_needs_token(http_url: str) -> None:
    health = httpx.get(f"{http_url}/health")
    assert health.status_code == 200 and health.json()["reachable"] is True
    denied = httpx.post(f"{http_url}/mcp", json={})
    assert denied.status_code == 401
    wrong = httpx.post(f"{http_url}/mcp", json={}, headers={"Authorization": "Bearer nope"})
    assert wrong.status_code == 401


@pytest.mark.anyio
async def test_streamable_http_round_trip(http_url: str) -> None:
    http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {TOKEN}"}, timeout=30)
    async with Client(streamable_http_client(f"{http_url}/mcp", http_client=http)) as client:
        result = await client.call_tool("run_query", {"sql": "SELECT count(*) AS n FROM products"})
    assert result.structured_content["rows"] == [[38]]


def test_transport_security_settings(settings: Settings) -> None:
    assert transport_security(settings) is None
    custom = settings.model_copy(update={"mcp_allowed_hosts": "analyst.example.com"})
    security = transport_security(custom)
    assert security is not None and "analyst.example.com" in security.allowed_hosts


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
