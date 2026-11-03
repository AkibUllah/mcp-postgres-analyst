from __future__ import annotations

import json
from pathlib import Path

import pytest

from pg_analyst.audit import AuditLog
from pg_analyst.cli import main


def _log(path: Path) -> AuditLog:
    log = AuditLog(path)
    log.record("list_schemas", "ok", session="stdio")
    log.record("run_query", "ok", session="a1", client="report-bot/2.1.0")
    log.record("run_query", "rate_limited", session="b2", retry_after_s=1.5)
    log.record("run_query", "rejected", session="a1", code="not_select")
    log.record("find_columns", "ok", remote="10.0.0.7")
    return log


def test_tail_filters_by_session(tmp_path: Path) -> None:
    log = _log(tmp_path / "audit.jsonl")
    assert [e["status"] for e in log.tail(10, session="a1")] == ["ok", "rejected"]
    assert [e["status"] for e in log.tail(1, session="a1")] == ["rejected"]
    assert log.tail(10, session="nobody") == []
    assert len(log.tail(3)) == 3 and log.tail(0) == []
    assert "session" not in log.tail(1)[0]
    assert AuditLog(None).tail(5, session="a1") == []


def test_cli_audit_session_filter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = tmp_path / "audit.jsonl"
    _log(path)
    monkeypatch.setenv("AUDIT_LOG_PATH", str(path))
    monkeypatch.chdir(tmp_path)
    assert main(["audit", "--session", "b2"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["status"] == "rate_limited" and entry["retry_after_s"] == 1.5
    assert main(["audit", "-n", "2"]) == 0
    assert len(capsys.readouterr().out.splitlines()) == 2
