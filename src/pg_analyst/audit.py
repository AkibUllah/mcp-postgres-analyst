"""Append-only JSONL audit log: one line per tool call, whatever the outcome."""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

MAX_SQL_IN_LOG = 4000


class AuditLog:
    def __init__(self, path: Path | None) -> None:
        self.path = path
        self._lock = threading.Lock()
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def enabled(self) -> bool:
        return self.path is not None

    def record(self, tool: str, status: str, **fields: Any) -> dict[str, Any]:
        entry: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "tool": tool,
            "status": status,
        }
        for key, value in fields.items():
            if value is None:
                continue
            if isinstance(value, str) and len(value) > MAX_SQL_IN_LOG:
                value = value[:MAX_SQL_IN_LOG] + "...[truncated]"
            entry[key] = value
        if self.path is not None:
            line = json.dumps(entry, ensure_ascii=False, default=str)
            with self._lock, self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        logger.info("audit %s %s", tool, status)
        return entry

    def tail(self, n: int = 20) -> list[dict[str, Any]]:
        if self.path is None or not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()[-n:]
        return [json.loads(line) for line in lines if line.strip()]
