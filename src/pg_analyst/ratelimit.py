"""Per-tool token buckets with an injectable clock."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from pg_analyst.policy import Policy, RateLimit


class RateLimited(Exception):
    def __init__(self, tool: str, retry_after: float) -> None:
        super().__init__(f"rate limit exceeded for {tool}; retry in {retry_after:.1f}s")
        self.tool = tool
        self.retry_after = retry_after


@dataclass
class _Bucket:
    limit: RateLimit
    tokens: float
    updated: float

    def take(self, now: float) -> float:
        """Consume one token; return 0 when allowed, else seconds until a token is available."""
        rate = self.limit.capacity / self.limit.per_seconds
        self.tokens = min(self.limit.capacity, self.tokens + (now - self.updated) * rate)
        self.updated = now
        if self.tokens >= 1:
            self.tokens -= 1
            return 0.0
        return (1 - self.tokens) / rate


class ToolRateLimiter:
    """One bucket per tool name, configured by the policy (``default`` applies to the rest)."""

    def __init__(self, policy: Policy, clock: Callable[[], float] = time.monotonic) -> None:
        self._policy = policy
        self._clock = clock
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def check(self, tool: str) -> None:
        limit = self._policy.rate_limit_for(tool)
        if limit is None:
            return
        with self._lock:
            now = self._clock()
            bucket = self._buckets.get(tool)
            if bucket is None:
                bucket = self._buckets[tool] = _Bucket(limit, float(limit.capacity), now)
            wait = bucket.take(now)
        if wait > 0:
            raise RateLimited(tool, wait)
