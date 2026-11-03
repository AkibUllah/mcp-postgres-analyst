"""Token buckets per caller and tool, with an injectable clock and a bounded caller map."""

from __future__ import annotations

import logging
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field

from pg_analyst.caller import STDIO_KEY
from pg_analyst.policy import Policy, RateLimit

logger = logging.getLogger(__name__)

DEFAULT_MAX_CALLERS = 1000
DEFAULT_IDLE_SECONDS = 600.0


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


@dataclass
class _CallerState:
    seen: float
    buckets: dict[str, _Bucket] = field(default_factory=dict)


class ToolRateLimiter:
    """One bucket per ``(caller, tool)``, configured by the policy (``default`` covers the rest).

    Callers are kept in least-recently-used order. A caller idle for ``idle_seconds`` is dropped
    on the next check, and the map never holds more than ``max_callers`` entries. The idle
    timeout is raised to the longest refill window in the policy, so forgetting an idle caller
    never hands out tokens it would not already have had back.
    """

    def __init__(
        self,
        policy: Policy,
        clock: Callable[[], float] = time.monotonic,
        *,
        max_callers: int = DEFAULT_MAX_CALLERS,
        idle_seconds: float = DEFAULT_IDLE_SECONDS,
    ) -> None:
        if max_callers < 1:
            raise ValueError("max_callers must be at least 1")
        if idle_seconds <= 0:
            raise ValueError("idle_seconds must be positive")
        self._policy = policy
        self._clock = clock
        self.max_callers = max_callers
        longest = max((r.per_seconds for r in policy.rate_limits.values()), default=0.0)
        self.idle_seconds = max(idle_seconds, longest)
        self._callers: OrderedDict[str, _CallerState] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def tracked(self) -> int:
        """Number of callers currently holding bucket state."""
        with self._lock:
            return len(self._callers)

    def check(self, tool: str, caller: str = STDIO_KEY) -> None:
        limit = self._policy.rate_limit_for(tool)
        if limit is None:
            return
        with self._lock:
            now = self._clock()
            self._evict_idle(now)
            state = self._callers.get(caller)
            if state is None:
                state = self._callers[caller] = _CallerState(seen=now)
                self._evict_overflow()
            else:
                self._callers.move_to_end(caller)
            state.seen = now
            bucket = state.buckets.get(tool)
            if bucket is None:
                bucket = state.buckets[tool] = _Bucket(limit, float(limit.capacity), now)
            wait = bucket.take(now)
        if wait > 0:
            raise RateLimited(tool, wait)

    def forget(self, caller: str) -> None:
        with self._lock:
            self._callers.pop(caller, None)

    def _evict_idle(self, now: float) -> None:
        # Least recently seen first, so stop at the first caller that is still active.
        while self._callers:
            key, state = next(iter(self._callers.items()))
            if now - state.seen < self.idle_seconds:
                break
            del self._callers[key]

    def _evict_overflow(self) -> None:
        while len(self._callers) > self.max_callers:
            key, _ = self._callers.popitem(last=False)
            logger.warning("rate limiter tracks %d callers; dropped %s", self.max_callers, key)
