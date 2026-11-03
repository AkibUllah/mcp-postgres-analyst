"""Who is calling: the identity used for per-session rate limits and audit attribution."""

from __future__ import annotations

from dataclasses import dataclass

STDIO_KEY = "stdio"


@dataclass(frozen=True)
class Caller:
    """One client of the server.

    ``key`` is what rate limits are bucketed by. Over stdio there is one client per process, so
    every call shares the fixed ``stdio`` key. ``session``, ``client`` and ``remote`` are only
    recorded in the audit log; ``client`` is self-reported by the client and never trusted for
    anything else.
    """

    key: str = STDIO_KEY
    session: str | None = STDIO_KEY
    client: str | None = None
    remote: str | None = None


STDIO = Caller()
