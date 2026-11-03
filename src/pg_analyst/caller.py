"""Who is calling: the identity used for per-session rate limits and audit attribution."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

STDIO_KEY = "stdio"
SESSION_HEADER = "mcp-session-id"
# Visible ASCII, as the SDK requires for session ids; bounded so a log line stays a log line.
_SESSION_ID = re.compile(r"[\x21-\x7e]{1,128}")


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


def _clean(value: str | None, limit: int) -> str | None:
    if not value:
        return None
    printable = "".join(ch for ch in value if ch.isprintable())
    return printable[:limit] or None


def resolve_caller(
    headers: Mapping[str, str] | None,
    *,
    client_name: str | None = None,
    client_version: str | None = None,
    remote: str | None = None,
) -> Caller:
    """Build the caller for one request from what the transport exposes.

    No headers means stdio (or the SDK's in-process client): the fixed ``stdio`` identity.
    Streamable HTTP clients on the session-based protocol send ``Mcp-Session-Id``, which the
    SDK has already matched to a live session, so it keys the buckets. Sessionless HTTP
    requests (protocol 2026-07-28 or a stateless deployment) fall back to the remote address.
    """
    client = _clean(client_name, 64)
    if client and (version := _clean(client_version, 32)):
        client = f"{client}/{version}"
    if headers is None:
        return Caller(client=client)
    remote = _clean(remote, 64)
    session = headers.get(SESSION_HEADER)
    if session and _SESSION_ID.fullmatch(session):
        return Caller(key=f"session:{session}", session=session, client=client, remote=remote)
    return Caller(key=f"remote:{remote or 'unknown'}", session=None, client=client, remote=remote)
