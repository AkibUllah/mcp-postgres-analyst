"""Streamable HTTP app: the SDK's Starlette app plus bearer-token auth and DNS-rebinding rules."""

from __future__ import annotations

import hmac

from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from pg_analyst.config import Settings

LOOPBACK = ("127.0.0.1", "localhost", "::1")
PUBLIC_PATHS = frozenset({"/health"})


class BearerTokenMiddleware:
    """Require ``Authorization: Bearer <token>`` on every path except the health check."""

    def __init__(self, app: ASGIApp, token: str) -> None:
        self.app = app
        self.expected = f"Bearer {token}".encode()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") in PUBLIC_PATHS:
            await self.app(scope, receive, send)
            return
        supplied = dict(scope.get("headers") or []).get(b"authorization", b"")
        if not hmac.compare_digest(supplied, self.expected):
            response = JSONResponse(
                {"error": "unauthorized", "detail": "missing or invalid bearer token"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


def transport_security(settings: Settings) -> TransportSecuritySettings | None:
    """DNS-rebinding protection: on for loopback binds (SDK default) and for explicit host lists.

    For a public bind with no host list (e.g. a container behind a platform proxy) the SDK
    leaves it off; protect that deployment with ``MCP_HTTP_TOKEN``.
    """
    extra = settings.extra_allowed_hosts
    if not extra:
        return None
    hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*", *extra]
    origins = ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]
    origins += [f"https://{h}" for h in extra] + [f"http://{h}" for h in extra]
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True, allowed_hosts=hosts, allowed_origins=origins
    )


def create_http_app(server: MCPServer, settings: Settings) -> ASGIApp:
    app = server.streamable_http_app(
        streamable_http_path="/mcp",
        transport_security=transport_security(settings),
        host=settings.mcp_host,
    )
    if settings.mcp_http_token:
        return BearerTokenMiddleware(app, settings.mcp_http_token)
    return app
