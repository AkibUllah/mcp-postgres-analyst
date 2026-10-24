"""Connect to the analyst server with the MCP Python SDK client and call a few tools.

python examples/client.py                                 # spawn the server over stdio
python examples/client.py --url http://127.0.0.1:8765/mcp # talk to a running HTTP server
python examples/client.py --url ... --token "$MCP_HTTP_TOKEN"
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from typing import Any

import httpx2
from mcp import Client, StdioServerParameters
from mcp.client.streamable_http import streamable_http_client


def make_client(url: str | None, token: str | None) -> Client:
    if url:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        http = httpx2.AsyncClient(headers=headers, timeout=30)
        return Client(streamable_http_client(url, http_client=http))
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "pg_analyst", "serve", "--transport", "stdio"],
        env={k: v for k, v in os.environ.items() if k in ("DATABASE_URL", "POLICY_PATH")},
    )
    return Client(params)


def show(title: str, payload: Any) -> None:
    print(f"\n== {title}")
    print(json.dumps(payload, indent=2, ensure_ascii=False)[:1500])


async def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--url", help="Streamable HTTP endpoint, e.g. http://127.0.0.1:8765/mcp")
    parser.add_argument("--token", default=os.environ.get("MCP_HTTP_TOKEN"))
    args = parser.parse_args()

    async with make_client(args.url, args.token) as client:
        tools = await client.list_tools()
        print("tools:", ", ".join(t.name for t in tools.tools))

        schemas = await client.call_tool("list_schemas", {})
        show("list_schemas", schemas.structured_content)

        result = await client.call_tool(
            "run_query",
            {
                "sql": (
                    "SELECT c.city, count(*) AS orders, round(sum(o.total_bdt), 2) AS revenue_bdt "
                    "FROM orders o JOIN customers c ON c.id = o.customer_id "
                    "WHERE o.status = 'delivered' GROUP BY c.city ORDER BY revenue_bdt DESC"
                )
            },
        )
        show("revenue by city", result.structured_content)

        masked = await client.call_tool("sample_rows", {"table": "customers", "n": 3})
        show("sample_rows customers (masked)", masked.structured_content)

        blocked = await client.call_tool("run_query", {"sql": "DELETE FROM orders"})
        show("a write attempt", {"is_error": blocked.is_error, "text": blocked.content[0].text})

        overview = await client.read_resource("schema://overview")
        print("\n== schema://overview (first lines)")
        print("\n".join(overview.contents[0].text.splitlines()[:12]))


if __name__ == "__main__":
    asyncio.run(main())
