"""End-to-end through the MCP protocol using the SDK's in-process client."""

from __future__ import annotations

import json

import pytest
from mcp import Client

pytestmark = pytest.mark.anyio

EXPECTED_TOOLS = {
    "list_schemas",
    "describe_table",
    "sample_rows",
    "run_query",
    "explain_query",
    "find_columns",
    "run_saved_query",
}


async def test_tools_are_listed_with_schemas_and_read_only_hints(server) -> None:
    async with Client(server) as client:
        tools = {t.name: t for t in (await client.list_tools()).tools}
    assert set(tools) == EXPECTED_TOOLS
    run_query = tools["run_query"]
    assert run_query.input_schema["required"] == ["sql"]
    assert "rows" in run_query.output_schema["properties"]
    assert all(t.annotations and t.annotations.read_only_hint for t in tools.values())


async def test_run_query_returns_structured_content(server) -> None:
    async with Client(server) as client:
        result = await client.call_tool(
            "run_query", {"sql": "SELECT status, count(*) AS n FROM orders GROUP BY status"}
        )
    assert not result.is_error
    data = result.structured_content
    assert data["columns"] == ["status", "n"]
    assert sum(row[1] for row in data["rows"]) == 2000
    assert json.loads(result.content[0].text)["row_count"] == data["row_count"]


async def test_guard_rejections_come_back_as_tool_errors(server) -> None:
    async with Client(server) as client:
        dropped = await client.call_tool("run_query", {"sql": "DROP TABLE orders"})
        slept = await client.call_tool("run_query", {"sql": "SELECT pg_sleep(30)"})
        still_there = await client.call_tool("run_query", {"sql": "SELECT count(*) FROM orders"})
    assert dropped.is_error and "not_select" in dropped.content[0].text
    assert slept.is_error and "blocked_function" in slept.content[0].text
    assert still_there.structured_content["rows"] == [[2000]]


async def test_invalid_arguments_are_rejected_by_schema(server) -> None:
    async with Client(server) as client:
        result = await client.call_tool("sample_rows", {"table": "orders", "n": 999})
    assert result.is_error


async def test_masking_through_the_protocol(server) -> None:
    async with Client(server) as client:
        result = await client.call_tool("sample_rows", {"table": "customers", "n": 2})
    data = result.structured_content
    email = data["rows"][0][data["columns"].index("email")]
    assert "***@" in email and "password_hash" not in data["columns"]


async def test_describe_and_find_columns_tools(server) -> None:
    async with Client(server) as client:
        described = await client.call_tool("describe_table", {"table": "payments"})
        found = await client.call_tool("find_columns", {"query": "nid"})
        explained = await client.call_tool("explain_query", {"sql": "SELECT * FROM orders"})
    assert any(c["name"] == "trx_id" for c in described.structured_content["columns"])
    assert found.structured_content["matches"][0]["masking"] == "last4"
    assert "SCAN" in explained.structured_content["plan"]


async def test_resources(server) -> None:
    async with Client(server) as client:
        listed = {str(r.uri) for r in (await client.list_resources()).resources}
        templates = [
            t.uri_template for t in (await client.list_resource_templates()).resource_templates
        ]
        overview = await client.read_resource("schema://overview")
        saved = await client.read_resource("queries://saved")
        one = await client.read_resource("queries://saved/top_products")
    assert {"schema://overview", "queries://saved"} <= listed
    assert templates == ["queries://saved/{name}"]
    assert "## main.orders" in overview.contents[0].text
    assert any(q["name"] == "payment_method_mix" for q in json.loads(saved.contents[0].text))
    assert "order_items" in one.contents[0].text


async def test_prompts(server) -> None:
    async with Client(server) as client:
        prompts = {p.name for p in (await client.list_prompts()).prompts}
        analyse = await client.get_prompt("analyse_table", {"table": "orders"})
        report = await client.get_prompt("write_report", {"question": "Which city spends most?"})
    assert prompts == {"analyse_table", "write_report"}
    assert "describe_table" in analyse.messages[0].content.text
    assert "Which city spends most?" in report.messages[0].content.text


async def test_saved_query_tool(server) -> None:
    async with Client(server) as client:
        result = await client.call_tool("run_saved_query", {"name": "payment_method_mix"})
    methods = {row[0] for row in result.structured_content["rows"]}
    assert methods == {"bkash", "nagad", "card", "cod"}
