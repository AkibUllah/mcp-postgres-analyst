"""MCP server definition: tools, resources and prompts on top of ``AnalystService``."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from typing import Annotated, TypeVar

import anyio
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ResourceNotFoundError, ToolError
from mcp.types import ToolAnnotations
from pydantic import Field
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from pg_analyst import __version__
from pg_analyst.config import Settings
from pg_analyst.models import (
    ColumnSearchResult,
    ExplainResult,
    QueryResult,
    SchemaListing,
    TableDescription,
)
from pg_analyst.service import AnalystError, AnalystService

logger = logging.getLogger(__name__)

T = TypeVar("T")

INSTRUCTIONS = """\
Read-only analyst access to a relational database.
Start with list_schemas or the schema://overview resource, then describe_table for the tables
you need. run_query accepts exactly one SELECT (or WITH ... SELECT) statement; anything else is
rejected. Results are capped (a LIMIT is added or lowered automatically) and some columns are
masked by policy: masked values are placeholders, so do not draw conclusions from them.
Prefer aggregates over pulling raw rows, and use explain_query before heavy queries.
"""

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True)


async def _run(fn: Callable[[], T]) -> T:
    try:
        return await anyio.to_thread.run_sync(fn)
    except AnalystError as exc:
        raise ToolError(str(exc)) from exc


def build_server(service: AnalystService) -> MCPServer:
    """Create the MCP server for an existing service (tests inject one with a temp database)."""
    mcp = MCPServer(
        "postgres-analyst",
        title="Postgres Analyst",
        description="Guarded read-only SQL access with masking, limits and an audit log",
        instructions=INSTRUCTIONS,
        version=__version__,
        website_url="https://github.com/AkibUllah/mcp-postgres-analyst",
    )

    # -- tools ------------------------------------------------------------------------------

    @mcp.tool(title="List schemas and tables", annotations=READ_ONLY)
    async def list_schemas() -> SchemaListing:
        """List the schemas and tables you can query, with row estimates and table comments."""
        return await _run(service.list_schemas)

    @mcp.tool(title="Describe a table", annotations=READ_ONLY)
    async def describe_table(
        table: Annotated[str, Field(description="Table name, optionally schema-qualified")],
    ) -> TableDescription:
        """Columns (type, nullability, default, comment, masking), primary key, foreign keys and
        indexes of one table."""
        return await _run(lambda: service.describe_table(table))

    @mcp.tool(title="Sample rows", annotations=READ_ONLY)
    async def sample_rows(
        table: Annotated[str, Field(description="Table name, optionally schema-qualified")],
        n: Annotated[int, Field(ge=1, le=50, description="Number of rows")] = 5,
    ) -> QueryResult:
        """Return the first n rows of a table, with masking applied."""
        return await _run(lambda: service.sample_rows(table, n))

    @mcp.tool(title="Run a read-only query", annotations=READ_ONLY)
    async def run_query(
        sql: Annotated[str, Field(description="One SELECT or WITH ... SELECT statement")],
        limit: Annotated[
            int | None,
            Field(ge=1, description="Maximum rows to return (capped by the server's MAX_ROWS)"),
        ] = None,
    ) -> QueryResult:
        """Execute a single read-only SELECT. The statement is parsed and validated first; the
        executed SQL (with its enforced LIMIT) is returned in `sql`."""
        return await _run(lambda: service.run_query(sql, limit))

    @mcp.tool(title="Explain a query", annotations=READ_ONLY)
    async def explain_query(
        sql: Annotated[str, Field(description="One SELECT or WITH ... SELECT statement")],
    ) -> ExplainResult:
        """Show the database's query plan without executing the query."""
        return await _run(lambda: service.explain_query(sql))

    @mcp.tool(title="Find columns", annotations=READ_ONLY)
    async def find_columns(
        query: Annotated[str, Field(description="Text to look for in column names and comments")],
    ) -> ColumnSearchResult:
        """Search every accessible table for columns whose name or comment contains the text."""
        return await _run(lambda: service.find_columns(query))

    @mcp.tool(title="Run a saved query", annotations=READ_ONLY)
    async def run_saved_query(
        name: Annotated[str, Field(description="Name from the queries://saved resource")],
    ) -> QueryResult:
        """Run one of the vetted queries published in the policy file."""
        return await _run(lambda: service.run_saved_query(name))

    # -- resources --------------------------------------------------------------------------

    @mcp.resource(
        "schema://overview",
        name="schema_overview",
        title="Schema overview",
        description="Every accessible table with columns, keys and masking notes",
        mime_type="text/markdown",
    )
    async def schema_overview() -> str:
        return await anyio.to_thread.run_sync(service.schema_overview_markdown)

    @mcp.resource(
        "queries://saved",
        name="saved_queries",
        title="Saved queries",
        description="Vetted queries from the policy file (name, description, SQL)",
        mime_type="application/json",
    )
    def saved_queries() -> str:
        return json.dumps([q.model_dump() for q in service.saved_queries()], indent=2)

    @mcp.resource(
        "queries://saved/{name}",
        name="saved_query",
        title="Saved query",
        description="SQL text of one saved query",
        mime_type="application/sql",
    )
    def saved_query(name: str) -> str:
        query = service.policy.saved_query(name)
        if query is None:
            raise ResourceNotFoundError(f"no saved query named {name!r}")
        return query.sql

    # -- prompts ----------------------------------------------------------------------------

    @mcp.prompt(title="Analyse a table")
    def analyse_table(table: str) -> str:
        """Profile one table: structure, data quality and notable distributions."""
        return (
            f"Analyse the `{table}` table.\n\n"
            "1. Call describe_table to get its columns, keys and masking notes.\n"
            "2. Call sample_rows with n=5 to see representative values.\n"
            "3. With run_query, profile it using aggregates only: row count, null rate per "
            "column, distinct counts for low-cardinality text columns, min/max/avg for numeric "
            "and date columns, and the top 5 values of categorical columns.\n"
            "4. Follow foreign keys to explain how the table relates to the rest of the schema.\n\n"
            "Report: a one-paragraph summary, a table of column findings, data quality issues, "
            "and three questions this table could answer for the business. Masked columns hold "
            "placeholders; mention that they are masked instead of analysing their values. "
            "Show every SQL statement you ran in an appendix."
        )

    @mcp.prompt(title="Write a data report")
    def write_report(question: str, audience: str = "management") -> str:
        """Answer a business question with queries and write it up as a short report."""
        return (
            f"Write a data report answering: {question}\n"
            f"Audience: {audience}.\n\n"
            "Work method:\n"
            "- Read schema://overview (or call list_schemas and describe_table) before "
            "writing SQL.\n"
            "- Check queries://saved for an existing vetted query first.\n"
            "- Use aggregates; keep each result small. Run explain_query on anything that joins "
            "more than two large tables.\n"
            "- Amounts are in Bangladeshi taka: format them as ৳1,23,456.78 style or 'BDT'.\n\n"
            "Structure: title, key findings (3-5 bullets with numbers), supporting tables, "
            "caveats (data gaps, masked fields, row limits hit), and an appendix with each SQL "
            "statement and what it measured."
        )

    # -- HTTP-only extras -------------------------------------------------------------------

    @mcp.custom_route("/health", methods=["GET"], include_in_schema=False)
    async def health(_: Request) -> Response:
        reachable = await anyio.to_thread.run_sync(service.db.ping)
        body = {
            "status": "ok" if reachable else "degraded",
            "database": service.db.dialect,
            "reachable": reachable,
            "version": __version__,
        }
        return JSONResponse(body, status_code=200 if reachable else 503)

    return mcp


def create_server(settings: Settings | None = None) -> tuple[MCPServer, AnalystService]:
    settings = settings or Settings()
    service = AnalystService(settings)
    return build_server(service), service
