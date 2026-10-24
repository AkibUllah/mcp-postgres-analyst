"""Structured tool outputs. MCP clients receive these as ``structuredContent`` plus JSON text."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class TableEntry(BaseModel):
    name: str
    row_estimate: int | None = None
    comment: str | None = None


class SchemaEntry(BaseModel):
    name: str
    tables: list[TableEntry]


class SchemaListing(BaseModel):
    database: str
    dialect: str
    schemas: list[SchemaEntry]


class ColumnEntry(BaseModel):
    name: str
    type: str
    nullable: bool
    default: str | None = None
    primary_key: bool = False
    comment: str | None = None
    masking: str | None = Field(
        default=None, description="Masking strategy applied to this column in query results"
    )


class ForeignKeyEntry(BaseModel):
    column: str
    references: str


class TableDescription(BaseModel):
    schema_name: str
    table: str
    comment: str | None = None
    row_estimate: int | None = None
    columns: list[ColumnEntry]
    foreign_keys: list[ForeignKeyEntry] = Field(default_factory=list)
    indexes: list[str] = Field(default_factory=list)


class QueryResult(BaseModel):
    sql: str = Field(description="The statement that was actually executed (after rewriting)")
    columns: list[str]
    rows: list[list[Any]]
    row_count: int
    truncated: bool = False
    truncated_reason: str | None = Field(
        default=None, description="'row_limit' or 'max_result_bytes' when rows were cut off"
    )
    limit: int
    limit_rewritten: bool = False
    masked_columns: list[str] = Field(default_factory=list)
    hidden_columns: list[str] = Field(default_factory=list)
    elapsed_ms: float


class ExplainResult(BaseModel):
    sql: str
    plan: str


class ColumnMatch(BaseModel):
    schema_name: str
    table: str
    column: str
    type: str
    comment: str | None = None
    masking: str | None = None


class ColumnSearchResult(BaseModel):
    query: str
    matches: list[ColumnMatch]
