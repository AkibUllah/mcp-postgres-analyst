"""Runtime settings, read from environment variables (and an optional .env file)."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    database_url: str = "sqlite:///data/demo.db"
    allowed_schemas: str = "public"
    policy_path: Path | None = Path("config/policy.yaml")

    default_limit: int = Field(default=100, ge=1)
    max_rows: int = Field(default=1000, ge=1)
    max_result_bytes: int = Field(default=256 * 1024, ge=1024)
    statement_timeout_ms: int = Field(default=5000, ge=100)

    audit_log_path: Path | None = Path("logs/audit.jsonl")

    mcp_host: str = "127.0.0.1"
    # PORT is what Render, Fly and Heroku-style platforms inject.
    mcp_port: int = Field(
        default=8765, validation_alias=AliasChoices("MCP_PORT", "PORT", "mcp_port")
    )
    mcp_http_token: str | None = None
    mcp_allowed_hosts: str = ""

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    @field_validator("database_url")
    @classmethod
    def _normalise_scheme(cls, value: str) -> str:
        # Heroku/Render style URLs use postgres://, psycopg accepts both but we normalise once.
        if value.startswith("postgres://"):
            return "postgresql://" + value[len("postgres://") :]
        return value

    @field_validator("policy_path", "audit_log_path", mode="before")
    @classmethod
    def _empty_is_none(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("mcp_http_token", mode="before")
    @classmethod
    def _empty_token_is_none(cls, value: object) -> object:
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @property
    def schemas(self) -> list[str]:
        return [s.strip() for s in self.allowed_schemas.split(",") if s.strip()]

    @property
    def extra_allowed_hosts(self) -> list[str]:
        return [h.strip() for h in self.mcp_allowed_hosts.split(",") if h.strip()]

    @property
    def effective_default_limit(self) -> int:
        return min(self.default_limit, self.max_rows)
