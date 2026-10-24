"""Safety policy loaded from YAML: masking rules, blocked objects, rate limits, saved queries."""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator

MaskStrategy = Literal["email", "phone", "last4", "hash", "redact"]

_RATE_RE = re.compile(r"^\s*(\d+)\s*/\s*(\d*)\s*(s|sec|second|m|min|minute|h|hour)s?\s*$", re.I)
_UNIT_SECONDS = {"s": 1, "sec": 1, "second": 1, "m": 60, "min": 60, "minute": 60}
_UNIT_SECONDS |= {"h": 3600, "hour": 3600}


class MaskRule(BaseModel):
    """Mask every result column whose name matches ``column`` (glob, case-insensitive)."""

    column: str
    strategy: MaskStrategy = "redact"

    def matches(self, name: str) -> bool:
        return fnmatch.fnmatchcase(name.lower(), self.column.lower())


class RateLimit(BaseModel):
    capacity: int = Field(ge=1)
    per_seconds: float = Field(gt=0)

    @classmethod
    def parse(cls, value: str | dict | RateLimit) -> RateLimit:
        """Accept ``"30/minute"``, ``"5/10s"`` or ``{capacity, per_seconds}``."""
        if isinstance(value, RateLimit):
            return value
        if isinstance(value, dict):
            return cls.model_validate(value)
        match = _RATE_RE.match(str(value))
        if not match:
            raise ValueError(f"invalid rate limit {value!r}; expected e.g. '30/minute' or '5/10s'")
        count, multiplier, unit = match.groups()
        seconds = _UNIT_SECONDS[unit.lower()] * (int(multiplier) if multiplier else 1)
        return cls(capacity=int(count), per_seconds=seconds)


class SavedQuery(BaseModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    description: str = ""
    sql: str


class Policy(BaseModel):
    masking: list[MaskRule] = Field(default_factory=list)
    blocked_tables: list[str] = Field(default_factory=list)
    blocked_columns: list[str] = Field(default_factory=list)
    blocked_functions: list[str] = Field(default_factory=list)
    rate_limits: dict[str, RateLimit] = Field(default_factory=dict)
    saved_queries: list[SavedQuery] = Field(default_factory=list)

    @field_validator("rate_limits", mode="before")
    @classmethod
    def _parse_rates(cls, value: object) -> object:
        if isinstance(value, dict):
            return {k: RateLimit.parse(v) for k, v in value.items()}
        return value

    @field_validator("blocked_tables", "blocked_columns", "blocked_functions")
    @classmethod
    def _lower(cls, value: list[str]) -> list[str]:
        return [v.strip().lower() for v in value if v.strip()]

    def mask_rule_for(self, column: str) -> MaskRule | None:
        for rule in self.masking:
            if rule.matches(column):
                return rule
        return None

    def rate_limit_for(self, tool: str) -> RateLimit | None:
        return self.rate_limits.get(tool) or self.rate_limits.get("default")

    def is_table_blocked(self, table: str, schema: str | None = None) -> bool:
        """Blocked entries are ``table`` (any schema) or ``schema.table``; globs allowed."""
        candidates = {table.lower()}
        if schema:
            candidates.add(f"{schema.lower()}.{table.lower()}")
        return any(
            fnmatch.fnmatchcase(c, pattern) for c in candidates for pattern in self.blocked_tables
        )

    def blocked_column_pairs(self) -> list[tuple[str, str]]:
        """``blocked_columns`` entries as ``(table, column)``; ``*`` table means any table."""
        pairs = []
        for entry in self.blocked_columns:
            table, _, column = entry.rpartition(".")
            pairs.append((table or "*", column))
        return pairs

    def saved_query(self, name: str) -> SavedQuery | None:
        return next((q for q in self.saved_queries if q.name == name), None)


def load_policy(path: Path | None) -> Policy:
    if path is None:
        return Policy()
    if not path.exists():
        raise FileNotFoundError(f"policy file not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"policy file {path} must contain a mapping at the top level")
    return Policy.model_validate(data)
