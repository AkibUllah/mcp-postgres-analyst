"""Value masking strategies applied to result columns after execution."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from pg_analyst.policy import MaskRule, MaskStrategy, Policy

REDACTED = "[REDACTED]"


def mask_email(value: str) -> str:
    local, sep, domain = value.partition("@")
    if not sep:
        return mask_redact(value)
    head = local[:1] if local else ""
    return f"{head}***@{domain}"


def mask_phone(value: str) -> str:
    """Keep separators and the last three digits: ``+880 1711-223344`` -> ``+*** ****-***344``."""
    remaining = sum(c.isdigit() for c in value)
    if remaining <= 3:
        return "***"
    out: list[str] = []
    for char in value:
        if char.isdigit():
            out.append(char if remaining <= 3 else "*")
            remaining -= 1
        else:
            out.append(char)
    return "".join(out)


def mask_last4(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return "*" * (len(value) - 4) + value[-4:]


def mask_hash(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"sha256:{digest}"


def mask_redact(_: str) -> str:
    return REDACTED


STRATEGIES: dict[MaskStrategy, Callable[[str], str]] = {
    "email": mask_email,
    "phone": mask_phone,
    "last4": mask_last4,
    "hash": mask_hash,
    "redact": mask_redact,
}


def mask_value(value: Any, strategy: MaskStrategy) -> Any:
    if value is None:
        return None
    return STRATEGIES[strategy](str(value))


def plan_masks(
    columns: Sequence[str],
    policy: Policy,
    tainted: Mapping[str, MaskRule] | None = None,
) -> dict[int, MaskRule]:
    """Decide, per result column index, which rule (if any) applies.

    A column is masked when its own name matches a rule, or when static analysis found that it
    is derived from a masked column (``tainted``, keyed by lower-case output name).
    """
    tainted = tainted or {}
    plan: dict[int, MaskRule] = {}
    for index, name in enumerate(columns):
        rule = policy.mask_rule_for(name) or tainted.get(name.lower())
        if rule is not None:
            plan[index] = rule
    return plan


def apply_masks(rows: list[list[Any]], plan: Mapping[int, MaskRule]) -> list[list[Any]]:
    if not plan:
        return rows
    for row in rows:
        for index, rule in plan.items():
            row[index] = mask_value(row[index], rule.strategy)
    return rows
