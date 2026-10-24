from __future__ import annotations

import pytest

from pg_analyst.masking import (
    REDACTED,
    apply_masks,
    mask_email,
    mask_hash,
    mask_last4,
    mask_phone,
    mask_value,
    plan_masks,
)
from pg_analyst.policy import MaskRule, Policy


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("rahim.hossain12@gmail.com", "r***@gmail.com"),
        ("a@b.co", "a***@b.co"),
        ("not-an-email", REDACTED),
    ],
)
def test_mask_email(value: str, expected: str) -> None:
    assert mask_email(value) == expected


def test_mask_phone_keeps_format_and_last_three_digits() -> None:
    assert mask_phone("+8801711223344") == "+**********344"
    assert mask_phone("+880 1711-223344") == "+*** ****-***344"
    assert mask_phone("12") == "***"


def test_mask_last4_and_hash() -> None:
    assert mask_last4("1990123456789") == "*********6789"
    assert mask_last4("123") == "***"
    assert mask_hash("BK7XQ2M9PA") == mask_hash("BK7XQ2M9PA")
    assert mask_hash("BK7XQ2M9PA").startswith("sha256:") and "BK7" not in mask_hash("BK7XQ2M9PA")


def test_mask_value_passes_none_and_stringifies() -> None:
    assert mask_value(None, "redact") is None
    assert mask_value(1234567890, "last4") == "******7890"


def test_plan_masks_uses_names_globs_and_taint(policy: Policy) -> None:
    columns = ["id", "EMAIL", "payer_phone", "shout", "city"]
    tainted = {"shout": MaskRule(column="email", strategy="email")}
    plan = plan_masks(columns, policy, tainted)
    assert {i: r.strategy for i, r in plan.items()} == {1: "email", 2: "phone", 3: "email"}


def test_apply_masks_rewrites_rows_in_place(policy: Policy) -> None:
    rows = [[1, "karim.uddin3@yahoo.com"], [2, None]]
    plan = plan_masks(["id", "email"], policy)
    assert apply_masks(rows, plan) == [[1, "k***@yahoo.com"], [2, None]]
