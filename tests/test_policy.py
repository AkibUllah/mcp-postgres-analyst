from __future__ import annotations

from pathlib import Path

import pytest

from pg_analyst.policy import Policy, RateLimit, load_policy
from pg_analyst.ratelimit import RateLimited, ToolRateLimiter


@pytest.mark.parametrize(
    ("text", "capacity", "seconds"),
    [("30/minute", 30, 60), ("5/10s", 5, 10), ("100/hour", 100, 3600), ("2 / 5 min", 2, 300)],
)
def test_rate_limit_parsing(text: str, capacity: int, seconds: float) -> None:
    limit = RateLimit.parse(text)
    assert (limit.capacity, limit.per_seconds) == (capacity, seconds)


def test_rate_limit_parsing_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        RateLimit.parse("lots")


def test_bundled_policy_loads(policy: Policy) -> None:
    assert policy.mask_rule_for("email").strategy == "email"
    assert policy.mask_rule_for("payer_phone").strategy == "phone"
    assert policy.mask_rule_for("city") is None
    assert policy.is_table_blocked("staff_payroll")
    assert policy.is_table_blocked("audit_events", "public")
    assert ("customers", "password_hash") in policy.blocked_column_pairs()
    assert policy.rate_limit_for("run_query").capacity == 30
    assert policy.rate_limit_for("describe_table").capacity == 60
    assert {q.name for q in policy.saved_queries} >= {"revenue_by_month", "top_products"}


def test_missing_or_invalid_policy_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_policy(tmp_path / "nope.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("- just\n- a list\n")
    with pytest.raises(ValueError):
        load_policy(bad)
    assert load_policy(None) == Policy()


def test_token_bucket_per_tool_refills_over_time() -> None:
    now = [0.0]
    policy = Policy.model_validate({"rate_limits": {"run_query": "2/10s"}})
    limiter = ToolRateLimiter(policy, clock=lambda: now[0])
    limiter.check("run_query")
    limiter.check("run_query")
    with pytest.raises(RateLimited) as info:
        limiter.check("run_query")
    assert info.value.retry_after == pytest.approx(5.0)
    limiter.check("list_schemas")  # no default rule: unlimited
    now[0] = 5.0
    limiter.check("run_query")
    with pytest.raises(RateLimited):
        limiter.check("run_query")
