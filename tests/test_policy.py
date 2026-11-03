from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from pg_analyst.config import Settings
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


def test_callers_get_independent_buckets() -> None:
    now = [0.0]
    policy = Policy.model_validate({"rate_limits": {"run_query": "2/10s"}})
    limiter = ToolRateLimiter(policy, clock=lambda: now[0])
    for _ in range(2):
        limiter.check("run_query", "session-a")
    with pytest.raises(RateLimited):
        limiter.check("run_query", "session-a")
    # Session b is untouched by a's exhaustion, and a's own bucket stays empty.
    limiter.check("run_query", "session-b")
    limiter.check("run_query", "session-b")
    with pytest.raises(RateLimited):
        limiter.check("run_query", "session-b")
    with pytest.raises(RateLimited):
        limiter.check("run_query", "session-a")
    assert limiter.tracked == 2


def test_default_caller_keeps_the_per_tool_behaviour() -> None:
    policy = Policy.model_validate({"rate_limits": {"default": "1/minute"}})
    limiter = ToolRateLimiter(policy, clock=lambda: 0.0)
    limiter.check("describe_table")
    limiter.check("run_query")
    with pytest.raises(RateLimited):
        limiter.check("describe_table")
    with pytest.raises(RateLimited):
        limiter.check("describe_table", "stdio")


def test_caller_map_is_bounded_lru() -> None:
    now = [0.0]
    policy = Policy.model_validate({"rate_limits": {"run_query": "1/minute"}})
    limiter = ToolRateLimiter(policy, clock=lambda: now[0], max_callers=3)
    for name in ("a", "b", "c"):
        limiter.check("run_query", name)
        now[0] += 1
    with pytest.raises(RateLimited):
        limiter.check("run_query", "a")  # touching a makes b the least recently used
    limiter.check("run_query", "d")
    assert limiter.tracked == 3
    limiter.check("run_query", "b")  # b was evicted, so it starts with a full bucket
    with pytest.raises(RateLimited):
        limiter.check("run_query", "a")
    for i in range(50):
        limiter.check("run_query", f"burst-{i}")
    assert limiter.tracked == 3


def test_idle_callers_are_dropped_without_granting_extra_tokens() -> None:
    now = [0.0]
    policy = Policy.model_validate({"rate_limits": {"run_query": "1/minute"}})
    limiter = ToolRateLimiter(policy, clock=lambda: now[0], idle_seconds=5)
    # The idle timeout never undercuts the longest refill window.
    assert limiter.idle_seconds == 60
    limiter.check("run_query", "old")
    now[0] = 30.0
    limiter.check("run_query", "fresh")
    assert limiter.tracked == 2
    with pytest.raises(RateLimited):
        limiter.check("run_query", "old")  # 30s idle is not enough to forget it
    now[0] = 95.0
    limiter.check("run_query", "fresh")
    assert limiter.tracked == 1  # "old" (last seen at 30s) was dropped on this check
    limiter.check("run_query", "old")


def test_unlimited_tools_do_not_track_callers() -> None:
    limiter = ToolRateLimiter(Policy(), clock=lambda: 0.0)
    for i in range(10):
        limiter.check("run_query", f"s{i}")
    assert limiter.tracked == 0


def test_forget_and_invalid_limiter_settings() -> None:
    policy = Policy.model_validate({"rate_limits": {"run_query": "1/minute"}})
    limiter = ToolRateLimiter(policy, clock=lambda: 0.0)
    limiter.check("run_query", "a")
    limiter.forget("a")
    limiter.forget("never-seen")
    limiter.check("run_query", "a")
    with pytest.raises(ValueError):
        ToolRateLimiter(policy, max_callers=0)
    with pytest.raises(ValueError):
        ToolRateLimiter(policy, idle_seconds=0)


def test_rate_limit_settings_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RATE_LIMIT_SCOPE", "global")
    monkeypatch.setenv("RATE_LIMIT_MAX_SESSIONS", "25")
    monkeypatch.setenv("RATE_LIMIT_IDLE_SECONDS", "120")
    settings = Settings(_env_file=None)
    assert settings.rate_limit_scope == "global"
    assert settings.rate_limit_max_sessions == 25
    assert settings.rate_limit_idle_seconds == 120
    for name in ("RATE_LIMIT_SCOPE", "RATE_LIMIT_MAX_SESSIONS", "RATE_LIMIT_IDLE_SECONDS"):
        monkeypatch.delenv(name)
    defaults = Settings(_env_file=None)
    assert (defaults.rate_limit_scope, defaults.rate_limit_max_sessions) == ("session", 1000)
    for bad in (
        {"rate_limit_scope": "user"},
        {"rate_limit_max_sessions": 0},
        {"rate_limit_idle_seconds": 0},
    ):
        with pytest.raises(ValidationError):
            Settings(_env_file=None, **bad)
