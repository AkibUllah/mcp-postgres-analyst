from __future__ import annotations

from pg_analyst.caller import STDIO, Caller, resolve_caller


def test_no_headers_is_the_stdio_identity() -> None:
    assert resolve_caller(None) == STDIO
    named = resolve_caller(None, client_name="Desktop Client", client_version="1.4.2")
    assert named == Caller(client="Desktop Client/1.4.2")
    assert named.key == "stdio" and named.session == "stdio"


def test_http_session_id_keys_the_caller() -> None:
    caller = resolve_caller(
        {"mcp-session-id": "5ba7ebe0ce764ad3", "host": "x"},
        client_name="report-bot",
        remote="10.1.2.3",
    )
    assert caller == Caller(
        key="session:5ba7ebe0ce764ad3",
        session="5ba7ebe0ce764ad3",
        client="report-bot",
        remote="10.1.2.3",
    )


def test_sessionless_http_falls_back_to_the_remote_address() -> None:
    caller = resolve_caller({"host": "x"}, remote="192.0.2.10")
    assert caller.key == "remote:192.0.2.10" and caller.session is None
    assert resolve_caller({}, remote=None).key == "remote:unknown"


def test_malformed_session_ids_are_not_trusted() -> None:
    for bad in ("", "has space", "tab\there", "x" * 129, "café"):
        caller = resolve_caller({"mcp-session-id": bad}, remote="192.0.2.10")
        assert caller.session is None and caller.key == "remote:192.0.2.10", bad
    assert resolve_caller({"mcp-session-id": "x" * 128}).session == "x" * 128


def test_client_info_is_cleaned_and_bounded() -> None:
    caller = resolve_caller(None, client_name="bot\n\x1b[31mred", client_version="9" * 100)
    assert caller.client == "bot[31mred/" + "9" * 32
    assert resolve_caller(None, client_name="", client_version="1.0").client is None
    assert resolve_caller(None, client_name="bot", client_version="").client == "bot"
