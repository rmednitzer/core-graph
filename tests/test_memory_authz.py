"""The memory tools consult Cerbos before doing anything (ADR-0018).

`policies/resource/memory.yaml` was declarative until now: it stated who may
write Layer 5 and nothing called it. These tests assert the wiring, and they
assert it the way it matters -- that a denial happens *before* the tool touches
the database, not after it has written half an episode.

No database and no Cerbos: `check_action` is the seam, and it is monkeypatched.
That keeps the tests about the wiring rather than about the policy, which
`tests/auth/cerbos_policies_test.yaml` covers.
"""

from __future__ import annotations

import importlib
from typing import Any

import pytest

from api.authz import cerbos

# --- the principal builder -------------------------------------------------


def test_principal_carries_actor_roles_and_attrs():
    principal = cerbos.principal_from_caller(
        {"actor": "agent-7", "roles": ["ai_agent"], "attr": {"team": "x"}}
    )
    assert principal == {"id": "agent-7", "roles": ["ai_agent"], "attr": {"team": "x"}}


@pytest.mark.parametrize("identity", [None, {}, {"max_tlp": 4}])
def test_a_caller_with_no_roles_gets_a_principal_with_none(identity):
    """Which every resource policy denies. Authorization is decided by role, so
    a caller that presents none has not established one -- and until ADR-0018
    the memory tools accepted exactly this shape."""
    assert cerbos.principal_from_caller(identity)["roles"] == []


# --- the raising wrapper ---------------------------------------------------


@pytest.mark.asyncio
async def test_require_raises_on_deny(monkeypatch: pytest.MonkeyPatch):
    async def deny(*_a: Any, **_k: Any) -> bool:
        return False

    monkeypatch.setattr(cerbos, "check_action", deny)
    with pytest.raises(PermissionError) as exc:
        await cerbos.require_caller_action(
            {"roles": ["external_auditor"]}, "memory", "s-1", "create"
        )
    # The message names the action and the roles, because the first question
    # asked of an authorization denial is always "as who?".
    assert "create on memory" in str(exc.value)
    assert "external_auditor" in str(exc.value)


@pytest.mark.asyncio
async def test_require_says_so_when_no_role_was_presented(monkeypatch: pytest.MonkeyPatch):
    async def deny(*_a: Any, **_k: Any) -> bool:
        return False

    monkeypatch.setattr(cerbos, "check_action", deny)
    with pytest.raises(PermissionError, match="none presented"):
        await cerbos.require_caller_action(None, "memory", "s-1", "read")


@pytest.mark.asyncio
async def test_require_is_silent_on_allow(monkeypatch: pytest.MonkeyPatch):
    async def allow(*_a: Any, **_k: Any) -> bool:
        return True

    monkeypatch.setattr(cerbos, "check_action", allow)
    result = await cerbos.require_caller_action({"roles": ["ai_agent"]}, "memory", "s", "create")
    assert result is None


# --- the wiring, per tool --------------------------------------------------


@pytest.fixture
def deny_everything(monkeypatch: pytest.MonkeyPatch):
    """Deny at the Cerbos seam, and make any database use an outright failure.

    `get_connection` is replaced with something that raises a distinctive error,
    so a tool that checks authorization *after* opening a connection fails this
    test with that error rather than passing quietly.
    """

    async def deny(*_a: Any, **_k: Any) -> bool:
        return False

    monkeypatch.setattr(cerbos, "check_action", deny)

    def exploded(*_a: Any, **_k: Any):
        raise AssertionError("the tool reached the database before authorizing")

    # import_module, not pytest.importorskip: these are first-party modules and
    # a failure to import them is a broken test run, not a reason to skip. An
    # importorskip here turned all four wiring tests into silent skips when a
    # dependency was missing locally, which is the failure mode these tests
    # exist to prevent in the code they cover.
    for module in (
        "api.mcp.tools.memory_remember",
        "api.mcp.tools.memory_recall",
        "api.mcp.tools.memory_session_start",
    ):
        mod = importlib.import_module(module)
        if hasattr(mod, "get_connection"):
            monkeypatch.setattr(mod, "get_connection", exploded)


@pytest.mark.asyncio
async def test_remember_denies_before_writing(deny_everything):
    from api.mcp.tools.memory_remember import tool_remember

    with pytest.raises(PermissionError, match="create on memory"):
        await tool_remember(
            session_id="s-1",
            content="something",
            caller_identity={"roles": ["external_auditor"], "max_tlp": 4},
        )


@pytest.mark.asyncio
async def test_record_extracted_fact_is_denied_before_it_writes(deny_everything):
    from api.mcp.tools.memory_remember import tool_record_extracted_fact

    with pytest.raises(PermissionError, match="create on memory"):
        await tool_record_extracted_fact(
            session_id="s-1",
            episode_graph_id=1,
            subject="a",
            predicate="b",
            obj="c",
            caller_identity={"roles": ["dpo"], "max_tlp": 4},
        )


@pytest.mark.asyncio
async def test_session_start_is_denied_before_it_reads(deny_everything):
    from api.mcp.tools.memory_session_start import tool_session_start

    with pytest.raises(PermissionError, match="read on memory"):
        await tool_session_start(
            session_id="s-1",
            caller_identity={"roles": ["it_operations"], "max_tlp": 4},
        )


@pytest.mark.asyncio
async def test_recall_denies_before_searching(deny_everything, monkeypatch):
    """Recall reaches hybrid_search rather than get_connection first, so the
    guard has to sit ahead of that too."""
    import api.mcp.tools.memory_recall as recall_mod

    async def exploded(*_a: Any, **_k: Any):
        raise AssertionError("the tool searched before authorizing")

    monkeypatch.setattr(recall_mod, "hybrid_search", exploded)

    with pytest.raises(PermissionError, match="read on memory"):
        await recall_mod.tool_recall(
            session_id="s-1",
            query="q",
            caller_identity={"roles": ["external_auditor"], "max_tlp": 4},
        )


@pytest.mark.asyncio
async def test_an_allowed_caller_gets_past_the_guard(monkeypatch: pytest.MonkeyPatch):
    """The mirror of the tests above: with Cerbos allowing, the tool proceeds
    and fails on the database instead. Without this, all of the above would
    still pass if the guard denied unconditionally."""

    async def allow(*_a: Any, **_k: Any) -> bool:
        return True

    monkeypatch.setattr(cerbos, "check_action", allow)

    import api.mcp.tools.memory_session_start as start_mod

    def reached_db(*_a: Any, **_k: Any):
        raise RuntimeError("reached the database")

    monkeypatch.setattr(start_mod, "get_connection", reached_db)

    with pytest.raises(RuntimeError, match="reached the database"):
        await start_mod.tool_session_start(
            session_id="s-1",
            caller_identity={"roles": ["ai_agent"], "max_tlp": 2},
        )
