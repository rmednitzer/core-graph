"""Tests for the Cerbos client wire format (``api.authz.cerbos``).

These guard the ``/api/check/resources`` request and response handling against
the documented Cerbos API shape (verified against the Cerbos v0.53 API):

* request:  ``{"principal": ..., "resources": [{"resource": ..., "actions": [...]}]}``
* response: ``{"results": [{"actions": {"<action>": "EFFECT_ALLOW"}}]}``

Regression target: the per-action effect is a **string**, not a nested object
with an ``effect`` key. The identity-attribution path previously read
``results[0].actions[action]["effect"]``, which raises ``AttributeError`` on the
real (string) response and silently fail-closed every *allow* decision -- so the
CISO-gated attribution tool denied every request against a live Cerbos.
"""

from __future__ import annotations

from typing import Any

import pytest

from api.authz import cerbos


class _FakeResponse:
    def __init__(self, payload: dict[str, Any], *, status_ok: bool = True) -> None:
        self._payload = payload
        self._status_ok = status_ok

    def raise_for_status(self) -> None:
        if not self._status_ok:
            raise RuntimeError("HTTP 500 from Cerbos")

    def json(self) -> dict[str, Any]:
        return self._payload


class _FakeClient:
    def __init__(self, response: _FakeResponse | Exception) -> None:
        self._response = response
        self.last_post: dict[str, Any] | None = None

    async def post(self, url: str, json: dict[str, Any]) -> _FakeResponse:
        self.last_post = {"url": url, "json": json}
        if isinstance(self._response, Exception):
            raise self._response
        return self._response


def _install(monkeypatch: pytest.MonkeyPatch, response: _FakeResponse | Exception) -> _FakeClient:
    client = _FakeClient(response)
    monkeypatch.setattr(cerbos, "_get_http_client", lambda: client)
    return client


def _effect(action: str, effect: str) -> _FakeResponse:
    """A real-shaped Cerbos response: actions[action] is the effect *string*."""
    return _FakeResponse(
        {"results": [{"resource": {"kind": "x", "id": "1"}, "actions": {action: effect}}]}
    )


@pytest.mark.asyncio
async def test_check_action_allow(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _effect("assert", "EFFECT_ALLOW"))
    allowed = await cerbos.check_action(
        {"id": "u", "roles": ["ciso"]}, "identity_attribution", "p:ta", "assert"
    )
    assert allowed is True


@pytest.mark.asyncio
async def test_check_action_deny(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _effect("assert", "EFFECT_DENY"))
    allowed = await cerbos.check_action(
        {"id": "u", "roles": ["soc_analyst"]}, "identity_attribution", "p:ta", "assert"
    )
    assert allowed is False


@pytest.mark.asyncio
async def test_effect_is_string_not_object(monkeypatch: pytest.MonkeyPatch) -> None:
    # The crux of the fixed bug: a real ALLOW response must read as allowed.
    # The previous ``.get("effect")`` access raised AttributeError on the
    # string and fail-closed -- this asserts we read the string directly.
    _install(monkeypatch, _effect("assert", "EFFECT_ALLOW"))
    assert await cerbos.check_action({"id": "u"}, "k", "id", "assert") is True


@pytest.mark.asyncio
async def test_request_uses_batch_resources_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _install(monkeypatch, _effect("assert", "EFFECT_ALLOW"))
    await cerbos.check_action(
        {"id": "u", "roles": ["ciso"]},
        "identity_attribution",
        "p:ta",
        "assert",
        {"investigation_id": "INV-1"},
    )
    assert client.last_post is not None
    assert client.last_post["url"] == "/api/check/resources"
    body = client.last_post["json"]
    # Batch shape only: a plural ``resources`` list, never the singular
    # ``resource`` + top-level ``actions`` form (which the plural endpoint
    # rejects).
    assert "resource" not in body
    assert "actions" not in body
    assert isinstance(body["resources"], list)
    assert len(body["resources"]) == 1
    entry = body["resources"][0]
    assert entry["resource"]["kind"] == "identity_attribution"
    assert entry["resource"]["id"] == "p:ta"
    assert entry["resource"]["attr"] == {"investigation_id": "INV-1"}
    assert entry["actions"] == ["assert"]
    assert body["principal"] == {"id": "u", "roles": ["ciso"]}


@pytest.mark.asyncio
async def test_empty_results_denies(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _FakeResponse({"results": []}))
    assert await cerbos.check_action({"id": "u"}, "k", "id", "assert") is False


@pytest.mark.asyncio
async def test_transport_error_denies(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, RuntimeError("connection refused"))
    assert await cerbos.check_action({"id": "u"}, "k", "id", "assert") is False


@pytest.mark.asyncio
async def test_http_error_denies(monkeypatch: pytest.MonkeyPatch) -> None:
    _install(monkeypatch, _FakeResponse({"results": []}, status_ok=False))
    assert await cerbos.check_action({"id": "u"}, "k", "id", "assert") is False


@pytest.mark.asyncio
async def test_wrong_action_key_denies(monkeypatch: pytest.MonkeyPatch) -> None:
    # If the response carries a different action than the one asked for, the
    # missing key must read as deny (not raise).
    _install(monkeypatch, _effect("read", "EFFECT_ALLOW"))
    assert await cerbos.check_action({"id": "u"}, "k", "id", "assert") is False


@pytest.mark.asyncio
async def test_check_resource_builds_principal_from_caller_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _install(monkeypatch, _effect("read", "EFFECT_ALLOW"))

    class _CI:
        sub = "user-1"
        roles = ["soc_analyst"]
        max_tlp = 2
        groups = ["g1"]
        department = "secops"
        allowed_compartments = ["INV-1"]

    allowed = await cerbos.check_resource(_CI(), "threat_entity", "ta-1", "read")
    assert allowed is True
    assert client.last_post is not None
    principal = client.last_post["json"]["principal"]
    assert principal["id"] == "user-1"
    assert principal["roles"] == ["soc_analyst"]
    assert principal["attr"]["max_tlp"] == 2
    assert principal["attr"]["allowed_compartments"] == ["INV-1"]
