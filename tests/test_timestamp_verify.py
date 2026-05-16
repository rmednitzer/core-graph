"""verify_timestamp: CA-pinning routing and fail-closed semantics.

rfc3161ng is a hard dependency, so the rfc3161ng branch always runs in
production. It verifies the message imprint + token signature but does
NOT chain the signer cert to a trusted CA. These tests pin the rule that
a configured CA forces the openssl ``-CAfile`` path and never silently
falls back to rfc3161ng (which would be false CA-pinning assurance).
"""

from __future__ import annotations

import sys
import types

import pytest

from evidence.signing import timestamp

_DIGEST = b"\x00" * 32
# Not a real path — verify_timestamp's subprocess call is mocked; this
# only needs to be a non-empty string that flows into argv.
_CA = "pinned-ca.pem"


def _fake_rfc3161ng(*, returns: bool | None = None, raises: bool = False):
    mod = types.ModuleType("rfc3161ng")

    def check_timestamp(**_kwargs):
        if raises:
            raise ValueError("bad token")
        return returns

    mod.check_timestamp = check_timestamp  # type: ignore[attr-defined]
    return mod


def test_pinned_ca_uses_openssl_cafile(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[list[str]] = []

    def fake_run(cmd, *a, **k):
        seen.append(cmd)
        return types.SimpleNamespace(returncode=0)

    monkeypatch.setattr(timestamp.subprocess, "run", fake_run)
    # rfc3161ng would say "valid" — must NOT be consulted when CA pinned.
    monkeypatch.setitem(sys.modules, "rfc3161ng", _fake_rfc3161ng(returns=True))

    assert timestamp.verify_timestamp(b"tok", _DIGEST, ca_cert_path=_CA) is True
    assert len(seen) == 1
    argv = seen[0]
    assert argv[0] == "openssl" and "-verify" in argv
    assert "-CAfile" in argv and _CA in argv


def test_pinned_ca_fail_closed_when_openssl_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(*a, **k):
        raise FileNotFoundError("openssl")

    monkeypatch.setattr(timestamp.subprocess, "run", fake_run)
    # Even though rfc3161ng would return True, a pinned CA must NOT fall
    # back to it — fail closed instead of false assurance.
    monkeypatch.setitem(sys.modules, "rfc3161ng", _fake_rfc3161ng(returns=True))

    assert timestamp.verify_timestamp(b"tok", _DIGEST, ca_cert_path=_CA) is False


def test_pinned_ca_fail_closed_on_verify_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        timestamp.subprocess,
        "run",
        lambda *a, **k: types.SimpleNamespace(returncode=1),
    )
    assert timestamp.verify_timestamp(b"tok", _DIGEST, ca_cert_path=_CA) is False


def test_no_ca_uses_rfc3161ng(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail_run(*a, **k):
        raise AssertionError("openssl must not run when rfc3161ng handles it")

    monkeypatch.setattr(timestamp.subprocess, "run", fail_run)
    monkeypatch.setitem(sys.modules, "rfc3161ng", _fake_rfc3161ng(returns=True))

    assert timestamp.verify_timestamp(b"tok", _DIGEST) is True


def test_no_ca_fail_closed_on_rfc3161ng_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "rfc3161ng", _fake_rfc3161ng(raises=True))
    # check_timestamp raising must yield False, not propagate and abort
    # the stamping batch.
    assert timestamp.verify_timestamp(b"tok", _DIGEST) is False
