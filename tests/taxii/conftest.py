"""tests/taxii/conftest.py — shared fixtures for TAXII endpoint tests.

The TAXII endpoint tests stub the DB connection and exercise the
endpoint logic in isolation. They are not auth-coverage tests, so the
OIDC middleware is bypassed via the equivalent of
``CG_OIDC_ENABLED=false`` + ``CG_DEV_MODE=true``. Real auth coverage
lives in the OIDC middleware unit tests and the Cerbos policy suite.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest


@pytest.fixture(autouse=True)
def _taxii_auth_bypass():
    """Inject the synthetic dev identity for the TAXII test suite."""
    with (
        patch("api.config.OIDC_ENABLED", False),
        patch("api.config.DEV_MODE", True),
    ):
        yield
