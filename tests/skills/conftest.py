"""Shared fixtures for skill tests."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _reset_module_cache():
    """Ensure skill module imports are fresh for each test."""
    yield
