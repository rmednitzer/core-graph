"""Unit tests for the embedding drift detector helpers (no DB needed)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "bench" / "embedding_drift.py"

_spec = importlib.util.spec_from_file_location("embedding_drift", SCRIPT)
assert _spec is not None and _spec.loader is not None
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


def test_kl_zero_for_identical_distributions() -> None:
    p = _mod._normalise([1.0, 2.0, 3.0, 4.0])
    assert abs(_mod._kl_divergence(p, p)) < 1e-9


def test_kl_positive_when_different() -> None:
    p = _mod._normalise([0.1, 0.2, 0.7])
    q = _mod._normalise([0.7, 0.2, 0.1])
    assert _mod._kl_divergence(p, q) > 0.0


def test_kl_handles_zero_in_p() -> None:
    p = _mod._normalise([1.0, 0.0, 1.0])
    q = _mod._normalise([0.5, 0.5, 0.5])
    out = _mod._kl_divergence(p, q)
    assert out >= 0.0


def test_histogram_bins_match_constant() -> None:
    bins = _mod._histogram([0.0, 0.1, -0.5, 0.99, -0.99])
    assert len(bins) == _mod.HIST_BINS
    assert abs(sum(bins) - 1.0) < 1e-9


def test_histogram_handles_out_of_range_values() -> None:
    bins = _mod._histogram([-2.0, 2.0])
    assert bins[0] > 0.0
    assert bins[-1] > 0.0


def test_threshold_constants_match_design() -> None:
    assert _mod.WARN_THRESHOLD == 0.1
    assert _mod.ERROR_THRESHOLD == 0.5
