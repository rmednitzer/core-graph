"""Embedding distribution drift detection.

Computes a coarse KL divergence between the current month's embedding
sample (10k random rows) and a baseline distribution stored in
tests/eval/baseline_embedding_dist.npz. Thresholds:

  KL > 0.1 → WARN  (logged, exposed as Prometheus gauge)
  KL > 0.5 → ERROR (exit 2; CI fails)

The "distribution" is a histogram of per-dimension means binned into 50
buckets in the range [-1, 1] — a good-enough proxy for whether the
embedding model has drifted dramatically without requiring full
distribution comparison (KS test on 768 dimensions × 10k samples is
expensive in CI).

Stores the current sample's histogram alongside the baseline if
--update-baseline is passed.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

logger = logging.getLogger(__name__)

DEFAULT_BASELINE = ROOT / "tests" / "eval" / "baseline_embedding_dist.npz"

# WARN / ERROR thresholds.
WARN_THRESHOLD = 0.1
ERROR_THRESHOLD = 0.5

# Histogram bin range / count.
HIST_BINS = 50
HIST_RANGE = (-1.0, 1.0)


def _kl_divergence(p: list[float], q: list[float], eps: float = 1e-12) -> float:
    """KL(P || Q). Both p and q are histograms (sum to 1)."""
    import math

    s = 0.0
    for pi, qi in zip(p, q, strict=True):
        if pi <= 0:
            continue
        s += pi * math.log((pi + eps) / (qi + eps))
    return s


def _normalise(hist: list[float]) -> list[float]:
    total = sum(hist)
    if total <= 0:
        return [0.0] * len(hist)
    return [v / total for v in hist]


def _histogram(values: list[float]) -> list[float]:
    """Bin values into HIST_BINS uniform buckets across HIST_RANGE."""
    lo, hi = HIST_RANGE
    width = (hi - lo) / HIST_BINS
    bins = [0.0] * HIST_BINS
    for v in values:
        if v < lo or v >= hi:
            # Out-of-range values land in the nearest edge bin.
            idx = 0 if v < lo else HIST_BINS - 1
        else:
            idx = int((v - lo) / width)
        bins[idx] += 1.0
    return _normalise(bins)


async def _sample_embedding_means(pg_dsn: str, sample_size: int) -> list[float]:
    """Pull a random sample of embeddings and return per-row mean values.

    We collapse each `dim`-vector to its mean to keep the histogram
    one-dimensional. Two distributions agree iff they're close at this
    coarse-grained level — coarse enough that random fluctuation doesn't
    trip the alarm.
    """
    import psycopg

    means: list[float] = []
    with psycopg.connect(pg_dsn) as conn:
        cur = conn.execute(
            """
            select embedding from embeddings
             order by random()
             limit %s
            """,
            (sample_size,),
        )
        for row in cur:
            raw = row[0]
            # pgvector returns vectors as strings like "[0.1,-0.2,...]"
            if isinstance(raw, str):
                trimmed = raw.strip("[]")
                if not trimmed:
                    continue
                values = [float(x) for x in trimmed.split(",")]
            else:
                values = [float(x) for x in raw]
            if not values:
                continue
            means.append(sum(values) / len(values))
    return means


def _load_baseline(path: Path) -> list[float] | None:
    if not path.is_file():
        return None
    try:
        import numpy as np

        with np.load(path) as data:
            return list(data["histogram"].astype(float))
    except Exception:
        # Fall back to JSON sidecar (numpy is optional).
        sidecar = path.with_suffix(".json")
        if sidecar.is_file():
            return json.loads(sidecar.read_text())["histogram"]
        return None


def _save_baseline(path: Path, hist: list[float]) -> None:
    try:
        import numpy as np

        path.parent.mkdir(parents=True, exist_ok=True)
        np.savez(path, histogram=np.array(hist, dtype=float))
    except Exception:
        # Plain JSON fallback for environments without numpy.
        path = path.with_suffix(".json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"histogram": hist}))


def _emit_prometheus_gauge(kl: float, status: str) -> None:
    try:
        from prometheus_client import Gauge, push_to_gateway, CollectorRegistry

        reg = CollectorRegistry()
        gauge = Gauge(
            "cg_embedding_drift_kl",
            "KL divergence of embedding mean distribution vs baseline",
            registry=reg,
        )
        gauge.set(kl)
        gateway = os.environ.get("CG_PROMETHEUS_PUSHGATEWAY")
        if gateway:
            push_to_gateway(gateway, job="cg-embedding-drift", registry=reg)
    except Exception:
        logger.debug("prometheus push skipped: %s", "unconfigured", exc_info=True)


async def _amain(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Embedding drift detector")
    parser.add_argument("--pg-dsn", default=os.environ.get("CG_PG_DSN", ""))
    parser.add_argument("--sample-size", type=int, default=10_000)
    parser.add_argument("--baseline", default=str(DEFAULT_BASELINE))
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="Persist the current histogram as the new baseline (used at first run).",
    )
    args = parser.parse_args(argv)

    if not args.pg_dsn:
        print("CG_PG_DSN is required", file=sys.stderr)
        return 1

    means = await _sample_embedding_means(args.pg_dsn, args.sample_size)
    if not means:
        print("warn: no embeddings sampled; skipping drift check", file=sys.stderr)
        return 0

    current_hist = _histogram(means)
    baseline_hist = _load_baseline(Path(args.baseline))

    if baseline_hist is None:
        if args.update_baseline:
            _save_baseline(Path(args.baseline), current_hist)
            print(json.dumps({"status": "baseline_initialised", "kl": 0.0}, indent=2))
            return 0
        print(
            json.dumps(
                {
                    "status": "no_baseline",
                    "kl": 0.0,
                    "hint": "run with --update-baseline once",
                },
                indent=2,
            )
        )
        return 0

    kl = _kl_divergence(current_hist, baseline_hist)
    if kl > ERROR_THRESHOLD:
        status = "ERROR"
        rc = 2
    elif kl > WARN_THRESHOLD:
        status = "WARN"
        rc = 0
    else:
        status = "OK"
        rc = 0

    _emit_prometheus_gauge(kl, status)

    if args.update_baseline and status != "ERROR":
        _save_baseline(Path(args.baseline), current_hist)

    print(
        json.dumps(
            {
                "status": status,
                "kl": round(kl, 6),
                "warn_threshold": WARN_THRESHOLD,
                "error_threshold": ERROR_THRESHOLD,
                "sample_size": len(means),
            },
            indent=2,
        )
    )
    return rc


def main() -> int:
    return asyncio.run(_amain())


if __name__ == "__main__":
    raise SystemExit(main())
