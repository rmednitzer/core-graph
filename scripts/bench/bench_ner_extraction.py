"""Benchmark script for Tier 1 NER IOC extraction throughput.

Generates text blocks with embedded IOCs and measures extraction performance.
Target: >= 10,000 IOC extractions/sec (regex only, no ML).
"""

from __future__ import annotations

import json
import random
import statistics
import sys
import time


def _generate_text_block(rng: random.Random) -> str:
    """Generate a text block with embedded IOCs."""
    iocs = [
        f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
        f"evil-{rng.randint(1000, 9999)}.example-threat.com",
        f"https://malware-c2-{rng.randint(100, 999)}.badsite.org/payload",
        f"CVE-{rng.randint(2020, 2025)}-{rng.randint(10000, 99999)}",
        f"T{rng.randint(1000, 1999)}.{rng.randint(1, 999):03d}",
        f"{''.join(rng.choices('abcdef0123456789', k=64))}",
    ]
    filler = [
        "The threat actor was observed using",
        "network traffic indicated connections to",
        "analysis revealed the following indicators",
        "the campaign leveraged",
        "associated infrastructure includes",
    ]
    parts = []
    for ioc in iocs:
        parts.append(f"{rng.choice(filler)} {ioc}.")
    return " ".join(parts)


def main() -> None:
    from ingest.ner.tier1_regex import extract_iocs

    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    rng = random.Random(42)

    text_blocks = [_generate_text_block(rng) for _ in range(n)]

    # Warm up
    extract_iocs(text_blocks[0])

    latencies: list[float] = []
    total_iocs = 0

    start_total = time.perf_counter()
    for block in text_blocks:
        t0 = time.perf_counter()
        results = extract_iocs(block, reject_private_ips=False)
        t1 = time.perf_counter()
        latencies.append(t1 - t0)
        total_iocs += len(results)
    elapsed_total = time.perf_counter() - start_total

    latencies.sort()
    p50 = statistics.median(latencies)
    p95 = latencies[int(len(latencies) * 0.95)]
    p99 = latencies[int(len(latencies) * 0.99)]

    result = {
        "benchmark": "ner_extraction",
        "blocks": n,
        "total_iocs": total_iocs,
        "elapsed_seconds": round(elapsed_total, 4),
        "extractions_per_second": round(n / elapsed_total, 2),
        "iocs_per_second": round(total_iocs / elapsed_total, 2),
        "latency_p50_ms": round(p50 * 1000, 4),
        "latency_p95_ms": round(p95 * 1000, 4),
        "latency_p99_ms": round(p99 * 1000, 4),
        "target_met": (total_iocs / elapsed_total) >= 10000,
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
