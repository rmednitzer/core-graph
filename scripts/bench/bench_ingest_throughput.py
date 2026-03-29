"""Benchmark script for ingest pipeline throughput.

Generates synthetic OCSF events, publishes to NATS in batches, and measures
sustained throughput and end-to-end latency.

Target: >= 1,000 events/sec sustained on local Docker stack.

Requires a running NATS instance.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import random
import statistics
import sys
import time
import uuid


async def main() -> None:
    import nats

    parser = argparse.ArgumentParser(description="Ingest throughput benchmark")
    parser.add_argument("--nats-url", default="nats://localhost:4222")
    parser.add_argument("--events", type=int, default=10000)
    parser.add_argument("--batch-size", type=int, default=100)
    args = parser.parse_args()

    rng = random.Random(42)
    categories = ["network", "system", "application", "security"]
    severities = [1, 2, 3, 4, 5]

    # Generate synthetic OCSF events
    events = []
    for _ in range(args.events):
        event = {
            "label": "SecurityEvent",
            "properties": {
                "event_id": str(uuid.uuid4()),
                "category": rng.choice(categories),
                "severity": rng.choice(severities),
                "tlp": rng.randint(0, 3),
                "source_ip": (
                    f"{rng.randint(1, 223)}.{rng.randint(0, 255)}"
                    f".{rng.randint(0, 255)}.{rng.randint(1, 254)}"
                ),
                "timestamp": (
                    f"2025-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}"
                    f"T{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}"
                    f":{rng.randint(0, 59):02d}Z"
                ),
            },
        }
        events.append(json.dumps(event).encode())

    nc = await nats.connect(args.nats_url)
    js = nc.jetstream()

    # Ensure stream exists
    try:
        await js.add_stream(
            name="ENRICHED",
            subjects=["enriched.entity.>"],
            retention="work_queue",
            max_bytes=1_073_741_824,
        )
    except Exception:
        pass  # Stream may already exist

    print(f"Publishing {args.events} events in batches of {args.batch_size}...", file=sys.stderr)

    latencies: list[float] = []
    start_total = time.perf_counter()

    for i in range(0, args.events, args.batch_size):
        batch = events[i : i + args.batch_size]
        for payload in batch:
            t0 = time.perf_counter()
            await js.publish("enriched.entity.bench", payload)
            t1 = time.perf_counter()
            latencies.append(t1 - t0)

    elapsed_total = time.perf_counter() - start_total

    await nc.close()

    latencies.sort()
    result = {
        "benchmark": "ingest_throughput",
        "events": args.events,
        "batch_size": args.batch_size,
        "elapsed_seconds": round(elapsed_total, 4),
        "events_per_second": round(args.events / elapsed_total, 2),
        "publish_latency_p50_ms": round(statistics.median(latencies) * 1000, 4),
        "publish_latency_p95_ms": round(latencies[int(len(latencies) * 0.95)] * 1000, 4),
        "publish_latency_p99_ms": round(latencies[int(len(latencies) * 0.99)] * 1000, 4),
        "target_met": (args.events / elapsed_total) >= 1000,
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
