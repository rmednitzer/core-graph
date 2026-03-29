"""Benchmark script for graph traversal latency via Apache AGE.

Seeds N vertices with random TLP levels and edges, then measures traversal
query latency at depths 1-5.

Target: <= 10 ms P99 for 2-hop, <= 50 ms P99 for 4-hop on 10k vertices.

Requires a running PostgreSQL instance with AGE extension.
"""

from __future__ import annotations

import argparse
import json
import random
import statistics
import sys
import time

import psycopg
from psycopg.rows import dict_row


def _seed_graph(conn: psycopg.Connection, n: int, rng: random.Random) -> None:
    """Seed test vertices and edges into a temporary graph."""
    conn.execute("select ag_catalog.create_graph('bench_graph')")
    conn.execute("set search_path = ag_catalog, '$user', public")

    # Create vertices
    for i in range(n):
        tlp = rng.randint(0, 4)
        conn.execute(
            """
            select * from ag_catalog.cypher('bench_graph', $$
                create (v:BenchNode {idx: %s, tlp_level: %s})
            $$) as (v agtype)
            """,
            (i, tlp),
        )

    # Create random edges (avg ~3 edges per vertex)
    edge_count = n * 3
    for _ in range(edge_count):
        src = rng.randint(0, n - 1)
        dst = rng.randint(0, n - 1)
        if src == dst:
            continue
        conn.execute(
            """
            select * from ag_catalog.cypher('bench_graph', $$
                match (a:BenchNode {idx: %s}), (b:BenchNode {idx: %s})
                create (a)-[:BENCH_EDGE]->(b)
            $$) as (e agtype)
            """,
            (src, dst),
        )

    conn.commit()


def _cleanup_graph(conn: psycopg.Connection) -> None:
    """Remove the benchmark graph."""
    try:
        conn.execute("select ag_catalog.drop_graph('bench_graph', true)")
        conn.commit()
    except Exception:
        conn.rollback()


def _run_traversal(conn: psycopg.Connection, depth: int, start_idx: int) -> float:
    """Run a traversal query at the given depth and return elapsed seconds."""
    query = f"""
        select * from ag_catalog.cypher('bench_graph', $$
            match (start:BenchNode {{idx: {start_idx}}})-[:BENCH_EDGE*1..{depth}]->(target)
            return count(target)
        $$) as (cnt agtype)
    """
    t0 = time.perf_counter()
    conn.execute(query)
    elapsed = time.perf_counter() - t0
    return elapsed


def main() -> None:
    parser = argparse.ArgumentParser(description="Graph traversal benchmark")
    parser.add_argument(
        "--pg-dsn",
        default="postgresql://cg_admin:cg_dev_only@localhost:5432/core_graph",
    )
    parser.add_argument("--vertices", type=int, default=10000)
    parser.add_argument("--iterations", type=int, default=50)
    args = parser.parse_args()

    rng = random.Random(42)
    conn = psycopg.connect(args.pg_dsn, row_factory=dict_row, autocommit=False)

    # Ensure AGE is loaded
    conn.execute("load 'age'")
    conn.execute("set search_path = ag_catalog, '$user', public")

    # Cleanup any previous run
    _cleanup_graph(conn)

    print(f"Seeding {args.vertices} vertices...", file=sys.stderr)
    _seed_graph(conn, args.vertices, rng)

    results: dict[int, dict] = {}
    start_nodes = [rng.randint(0, args.vertices - 1) for _ in range(args.iterations)]

    for depth in range(1, 6):
        latencies: list[float] = []
        for start_idx in start_nodes:
            elapsed = _run_traversal(conn, depth, start_idx)
            latencies.append(elapsed)

        latencies.sort()
        results[depth] = {
            "depth": depth,
            "iterations": args.iterations,
            "p50_ms": round(statistics.median(latencies) * 1000, 4),
            "p95_ms": round(latencies[int(len(latencies) * 0.95)] * 1000, 4),
            "p99_ms": round(latencies[int(len(latencies) * 0.99)] * 1000, 4),
            "mean_ms": round(statistics.mean(latencies) * 1000, 4),
        }

    _cleanup_graph(conn)
    conn.close()

    output = {
        "benchmark": "graph_traversal",
        "vertices": args.vertices,
        "iterations_per_depth": args.iterations,
        "results": list(results.values()),
        "targets": {
            "2_hop_p99_ms": 10,
            "4_hop_p99_ms": 50,
        },
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
