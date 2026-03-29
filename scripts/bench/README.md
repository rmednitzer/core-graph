# Performance Benchmarks

Benchmark scripts for core-graph performance validation.

## Scripts

| Script | What it measures | Target |
|--------|-----------------|--------|
| `bench_ner_extraction.py` | Tier 1 NER regex throughput | >= 10,000 IOC extractions/sec |
| `bench_graph_traversal.py` | AGE graph traversal latency | <= 10 ms P99 2-hop, <= 50 ms P99 4-hop |
| `bench_ingest_throughput.py` | End-to-end ingest pipeline | >= 1,000 events/sec sustained |

## Running

```bash
# All benchmarks
make bench

# Individual
python scripts/bench/bench_ner_extraction.py
python scripts/bench/bench_graph_traversal.py --pg-dsn postgresql://cg_admin:cg_dev_only@localhost:5432/core_graph
python scripts/bench/bench_ingest_throughput.py --nats-url nats://localhost:4222
```

## Methodology

- Each benchmark runs independently and outputs JSON results to stdout
- Latency benchmarks report P50/P95/P99 percentiles
- Throughput benchmarks report sustained ops/sec over the full run
- Graph traversal seeds its own test data and cleans up after
- NER benchmark is CPU-only (no external dependencies)
- Ingest benchmark requires a running NATS and PostgreSQL stack

## CI Integration

Benchmark results are JSON-formatted for consumption by CI dashboards.
The `make bench` target runs all benchmarks sequentially.
