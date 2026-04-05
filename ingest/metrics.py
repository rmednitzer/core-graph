"""ingest.metrics — Prometheus metrics for the ingest pipeline.

Provides counters, histograms, and gauges for monitoring the ingest
pipeline, graph writer, dedup, and DLQ subsystems.
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

ingest_events_total = Counter(
    "cg_ingest_events_total",
    "Total ingest events processed",
    ["source", "status"],
)

ingest_latency_seconds = Histogram(
    "cg_ingest_latency_seconds",
    "Ingest processing latency in seconds",
    ["source"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

ingest_dlq_total = Counter(
    "cg_ingest_dlq_total",
    "Total messages sent to dead-letter queue",
    ["subject"],
)

graph_writes_total = Counter(
    "cg_graph_writes_total",
    "Total graph write operations",
    ["label", "operation"],
)

bloom_checks_total = Counter(
    "cg_bloom_checks_total",
    "Total bloom filter dedup checks",
    ["result"],
)

audit_log_entries_total = Counter(
    "cg_audit_log_entries_total",
    "Total audit log entries written",
)

dlq_by_class_total = Counter(
    "cg_ingest_dlq_by_class_total",
    "DLQ entries by error classification",
    ["error_class"],
)

# -- Adapter-level metrics (used by AdapterBase) ----------------------------

adapter_fetch_total = Counter(
    "cg_adapter_fetch_total",
    "Total adapter fetch operations",
    ["adapter", "status"],
)

adapter_entities_total = Counter(
    "cg_adapter_entities_total",
    "Total entities published by adapters",
    ["adapter", "label"],
)

adapter_delta_lag_seconds = Gauge(
    "cg_adapter_delta_lag_seconds",
    "Seconds since last successful delta sync",
    ["adapter"],
)
