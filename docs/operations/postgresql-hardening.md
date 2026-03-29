# PostgreSQL Hardening Guide

Production PostgreSQL hardening for core-graph, aligned with CIS PostgreSQL
16 Benchmark key recommendations.

## 1. CIS Benchmark Alignment

The `postgresql-hardened.conf` overlay addresses the following CIS controls:

- **2.1** Ensure `ssl` is enabled — enforced via `ssl = on`
- **2.2** Ensure `ssl_min_protocol_version` is set — TLS 1.3 minimum
- **3.1** Ensure `password_encryption` is `scram-sha-256` — set explicitly
- **3.2** Ensure `pg_hba.conf` does not use `trust` or `md5` — hardened HBA
  file uses only `scram-sha-256`
- **4.1** Ensure `log_connections` is enabled — via pgAudit
- **6.2** Ensure `shared_preload_libraries` includes `pgaudit`
- **7.1** Ensure a replication user exists — WAL configured for streaming

## 2. Connection Security

### TLS 1.3

All connections require TLS 1.3 minimum:

```ini
ssl = on
ssl_min_protocol_version = 'TLSv1.3'
```

Certificate files must be provisioned at:
- `/etc/ssl/certs/server.crt` (server certificate)
- `/etc/ssl/private/server.key` (private key, mode 0600)

In production, use certificates issued by the internal CA or Let's Encrypt
with automatic renewal via cert-manager (Kubernetes) or certbot (bare metal).

### SCRAM-SHA-256

All authentication uses SCRAM-SHA-256. The `pg_hba-hardened.conf` prohibits
`trust` and `md5` methods entirely:

```
local   all   all   scram-sha-256
host    all   all   0.0.0.0/0   scram-sha-256
hostssl all   all   0.0.0.0/0   scram-sha-256
```

## 3. pgAudit Configuration

pgAudit logs DDL and write operations with parameter values:

```ini
pgaudit.log = 'ddl,write'
pgaudit.log_parameter = on
pgaudit.log_statement_once = on
```

### Log Review

Review pgAudit logs for:
- Unexpected DDL (schema changes outside migration windows)
- Write operations from unexpected roles
- Bulk DELETE or TRUNCATE operations

```sql
-- Recent pgAudit entries (from PostgreSQL log)
-- Use log aggregation (Loki, OpenSearch) in production
select * from pg_catalog.pg_stat_activity
where state = 'active' and query like '%audit%';
```

## 4. Statement Timeouts

Prevent runaway queries and idle transaction accumulation:

```ini
statement_timeout = '30s'
idle_in_transaction_session_timeout = '60s'
```

The 30s statement timeout covers normal operational queries. Long-running
analytical queries should use `SET LOCAL statement_timeout = '5min'` within
an explicit transaction.

## 5. Memory Tuning

Tuned for Hetzner CCX23 (4 vCPU, 16 GB RAM):

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `shared_buffers` | 256 MB | ~1.6% of RAM; conservative start |
| `work_mem` | 16 MB | Per-sort/hash; 100 connections * 16 MB = 1.6 GB max |
| `maintenance_work_mem` | 128 MB | VACUUM, CREATE INDEX |
| `effective_cache_size` | 1 GB | Planner hint for OS page cache |

Increase `shared_buffers` to 4 GB (25% RAM) after baseline benchmarking
confirms benefit with the core-graph workload.

## 6. WAL Configuration

WAL is configured for pgBackRest compatibility and optional streaming
replication:

```ini
wal_level = 'replica'
max_wal_senders = 5
wal_keep_size = '1GB'
```

pgBackRest requires `wal_level = 'replica'` minimum. The 1 GB WAL retention
prevents segment recycling during backup windows.

## 7. Monitoring Queries

### Connection Count

```sql
select count(*), state
from pg_stat_activity
group by state;
```

### Cache Hit Ratio

Target: >= 99% for hot workloads.

```sql
select
    sum(blks_hit) * 100.0 / nullif(sum(blks_hit) + sum(blks_read), 0)
        as cache_hit_ratio
from pg_stat_database;
```

### Replication Lag

```sql
select
    client_addr,
    state,
    sent_lsn,
    write_lsn,
    flush_lsn,
    replay_lsn,
    pg_wal_lsn_diff(sent_lsn, replay_lsn) as lag_bytes
from pg_stat_replication;
```

### Long-Running Queries

```sql
select pid, now() - pg_stat_activity.query_start as duration, query, state
from pg_stat_activity
where (now() - pg_stat_activity.query_start) > interval '30 seconds'
  and state != 'idle'
order by duration desc;
```

### Table Bloat

```sql
select schemaname, relname,
    pg_size_pretty(pg_total_relation_size(relid)) as total_size
from pg_stat_user_tables
order by pg_total_relation_size(relid) desc
limit 20;
```
