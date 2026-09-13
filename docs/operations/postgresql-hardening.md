# PostgreSQL Hardening Guide

Production PostgreSQL hardening for core-graph, aligned with CIS PostgreSQL
16 Benchmark key recommendations.

## 1. CIS Benchmark Alignment

The `postgresql-hardened.conf` overlay addresses the following CIS controls:

- **2.1** Ensure `ssl` is enabled — enforced via `ssl = on`
- **2.2** Ensure `ssl_min_protocol_version` is set — TLS 1.3 minimum
- **3.1** Ensure `password_encryption` is `scram-sha-256` — set explicitly
- **3.2** Ensure `pg_hba.conf` does not use `trust` or `md5` — hardened HBA
  file uses only `scram-sha-256`, refuses cleartext TCP, and ends in an
  explicit `reject`
- **4.1** Ensure `log_connections` is enabled — set directly
  (`log_connections = 'authorization'`, the PostgreSQL 18 list form);
  pgAudit does not log connections, it logs statements
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
`trust` and `md5` methods entirely, refuses cleartext TCP before any TLS line
is consulted, and ends in an explicit `reject`:

```
local      all   all                 scram-sha-256
hostnossl  all   all   0.0.0.0/0     reject
hostnossl  all   all   ::/0          reject
hostssl    all   all   0.0.0.0/0     scram-sha-256
hostssl    all   all   ::/0          scram-sha-256
host       all   all   all           reject
```

PostgreSQL uses the first matching line. An earlier revision listed a plain
`host ... scram-sha-256` line ahead of the `hostssl` lines, which made the TLS
lines unreachable and accepted non-TLS connections despite
`ssl_min_protocol_version = 'TLSv1.3'`. The `hostnossl ... reject` pair is
what actually enforces "TLS only"; `ssl_min_protocol_version` only governs
the TLS handshake once one is attempted.

The reference production deployment goes one step further for local
service roles: peer authentication over the Unix socket with a
`pg_ident.conf` map from OS user to a purpose-scoped role, so no service
holds a database password at all, and a final `local all all reject`
catches anything unmapped. That layout is host-specific (it depends on the
OS users that exist) and is documented here as the target shape for a
bare-metal deployment; the containerised stack keeps SCRAM because the
application connects over TCP.

## 3. pgAudit Configuration

pgAudit logs DDL, role changes, and write operations with parameter values:

```ini
pgaudit.log = 'ddl,role,write'
pgaudit.log_parameter = on
pgaudit.log_statement_once = on
```

`role` covers `GRANT`, `REVOKE`, `CREATE/ALTER/DROP ROLE` and role
membership. pgAudit does not log those under `ddl`, and they are exactly the
events an access-control review needs (the clearance roles of ADR-0015 and
the `cg_app` grants of migration 038 are all role events).

### Query and connection evidence

pgAudit is statement-level. The hardened configuration also enables the
bounded server-side evidence the reference deployment relies on for
slow-query and lock review:

```ini
track_io_timing = on
log_min_duration_statement = 1000
log_lock_waits = on
deadlock_timeout = '1s'
log_connections = 'authorization'
log_disconnections = on
shared_preload_libraries = 'age,pgaudit,pg_cron,pg_stat_statements'
```

`pg_stat_statements` is created by migration 043 and must be preloaded, or
the view exists but raises at query time. Review the top statements by mean
execution time:

```sql
select calls, round(mean_exec_time::numeric, 1) as mean_ms,
       round(total_exec_time::numeric, 0) as total_ms, left(query, 120) as query
from pg_stat_statements
order by mean_exec_time desc
limit 20;
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

Prevent runaway queries and idle transaction accumulation. The idle timeout
is global; the statement ceiling is scoped to the request-serving role
(migration 043):

```ini
idle_in_transaction_session_timeout = '60s'   # postgresql-hardened.conf
```

```sql
alter role cg_app set statement_timeout = '30s';                   -- migration 043
alter role cg_app set idle_in_transaction_session_timeout = '60s';
```

A cluster-wide `statement_timeout = '30s'` (the previous layout) also applied
to the owner identity that runs migrations and builds HNSW indexes, and to
pg_cron jobs; an index build on a populated `embeddings` table takes longer
than that. The reference production deployment sets no global statement
ceiling for the same reason. `api.db.get_connection` additionally sets a
role-derived `statement_timeout` on every pooled connection, so every
request path (REST, MCP, TAXII, ingest) is bounded regardless of the role
default; the role default covers connections that do not go through the
pool. Long-running analytical work on the owner identity should still use
`SET LOCAL statement_timeout` inside an explicit transaction rather than
relying on the absence of a ceiling.

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

### Reference profile (single-node, 125 GiB RAM, NVMe on ZFS)

The production reference deployment runs the same extension set (AGE 1.7.0,
pgvector 0.8.6, pg_cron 1.6, pgAudit 18.0, pg_stat_statements) on one
PostgreSQL 18 host. Its tuning, after two correction rounds, is the profile
to scale from rather than the 16 GB table above:

| Parameter | Value | Note |
|-----------|-------|------|
| `shared_buffers` | 8 GB | Backed down from 32 GB; ZFS ARC holds the rest |
| `effective_cache_size` | 24 GB | Planner hint only |
| `work_mem` | 32 MB | See the hazard below |
| `hash_mem_multiplier` | 2.0 | |
| `maintenance_work_mem` | 2 GB | HNSW builds; `autovacuum_work_mem = 1GB` separately |
| `huge_pages` | try | |
| `wal_buffers` | 64 MB | |
| `max_worker_processes` / `max_parallel_workers` | 32 / 24 | `per_gather` and `maintenance` 8 each |
| `random_page_cost` | 1.1 | NVMe |
| `effective_io_concurrency` / `maintenance_io_concurrency` | 256 | |
| `default_statistics_target` | 200 | |
| `jit` | off | Short AGE/pgvector statements lose more to JIT compile than they gain |
| `wal_compression` | zstd | Requires a server built with zstd; check `pg_config --configure` |
| `max_wal_size` / `min_wal_size` | 16 GB / 4 GB | with `checkpoint_timeout = 15min`, target 0.9 |
| `max_connections` | 100 | |
| `autovacuum_vacuum_scale_factor` / `_analyze_` | 0.05 / 0.02 | Append-heavy `embeddings` and `documents` |
| `autovacuum_naptime` / `autovacuum_max_workers` | 30s / 6 | |

**`work_mem` hazard.** The first cut of that profile set `work_mem = 256MB`.
The worst-case sort/hash allocation is
`work_mem × hash_mem_multiplier × max_connections` per concurrent operation
class: 256 MB × 2 × 100 is 51 GB on a 125 GiB host that also carries the
inference stack, and it was corrected downward at runtime through
`ALTER SYSTEM` before the file caught up. Size `work_mem` from
`max_connections`, not from available RAM, and keep the file and any
`postgresql.auto.conf` overlay in agreement (`select name, source, sourcefile
from pg_settings where source <> 'default'` shows where each value comes
from).

## 8. Corruption Detection

- **Data checksums.** Enabled at `initdb` time
  (`POSTGRES_INITDB_ARGS=--data-checksums` in the compose file, the Helm
  statefulset and the CI action); they cannot be switched on later without
  `pg_checksums` downtime. Poll `checksum_failures`:

  ```sql
  select datname, checksum_failures, checksum_last_failure
  from pg_stat_database
  where datname not in ('template0', 'template1');
  ```

- **amcheck.** `bt_index_check()` verifies B-tree indexes only; HNSW and GIN
  indexes are not covered and the call errors on them. Run it against the
  primary keys and the AGE label indexes, not against `idx_embeddings_hnsw`.

- **WAL archive integrity.** An `archive_command` must never replace an
  already-archived segment with different contents, and must compare
  contents rather than test for existence: an interrupted or short copy
  must be re-archived, never declared done. pgBackRest's `archive-push`
  does this; a hand-written `test ! -f ... && cp` does not. See
  `docs/operations/backup-restore.md`.

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
