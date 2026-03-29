# Runbook: Ingest Pipeline Stalled

## Symptoms

- NATS consumer lag increasing on the `ENRICHED` stream (Grafana panel
  "NATS Consumer Lag")
- `cg_graph_writes_total` metric is flat (no new graph writes)
- `cg_ingest_events_total` may still be increasing (connectors producing,
  writer not consuming)

## Diagnostic Steps

### 1. Check graph-writer process

```bash
# Docker Compose
docker compose -f deploy/docker/docker-compose.yml logs --tail=100 cg-api

# Kubernetes
kubectl -n core-graph logs -l app.kubernetes.io/name=graph-writer --tail=100
```

Look for: connection errors, exception tracebacks, "Error processing message"
log lines.

### 2. Check NATS stream info

```bash
# Via NATS CLI
nats stream info ENRICHED
nats consumer info ENRICHED graph_writer
```

Key metrics:
- `num_pending`: messages waiting to be delivered
- `num_redelivered`: messages that failed processing and were redelivered
- `last_delivered`: timestamp of last successful delivery

### 3. Check PostgreSQL connectivity

```bash
psql "$CG_PG_DSN" -c "select 1"
```

If this fails, the graph writer cannot write. Check PostgreSQL logs and
`pg_stat_activity` for connection saturation.

### 4. Check DLQ depth

```sql
select count(*) from dlq_archive where resolved = false;
select original_subject, count(*)
from dlq_archive
where resolved = false
group by original_subject
order by count(*) desc;
```

High DLQ counts indicate systematic processing failures.

## Resolution Steps

### Root cause: Graph writer crashed

Restart the graph writer:

```bash
# Docker Compose
docker compose -f deploy/docker/docker-compose.yml restart cg-api

# Kubernetes
kubectl -n core-graph rollout restart deployment/graph-writer
```

### Root cause: PostgreSQL connection exhaustion

```sql
-- Check active connections
select count(*), state from pg_stat_activity group by state;

-- Terminate idle-in-transaction connections older than 5 minutes
select pg_terminate_backend(pid)
from pg_stat_activity
where state = 'idle in transaction'
  and state_change < now() - interval '5 minutes';
```

### Root cause: NATS stream full

```bash
nats stream info ENRICHED
```

If `bytes` is at `max_bytes`, increase the stream limit or purge acknowledged
messages:

```bash
nats stream purge ENRICHED --keep=0
```

### Root cause: Schema migration failure

Check if a recent migration left the database in an inconsistent state:

```sql
select * from audit_log order by recorded_at desc limit 10;
```

## Verification

After resolution:
1. Consumer lag should start decreasing
2. `cg_graph_writes_total` should resume incrementing
3. No new errors in graph-writer logs

```bash
# Watch consumer lag decrease
watch -n5 'nats consumer info ENRICHED graph_writer | grep pending'
```

## Escalation Criteria

Escalate if:
- Pipeline remains stalled for > 15 minutes after restart
- DLQ depth exceeds 1000 unresolved entries
- PostgreSQL connection issues persist after idle connection cleanup
- Data loss is suspected (gap between NATS sequence numbers)
