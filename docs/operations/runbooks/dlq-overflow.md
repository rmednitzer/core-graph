# Runbook: DLQ Overflow

## Symptoms

- `dlq_archive` table row count growing beyond expected baseline
- Grafana "DLQ Depth" panel shows sustained increase
- Alert on `cg_ingest_dlq_total` exceeding threshold
- Unresolved DLQ entries accumulating over time

## Diagnostic Queries

### 1. Current DLQ depth

```sql
select count(*) as total,
       count(*) filter (where resolved = false) as unresolved,
       count(*) filter (where resolved = true) as resolved
from dlq_archive;
```

### 2. Group by original subject (identify source)

```sql
select original_subject,
       count(*) as count,
       min(first_failed) as earliest,
       max(first_failed) as latest
from dlq_archive
where resolved = false
group by original_subject
order by count desc;
```

### 3. Check error patterns

```sql
select error_message,
       count(*) as occurrences
from dlq_archive
where resolved = false
group by error_message
order by occurrences desc
limit 20;
```

### 4. Check retry counts

```sql
select retry_count, count(*)
from dlq_archive
where resolved = false
group by retry_count
order by retry_count;
```

High retry counts with the same error indicate a systematic issue that
retries cannot resolve.

## Resolution Steps

### 1. Identify the root cause

Common causes:

- **Schema mismatch**: Incoming data does not match expected graph labels
- **Upstream data quality**: Malformed payloads from satellite connectors
- **PostgreSQL errors**: Connection issues, constraint violations
- **AGE query failures**: Invalid Cypher parameters

### 2. Fix the upstream issue

Fix the root cause before bulk-resolving DLQ entries, or they will
recur:

- Schema issues: Add new merge template or fix data mapping
- Data quality: Update the connector adapter's validation/normalization
- Connection issues: Check PostgreSQL availability, pool sizing

### 3. Bulk resolution after fix

```sql
-- Mark entries as resolved after confirming the root cause is fixed
update dlq_archive
set resolved = true,
    resolved_at = now(),
    resolution_note = 'Root cause fixed: <description>'
where resolved = false
  and original_subject = '<affected_subject>';
```

### 4. Reprocess if needed

For entries that should have been ingested successfully:

```bash
# Re-publish DLQ entries to the original stream
python -m ingest.dlq.processor --reprocess --subject='<affected_subject>'
```

## Prevention

1. **Monitor DLQ depth**: Set alerting thresholds in Grafana
2. **Review error patterns weekly**: Catch systematic issues early
3. **Validate upstream data**: Add schema validation in connector adapters
4. **Test merge templates**: Ensure all expected entity labels have templates

## Thresholds

| Metric | Warning | Critical |
|--------|---------|----------|
| Unresolved DLQ entries | > 50 | > 500 |
| DLQ growth rate | > 10/min sustained | > 100/min sustained |
| Single-subject concentration | > 80% of DLQ from one subject | - |
