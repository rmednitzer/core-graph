# Runbook: Audit Hash Chain Broken

## Symptoms

- `python -m evidence.chain.verify` reports broken hash chain links
- Monitoring alert on `cg_audit_chain_breaks_total` metric (if configured)
- Manual inspection shows `prev_hash` mismatch between consecutive entries

## Severity Assessment

A broken hash chain is a **high-severity** event. It indicates either:

1. A software bug in the hash chain computation
2. Unauthorized modification of the audit log
3. Database-level corruption or improper restore

### Identify affected entries

```sql
-- Find the break point(s)
select a.id as current_id,
       a.prev_hash as expected_prev,
       b.entry_hash as actual_prev,
       a.recorded_at
from audit_log a
left join audit_log b on b.id = a.id - 1
where a.id > 1
  and a.prev_hash != coalesce(b.entry_hash, '')
order by a.id;
```

## Preservation

**CRITICAL: Do NOT modify the audit_log table.**

The immutability trigger (migration 008) prevents UPDATE and DELETE. Even if
the chain is broken, the current state is evidence.

### 1. Snapshot current state

```bash
pg_dump -t audit_log --data-only core_graph > audit_log_snapshot_$(date +%Y%m%d_%H%M%S).sql
```

### 2. Upload snapshot to MinIO WORM

```bash
mc cp audit_log_snapshot_*.sql minio/evidence/audit-chain-break/
```

### 3. Record the verification output

```bash
python -m evidence.chain.verify > chain_verify_$(date +%Y%m%d_%H%M%S).txt 2>&1
mc cp chain_verify_*.txt minio/evidence/audit-chain-break/
```

## Diagnostic Steps

### 1. Check pgAudit logs

Review PostgreSQL logs around the break point timestamp for any DDL
operations, superuser activity, or direct SQL modifications:

```bash
grep -i "audit_log" /var/log/postgresql/postgresql-*.log | \
    grep -E "(UPDATE|DELETE|ALTER|TRUNCATE)"
```

### 2. Check for backup/restore events

A point-in-time recovery (PITR) or pg_restore could introduce chain breaks
if partial data was restored:

```bash
grep -i "recovery\|restore\|pitr" /var/log/postgresql/postgresql-*.log
```

### 3. Check application logs

Look for hash computation errors around the break point:

```bash
grep -i "hash\|chain\|audit" /var/log/core-graph/*.log
```

### 4. Verify the hash chain algorithm

The hash chain is computed by the INSERT trigger in migration 005. Verify
the algorithm matches expectations:

```sql
-- Recompute hash for a specific entry to verify
select id, entry_hash,
       encode(sha256(
           (coalesce(prev_hash, '') || id::text || entity_label ||
            operation || coalesce(new_value_hash, '') || actor ||
            recorded_at::text)::bytea
       ), 'hex') as recomputed_hash
from audit_log
where id = <break_point_id>;
```

## Recovery Options

The hash chain **cannot be repaired** without modifying the audit log, which
would itself be an integrity violation. Options:

1. **Document the gap**: Record the break point, cause, and scope in a signed
   incident report stored in MinIO WORM
2. **Start a new chain segment**: Future entries continue chaining from the
   last valid entry. The gap is permanently documented
3. **Forensic analysis**: If unauthorized modification is suspected, preserve
   all evidence and engage incident response

## Regulatory Notification

### NIS2 Art. 23 Timeline

If the chain break indicates a security incident:

- **24 hours**: Early warning to competent authority (BSI for DE)
- **72 hours**: Incident notification with initial assessment
- **1 month**: Final report with root cause and remediation

### Evidence Preservation

All artifacts must be:

1. Signed with cosign (`python -m evidence.signing.sign <file>`)
2. Uploaded to MinIO WORM bucket (object lock prevents deletion)
3. Registered in Rekor transparency log

```bash
python -m evidence.signing.sign audit_log_snapshot_*.sql
python -m evidence.signing.sign chain_verify_*.txt
```
