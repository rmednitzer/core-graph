-- 012_scheduled_jobs.sql
-- Scheduled pg_cron jobs for audit log maintenance.
-- Uses the three-argument cron.schedule() form for idempotency (pg_cron 1.3+).
-- Idempotent: safe to run multiple times.

-- Merkle root computation over audit_log batches (every 6 hours).
-- Computes a rolling SHA-256 root over the latest batch of entries
-- and stores it as a self-referencing audit_log entry for verification.
select cron.schedule(
    'audit-merkle-root',
    '0 */6 * * *',
    $$
    insert into audit_log
        (entity_label, operation, actor, new_value_hash, correlation_id)
    select
        'merkle_root',
        'MERKLE_COMPUTE',
        'pg_cron',
        encode(digest(string_agg(entry_hash, '' order by id), 'sha256'), 'hex'),
        gen_random_uuid()
    from audit_log
    where created_at > now() - interval '6 hours'
    having count(*) > 0
    $$
);

-- Stale embedding cleanup (daily at 03:00 UTC).
-- Removes embeddings for graph vertices that no longer exist.
-- NOTE: ag_catalog.cypher() cannot be used inside a subquery in all AGE
-- versions. This uses the internal AGE vertex catalog table instead.
-- Alternative if your AGE version supports subquery cypher():
--   delete from embeddings e
--   where not exists (
--       select 1 from ag_catalog.cypher('core_graph', $$
--           match (v) where id(v) = e.graph_id return v
--       $$) as (v agtype)
--   )
select cron.schedule(
    'stale-embedding-cleanup',
    '0 3 * * *',
    $$
    delete from embeddings e
    where not exists (
        select 1 from core_graph._ag_label_vertex v
        where v.id = e.graph_id
    )
    $$
);

-- DLQ archive cleanup: mark resolved entries older than 90 days (weekly).
select cron.schedule(
    'dlq-archive-cleanup',
    '0 4 * * 0',
    $$
    update dlq_archive
    set resolved = true,
        resolved_at = now(),
        resolution_note = 'Auto-resolved: older than 90 days'
    where resolved = false
      and first_failed < now() - interval '90 days'
    $$
);
