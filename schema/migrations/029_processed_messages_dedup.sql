-- 029_processed_messages_dedup.sql
-- Graph-writer replay idempotency ledger.
--
-- NATS JetStream is at-least-once: the graph writer can see a message more than
-- once (redelivery after an ack-wait timeout, a consumer restart, etc.). The
-- vertex MERGE is naturally idempotent, but the audit_log and temporal_facts
-- INSERTs are not — a redelivery would append a duplicate audit entry (with a
-- fresh correlation_id) and a duplicate temporal fact, corrupting the evidence
-- trail this platform exists to protect.
--
-- The writer claims a delivery key in the SAME transaction as the
-- MERGE/audit/temporal writes, so a key becomes durable only when the whole
-- unit commits: a redelivery of a committed message hits the primary-key
-- conflict and is skipped, while a redelivery of a *failed* (rolled-back)
-- message is retried normally. The key is the source ingest delivery id when
-- present (carried through enrichment) else the JetStream (stream, sequence)
-- pair — see ingest/graph_writer.py and ingest/enrichment_worker.py.
--
-- Explicitly created in `public` (not the search_path's first schema, which is
-- ag_catalog after 001) so it never lands among AGE's catalog tables.
--
-- Idempotent.

create table if not exists public.processed_messages (
    delivery_key text primary key,
    processed_at timestamptz not null default now()
);

create index if not exists idx_processed_messages_processed_at
    on public.processed_messages (processed_at);

-- Retention. The INGEST/ENRICHED streams use work_queue retention with no
-- max_age (ingest/streams.py), so a message committed-but-not-acked before a
-- crash has no upstream time bound on when it may be redelivered. The purge
-- window must therefore comfortably exceed the worst-case recovery outage: a
-- claim deleted before its (eventual) redelivery would let the duplicate
-- audit/temporal rows through. 90 days covers realistic disaster-recovery
-- while keeping the ledger bounded; operators planning longer outages should
-- raise it (or bound stream max_age) to match. Three-arg cron.schedule() is
-- idempotent (pg_cron 1.3+): re-running this migration updates the schedule.
select cron.schedule(
    'purge-processed-messages',
    '17 3 * * *',
    $$delete from public.processed_messages where processed_at < now() - interval '90 days'$$
);
