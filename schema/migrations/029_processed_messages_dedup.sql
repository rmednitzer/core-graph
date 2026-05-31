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
-- The writer claims a delivery key — the JetStream (stream, stream-sequence)
-- pair, which is stable across redeliveries of the same stored message — in the
-- SAME transaction as the MERGE/audit/temporal writes. A key therefore becomes
-- durable only when the whole unit commits: a redelivery of a committed message
-- hits the primary-key conflict and is skipped, while a redelivery of a *failed*
-- (rolled-back) message is retried normally.
--
-- Idempotent.

create table if not exists processed_messages (
    delivery_key text primary key,
    processed_at timestamptz not null default now()
);

create index if not exists idx_processed_messages_processed_at
    on processed_messages (processed_at);

-- Retention: the dedup window only needs to outlive JetStream's redelivery
-- horizon (minutes), so a generous 7-day purge keeps the table small without
-- risking a missed dedup. The three-argument cron.schedule() form is idempotent
-- (pg_cron 1.3+): re-running this migration updates the existing schedule.
select cron.schedule(
    'purge-processed-messages',
    '17 * * * *',
    $$delete from processed_messages where processed_at < now() - interval '7 days'$$
);
