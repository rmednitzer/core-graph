-- 007_dlq_archive.sql — Dead-letter queue archive table
-- Stores permanently failed ingest messages after max retries exhausted.

create table if not exists dlq_archive (
    id              bigserial primary key,
    original_subject text not null,
    payload         jsonb not null,
    error_message   text,
    retry_count     int not null default 0,
    first_failed    timestamptz not null,
    last_failed     timestamptz not null default now(),
    resolved        boolean not null default false,
    resolved_at     timestamptz,
    resolved_by     text
);

create index if not exists idx_dlq_archive_resolved
    on dlq_archive (resolved) where not resolved;

create index if not exists idx_dlq_archive_subject
    on dlq_archive (original_subject);
