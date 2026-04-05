-- 018_dlq_error_class.sql
-- Add error classification to DLQ archive.
-- Idempotent.

alter table dlq_archive
    add column if not exists error_class text not null default 'unknown';

create index if not exists idx_dlq_archive_error_class
    on dlq_archive (error_class, resolved) where not resolved;
