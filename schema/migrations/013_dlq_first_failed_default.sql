-- 013_dlq_first_failed_default.sql
-- Add default timestamp to dlq_archive.first_failed for robustness.
-- Idempotent: ALTER COLUMN SET DEFAULT is safe to re-run.

alter table dlq_archive
    alter column first_failed set default now();
