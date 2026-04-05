-- 015_merkle_root_table.sql
-- Periodic Merkle root storage for audit log integrity verification.
-- Idempotent: safe to run multiple times.

create table if not exists audit_merkle_roots (
    id          bigserial primary key,
    batch_start bigint not null,
    batch_end   bigint not null,
    root_hash   text not null,
    entry_count int not null,
    rfc3161_token bytea,
    computed_at timestamptz not null default now()
);

create index if not exists idx_merkle_roots_batch
    on audit_merkle_roots (batch_start, batch_end);
