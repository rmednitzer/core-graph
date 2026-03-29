-- 005_audit_tables.sql
-- Append-only audit log with hash chain for evidence integrity.
-- Idempotent: safe to run multiple times.

create table if not exists audit_log (
    id              bigserial primary key,
    entity_id       bigint,
    entity_label    text,
    operation       text not null,
    old_value_hash  text,
    new_value_hash  text,
    actor           text not null,
    correlation_id  uuid,
    prev_entry_hash text,
    entry_hash      text not null,
    created_at      timestamptz not null default now()
);

-- Index for correlation lookups
create index if not exists idx_audit_log_correlation
    on audit_log (correlation_id);

create index if not exists idx_audit_log_entity
    on audit_log (entity_id, entity_label);

create index if not exists idx_audit_log_created
    on audit_log (created_at);

-- ---------------------------------------------------------------------------
-- Audit writer role (append-only)
-- ---------------------------------------------------------------------------

do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'cg_audit_writer') then
        create role cg_audit_writer nologin;
    end if;
end $$;

grant insert on audit_log to cg_audit_writer;
revoke update, delete on audit_log from cg_audit_writer;

-- ---------------------------------------------------------------------------
-- Hash chain trigger function (pgcrypto required)
-- ---------------------------------------------------------------------------

create or replace function audit_log_hash_chain()
returns trigger as $$
declare
    prev_hash text;
begin
    select entry_hash into prev_hash
    from audit_log
    order by id desc
    limit 1;

    new.prev_entry_hash := coalesce(prev_hash, 'genesis');

    new.entry_hash := encode(digest(
        coalesce(new.entity_id::text, '') ||
        coalesce(new.entity_label, '') ||
        new.operation ||
        coalesce(new.old_value_hash, '') ||
        coalesce(new.new_value_hash, '') ||
        new.actor ||
        coalesce(new.correlation_id::text, '') ||
        new.prev_entry_hash ||
        new.created_at::text,
        'sha256'
    ), 'hex');

    return new;
end;
$$ language plpgsql;

-- ---------------------------------------------------------------------------
-- Attach trigger (drop first for idempotency)
-- ---------------------------------------------------------------------------

drop trigger if exists trg_audit_log_hash_chain on audit_log;
create trigger trg_audit_log_hash_chain
    before insert on audit_log
    for each row
    execute function audit_log_hash_chain();
