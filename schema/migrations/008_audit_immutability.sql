-- 008_audit_immutability.sql
-- Enforce append-only semantics on audit_log.
-- The hash chain trigger (005) handles INSERT; this prevents mutation.
-- Idempotent.

create or replace function audit_log_immutable()
returns trigger as $$
begin
    raise exception 'audit_log is append-only: % not permitted', tg_op;
end;
$$ language plpgsql;

drop trigger if exists trg_audit_log_no_update on audit_log;
create trigger trg_audit_log_no_update
    before update on audit_log
    for each row
    execute function audit_log_immutable();

drop trigger if exists trg_audit_log_no_delete on audit_log;
create trigger trg_audit_log_no_delete
    before delete on audit_log
    for each row
    execute function audit_log_immutable();
