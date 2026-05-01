-- 020_temporal_invariants.sql
-- Strengthen bitemporal invariants and append-only semantics for evidentiary facts.
-- Idempotent where practical.

alter table temporal_facts
    alter column source set not null,
    add column if not exists mutation_actor text,
    add column if not exists mutation_reason text,
    add column if not exists superseded_by_fact_id bigint,
    alter column mutation_actor set not null,
    alter column mutation_reason set not null;

alter table temporal_facts
    add constraint if not exists fk_temporal_superseded_by
    foreign key (superseded_by_fact_id) references temporal_facts(id);

alter table temporal_facts
    add constraint if not exists chk_temporal_valid_window
    check (t_invalid is null or t_valid <= t_invalid);

alter table temporal_facts
    add constraint if not exists chk_temporal_recorded_window
    check (t_superseded is null or t_recorded <= t_superseded);

create unique index if not exists uq_temporal_active_fact
    on temporal_facts (source_id, target_id, edge_label, fact_type)
    where t_invalid is null and t_superseded is null;

create extension if not exists btree_gist;

alter table temporal_facts
    add constraint if not exists ex_temporal_no_overlap
    exclude using gist (
        source_id with =,
        target_id with =,
        edge_label with =,
        fact_type with =,
        valid_range with &&
    );

create or replace function temporal_facts_block_delete()
returns trigger as $$
begin
    raise exception 'temporal_facts is append-only; use supersession via t_superseded/t_invalid';
end;
$$ language plpgsql;

drop trigger if exists trg_temporal_facts_no_delete on temporal_facts;
create trigger trg_temporal_facts_no_delete
    before delete on temporal_facts
    for each row execute function temporal_facts_block_delete();
