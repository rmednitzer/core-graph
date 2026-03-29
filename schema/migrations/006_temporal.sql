-- 006_temporal.sql
-- Bitemporal fact table for the Graphiti-inspired temporal model.
-- Idempotent: safe to run multiple times.

create table if not exists temporal_facts (
    id              bigserial primary key,
    edge_id         bigint not null,
    edge_label      text not null,
    source_id       bigint not null,
    target_id       bigint not null,
    fact_type       text not null,
    fact_value      jsonb,
    t_valid         timestamptz not null,
    t_invalid       timestamptz,
    t_recorded      timestamptz not null default now(),
    t_superseded    timestamptz,
    source          text,
    confidence      real check (confidence between 0.0 and 1.0),
    valid_range     tstzrange generated always as (
        tstzrange(t_valid, coalesce(t_invalid, 'infinity'::timestamptz))
    ) stored
);

create index if not exists idx_temporal_valid_range
    on temporal_facts using gist (valid_range);

create index if not exists idx_temporal_edge
    on temporal_facts (edge_id);

create index if not exists idx_temporal_type
    on temporal_facts (fact_type);
