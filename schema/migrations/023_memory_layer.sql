\echo 'applying 023_memory_layer.sql'
-- 023_memory_layer.sql
-- Phase 3 — AI Memory layer (Layer 5).
--
-- Adds AGE labels for the episodic memory model (Session, Episode,
-- ExtractedFact, ConceptEntity and the four edges BELONGS_TO,
-- EXTRACTED_FROM, MENTIONS, SUPERSEDES) plus three relational shadow
-- tables that the application uses for hot-path correctness:
--
--   * memory_session_counters — atomic per-session sequence allocator,
--     enforces the (session_id, sequence_no) Episode invariant.
--   * memory_extracted_fact_index — (subject_hash, predicate_hash) → fact
--     vertex id, used for supersession detection without scanning AGE.
--   * memory_episode_salience — materialised salience score per episode,
--     refreshed by a pg_cron job. Cheap to query at recall time.
--
-- Bitemporal contract: every memory vertex carries t_valid, t_invalid,
-- t_recorded, t_superseded as AGE properties. Application writers are
-- responsible for setting them; supersession detection writes the
-- SUPERSEDES edge and the old fact's t_superseded.
--
-- TLP: AI memory is not IAM; default tlp_level for memory vertices is 1
-- (GREEN), application writers may raise it.
--
-- Idempotent.

-- ---------------------------------------------------------------------------
-- 1. AGE vertex labels
-- ---------------------------------------------------------------------------

do $$
declare
    l text;
    labels constant text[] := array['Session', 'Episode', 'ExtractedFact', 'ConceptEntity'];
begin
    foreach l in array labels loop
        if not exists (
            select 1 from ag_catalog.ag_label
             where name = l
               and graph = (select graphid from ag_catalog.ag_graph where name = 'core_graph')
        ) then
            perform ag_catalog.create_label('core_graph', l, 'v');
        end if;
    end loop;
end $$;

-- ---------------------------------------------------------------------------
-- 2. AGE edge labels
-- ---------------------------------------------------------------------------

do $$
declare
    l text;
    labels constant text[] := array['belongs_to', 'extracted_from', 'mentions', 'supersedes'];
begin
    foreach l in array labels loop
        if not exists (
            select 1 from ag_catalog.ag_label
             where name = l
               and graph = (select graphid from ag_catalog.ag_graph where name = 'core_graph')
        ) then
            perform ag_catalog.create_label('core_graph', l, 'e');
        end if;
    end loop;
end $$;

-- ---------------------------------------------------------------------------
-- 3. Shadow tables (relational, hot-path)
-- ---------------------------------------------------------------------------

create table if not exists memory_session_counters (
    session_id        text primary key,
    last_sequence_no  bigint not null default 0,
    started_at        timestamptz not null default now(),
    last_episode_at   timestamptz
);

create table if not exists memory_extracted_fact_index (
    subject_hash      text not null,
    predicate_hash   text not null,
    fact_graph_id    bigint not null,
    object_hash      text not null,
    t_recorded       timestamptz not null default now(),
    t_superseded     timestamptz,
    primary key (subject_hash, predicate_hash, fact_graph_id)
);

create index if not exists idx_extracted_fact_active
    on memory_extracted_fact_index (subject_hash, predicate_hash)
    where t_superseded is null;

create table if not exists memory_episode_salience (
    episode_graph_id  bigint primary key,
    session_id        text not null,
    created_at        timestamptz not null default now(),
    salience          real not null default 0.0,
    access_count      int not null default 0,
    last_accessed_at  timestamptz,
    computed_at       timestamptz not null default now()
);

-- Backfill `created_at` for tables that pre-date this column (idempotency).
alter table memory_episode_salience
    add column if not exists created_at timestamptz not null default now();

create index if not exists idx_memory_episode_salience_session
    on memory_episode_salience (session_id, salience desc);

-- ---------------------------------------------------------------------------
-- 4. Helper: atomic next-sequence allocation per session.
-- ---------------------------------------------------------------------------

create or replace function memory_next_sequence(p_session_id text)
returns bigint as $$
declare
    next_seq bigint;
begin
    insert into memory_session_counters (session_id, last_sequence_no, last_episode_at)
         values (p_session_id, 1, now())
    on conflict (session_id) do update
        set last_sequence_no = memory_session_counters.last_sequence_no + 1,
            last_episode_at  = now()
    returning last_sequence_no into next_seq;
    return next_seq;
end;
$$ language plpgsql;

-- ---------------------------------------------------------------------------
-- 5. Helper: recompute salience for one or all episodes.
-- ---------------------------------------------------------------------------
-- salience = recency_weight * exp(-decay * age_seconds)
--          + access_weight  * log(1 + access_count)
--          + relevance_weight * cosine_sim_to_session_anchor
--
-- The relevance term requires the session anchor embedding; this function
-- defaults to 0 for the relevance term (callers can extend per-session).
-- The materialised value is good enough for ranking inside a session.

create or replace function memory_recompute_salience(
    p_recency_weight  real default 0.5,
    p_access_weight   real default 0.2,
    p_relevance_weight real default 0.3,
    p_decay           real default 1.0 / 86400.0,
    p_relevance_default real default 0.0,
    p_episode_id      bigint default null
)
returns int as $$
declare
    n int;
begin
    -- Recency uses each episode's own `created_at` so older episodes in the
    -- same session decay correctly relative to newer ones (the previous
    -- session-wide `last_episode_at` collapsed all per-episode freshness).
    update memory_episode_salience s
       set salience    = p_recency_weight
                       * exp(-p_decay * extract(epoch from (now() - s.created_at)))
                       + p_access_weight
                       * ln(1 + s.access_count)
                       + p_relevance_weight * p_relevance_default,
           computed_at = now()
     where (p_episode_id is null or s.episode_graph_id = p_episode_id);
    get diagnostics n = row_count;
    return n;
end;
$$ language plpgsql;

-- ---------------------------------------------------------------------------
-- 6. Scheduled job: refresh salience every 5 minutes.
-- ---------------------------------------------------------------------------
-- Use cron.schedule's three-arg form so it's idempotent across reruns.

select cron.schedule(
    'memory-salience-recompute',
    '*/5 * * * *',
    $$ select memory_recompute_salience(); $$
);

-- ---------------------------------------------------------------------------
-- 7. Trigger: detect supersession on insert into the fact index.
-- ---------------------------------------------------------------------------
-- When a new fact lands with the same (subject_hash, predicate_hash) but a
-- different object_hash than the active row, mark the active row superseded
-- so SQL queries see only one active object per (subject, predicate).
-- The application is responsible for inserting the SUPERSEDES *edge* into
-- AGE — this trigger only updates the relational shadow.

create or replace function memory_mark_supersession()
returns trigger as $$
begin
    update memory_extracted_fact_index
       set t_superseded = now()
     where subject_hash  = new.subject_hash
       and predicate_hash = new.predicate_hash
       and fact_graph_id <> new.fact_graph_id
       and object_hash   <> new.object_hash
       and t_superseded is null;
    return new;
end;
$$ language plpgsql;

drop trigger if exists trg_memory_supersession on memory_extracted_fact_index;
create trigger trg_memory_supersession
    after insert on memory_extracted_fact_index
    for each row execute function memory_mark_supersession();
