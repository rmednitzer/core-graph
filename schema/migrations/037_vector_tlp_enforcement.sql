\echo 'applying 037_vector_tlp_enforcement.sql'
-- 037_vector_tlp_enforcement.sql
-- TLP enforcement on the vector tier.
--
-- Closes the gap recorded in ADR-0011: RLS was applied only to `core_graph.*`
-- (migrations 004, 010, 022, 028), so `embeddings` and `retrieval_embeddings`
-- carried no policy. `get_connection()` sets `app.max_tlp`, but that GUC is
-- read by policies that existed only on the graph tables, and neither
-- `vector_search` nor `hybrid_search` applied a post-filter. Retrieval
-- therefore returned content at any TLP level to any caller, contradicting
-- "Row-Level Security enforces TLP markings at the engine level".
--
-- This is the design the repository already assumed. Migration 027's own
-- rationale reads "candidates governed by hnsw.ef_search; if RLS then filters
-- most of them", and enabled HNSW iterative scans specifically so a filtered
-- vector search would not under-return. That groundwork was laid for a policy
-- that was never created. `tests/eval/test_rls_retrieval_correctness.py`
-- asserts the property and calls itself a hard CI fail; it has never run,
-- because it needs an embedding provider and CI has none.
--
-- NECESSARY BUT NOT SUFFICIENT. This migration adds the missing policy. It
-- does not by itself make retrieval TLP-safe, because of a separate and larger
-- gap found while writing it:
--
--   * The `cg_*` roles created by 004, 005 and 010 are all NOLOGIN. They are
--     grant targets, not connection identities.
--   * Nothing outside tests ever issues SET ROLE. `get_connection()` sets
--     `app.max_tlp` and `app.allowed_compartments` as GUCs and leaves the
--     session role untouched.
--   * The application connects as `cg_admin` (deploy/docker/docker-compose.yml),
--     which is POSTGRES_USER in the official postgres image and therefore a
--     superuser.
--
-- Superusers bypass row-level security unconditionally, so no policy on any
-- table is evaluated for the application's connection. That applies to the
-- policies 004, 010, 022 and 028 already created on `core_graph.*` just as much
-- as to the ones added here. The `tests/rls/*.sql` suites pass because they
-- create their own non-superuser roles and SET ROLE to them, which verifies the
-- policies are correct without verifying that the application ever reaches
-- them.
--
-- Closing that requires the application to connect as a non-superuser, or to
-- SET ROLE per request from the caller identity. Both are changes to the
-- connection model rather than to the schema, and neither belongs in a
-- migration. Raised separately.
--
-- This migration is still worth applying: the policy is a precondition for any
-- of those fixes, and its absence is a second, independent defect.
--
-- Fail-closed default. `tlp_level` defaults to 4, the most restrictive level,
-- so an unlabelled row is visible only to a caller cleared to 4 (cg_ciso).
-- Nothing in this repository writes `embeddings`, so in a deployment fed only
-- by this repo the table is empty and the default costs nothing. Where an
-- out-of-tree producer has populated it, those rows become ciso-only until the
-- producer sets a level: a visible, safe failure rather than a silent leak.
-- The opposite default would have codified the current exposure.
--
-- Idempotent.

-- ---------------------------------------------------------------------------
-- 1. tlp_level on both vector tables
-- ---------------------------------------------------------------------------

alter table embeddings
    add column if not exists tlp_level smallint not null default 4;

-- Denormalised onto the serving tier as well, deliberately diverging from
-- axiom (whose serving table carries no tlp_level, because axiom does not
-- enforce TLP there at all). The ANN in `_vector_candidates` runs in a CTE
-- against `retrieval_embeddings` before joining `embeddings`, so a policy on
-- `embeddings` alone would filter only after top-k had already been chosen
-- from unfiltered vectors. Correct, but it would silently return fewer than k.
-- Carrying the level here lets the policy apply to the ANN scan itself, which
-- is the case 027's iterative scans were enabled for. Precedent for
-- denormalising a TLP level onto a hot path: migrations 022 and 032.
alter table retrieval_embeddings
    add column if not exists tlp_level smallint not null default 4;

do $$
begin
    if not exists (
        select 1 from pg_constraint
         where conname = 'embeddings_tlp_level_check'
           and conrelid = 'embeddings'::regclass
    ) then
        alter table embeddings
            add constraint embeddings_tlp_level_check
            check (tlp_level between 0 and 4);
    end if;

    if not exists (
        select 1 from pg_constraint
         where conname = 'retrieval_embeddings_tlp_level_check'
           and conrelid = 'retrieval_embeddings'::regclass
    ) then
        alter table retrieval_embeddings
            add constraint retrieval_embeddings_tlp_level_check
            check (tlp_level between 0 and 4);
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- 2. Resync the serving tier from the source of truth
-- ---------------------------------------------------------------------------

-- 036's backfill predates this column, so rows it inserted carry the default
-- rather than the level of the subject they came from. Same shape as migration
-- 032, which resynced denormalised edge TLP after 022 introduced it.
update retrieval_embeddings re
   set tlp_level = e.tlp_level
  from embeddings e
 where e.graph_id = re.graph_id
   and e.model_id = re.model_id
   and re.tlp_level is distinct from e.tlp_level;

-- ---------------------------------------------------------------------------
-- 3. Policies
-- ---------------------------------------------------------------------------

-- RLS is enabled but deliberately NOT forced, which diverges from 004 and 028.
--
-- FORCE applies policies to the table owner as well. The owner here is the
-- identity that runs migrations, and migration 036 re-runs on every `make
-- migrate` and every replay in tests/schema/test_migrations.sh. Its backfill
-- reads `embeddings` and writes `retrieval_embeddings`; under FORCE that read
-- would be subject to the policy with `app.max_tlp` unset, coalescing to 1, so
-- every subject above TLP:1 would silently stop being copied. The parity view
-- would report the resulting gap, but the migration would still be wrong.
--
-- The application connects as a cg_* role, not as the owner, so policies apply
-- to it either way. What FORCE would add is protection against a deployment
-- that connects as the owner, which is already outside the model the cg_*
-- grants describe.
do $$
declare
    pred text := 'tlp_level <= coalesce(nullif(current_setting(''app.max_tlp'', true), '''')::smallint, 1::smallint)';
    tbl  text;
begin
    foreach tbl in array array['embeddings', 'retrieval_embeddings'] loop
        execute format('alter table %I enable row level security', tbl);

        execute format('drop policy if exists tlp_read_policy on %I', tbl);
        execute format(
            'create policy tlp_read_policy on %I for select using (%s)', tbl, pred
        );

        execute format('drop policy if exists ciso_full_access on %I', tbl);
        execute format(
            'create policy ciso_full_access on %I for select to cg_ciso using (true)', tbl
        );

        -- Write path, mirroring 028: a caller may not insert or modify a row
        -- above its own ceiling, which stops a lower-cleared writer from
        -- planting content that a higher-cleared reader would trust.
        execute format('drop policy if exists tlp_write_insert on %I', tbl);
        execute format(
            'create policy tlp_write_insert on %I for insert with check (%s)', tbl, pred
        );
        execute format('drop policy if exists tlp_write_update on %I', tbl);
        execute format(
            'create policy tlp_write_update on %I for update using (%s) with check (%s)',
            tbl, pred, pred
        );
        execute format('drop policy if exists tlp_write_delete on %I', tbl);
        execute format(
            'create policy tlp_write_delete on %I for delete using (%s)', tbl, pred
        );

        execute format('drop policy if exists ciso_full_write on %I', tbl);
        execute format(
            'create policy ciso_full_write on %I for all to cg_ciso using (true) with check (true)',
            tbl
        );
    end loop;
end $$;

-- ---------------------------------------------------------------------------
-- 4. Grants
-- ---------------------------------------------------------------------------

-- Mirrors the grant list 004 applies to the graph tables. Guarded because the
-- cg_* roles are created by schema/seed, which a bare migration run may not
-- have applied yet.
do $$
declare
    r    text;
    tbl  text;
begin
    foreach tbl in array array['embeddings', 'retrieval_embeddings'] loop
        foreach r in array array['cg_ciso', 'cg_soc_analyst', 'cg_compliance_officer',
                                 'cg_it_operations', 'cg_dpo', 'cg_external_auditor',
                                 'cg_ai_agent'] loop
            if exists (select 1 from pg_roles where rolname = r) then
                execute format('grant select on %I to %I', tbl, r);
            end if;
        end loop;
    end loop;
end $$;

create index if not exists idx_embeddings_tlp_level
    on embeddings (tlp_level);

create index if not exists idx_retrieval_embeddings_tlp
    on retrieval_embeddings (tlp_level);
