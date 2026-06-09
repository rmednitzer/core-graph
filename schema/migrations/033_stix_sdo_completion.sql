-- 033_stix_sdo_completion.sql
-- Complete the STIX 2.1 SDO vertex labels (ADR-0007 roadmap #1, final part):
-- IntrusionSet, Identity, Location, Report.
--
-- 002 created the original Layer-1 labels and PR #47 added MERGE templates for
-- ThreatActor/Malware/Campaign/AttackPattern/Vulnerability/Tool. The remaining
-- four SDO types were deferred: the OpenCTI adapter already maps them
-- (intrusion-set -> IntrusionSet, ...) and the TAXII threat-intel collection
-- already advertises intrusion-set, but the enrichment stage had to defer the
-- envelopes because no vlabel/template existed. This migration creates the
-- vertex labels; the matching writer templates ship in the same change set.
--
-- Three parts, mirroring how the existing labels are provisioned:
--   1. create_vlabel (002 pattern)
--   2. RLS enable + TLP read/write policies (028 pattern — 028 walked the
--      tables that existed when it ran, so labels created after it must
--      re-assert the same policy set or they would be readable/writable
--      regardless of TLP)
--   3. stix_id / stix_type btree indexes (030 pattern — every SDO upsert
--      MERGEs by stix_id and TAXII filters by stix_type)
--
-- Idempotent.

-- ---------------------------------------------------------------------------
-- 1. Vertex labels (Layer 1: threat intelligence)
-- ---------------------------------------------------------------------------

do $$
declare
    lbl text;
begin
    foreach lbl in array array['IntrusionSet', 'Identity', 'Location', 'Report'] loop
        if not exists (
            select 1 from ag_catalog.ag_label
            where name = lbl and graph = (
                select graphid from ag_catalog.ag_graph where name = 'core_graph'
            )
        ) then
            perform ag_catalog.create_vlabel('core_graph', lbl);
        end if;
    end loop;
end $$;

-- ---------------------------------------------------------------------------
-- 2. RLS: enable + TLP read/write policies (exact 028 predicate for vertex
--    tables; these labels have no denormalized tlp_level column)
-- ---------------------------------------------------------------------------

do $$
declare
    lbl text;
    pred constant text :=
        'coalesce(((properties::text)::jsonb->>''tlp_level'')::int, 1) '
        '<= coalesce(nullif(current_setting(''app.max_tlp'', true), '''')::int, 1)';
begin
    foreach lbl in array array['IntrusionSet', 'Identity', 'Location', 'Report'] loop
        execute format('alter table core_graph.%I enable row level security', lbl);
        execute format('alter table core_graph.%I force row level security', lbl);

        execute format('drop policy if exists tlp_read_policy on core_graph.%I', lbl);
        execute format(
            'create policy tlp_read_policy on core_graph.%I for select using (%s)',
            lbl, pred
        );
        execute format('drop policy if exists ciso_full_access on core_graph.%I', lbl);
        execute format(
            'create policy ciso_full_access on core_graph.%I for select to cg_ciso using (true)',
            lbl
        );

        execute format('drop policy if exists tlp_write_insert on core_graph.%I', lbl);
        execute format(
            'create policy tlp_write_insert on core_graph.%I for insert with check (%s)',
            lbl, pred
        );
        execute format('drop policy if exists tlp_write_update on core_graph.%I', lbl);
        execute format(
            'create policy tlp_write_update on core_graph.%I '
            'for update using (%s) with check (%s)',
            lbl, pred, pred
        );
        execute format('drop policy if exists tlp_write_delete on core_graph.%I', lbl);
        execute format(
            'create policy tlp_write_delete on core_graph.%I for delete using (%s)',
            lbl, pred
        );

        execute format('drop policy if exists ciso_full_write on core_graph.%I', lbl);
        execute format(
            'create policy ciso_full_write on core_graph.%I '
            'for all to cg_ciso using (true) with check (true)',
            lbl
        );

        -- SELECT grant parity with the sibling Layer-1 labels (004 granted
        -- per-table, so labels created later must repeat it).
        execute format(
            'grant select on core_graph.%I to cg_ciso, cg_soc_analyst, '
            'cg_compliance_officer, cg_it_operations, cg_dpo, '
            'cg_external_auditor, cg_ai_agent',
            lbl
        );
    end loop;
end $$;

-- ---------------------------------------------------------------------------
-- 3. Indexes: stix_id (MERGE key) + stix_type (TAXII match[type] filter)
-- ---------------------------------------------------------------------------

create index if not exists idx_age_intrusion_set_stix_id
    on core_graph."IntrusionSet" using btree (((properties::text)::jsonb->>'stix_id'));
create index if not exists idx_age_identity_stix_id
    on core_graph."Identity" using btree (((properties::text)::jsonb->>'stix_id'));
create index if not exists idx_age_location_stix_id
    on core_graph."Location" using btree (((properties::text)::jsonb->>'stix_id'));
create index if not exists idx_age_report_stix_id
    on core_graph."Report" using btree (((properties::text)::jsonb->>'stix_id'));

create index if not exists idx_age_intrusion_set_stix_type
    on core_graph."IntrusionSet" using btree (((properties::text)::jsonb->>'stix_type'));
create index if not exists idx_age_identity_stix_type
    on core_graph."Identity" using btree (((properties::text)::jsonb->>'stix_type'));
create index if not exists idx_age_location_stix_type
    on core_graph."Location" using btree (((properties::text)::jsonb->>'stix_type'));
create index if not exists idx_age_report_stix_type
    on core_graph."Report" using btree (((properties::text)::jsonb->>'stix_type'));
