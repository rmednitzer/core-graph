-- 028_rls_write_path_policies.sql
-- Complete RLS coverage on core_graph: enable RLS everywhere + TLP-enforcing
-- read AND write policies.
--
-- Two gaps motivated this:
--   1. 004 enabled RLS + read policies only on tables that existed then.
--      009 (Host/Network/Site/Interface/Service/MonitoringAlert) and 023
--      (memory labels) create their vertex labels with create_vlabel only —
--      they never enable RLS — so those vertices were readable regardless of
--      TLP, and any write policy added here would be inert (policies are
--      ignored while relrowsecurity is false).
--   2. 004 created SELECT-only policies; INSERT/UPDATE/DELETE were
--      unconstrained at the RLS layer.
--
-- This migration walks every core_graph table and idempotently (re-)asserts:
-- enable+force RLS, the TLP read policy, cg_ciso full read, the TLP
-- INSERT/UPDATE/DELETE write policies, and cg_ciso full write. The graph-writer
-- service role (cg_admin) is a superuser and bypasses RLS, so ingestion is
-- unaffected; the write policies bite only if a non-superuser role is granted
-- writes, which then cannot create/modify/delete a row above its session
-- clearance (app.max_tlp).
--
-- The predicate mirrors per-table type: edge tables use the denormalized
-- tlp_level column added in 022; vertex tables read tlp_level from the
-- properties agtype. Both carry the migration-014 nullif guard so a rolled-back
-- SET LOCAL (empty string) falls back to GREEN rather than aborting on ''::int.
--
-- IAM vertex labels additionally get a RESTRICTIVE TLP:AMBER write floor
-- mirroring the 010 read floor. The floor is applied to the IAM *vertex* labels
-- only: IAM edges already inherit the AMBER level through 022's edge-tlp trigger
-- (GREATEST of endpoints) enforced by the standard write policy, and the
-- member_of/owns edge labels are shared with non-IAM domains, so flooring them
-- would wrongly block ordinary infrastructure edge writes.
--
-- Idempotent.

do $$
declare
    tbl record;
    has_tlp_col boolean;
    pred text;
begin
    for tbl in
        select c.relname
          from pg_class c
          join pg_namespace n on n.oid = c.relnamespace
         where n.nspname = 'core_graph'
           and c.relkind = 'r'
    loop
        select exists (
            select 1 from pg_attribute a
             where a.attrelid = format('core_graph.%I', tbl.relname)::regclass
               and a.attname = 'tlp_level'
               and not a.attisdropped
        ) into has_tlp_col;

        if has_tlp_col then
            pred := 'tlp_level <= '
                 || 'coalesce(nullif(current_setting(''app.max_tlp'', true), '''')::smallint, '
                 || '1::smallint)';
        else
            pred := 'coalesce(((properties::text)::jsonb->>''tlp_level'')::int, 1) '
                 || '<= coalesce(nullif(current_setting(''app.max_tlp'', true), '''')::int, 1)';
        end if;

        -- Enable RLS (essential for 009/023 labels that never had it).
        execute format('alter table core_graph.%I enable row level security', tbl.relname);
        execute format('alter table core_graph.%I force row level security', tbl.relname);

        -- Read: TLP clearance + cg_ciso unrestricted (idempotent re-assert,
        -- closing the 009/023 read gap).
        execute format('drop policy if exists tlp_read_policy on core_graph.%I', tbl.relname);
        execute format(
            'create policy tlp_read_policy on core_graph.%I for select using (%s)',
            tbl.relname, pred
        );
        execute format('drop policy if exists ciso_full_access on core_graph.%I', tbl.relname);
        execute format(
            'create policy ciso_full_access on core_graph.%I for select to cg_ciso using (true)',
            tbl.relname
        );

        -- Write: TLP clearance on INSERT/UPDATE/DELETE.
        execute format('drop policy if exists tlp_write_insert on core_graph.%I', tbl.relname);
        execute format(
            'create policy tlp_write_insert on core_graph.%I for insert with check (%s)',
            tbl.relname, pred
        );
        execute format('drop policy if exists tlp_write_update on core_graph.%I', tbl.relname);
        execute format(
            'create policy tlp_write_update on core_graph.%I '
            'for update using (%s) with check (%s)',
            tbl.relname, pred, pred
        );
        execute format('drop policy if exists tlp_write_delete on core_graph.%I', tbl.relname);
        execute format(
            'create policy tlp_write_delete on core_graph.%I for delete using (%s)',
            tbl.relname, pred
        );

        -- cg_ciso writes unrestricted, mirroring ciso_full_access (SELECT).
        execute format('drop policy if exists ciso_full_write on core_graph.%I', tbl.relname);
        execute format(
            'create policy ciso_full_write on core_graph.%I '
            'for all to cg_ciso using (true) with check (true)',
            tbl.relname
        );
    end loop;
end $$;

-- RESTRICTIVE TLP:AMBER write floor on IAM vertex labels (parity with the read
-- floor in 010). RESTRICTIVE policies AND with the clearance check above and
-- apply to every role (including cg_ciso), so IAM vertex writes always require
-- app.max_tlp >= 2. Edges are intentionally excluded — see header.
do $$
declare
    iam_tbl text;
    floor_expr constant text :=
        'coalesce(nullif(current_setting(''app.max_tlp'', true), '''')::int, 1) >= 2';
    iam_labels constant text[] := array[
        'Principal', 'Role', 'Group', 'Permission', 'AccessPolicy'
    ];
begin
    foreach iam_tbl in array iam_labels loop
        if exists (
            select 1 from pg_class c
              join pg_namespace n on n.oid = c.relnamespace
             where n.nspname = 'core_graph' and c.relname = iam_tbl and c.relkind = 'r'
        ) then
            execute format('drop policy if exists iam_write_floor_insert on core_graph.%I', iam_tbl);
            execute format(
                'create policy iam_write_floor_insert on core_graph.%I as restrictive '
                'for insert with check (%s)', iam_tbl, floor_expr
            );
            execute format('drop policy if exists iam_write_floor_update on core_graph.%I', iam_tbl);
            execute format(
                'create policy iam_write_floor_update on core_graph.%I as restrictive '
                'for update using (%s) with check (%s)', iam_tbl, floor_expr, floor_expr
            );
            execute format('drop policy if exists iam_write_floor_delete on core_graph.%I', iam_tbl);
            execute format(
                'create policy iam_write_floor_delete on core_graph.%I as restrictive '
                'for delete using (%s)', iam_tbl, floor_expr
            );
        end if;
    end loop;
end $$;
