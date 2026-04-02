-- 014_rls_nullif_guard.sql
-- Add NULLIF guard to RLS current_setting calls.
--
-- After a rolled-back SET LOCAL, current_setting() returns empty string ''
-- rather than NULL, causing ''::int to error. Wrapping with NULLIF handles
-- both NULL and empty-string returns safely.
--
-- Recreates tlp_read_policy on all core_graph tables (from 004) and
-- iam_tlp_floor on IAM tables (from 010). Idempotent: safe to re-run.

-- ---------------------------------------------------------------------------
-- Recreate tlp_read_policy on all core_graph tables with NULLIF guard
-- ---------------------------------------------------------------------------

do $$
declare
    tbl record;
begin
    for tbl in
        select c.relname
        from pg_class c
        join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'core_graph'
          and c.relkind = 'r'
    loop
        execute format('drop policy if exists tlp_read_policy on core_graph.%I', tbl.relname);
        execute format(
            'create policy tlp_read_policy on core_graph.%I for select using (
                coalesce(((properties::text)::jsonb->>''tlp_level'')::int, 1)
                <= coalesce(nullif(current_setting(''app.max_tlp'', true), '''')::int, 1)
            )',
            tbl.relname
        );
    end loop;
end $$;

-- ---------------------------------------------------------------------------
-- Recreate iam_tlp_floor on IAM vertex and edge tables with NULLIF guard
-- ---------------------------------------------------------------------------

do $$
declare
    iam_label text;
begin
    foreach iam_label in array array['Principal', 'Role', 'Group', 'Permission', 'AccessPolicy']
    loop
        -- Vertex tables: recreate tlp_read_policy with NULLIF guard
        execute format('drop policy if exists tlp_read_policy on core_graph.%I', iam_label);
        execute format(
            'create policy tlp_read_policy on core_graph.%I for select using (
                coalesce(((properties::text)::jsonb->>''tlp_level'')::int, 1)
                <= coalesce(nullif(current_setting(''app.max_tlp'', true), '''')::int, 1)
            )',
            iam_label
        );

        -- Vertex tables: recreate iam_tlp_floor with NULLIF guard
        execute format('drop policy if exists iam_tlp_floor on core_graph.%I', iam_label);
        execute format(
            'create policy iam_tlp_floor on core_graph.%I as restrictive for select using (
                coalesce(nullif(current_setting(''app.max_tlp'', true), '''')::int, 1) >= 2
            )',
            iam_label
        );
    end loop;
end $$;

do $$
declare
    iam_edge text;
begin
    foreach iam_edge in array array['has_role', 'grants', 'actor_in', 'manages', 'owns']
    loop
        if exists (
            select 1 from pg_class c
            join pg_namespace n on n.oid = c.relnamespace
            where n.nspname = 'core_graph' and c.relname = iam_edge
        ) then
            execute format('drop policy if exists iam_tlp_floor on core_graph.%I', iam_edge);
            execute format(
                'create policy iam_tlp_floor on core_graph.%I as restrictive for select using (
                    coalesce(nullif(current_setting(''app.max_tlp'', true), '''')::int, 1) >= 2
                )',
                iam_edge
            );
        end if;
    end loop;
end $$;
