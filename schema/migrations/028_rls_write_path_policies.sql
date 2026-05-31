-- 028_rls_write_path_policies.sql
-- Defense-in-depth: TLP-enforcing INSERT/UPDATE/DELETE RLS on core_graph tables.
--
-- 004 created SELECT-only policies. Writes were unconstrained at the RLS layer:
-- they are performed by the graph-writer service role (cg_admin, the database
-- superuser, which bypasses RLS) and gated by Cerbos at the application layer.
-- These policies add engine-level enforcement so that IF any non-superuser role
-- is ever granted write access, it cannot create, modify, or delete a row whose
-- TLP level exceeds its session clearance (app.max_tlp). The superuser writer is
-- unaffected — RLS never applies to it — so this cannot regress ingestion.
--
-- Vertex tables carry tlp_level inside the `properties` agtype; edge tables
-- carry the denormalized tlp_level column added in 022. The write predicate
-- mirrors the existing read predicate per table type (including the migration
-- 014 nullif guard, so a rolled-back SET LOCAL leaving an empty string falls
-- back to GREEN rather than aborting on ''::int).
--
-- IAM tables (Layer 8) additionally carry a RESTRICTIVE TLP:AMBER write floor
-- mirroring the read floor from 010, so a sub-AMBER session can never mint IAM
-- rows even if granted writes.
--
-- Idempotent: guarded create-or-replace of each policy.

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
            -- Edge table: denormalized smallint column (matches 022's read policy).
            pred := 'tlp_level <= '
                 || 'coalesce(nullif(current_setting(''app.max_tlp'', true), '''')::smallint, '
                 || '1::smallint)';
        else
            -- Vertex table: tlp_level inside properties agtype (matches 004 + 014).
            pred := 'coalesce(((properties::text)::jsonb->>''tlp_level'')::int, 1) '
                 || '<= coalesce(nullif(current_setting(''app.max_tlp'', true), '''')::int, 1)';
        end if;

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

        -- cg_ciso writes are unrestricted, mirroring ciso_full_access (SELECT) in 004.
        execute format('drop policy if exists ciso_full_write on core_graph.%I', tbl.relname);
        execute format(
            'create policy ciso_full_write on core_graph.%I '
            'for all to cg_ciso using (true) with check (true)',
            tbl.relname
        );
    end loop;
end $$;

-- RESTRICTIVE TLP:AMBER write floor on IAM tables (parity with the read floor
-- in 010). RESTRICTIVE policies AND with the clearance check above and apply to
-- every role (including cg_ciso), so IAM writes always require app.max_tlp >= 2.
do $$
declare
    iam_tbl text;
    floor_expr constant text :=
        'coalesce(nullif(current_setting(''app.max_tlp'', true), '''')::int, 1) >= 2';
    iam_tables constant text[] := array[
        'Principal', 'Role', 'Group', 'Permission', 'AccessPolicy',
        'has_role', 'grants', 'actor_in', 'manages', 'owns', 'member_of'
    ];
begin
    foreach iam_tbl in array iam_tables loop
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
