-- 004_rls_policies.sql
-- Row-Level Security policies enforcing TLP markings on AGE graph tables.
-- Uses session-scoped current_setting('app.max_tlp', true) for enforcement.
-- Idempotent: safe to run multiple times.

-- ---------------------------------------------------------------------------
-- Create database roles (idempotent)
-- ---------------------------------------------------------------------------

do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'cg_ciso') then
        create role cg_ciso nologin;
    end if;
end $$;

do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'cg_soc_analyst') then
        create role cg_soc_analyst nologin;
    end if;
end $$;

do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'cg_compliance_officer') then
        create role cg_compliance_officer nologin;
    end if;
end $$;

do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'cg_it_operations') then
        create role cg_it_operations nologin;
    end if;
end $$;

do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'cg_dpo') then
        create role cg_dpo nologin;
    end if;
end $$;

do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'cg_external_auditor') then
        create role cg_external_auditor nologin;
    end if;
end $$;

do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'cg_ai_agent') then
        create role cg_ai_agent nologin;
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- Enable RLS and create TLP-based policies on all core_graph tables
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
        -- Enable and force RLS
        execute format('alter table core_graph.%I enable row level security', tbl.relname);
        execute format('alter table core_graph.%I force row level security', tbl.relname);

        -- Drop existing policies if any
        execute format('drop policy if exists tlp_read_policy on core_graph.%I', tbl.relname);
        execute format('drop policy if exists ciso_full_access on core_graph.%I', tbl.relname);

        -- Create TLP-based read policy for general roles
        -- AGE stores properties as agtype; cast to text first, then to jsonb
        execute format(
            'create policy tlp_read_policy on core_graph.%I for select using (
                coalesce(((properties::text)::jsonb->>''tlp_level'')::int, 1)
                <= coalesce(current_setting(''app.max_tlp'', true)::int, 1)
            )',
            tbl.relname
        );

        -- Create unrestricted policy for cg_ciso (sees everything)
        execute format(
            'create policy ciso_full_access on core_graph.%I for select to cg_ciso using (true)',
            tbl.relname
        );

        -- Grant SELECT to all roles
        execute format(
            'grant select on core_graph.%I to cg_ciso, cg_soc_analyst, cg_compliance_officer, cg_it_operations, cg_dpo, cg_external_auditor, cg_ai_agent',
            tbl.relname
        );
    end loop;
end $$;
