-- 010_iam_layer.sql
-- Layer 8: Identity & Access Management — vertex and edge labels for
-- Keycloak users, groups, roles, permissions, and access policies.
-- Idempotent: safe to run multiple times.

-- ---------------------------------------------------------------------------
-- Layer 8: IAM — vertex labels
-- ---------------------------------------------------------------------------

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'Principal' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'Principal');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'Role' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'Role');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'Group' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'Group');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'Permission' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'Permission');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'AccessPolicy' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'AccessPolicy');
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- Layer 8: IAM — edge labels
-- ---------------------------------------------------------------------------

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'has_role' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'has_role');
    end if;
end $$;

-- member_of already exists from 009_infra_layer.sql (Interface → Host);
-- AGE edge labels are not type-restricted, reusable for Principal → Group.

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'grants' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'grants');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'actor_in' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'actor_in');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'manages' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'manages');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'owns' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'owns');
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- RLS: Enable and apply policies on IAM vertex tables
-- ---------------------------------------------------------------------------

do $$
declare
    iam_label text;
begin
    foreach iam_label in array array['Principal', 'Role', 'Group', 'Permission', 'AccessPolicy']
    loop
        -- Enable and force RLS
        execute format('alter table core_graph.%I enable row level security', iam_label);
        execute format('alter table core_graph.%I force row level security', iam_label);

        -- Standard TLP-based read policy (same as 004)
        execute format('drop policy if exists tlp_read_policy on core_graph.%I', iam_label);
        execute format(
            'create policy tlp_read_policy on core_graph.%I for select using (
                coalesce(((properties::text)::jsonb->>''tlp_level'')::int, 1)
                <= coalesce(current_setting(''app.max_tlp'', true)::int, 1)
            )',
            iam_label
        );

        -- CISO full access
        execute format('drop policy if exists ciso_full_access on core_graph.%I', iam_label);
        execute format(
            'create policy ciso_full_access on core_graph.%I for select to cg_ciso using (true)',
            iam_label
        );

        -- IAM TLP floor: never visible below TLP:AMBER (app.max_tlp >= 2)
        -- RESTRICTIVE policy: AND'd with permissive policies, not OR'd.
        -- Without AS RESTRICTIVE, PostgreSQL OR's multiple permissive policies,
        -- which would defeat the floor (tlp_read_policy alone could grant access).
        execute format('drop policy if exists iam_tlp_floor on core_graph.%I', iam_label);
        execute format(
            'create policy iam_tlp_floor on core_graph.%I as restrictive for select using (
                coalesce(current_setting(''app.max_tlp'', true)::int, 1) >= 2
            )',
            iam_label
        );

        -- Grant SELECT to all roles
        execute format(
            'grant select on core_graph.%I to cg_ciso, cg_soc_analyst, '
            'cg_compliance_officer, cg_it_operations, cg_dpo, '
            'cg_external_auditor, cg_ai_agent',
            iam_label
        );
    end loop;
end $$;

-- ---------------------------------------------------------------------------
-- RLS: Apply policies on IAM edge tables
-- ---------------------------------------------------------------------------

do $$
declare
    iam_edge text;
begin
    foreach iam_edge in array array['has_role', 'grants', 'actor_in', 'manages', 'owns']
    loop
        -- Only apply if the table exists (edge labels create tables)
        if exists (
            select 1 from pg_class c
            join pg_namespace n on n.oid = c.relnamespace
            where n.nspname = 'core_graph' and c.relname = iam_edge
        ) then
            execute format('alter table core_graph.%I enable row level security', iam_edge);
            execute format('alter table core_graph.%I force row level security', iam_edge);

            execute format('drop policy if exists iam_tlp_floor on core_graph.%I', iam_edge);
            execute format(
                'create policy iam_tlp_floor on core_graph.%I as restrictive for select using (
                    coalesce(current_setting(''app.max_tlp'', true)::int, 1) >= 2
                )',
                iam_edge
            );

            execute format('drop policy if exists ciso_full_access on core_graph.%I', iam_edge);
            execute format(
                'create policy ciso_full_access on core_graph.%I for select to cg_ciso using (true)',
                iam_edge
            );

            execute format(
                'grant select on core_graph.%I to cg_ciso, cg_soc_analyst, '
                'cg_compliance_officer, cg_it_operations, cg_dpo, '
                'cg_external_auditor, cg_ai_agent',
                iam_edge
            );
        end if;
    end loop;
end $$;
