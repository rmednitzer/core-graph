-- 009_infra_layer.sql
-- Layer 7: Infrastructure & Assets — vertex and edge labels for CMDB,
-- network inventory, and monitoring alert data (Netbox, Prometheus).
-- Idempotent: safe to run multiple times.

-- ---------------------------------------------------------------------------
-- Layer 7: Infrastructure & Assets — vertex labels
-- ---------------------------------------------------------------------------

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'Host' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'Host');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'Network' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'Network');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'Site' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'Site');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'Interface' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'Interface');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'Service' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'Service');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'MonitoringAlert' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'MonitoringAlert');
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- Layer 7: Infrastructure & Assets — edge labels
-- ---------------------------------------------------------------------------

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'hosted_on' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'hosted_on');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'member_of' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'member_of');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'connects_to' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'connects_to');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'located_at' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'located_at');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'monitors' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'monitors');
    end if;
end $$;
