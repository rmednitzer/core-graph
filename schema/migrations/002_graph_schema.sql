-- 002_graph_schema.sql
-- Apache AGE graph schema for the six ontology layers plus cross-layer canonical entities.
-- Creates the 'core_graph' graph and all vertex/edge labels.
-- Idempotent: safe to run multiple times.

-- Create the graph
do $$
begin
    if not exists (select 1 from ag_catalog.ag_graph where name = 'core_graph') then
        perform ag_catalog.create_graph('core_graph');
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- Layer 1: Threat intelligence (STIX 2.1)
-- ---------------------------------------------------------------------------

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'ThreatActor' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'ThreatActor');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'Campaign' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'Campaign');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'AttackPattern' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'AttackPattern');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'Indicator' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'Indicator');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'Malware' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'Malware');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'Vulnerability' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'Vulnerability');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'Tool' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'Tool');
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- Layer 2: Security events (OCSF)
-- ---------------------------------------------------------------------------

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'SecurityEvent' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'SecurityEvent');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'NetworkActivity' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'NetworkActivity');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'AuthEvent' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'AuthEvent');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'ProcessEvent' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'ProcessEvent');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'Finding' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'Finding');
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- Layer 3: OSINT
-- ---------------------------------------------------------------------------

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'Article' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'Article');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'FeedItem' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'FeedItem');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'Source' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'Source');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'ExtractedEntity' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'ExtractedEntity');
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- Layer 4: Audit and compliance
-- ---------------------------------------------------------------------------

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'EvidenceRecord' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'EvidenceRecord');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'ComplianceControl' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'ComplianceControl');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'Framework' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'Framework');
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- Layer 5: AI conversation memory
-- ---------------------------------------------------------------------------

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'Session' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'Session');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'Episode' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'Episode');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'ExtractedFact' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'ExtractedFact');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'ConceptEntity' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'ConceptEntity');
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- Layer 6: Forensic timeline
-- ---------------------------------------------------------------------------

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'TimelineEvent' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'TimelineEvent');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'CausalChain' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'CausalChain');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'EvidenceLink' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'EvidenceLink');
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- Cross-layer canonical entities
-- ---------------------------------------------------------------------------

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'CanonicalIP' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'CanonicalIP');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'CanonicalDomain' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'CanonicalDomain');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'CanonicalPerson' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'CanonicalPerson');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'CanonicalOrganization' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_vlabel('core_graph', 'CanonicalOrganization');
    end if;
end $$;

-- ===========================================================================
-- Edge labels
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- Layer 1: Threat intelligence edges
-- ---------------------------------------------------------------------------

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'uses' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'uses');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'targets' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'targets');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'attributed_to' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'attributed_to');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'indicates' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'indicates');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'mitigates' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'mitigates');
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- Layer 2: Security event edges
-- ---------------------------------------------------------------------------

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'triggered_by' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'triggered_by');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'observed_on' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'observed_on');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'detected_by' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'detected_by');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'correlated_with' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'correlated_with');
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- Layer 3: OSINT edges
-- ---------------------------------------------------------------------------

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'mentions' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'mentions');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'extracted_from' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'extracted_from');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'published_by' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'published_by');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'corroborates' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'corroborates');
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- Layer 4: Audit and compliance edges
-- ---------------------------------------------------------------------------

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'satisfies' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'satisfies');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'evidenced_by' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'evidenced_by');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'controls' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'controls');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'audited_by' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'audited_by');
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- Layer 5: AI conversation memory edges
-- ---------------------------------------------------------------------------

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'derived_from' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'derived_from');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'supersedes' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'supersedes');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'valid_during' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'valid_during');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'mentioned_in' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'mentioned_in');
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- Layer 6: Forensic timeline edges
-- ---------------------------------------------------------------------------

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'caused_by' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'caused_by');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'preceded_by' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'preceded_by');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'contemporaneous_with' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'contemporaneous_with');
    end if;
end $$;

-- ---------------------------------------------------------------------------
-- Cross-layer edges
-- ---------------------------------------------------------------------------

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'observed_as' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'observed_as');
    end if;
end $$;

do $$
begin
    if not exists (
        select 1 from ag_catalog.ag_label
        where name = 'same_as' and graph = (
            select graphid from ag_catalog.ag_graph where name = 'core_graph'
        )
    ) then
        perform ag_catalog.create_elabel('core_graph', 'same_as');
    end if;
end $$;
