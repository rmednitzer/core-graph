-- 030_stix_sdo_indexes.sql
-- AGE property indexes for the STIX SDO labels given MERGE templates in this
-- change set. Every SDO upsert MERGEs by stix_id (so each TAXII/OpenCTI
-- delivery and redelivery probes that key) and the TAXII endpoint filters by
-- stix_type (match[type]); without these indexes both degrade to per-label
-- sequential scans on large threat-intel feeds. 017 already indexes
-- ThreatActor.stix_id and Vulnerability.cve_id.
--
-- AGE stores vertex properties in a single agtype `properties` column, so an
-- index is a btree over the extracted JSON key (matching 017's pattern).
--
-- Idempotent.

-- stix_id (the MERGE key) for the SDO labels that lack one.
create index if not exists idx_age_malware_stix_id
    on core_graph."Malware" using btree (((properties::text)::jsonb->>'stix_id'));
create index if not exists idx_age_campaign_stix_id
    on core_graph."Campaign" using btree (((properties::text)::jsonb->>'stix_id'));
create index if not exists idx_age_attack_pattern_stix_id
    on core_graph."AttackPattern" using btree (((properties::text)::jsonb->>'stix_id'));
create index if not exists idx_age_vulnerability_stix_id
    on core_graph."Vulnerability" using btree (((properties::text)::jsonb->>'stix_id'));
create index if not exists idx_age_tool_stix_id
    on core_graph."Tool" using btree (((properties::text)::jsonb->>'stix_id'));

-- stix_type (the TAXII match[type] filter) for every SDO label.
create index if not exists idx_age_threat_actor_stix_type
    on core_graph."ThreatActor" using btree (((properties::text)::jsonb->>'stix_type'));
create index if not exists idx_age_malware_stix_type
    on core_graph."Malware" using btree (((properties::text)::jsonb->>'stix_type'));
create index if not exists idx_age_campaign_stix_type
    on core_graph."Campaign" using btree (((properties::text)::jsonb->>'stix_type'));
create index if not exists idx_age_attack_pattern_stix_type
    on core_graph."AttackPattern" using btree (((properties::text)::jsonb->>'stix_type'));
create index if not exists idx_age_vulnerability_stix_type
    on core_graph."Vulnerability" using btree (((properties::text)::jsonb->>'stix_type'));
create index if not exists idx_age_tool_stix_type
    on core_graph."Tool" using btree (((properties::text)::jsonb->>'stix_type'));
