-- 017_age_indexes.sql
-- Performance indexes on AGE vertex property columns.
-- Idempotent: uses IF NOT EXISTS.

-- CanonicalIP: value lookups
create index if not exists idx_age_canonical_ip_value
    on core_graph."CanonicalIP"
    using btree (((properties::text)::jsonb->>'value'));

-- CanonicalDomain: value lookups
create index if not exists idx_age_canonical_domain_value
    on core_graph."CanonicalDomain"
    using btree (((properties::text)::jsonb->>'value'));

-- Host: canonical_key lookups
create index if not exists idx_age_host_canonical_key
    on core_graph."Host"
    using btree (((properties::text)::jsonb->>'canonical_key'));

-- Host: name lookups
create index if not exists idx_age_host_name
    on core_graph."Host"
    using btree (((properties::text)::jsonb->>'name'));

-- MonitoringAlert: fingerprint lookups
create index if not exists idx_age_alert_fingerprint
    on core_graph."MonitoringAlert"
    using btree (((properties::text)::jsonb->>'fingerprint'));

-- MonitoringAlert: status filter
create index if not exists idx_age_alert_status
    on core_graph."MonitoringAlert"
    using btree (((properties::text)::jsonb->>'status'));

-- Principal: canonical_key lookups
create index if not exists idx_age_principal_canonical_key
    on core_graph."Principal"
    using btree (((properties::text)::jsonb->>'canonical_key'));

-- Principal: principal_id lookups
create index if not exists idx_age_principal_id
    on core_graph."Principal"
    using btree (((properties::text)::jsonb->>'principal_id'));

-- ThreatActor: name lookups
create index if not exists idx_age_threat_actor_name
    on core_graph."ThreatActor"
    using btree (((properties::text)::jsonb->>'name'));

-- ThreatActor: stix_id lookups
create index if not exists idx_age_threat_actor_stix_id
    on core_graph."ThreatActor"
    using btree (((properties::text)::jsonb->>'stix_id'));

-- Indicator: value lookups
create index if not exists idx_age_indicator_value
    on core_graph."Indicator"
    using btree (((properties::text)::jsonb->>'value'));

-- Vulnerability: cve_id lookups
create index if not exists idx_age_vulnerability_cve
    on core_graph."Vulnerability"
    using btree (((properties::text)::jsonb->>'cve_id'));

-- Role: canonical_key
create index if not exists idx_age_role_canonical_key
    on core_graph."Role"
    using btree (((properties::text)::jsonb->>'canonical_key'));

-- Group: canonical_key
create index if not exists idx_age_group_canonical_key
    on core_graph."Group"
    using btree (((properties::text)::jsonb->>'canonical_key'));

-- ComplianceControl: control_id
create index if not exists idx_age_compliance_control_id
    on core_graph."ComplianceControl"
    using btree (((properties::text)::jsonb->>'control_id'));
