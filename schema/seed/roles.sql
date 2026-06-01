-- schema/seed/roles.sql
-- Seed default clearances for the seven-role hierarchy into user_clearances.
-- Idempotent: uses ON CONFLICT DO NOTHING.
--
-- user_id holds the *application* role name as the OIDC IdP emits it in the JWT
-- `roles` claim — the bare hierarchy (`ciso`, ...), NOT the cg_-prefixed
-- PostgreSQL database roles that the RLS GRANTs target (those are a separate
-- namespace; see ADR-0008). These are placeholder role->clearance defaults; a
-- real deployment also keys clearances on the OIDC subject.

insert into user_clearances (user_id, max_tlp, compartments) values
    ('ciso',                4, '{}'),
    ('soc_analyst',         3, '{}'),
    ('compliance_officer',  2, '{}'),
    ('it_operations',       2, '{}'),
    ('dpo',                 0, '{}'),
    ('external_auditor',    1, '{}'),
    ('ai_agent',            2, '{}')
on conflict (user_id) do nothing;
