-- schema/seed/roles.sql
-- Seed the seven-role hierarchy into user_clearances.
-- Idempotent: uses ON CONFLICT DO NOTHING.

insert into user_clearances (user_id, max_tlp, compartments) values
    ('cg_ciso',                4, '{}'),
    ('cg_soc_analyst',         3, '{}'),
    ('cg_compliance_officer',  2, '{}'),
    ('cg_it_operations',       2, '{}'),
    ('cg_dpo',                 0, '{}'),
    ('cg_external_auditor',    2, '{}'),
    ('cg_ai_agent',            2, '{}')
on conflict (user_id) do nothing;
