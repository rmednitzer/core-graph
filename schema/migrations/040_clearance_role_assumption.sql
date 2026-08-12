\echo 'applying 040_clearance_role_assumption.sql'
-- 040_clearance_role_assumption.sql
-- Let cg_app assume a caller's clearance role, and give those roles enough
-- privilege to serve a request.
--
-- ADR-0015. Migration 038 created cg_app and ADR-0014 pointed the serving pool
-- at it, which made the TLP policies real. Enforcement still rested entirely on
-- one GUC: every policy reads `app.max_tlp`, and the seven clearance roles from
-- 004, 010 and 033 were grant targets that nothing ever connected or switched
-- to. The role-targeted policies (`ciso_full_access`, `ciso_full_write`) could
-- not match, and the roles' own table grants sat between nothing and nothing.
--
-- This migration is the schema half of putting them in the request path.
--
-- ---------------------------------------------------------------------------
-- Why membership does not hand cg_app the clearances
-- ---------------------------------------------------------------------------
--
-- cg_app is NOINHERIT (038), and the grants below are explicit about it:
-- `with inherit false, set true`. That combination means cg_app may *assume* a
-- clearance role via SET ROLE but holds none of its privileges passively. A
-- query issued as cg_app is checked against cg_app's own grants, not against
-- the union of seven roles.
--
-- Verified rather than assumed: with the membership in place, cg_app selecting
-- from a table granted only to cg_ciso gets "permission denied for table", and
-- the same select after `SET ROLE cg_ciso` succeeds as cg_ciso. Stating
-- `inherit false` explicitly rather than relying on cg_app's NOINHERIT default
-- means a later `ALTER ROLE cg_app INHERIT` cannot silently widen every
-- membership at once.
--
-- ---------------------------------------------------------------------------
-- Why every clearance role gets the same grants
-- ---------------------------------------------------------------------------
--
-- Deliberately behaviour-preserving. The roles currently hold SELECT on
-- `core_graph.*` and nothing else: migration 028 added write *policies* but no
-- write *grants*, noting that they "bite only if a non-superuser role is
-- granted" write. Because cg_app is NOINHERIT, assuming a clearance role drops
-- everything cg_app has -- INSERT on audit_log, USAGE on ag_catalog, the
-- sequences, the functions -- so a request that wrote anything would fail on
-- privilege rather than on policy.
--
-- Mirroring cg_app's surface onto all seven keeps the change reversible and
-- keeps this migration free of a governance decision. Which clearances *should*
-- be read-only is a real decision (an external auditor arguably should never
-- write, whatever the policies say) and it belongs in its own change, as a
-- narrowing, once someone has made it. Nothing widens today: every one of these
-- roles is reachable only by a caller that could already reach cg_app, and
-- cg_app already holds this exact surface.
--
-- One thing does change: `ciso_full_access` starts matching for a ciso caller,
-- so their reads OR past `tlp_read_policy` instead of being filtered by
-- `app.max_tlp`. The seeded ciso clearance is 4, which already saw everything,
-- so the effect is nil today. The IAM floor from 010 is unaffected -- it is
-- RESTRICTIVE and keyed on the GUC, so it still AND's for cg_ciso.
--
-- Idempotent.

-- ---------------------------------------------------------------------------
-- 1. Assumption rights
-- ---------------------------------------------------------------------------

do $$
declare
    r text;
begin
    foreach r in array array['cg_ciso', 'cg_soc_analyst', 'cg_compliance_officer',
                             'cg_it_operations', 'cg_dpo', 'cg_external_auditor',
                             'cg_ai_agent'] loop
        if exists (select 1 from pg_roles where rolname = r)
           and exists (select 1 from pg_roles where rolname = 'cg_app') then
            execute format('grant %I to cg_app with inherit false, set true', r);
        end if;
    end loop;
end $$;

-- ---------------------------------------------------------------------------
-- 2. Enough privilege to serve a request
-- ---------------------------------------------------------------------------

-- The same surface 038 gives cg_app, for the same reasons stated there: table
-- grants are broad and row-level access is what constrains them, which is the
-- model 004 established. Narrowing table grants instead would restate the
-- policy in a second place that can drift from it.
do $$
declare
    r   text;
    sch text;
begin
    foreach r in array array['cg_ciso', 'cg_soc_analyst', 'cg_compliance_officer',
                             'cg_it_operations', 'cg_dpo', 'cg_external_auditor',
                             'cg_ai_agent'] loop
        if not exists (select 1 from pg_roles where rolname = r) then
            continue;
        end if;

        foreach sch in array array['public', 'ag_catalog', 'core_graph'] loop
            if not exists (select 1 from pg_namespace where nspname = sch) then
                continue;
            end if;

            execute format('grant usage on schema %I to %I', sch, r);
            execute format(
                'grant select, insert, update, delete on all tables in schema %I to %I', sch, r
            );
            execute format('grant usage, select on all sequences in schema %I to %I', sch, r);
            execute format('grant execute on all functions in schema %I to %I', sch, r);

            execute format(
                'alter default privileges in schema %I '
                'grant select, insert, update, delete on tables to %I', sch, r
            );
            execute format(
                'alter default privileges in schema %I grant usage, select on sequences to %I',
                sch, r
            );
            execute format(
                'alter default privileges in schema %I grant execute on functions to %I', sch, r
            );
        end loop;
    end loop;
end $$;

-- ---------------------------------------------------------------------------
-- 3. The same carve-outs 038 applies to cg_app
-- ---------------------------------------------------------------------------

-- A clearance role reached through SET ROLE is the identity a request runs as,
-- so the append-only property of the audit log (024) and the read-only
-- treatment of AGE's registries have to hold for it too. Without these the
-- carve-outs on cg_app would be trivially sidestepped by assuming any clearance.
do $$
declare
    r   text;
    rel text;
begin
    foreach r in array array['cg_ciso', 'cg_soc_analyst', 'cg_compliance_officer',
                             'cg_it_operations', 'cg_dpo', 'cg_external_auditor',
                             'cg_ai_agent'] loop
        if not exists (select 1 from pg_roles where rolname = r) then
            continue;
        end if;

        if to_regclass('audit_log') is not null then
            execute format('revoke update, delete on audit_log from %I', r);
        end if;

        foreach rel in array array['ag_catalog.ag_graph', 'ag_catalog.ag_label'] loop
            if to_regclass(rel) is not null then
                execute format('revoke insert, update, delete on %s from %I', rel, r);
            end if;
        end loop;
    end loop;
end $$;
