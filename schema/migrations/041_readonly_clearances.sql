\echo 'applying 041_readonly_clearances.sql'
-- 041_readonly_clearances.sql
-- The narrowing migration 040 was shaped to make possible: clearances that the
-- authorization model describes as read-only become read-only at the engine.
--
-- ADR-0016. Migration 040 gave all seven clearance roles the same grants
-- deliberately, so that assumption could ship without carrying a governance
-- decision. This is that decision, and it is derived rather than invented: two
-- independent sources in this repository already say who may mutate, and they
-- agree exactly.
--
--   Cerbos (policies/resource/*.yaml), parsed for actions in
--   {*, create, update, delete, assert}:
--
--     ciso                evidence_record:*, incident:*, threat_entity:*,
--                         identity_attribution:assert
--     soc_analyst         incident:update
--     compliance_officer  none
--     it_operations       none
--     dpo                 none
--     external_auditor    none
--     ai_agent            none
--
--   docs/architecture/authorization-model.md, "Seven-role hierarchy":
--
--     ciso                "Full operational oversight"
--     soc_analyst         "Threat investigation and response"
--     compliance_officer  "Audit, compliance mapping, evidence review"
--     it_operations       "Infrastructure monitoring and alerting"
--     dpo                 "Data protection duties, pseudonymisation oversight"
--     external_auditor    "Third-party audit with read-only, scoped access"
--     ai_agent            "Automated analysis via MCP, bounded scope"
--
-- Every role Cerbos grants no mutating action is described in prose as review,
-- oversight, monitoring, audit or analysis. `external_auditor` is documented as
-- "read-only" in as many words. So the split below is what the repository
-- already asserts; until now it asserted it only where a policy engine or a
-- reader would look, and never where the database would enforce it.
--
-- ---------------------------------------------------------------------------
-- What this changes in practice
-- ---------------------------------------------------------------------------
--
-- A request from one of the five read-only clearances can no longer write,
-- whatever the RLS policies say and whatever a future policy bug allows. That
-- is the point: 028's write policies are predicates, and a predicate that is
-- wrong is a hole. A missing GRANT is not.
--
-- ai_agent deserves calling out because it is the one that will surprise. The
-- AI memory layer (023) is the only graph-write path reachable through the
-- request pool, and an agent writing memory as `ai_agent` will now get
-- `permission denied`. That is deliberate. Cerbos grants ai_agent no mutating
-- action on any resource, the memory tools do not consult Cerbos at all, and
-- 023 attributes memory writes to "application writers" rather than to a role.
-- If a deployment does want agents writing Layer 5, the fix is a Cerbos policy
-- for the memory resource that says so -- making the decision explicit and
-- reviewable -- plus a grant here. Not a silent exception in this file, which
-- would put the engine and the authorization model back out of step.
--
-- ---------------------------------------------------------------------------
-- What is deliberately kept
-- ---------------------------------------------------------------------------
--
--   * SELECT everywhere. These roles read; RLS decides which rows.
--   * INSERT on audit_log. Every audited tool writes an entry, so revoking it
--     would fail every call by a read-only caller rather than only its writes.
--     UPDATE and DELETE stay revoked (038, 040), so the log is still
--     append-only for them.
--   * Sequence USAGE, which the audit_log bigserial needs.
--   * Function EXECUTE. Functions here are SECURITY INVOKER, so one that writes
--     still fails on the table grant; revoking EXECUTE would break reads.
--
-- Idempotent.

-- ---------------------------------------------------------------------------
-- 1. Revoke the write surface
-- ---------------------------------------------------------------------------

do $$
declare
    r   text;
    sch text;
begin
    foreach r in array array['cg_compliance_officer', 'cg_it_operations', 'cg_dpo',
                             'cg_external_auditor', 'cg_ai_agent'] loop
        if not exists (select 1 from pg_roles where rolname = r) then
            continue;
        end if;

        foreach sch in array array['public', 'ag_catalog', 'core_graph'] loop
            if not exists (select 1 from pg_namespace where nspname = sch) then
                continue;
            end if;

            execute format(
                'revoke insert, update, delete on all tables in schema %I from %I', sch, r
            );

            -- The half that is easy to forget and silently undoes the other.
            -- 040 set default privileges granting write on tables created
            -- later; leaving them in place would re-widen these roles the next
            -- time a migration adds a table, with nothing to notice it.
            execute format(
                'alter default privileges in schema %I '
                'revoke insert, update, delete on tables from %I', sch, r
            );
        end loop;
    end loop;
end $$;

-- ---------------------------------------------------------------------------
-- 2. Give back the one write every caller needs
-- ---------------------------------------------------------------------------

-- Ordered after the revoke, not merged into it: the blanket revoke above is
-- what makes this exception visible as an exception.
do $$
declare
    r text;
begin
    if to_regclass('audit_log') is null then
        return;
    end if;

    foreach r in array array['cg_compliance_officer', 'cg_it_operations', 'cg_dpo',
                             'cg_external_auditor', 'cg_ai_agent'] loop
        if exists (select 1 from pg_roles where rolname = r) then
            execute format('grant insert on audit_log to %I', r);
        end if;
    end loop;
end $$;

-- ---------------------------------------------------------------------------
-- 3. A view so the split is inspectable rather than inferred
-- ---------------------------------------------------------------------------

-- Whether a clearance can write is now a property of the database, and an
-- auditor should be able to read it off without reconstructing this file.
create or replace view cg_clearance_write_surface as
select r.rolname                                            as clearance,
       count(*) filter (where p.privilege_type = 'INSERT')  as tables_insertable,
       count(*) filter (where p.privilege_type = 'UPDATE')  as tables_updatable,
       count(*) filter (where p.privilege_type = 'DELETE')  as tables_deletable
  from pg_roles r
  left join information_schema.table_privileges p
         on p.grantee = r.rolname
        and p.table_schema in ('public', 'ag_catalog', 'core_graph')
 where r.rolname like 'cg\_%'
 group by r.rolname;

comment on view cg_clearance_write_surface is
    'Per clearance role: how many tables it may INSERT, UPDATE or DELETE across '
    'the three application schemas. The read-only clearances from migration 041 '
    'show 1 insertable table (audit_log, which is append-only for them) and zero '
    'updatable or deletable.';
