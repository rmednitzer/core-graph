# Runbook: RLS Misconfiguration

## Symptoms

- Users report seeing data above their TLP clearance level
- Users report missing data they should be able to access
- Cerbos policy test failures in CI
- Audit log shows access patterns inconsistent with role assignments

## Diagnostic Queries

### 1. Check current RLS policies

```sql
select schemaname, tablename, policyname, permissive, roles, cmd, qual
from pg_policies
order by tablename, policyname;
```

### 2. Verify session variables

```sql
-- Check what the application sets for a given role
select current_setting('app.max_tlp', true) as max_tlp,
       current_setting('app.allowed_compartments', true) as compartments;
```

### 3. Test with SET ROLE

```sql
-- Simulate a specific user's access
begin;
set local role cg_reader;
select set_config('app.max_tlp', '1', true);  -- GREEN only
select count(*) from threat_entities;  -- Should only return TLP <= 1
rollback;
```

### 4. Check user_clearances seed data

```sql
select * from user_clearances order by max_tlp desc;
```

Verify values match the documented role hierarchy in
`docs/architecture/authorization-model.md`.

### 5. Check for policy gaps

```sql
-- Tables without RLS enabled
select schemaname, tablename
from pg_tables
where schemaname = 'public'
  and tablename not in (
    select tablename from pg_policies where schemaname = 'public'
  );
```

## Immediate Containment

If users are seeing data above their clearance:

```sql
-- Temporarily restrict the affected role (emergency only)
revoke select on threat_entities from cg_reader;
```

Document the revocation in the audit log and notify the incident response
team.

## Root Cause Analysis

1. **Policy predicate error**: The RLS policy `qual` expression may have
   a logic error (e.g., `>=` instead of `<=` for TLP comparison)
2. **Missing session variable**: The application may not be setting
   `app.max_tlp` before queries execute
3. **Seed data mismatch**: `user_clearances` values may not match the
   authorization model document
4. **New table without RLS**: A migration added a table with sensitive
   data but did not enable RLS

## Recovery and Verification

1. Fix the identified root cause (migration, seed data, or application code)
2. Run the RLS enforcement test suite:

```bash
psql -f tests/rls/test_tlp_enforcement.sql
```

1. Run the Cerbos policy tests:

```bash
cerbos compile --tests=tests/auth policies/
```

1. Verify with manual spot checks at each TLP level:

```sql
begin;
select set_config('app.max_tlp', '0', true);
select count(*) from threat_entities;  -- Should be minimal
rollback;

begin;
select set_config('app.max_tlp', '4', true);
select count(*) from threat_entities;  -- Should be all
rollback;
```

## Post-Incident Documentation

File an incident report covering:

- Timeline of the misconfiguration (when introduced, when detected)
- Scope of exposure (which data, which users)
- Root cause and fix applied
- Preventive measures (additional test cases, CI checks)

If PII was exposed to unauthorized users, follow the GDPR Art. 33
notification procedure (72-hour window) and the NIS2 Art. 23 timeline.
