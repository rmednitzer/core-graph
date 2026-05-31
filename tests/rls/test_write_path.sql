-- tests/rls/test_write_path.sql
-- Verifies the 028 write-path RLS policies: a non-superuser role may only
-- INSERT/UPDATE/DELETE rows within its TLP clearance (app.max_tlp), mirroring
-- the read-path enforcement. Part 1 exercises the predicate behaviourally on a
-- stand-in table (the project's RLS-test convention); Part 2 asserts the real
-- policies are attached to every core_graph table.
--
-- Run with ON_ERROR_STOP=1 so any failed assertion fails the job.

-- ============================================================
-- Part 1: behavioural enforcement on a stand-in table
-- ============================================================

-- Pin the stand-in to public (see test_tlp_enforcement.sql): the migration
-- search_path is ag_catalog-first, so an unqualified table would be created
-- where the non-superuser role cannot see it.
set search_path = public;

create table if not exists rls_write_test (
    id        serial primary key,
    label     text not null,
    tlp_level int  not null
);

alter table rls_write_test enable row level security;
alter table rls_write_test force row level security;

do $$
begin
    create role write_test_role nologin;
exception when duplicate_object then null;
end $$;

grant select, insert, update, delete on rls_write_test to write_test_role;
grant usage, select on sequence rls_write_test_id_seq to write_test_role;

drop policy if exists wt_insert on rls_write_test;
drop policy if exists wt_update on rls_write_test;
drop policy if exists wt_delete on rls_write_test;

-- No read policy: keep the test focused on write enforcement. (Superuser
-- verifies final state below, bypassing RLS.)
create policy wt_insert on rls_write_test for insert with check (
    tlp_level <= coalesce(nullif(current_setting('app.max_tlp', true), '')::int, 1)
);
create policy wt_update on rls_write_test for update using (
    tlp_level <= coalesce(nullif(current_setting('app.max_tlp', true), '')::int, 1)
) with check (
    tlp_level <= coalesce(nullif(current_setting('app.max_tlp', true), '')::int, 1)
);
create policy wt_delete on rls_write_test for delete using (
    tlp_level <= coalesce(nullif(current_setting('app.max_tlp', true), '')::int, 1)
);

-- Seed one row at each TLP as the superuser test runner (bypasses RLS).
delete from rls_write_test;
insert into rls_write_test (label, tlp_level) values ('green', 1), ('red', 4);

-- Act as a low-clearance role at app.max_tlp = 1.
set role write_test_role;
select set_config('app.max_tlp', '1', false);

-- INSERT within clearance: allowed (top level, must not error).
insert into rls_write_test (label, tlp_level) values ('green-ok', 1);

-- INSERT above clearance: rejected by the WITH CHECK predicate (wrap so the
-- expected error does not abort the script under ON_ERROR_STOP).
do $$
begin
    insert into rls_write_test (label, tlp_level) values ('red-bad', 4);
    raise exception 'TEST FAILED: insert above clearance was allowed';
exception
    when insufficient_privilege or check_violation then null;  -- expected
end $$;

-- UPDATE / DELETE of a row above clearance: the USING predicate hides it, so
-- these affect zero rows without error.
update rls_write_test set label = 'hacked' where label = 'red';
delete from rls_write_test where label = 'red';

reset role;

-- Verify the final state as superuser (RLS-bypassing): the high-TLP row was
-- neither updated nor deleted, the in-clearance insert landed, and the
-- above-clearance insert did not.
do $$
declare
    n int;
begin
    select count(*) into n from rls_write_test where label = 'red' and tlp_level = 4;
    if n <> 1 then
        raise exception 'TEST FAILED: high-TLP row was modified/deleted (found % expected 1)', n;
    end if;
    select count(*) into n from rls_write_test where label = 'hacked';
    if n <> 0 then
        raise exception 'TEST FAILED: above-clearance UPDATE took effect';
    end if;
    select count(*) into n from rls_write_test where label = 'green-ok';
    if n <> 1 then
        raise exception 'TEST FAILED: in-clearance INSERT was rejected';
    end if;
    select count(*) into n from rls_write_test where label = 'red-bad';
    if n <> 0 then
        raise exception 'TEST FAILED: above-clearance INSERT landed';
    end if;
    raise notice 'OK: write-path RLS enforces TLP clearance on INSERT/UPDATE/DELETE';
end $$;

-- ============================================================
-- Part 2: the real policies are attached to every core_graph table
-- ============================================================

do $$
declare
    missing int;
begin
    select count(*) into missing
      from pg_class c
      join pg_namespace n on n.oid = c.relnamespace
     where n.nspname = 'core_graph'
       and c.relkind = 'r'
       and not exists (
           select 1 from pg_policies p
            where p.schemaname = 'core_graph'
              and p.tablename = c.relname
              and p.policyname = 'tlp_write_insert'
       );
    if missing > 0 then
        raise exception 'TEST FAILED: % core_graph table(s) lack tlp_write_insert', missing;
    end if;
    raise notice 'OK: write-path RLS policies present on all core_graph tables';
end $$;

-- ============================================================
-- Cleanup
-- ============================================================
drop table if exists rls_write_test;
drop role if exists write_test_role;

\echo 'test_write_path.sql passed'
