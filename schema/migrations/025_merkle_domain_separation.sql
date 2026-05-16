-- 025_merkle_domain_separation.sql
-- Fix the second-preimage / forgery weakness (CVE-2012-2459 class) in the
-- audit Merkle tree.
--
-- 016's compute_audit_merkle_root() hashed `left || right` with no
-- domain separation between leaves and internal nodes, and padded odd
-- layers by duplicating the last node. Both flaws let two distinct audit
-- row sets yield the same root (e.g. leaves [a,b,c] collide with
-- [a,b,c,c]; a leaf equal to an internal digest can be presented as the
-- other in an inclusion proof). For court-admissible evidence this breaks
-- the "this exact set of audit rows" guarantee.
--
-- RFC 6962-style fix, mirrored byte-for-byte in evidence/chain/merkle.py:
--   leaf     = SHA256(0x00 || raw(entry_hash))
--   internal = SHA256(0x01 || raw(left) || raw(right))
--   odd node = promoted unchanged (no duplication)
--
-- This changes computed root values. Intentional and safe pre-production:
-- the old roots were cryptographically unsound. Roots are recomputed by
-- the existing pg_cron schedule (unchanged here); re-baseline after apply.
--
-- Idempotent: CREATE OR REPLACE only (the schedule from 016 still targets
-- this function name and is left intact).

create or replace function compute_audit_merkle_root()
returns void
language plpgsql
as $$
declare
    v_batch_start bigint;
    v_batch_end   bigint;
    v_count       int;
    v_root        text;
    v_layer       text[];
    v_next_layer  text[];
    v_i           int;
    v_n           int;
begin
    select batch_end into v_batch_start
    from audit_merkle_roots
    order by id desc
    limit 1;

    if v_batch_start is null then
        v_batch_start := 0;
    else
        v_batch_start := v_batch_start + 1;
    end if;

    -- Domain-separated leaves: SHA256(0x00 || raw(entry_hash)).
    select array_agg(
               encode(
                   digest(E'\\x00'::bytea || decode(entry_hash, 'hex'), 'sha256'),
                   'hex'
               )
               order by id
           ),
           max(id),
           count(*)
      into v_layer, v_batch_end, v_count
      from audit_log
     where id >= v_batch_start;

    if v_count is null or v_count = 0 then
        return;
    end if;

    while array_length(v_layer, 1) > 1 loop
        v_next_layer := '{}';
        v_i := 1;
        v_n := array_length(v_layer, 1);
        while v_i <= v_n loop
            if v_i < v_n then
                -- Internal node: SHA256(0x01 || raw(left) || raw(right)).
                v_next_layer := v_next_layer || encode(
                    digest(
                        E'\\x01'::bytea
                        || decode(v_layer[v_i], 'hex')
                        || decode(v_layer[v_i + 1], 'hex'),
                        'sha256'
                    ),
                    'hex'
                );
                v_i := v_i + 2;
            else
                -- Lone (odd) node: promote unchanged, do not duplicate.
                v_next_layer := v_next_layer || v_layer[v_i];
                v_i := v_i + 1;
            end if;
        end loop;
        v_layer := v_next_layer;
    end loop;

    v_root := v_layer[1];

    insert into audit_merkle_roots (batch_start, batch_end, root_hash, entry_count)
    values (v_batch_start, v_batch_end, v_root, v_count);
end;
$$;
