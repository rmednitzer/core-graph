-- 016_merkle_scheduled_job.sql
-- Replace the audit-merkle-root cron job with proper Merkle tree computation.
-- Computes a binary Merkle tree over entry_hash values and stores the root
-- in audit_merkle_roots. Idempotent.

-- Remove the old simple hash concatenation job from 012.
select cron.unschedule('audit-merkle-root');

-- Proper Merkle root computation function.
-- Recursively pairs and hashes until one root remains.
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
begin
    -- Determine batch range: from last batch_end + 1, or all entries.
    select batch_end into v_batch_start
    from audit_merkle_roots
    order by id desc
    limit 1;

    if v_batch_start is null then
        v_batch_start := 0;
    else
        v_batch_start := v_batch_start + 1;
    end if;

    -- Collect entry hashes for this batch.
    select array_agg(entry_hash order by id), max(id), count(*)
    into v_layer, v_batch_end, v_count
    from audit_log
    where id >= v_batch_start;

    -- Nothing to process.
    if v_count is null or v_count = 0 then
        return;
    end if;

    -- Binary Merkle tree: pair and hash until one root remains.
    while array_length(v_layer, 1) > 1 loop
        -- Pad odd layers by duplicating last element.
        if array_length(v_layer, 1) % 2 = 1 then
            v_layer := v_layer || v_layer[array_length(v_layer, 1)];
        end if;

        v_next_layer := '{}';
        v_i := 1;
        while v_i <= array_length(v_layer, 1) loop
            v_next_layer := v_next_layer ||
                encode(digest(v_layer[v_i] || v_layer[v_i + 1], 'sha256'), 'hex');
            v_i := v_i + 2;
        end loop;

        v_layer := v_next_layer;
    end loop;

    v_root := v_layer[1];

    -- Store the computed root.
    insert into audit_merkle_roots (batch_start, batch_end, root_hash, entry_count)
    values (v_batch_start, v_batch_end, v_root, v_count);
end;
$$;

-- Schedule every 6 hours (same cadence as the original job).
select cron.schedule(
    'audit-merkle-root',
    '0 */6 * * *',
    $$ select compute_audit_merkle_root() $$
);
