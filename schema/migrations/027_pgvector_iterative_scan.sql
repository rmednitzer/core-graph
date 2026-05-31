-- 027_pgvector_iterative_scan.sql
-- pgvector 0.8 modernisation — enable HNSW iterative index scans.
--
-- Why this matters for core-graph specifically:
--
-- Every vector query in this system runs UNDER Row-Level Security. RLS
-- predicates (TLP clearance, IAM AMBER floor, compartment filters) are
-- applied AFTER the HNSW index returns its candidate set. With a plain
-- (non-iterative) HNSW scan, the index hands back a fixed number of
-- candidates governed by hnsw.ef_search; if RLS then filters most of them
-- out, the query returns FEWER than the requested LIMIT — "overfiltering".
-- A caller asking for the 10 nearest neighbours they are cleared to see can
-- silently get 3, with no error, because the other 7 were pruned post-index.
--
-- pgvector 0.8 added iterative index scans precisely for this filtered-search
-- case: when the first batch is exhausted before LIMIT is satisfied, pgvector
-- transparently resumes the index scan for more candidates, up to a bounded
-- ceiling. See https://github.com/pgvector/pgvector#iterative-index-scans.
--
-- We choose strict_order (exact distance ordering preserved) over
-- relaxed_order because the pure vector_search tool returns rows ordered by
-- distance and this is an evidence-producing platform where result ordering
-- is part of the contract. Operators who favour throughput over strict
-- ordering for the hybrid (re-ranked) path can switch to relaxed_order.
--
-- max_scan_tuples bounds the worst case so a heavily-filtered query cannot
-- walk the entire index; 20000 is pgvector's own default and is kept explicit
-- here to document the latency ceiling.
--
-- halfvec storage (2-byte floats, the other headline pgvector 0.8 feature)
-- is already provisioned by 021_embedding_models_and_hybrid.sql via the
-- embeddings.embedding_half column and its partial HNSW index; this migration
-- does not revisit it.
--
-- Idempotent: ALTER DATABASE ... SET overwrites in place. The whole block is
-- guarded so that on a pgvector build older than 0.8 (where these GUCs do not
-- exist) the migration logs a NOTICE and still succeeds, never breaking the
-- migration chain.

do $$
begin
    execute format(
        'alter database %I set hnsw.iterative_scan = %L',
        current_database(), 'strict_order'
    );
    execute format(
        'alter database %I set hnsw.max_scan_tuples = %L',
        current_database(), '20000'
    );
    raise notice
        'pgvector 0.8 HNSW iterative scan enabled (strict_order) on database %',
        current_database();
exception
    when others then
        raise notice
            'Skipped hnsw.iterative_scan setup (pgvector < 0.8 or GUC unavailable): %',
            sqlerrm;
end $$;
