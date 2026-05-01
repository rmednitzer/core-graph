# ADR-0002: Hybrid retrieval algorithm (BM25 + vector with RRF)

## Status

Accepted (Phase 1, v1.x).

## Context

core-graph stores embeddings in pgvector (HNSW, cosine) alongside textual
content in the same table. Vector-only retrieval has well-known failure modes
on rare-token queries (e.g. CVE IDs, unique IOC values, exact STIX IDs) where
lexical match dominates semantic similarity. BM25-only retrieval, conversely,
loses to vectors on paraphrased queries common in analyst chat.

We need a single retrieval call that combines both signals safely under RLS,
without introducing a new index server (Elasticsearch) and without changing
the canonical store.

## Decision

Implement hybrid retrieval inside PostgreSQL using:

* **Lexical**: a tsvector column `content_tsv` populated by trigger from
  `content`, indexed with GIN; ranked via `ts_rank_cd`.
* **Vector**: existing `embedding vector(N)` HNSW index plus a sibling
  `embedding_half halfvec(N)` HNSW index for low-latency queries.
* **Fusion**: Reciprocal Rank Fusion (RRF) with the canonical
  Cormack/Clarke/Buettcher 2009 constant `k = 60`. Each constituent list is
  fetched at `k * 4` then truncated to the requested `k` after fusion.
* **Optional reranker**: a hook that POSTs candidate texts to
  `CG_RERANKER_URL`. When unset, RRF result is final. The hook is opt-in so
  we can ship hybrid retrieval without coupling to a model server.

## Why RRF, not weighted-sum / Borda / CombSUM

RRF is rank-only: it does not require the constituent scores to be
calibrated or comparable. ts_rank_cd is unbounded and corpus-dependent;
cosine distance is bounded but inversely related to relevance. Forcing
either onto a shared scale needs per-domain tuning.

RRF is also robust to one list being empty (e.g. the query has no lexical
match): the missing list contributes nothing and the other list dominates.

## Why pgvector halfvec

Halfvec stores 16-bit floats and roughly halves index memory at the cost of
~1-3% recall@10 in typical setups. We index both columns so the caller can
choose latency vs accuracy per query (`use_halfvec=True` on
`vector_search`). The Phase 5 eval harness produces the recall delta on the
golden set.

## Why per-model partial HNSW indexes

A single HNSW per table is opinionated about which model "wins" the
similarity comparison. With a partial index per model_id (`WHERE model_id =
'<m>'`), each model gets its own index that the planner picks when a query
constrains `model_id`. New models register via `cg_register_embedding_model`
which creates the index pair atomically.

Inactive models keep their indexes until explicitly dropped via the runbook —
this avoids the embarrassment of dropping an index just before a rollback.

## Consequences

* `embeddings` table grows by `dim * 2 bytes` per row (halfvec) plus a
  tsvector. On a 768-dim corpus of 1M rows: ~1.5 GB halfvec column + a few
  hundred MB tsvector + GIN.
* HNSW build time is per-model. Operators must size maintenance windows
  accordingly when registering new models.
* Hybrid_search's audit log entry replaces the previous vector_search-only
  entry on hybrid paths; auditors must consult both `vector_search` and
  `hybrid_search` operation kinds for retrieval activity.
* Reranker is out of scope for the canonical stack — it is consumed via env
  URL only.

## Alternatives considered

* **Weighted-sum fusion** — requires per-corpus calibration; rejected.
* **Single combined index (e.g. tsvector + vector)** — pgvector and tsvector
  use incompatible operators; rejected.
* **Move to OpenSearch for hybrid** — violates "PostgreSQL is the core".

## References

* Cormack, Clarke, Buettcher 2009 — *Reciprocal Rank Fusion outperforms
  Condorcet and individual Rank Learning Methods*.
* pgvector README — halfvec, ef_search, partial HNSW indexes.
