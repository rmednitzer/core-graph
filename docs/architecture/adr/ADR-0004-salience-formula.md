# ADR-0004: AI memory salience formula

## Status

Accepted (Phase 3, v1.x).

## Context

The Layer-5 episodic memory needs a single per-Episode score that ranks
"this is worth retrieving right now". The score must combine:

* **Recency** — older Episodes are usually less relevant.
* **Access** — Episodes the agent has touched recently are more relevant
  in the current arc of work.
* **Relevance** — semantic proximity to the current session anchor (the
  embedding of the most recent N Episodes or a per-session pinned
  embedding).

Pure recency loses long-tail facts; pure cosine similarity misses what
the agent literally just discussed; pure access frequency drowns out
new information.

## Decision

```
salience = recency_weight  * exp(-decay * age_seconds)
         + access_weight   * log(1 + access_count)
         + relevance_weight * cosine_sim_to_session_anchor
```

Defaults (also exposed as `CG_SALIENCE_*` env vars):

| Term | Constant | Default |
|------|----------|---------|
| recency_weight | `SALIENCE_RECENCY_WEIGHT` | 0.5 |
| access_weight  | `SALIENCE_ACCESS_WEIGHT`  | 0.2 |
| relevance_weight | `SALIENCE_RELEVANCE_WEIGHT` | 0.3 |
| decay | `SALIENCE_DECAY` | `1/86400` (1-day half-life) |

The score is materialised in `memory_episode_salience` and refreshed by
the pg_cron job `memory-salience-recompute` every 5 minutes. Recall-time
ranking combines hybrid retrieval score with materialised salience as
`0.7 * hybrid + 0.3 * salience`.

## Why exp-decay on recency

Linear decay yields a hard cliff and either over-weighs old episodes or
discards them too aggressively. Exponential decay with a 1-day half-life
matches typical analyst recall horizons (the conversation from "this
morning" is more relevant than "last Wednesday") and is symmetric to
standard memory-decay literature.

## Why log on access count

Access frequency follows a Zipfian distribution — a handful of Episodes
get hammered, most are touched once or twice. Linear access weight would
let a single hot Episode dominate forever. `log(1 + n)` keeps the access
boost meaningful for a handful of accesses without runaway dominance.

## Why cosine for relevance

Cosine is the existing pgvector default and is bounded `[-1, 1]`, which
keeps the term well-behaved at small weight. The session anchor is the
mean embedding of the last 5 episodes or a pinned anchor.

## Materialisation strategy

The salience score is recomputed every 5 minutes by pg_cron. This is
"good enough" for hot recall paths because:

* The recency term changes continuously but slowly.
* The access term changes step-wise per recall and is bumped
  immediately by `tool_recall` (the cron job recomputes shortly after).
* The relevance term changes when new Episodes are added; defaulting it
  to 0 in the cron job keeps the cron lightweight, while
  `tool_session_start` and `tool_recall` use the session anchor live
  for the relevance term.

If real-time relevance is needed (e.g. very chatty agents) the cron
period can be shortened or the score can be computed per-recall on the
fly using the materialised access/recency terms plus an in-call cosine.

## Consequences

* `memory_episode_salience` adds one row per Episode (~ a few dozen
  bytes). Acceptable for the Layer-5 footprint.
* The cron job touches every salience row every 5 minutes — O(N) per
  refresh. For a 1M-Episode corpus this is ~100 ms per run on a warm
  cache; if it ever becomes the bottleneck, partition on
  `last_episode_at` so we only refresh recent sessions.
* The relevance term is currently 0 in the cron-computed materialisation;
  recall-time ranking re-blends with hybrid score so this is not a
  correctness issue, but it does mean the materialised value is a lower
  bound.

## Alternatives considered

* **No materialisation, compute on every recall** — rejected for cost
  on very chatty agents; one cron tick is amortised.
* **Per-session formula tuning** — premature; ship the global default,
  add per-session overrides if a real workload needs them.
* **Reciprocal-rank-weighted access** — possible future refinement,
  rejected for v1.x simplicity.

## References

* `schema/migrations/023_memory_layer.sql`
* `api/config.py` (CG_SALIENCE_* env vars)
* `api/mcp/tools/memory_recall.py`
