"""api.mcp.tools.memory_remember — Append an Episode to a Session.

`tool_remember(session_id, content, source_kind)`:
  1. Allocates the next sequence_no via memory_next_sequence (atomic).
  2. MERGEs / CREATEs the Session vertex if needed.
  3. CREATEs an Episode vertex with bitemporal + TLP properties.
  4. Connects Session and Episode via belongs_to.
  5. Extracts IOCs via tier1_regex; for each, MERGEs a ConceptEntity
     vertex and creates a mentions edge.
  6. Inserts an audit_log row.

The Episode's `content` field is stored verbatim (post-RLS/TLP filter at
read time). Embedding generation is asynchronous: the writer enqueues a
later embedding pass via the existing pipeline.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from api.authz.cerbos import require_caller_action
from api.config import DEFAULT_TLP
from api.db import get_connection
from api.utils.edge_tlp import resync_vertex_edges
from ingest.canonical import canonical_key
from ingest.ner.tier1_regex import extract_iocs

logger = logging.getLogger(__name__)


@dataclass
class Episode:
    graph_id: int
    session_id: str
    sequence_no: int
    content: str
    source_kind: str
    t_recorded: str
    tlp_level: int


def _hash_string(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


async def tool_remember(
    session_id: str,
    content: str,
    source_kind: str = "user",
    *,
    tlp_level: int | None = None,
    caller_identity: dict[str, Any] | None = None,
) -> Episode:
    """Append an Episode and its derived ConceptEntity mentions.

    Args:
        session_id: Stable session identifier (string).
        content: Episode text. Stored verbatim.
        source_kind: 'user', 'agent', 'system', 'tool', etc.
        tlp_level: Override default TLP. Defaults to DEFAULT_TLP.
        caller_identity: MCP session context.

    Returns:
        Episode dataclass with graph_id and sequence_no.
    """
    if not session_id or not content:
        raise ValueError("session_id and content are required")

    caller = caller_identity or {"max_tlp": DEFAULT_TLP, "allowed_compartments": []}
    tlp = int(tlp_level if tlp_level is not None else DEFAULT_TLP)
    if tlp < 0 or tlp > 4:
        raise ValueError(f"tlp_level must be 0..4, got {tlp}")

    # ADR-0018. Checked before anything is written, and before the connection is
    # acquired: a denial should cost a policy round-trip, not a pooled
    # connection and a half-built episode.
    await require_caller_action(
        caller_identity,
        resource_kind="memory",
        resource_id=session_id,
        action="create",
        resource_attrs={"session_id": session_id, "tlp_level": tlp},
    )

    correlation_id = uuid.uuid4()
    now_iso = datetime.now(UTC).isoformat()

    async with get_connection(caller) as conn:
        seq_cursor = await conn.execute("select memory_next_sequence(%s) as seq", (session_id,))
        seq_row = await seq_cursor.fetchone()
        sequence_no = int(seq_row["seq"])

        # MERGE Session, then CREATE Episode and BELONGS_TO edge.
        merge_session_sql = """
            select * from ag_catalog.cypher('core_graph', $cypher$
                merge (s:Session {session_id: $session_id})
                set s.t_valid = coalesce(s.t_valid, $now),
                    s.t_recorded = coalesce(s.t_recorded, $now),
                    s.tlp_level = coalesce(s.tlp_level, $tlp)
                return id(s)
            $cypher$, %s) as (id agtype)
        """
        cur = await conn.execute(
            merge_session_sql,
            (json.dumps({"session_id": session_id, "now": now_iso, "tlp": tlp}),),
        )
        # Drain the cursor; the Session graph_id is implicit via the
        # subsequent MATCH (s:Session {session_id: ...}).
        await cur.fetchone()

        # CREATE Episode + edge atomically. Sequence is unique by construction
        # because memory_next_sequence allocates atomically.
        episode_sql = """
            select * from ag_catalog.cypher('core_graph', $cypher$
                match (s:Session {session_id: $session_id})
                create (e:Episode {
                    session_id: $session_id,
                    sequence_no: $sequence_no,
                    content: $content,
                    source_kind: $source_kind,
                    t_valid: $now,
                    t_recorded: $now,
                    tlp_level: $tlp
                })
                create (e)-[:belongs_to]->(s)
                return id(e)
            $cypher$, %s) as (id agtype)
        """
        cur = await conn.execute(
            episode_sql,
            (
                json.dumps(
                    {
                        "session_id": session_id,
                        "sequence_no": sequence_no,
                        "content": content,
                        "source_kind": source_kind,
                        "now": now_iso,
                        "tlp": tlp,
                    }
                ),
            ),
        )
        episode_row = await cur.fetchone()
        episode_graph_id = int(str(episode_row["id"]).strip('"'))

        # Initialise the salience materialisation row (zero score, score
        # is recomputed by the cron job).
        await conn.execute(
            """
            insert into memory_episode_salience
                (episode_graph_id, session_id, salience, access_count, last_accessed_at)
            values (%s, %s, 0.0, 0, null)
            on conflict (episode_graph_id) do nothing
            """,
            (episode_graph_id, session_id),
        )

        # NER pass: each IOC becomes a ConceptEntity + a MENTIONS edge.
        iocs = extract_iocs(content)
        for ioc in iocs:
            ckey = canonical_key(ioc["type"], ioc["value"])
            await conn.execute(
                """
                select * from ag_catalog.cypher('core_graph', $cypher$
                    merge (c:ConceptEntity {canonical_key: $ckey})
                    set c.entity_type = coalesce(c.entity_type, $entity_type),
                        c.value = coalesce(c.value, $value),
                        c.t_valid = coalesce(c.t_valid, $now),
                        c.t_recorded = coalesce(c.t_recorded, $now),
                        c.tlp_level = coalesce(c.tlp_level, $tlp)
                    with c
                    match (e:Episode) where id(e) = $episode_id
                    merge (e)-[m:mentions]->(c)
                    set m.t_recorded = coalesce(m.t_recorded, $now),
                        m.tlp_level = coalesce(m.tlp_level, $tlp)
                    return id(c)
                $cypher$, %s) as (id agtype)
                """,
                (
                    json.dumps(
                        {
                            "ckey": ckey,
                            "entity_type": ioc["type"],
                            "value": ioc["value"],
                            "now": now_iso,
                            "tlp": tlp,
                            "episode_id": episode_graph_id,
                        }
                    ),
                ),
            )

        # AGE does not fire trg_edge_tlp_sync for the Cypher writes above, so the
        # mentions edges' denormalized tlp_level column would stay 0. Re-derive
        # every edge incident to the new Episode (belongs_to has no such column
        # and is skipped by the helper; mentions edges are synced).
        await resync_vertex_edges(conn, episode_graph_id)

        await conn.execute(
            """
            insert into audit_log
                (entity_id, entity_label, operation, actor, correlation_id)
            values (%s, %s, %s, %s, %s)
            """,
            (
                episode_graph_id,
                "Episode",
                "MEMORY_REMEMBER",
                caller.get("actor", "mcp"),
                correlation_id,
            ),
        )
        await conn.commit()

    logger.info(
        "Episode appended: session=%s seq=%d graph_id=%d iocs=%d correlation=%s",
        session_id,
        sequence_no,
        episode_graph_id,
        len(iocs),
        correlation_id,
    )

    return Episode(
        graph_id=episode_graph_id,
        session_id=session_id,
        sequence_no=sequence_no,
        content=content,
        source_kind=source_kind,
        t_recorded=now_iso,
        tlp_level=tlp,
    )


def fact_subject_predicate_hash(subject: str, predicate: str) -> tuple[str, str]:
    """Convenience exposed for test isolation."""
    return _hash_string(subject), _hash_string(predicate)


async def tool_record_extracted_fact(
    session_id: str,
    episode_graph_id: int,
    subject: str,
    predicate: str,
    obj: str,
    *,
    tlp_level: int | None = None,
    caller_identity: dict[str, Any] | None = None,
) -> int:
    """Record an ExtractedFact (subject, predicate, object) and detect
    supersession against any active fact with the same (subject, predicate)
    but a different object.

    Returns the ExtractedFact graph_id.
    """
    caller = caller_identity or {"max_tlp": DEFAULT_TLP, "allowed_compartments": []}
    tlp = int(tlp_level if tlp_level is not None else DEFAULT_TLP)

    # `create` rather than `update`, even though the supersession trigger
    # updates the previous fact's row: what the caller is authorized to do is
    # record a fact. The update is the model's bookkeeping, not a second
    # operation the caller chose.
    await require_caller_action(
        caller_identity,
        resource_kind="memory",
        resource_id=session_id,
        action="create",
        resource_attrs={"session_id": session_id, "tlp_level": tlp},
    )

    now_iso = datetime.now(UTC).isoformat()

    subj_hash = _hash_string(subject)
    pred_hash = _hash_string(predicate)
    obj_hash = _hash_string(obj)

    async with get_connection(caller) as conn:
        # Look up any active fact for this (subject, predicate) before insert.
        prior_cur = await conn.execute(
            """
            select fact_graph_id, object_hash
              from memory_extracted_fact_index
             where subject_hash  = %s
               and predicate_hash = %s
               and t_superseded is null
             limit 1
            """,
            (subj_hash, pred_hash),
        )
        prior = await prior_cur.fetchone()

        # CREATE the new ExtractedFact vertex + EXTRACTED_FROM edge.
        sql = """
            select * from ag_catalog.cypher('core_graph', $cypher$
                match (e:Episode) where id(e) = $episode_id
                create (f:ExtractedFact {
                    subject: $subject,
                    predicate: $predicate,
                    object: $object,
                    t_valid: $now,
                    t_recorded: $now,
                    tlp_level: $tlp
                })
                create (f)-[:extracted_from]->(e)
                return id(f)
            $cypher$, %s) as (id agtype)
        """
        cur = await conn.execute(
            sql,
            (
                json.dumps(
                    {
                        "episode_id": episode_graph_id,
                        "subject": subject,
                        "predicate": predicate,
                        "object": obj,
                        "now": now_iso,
                        "tlp": tlp,
                    }
                ),
            ),
        )
        row = await cur.fetchone()
        fact_graph_id = int(str(row["id"]).strip('"'))

        # Insert into shadow index. The trigger marks any prior active fact
        # superseded; we then write the SUPERSEDES edge.
        await conn.execute(
            """
            insert into memory_extracted_fact_index
                (subject_hash, predicate_hash, fact_graph_id, object_hash)
            values (%s, %s, %s, %s)
            """,
            (subj_hash, pred_hash, fact_graph_id, obj_hash),
        )

        if prior is not None and prior["object_hash"] != obj_hash:
            prior_id = int(prior["fact_graph_id"])
            await conn.execute(
                """
                select * from ag_catalog.cypher('core_graph', $cypher$
                    match (new_f:ExtractedFact) where id(new_f) = $new_id
                    match (old_f:ExtractedFact) where id(old_f) = $old_id
                    create (new_f)-[s:supersedes]->(old_f)
                    set old_f.t_superseded = $now,
                        s.t_recorded = $now,
                        s.tlp_level  = $tlp
                    return id(s)
                $cypher$, %s) as (id agtype)
                """,
                (
                    json.dumps(
                        {
                            "new_id": fact_graph_id,
                            "old_id": prior_id,
                            "now": now_iso,
                            "tlp": tlp,
                        }
                    ),
                ),
            )

        # AGE does not fire trg_edge_tlp_sync for the Cypher edge writes above,
        # so the extracted_from (and any supersedes) edge tlp_level column would
        # stay 0. Re-derive every edge incident to the new fact vertex.
        await resync_vertex_edges(conn, fact_graph_id)

        await conn.commit()

    logger.info(
        "ExtractedFact recorded: session=%s episode=%d fact=%d superseded_prior=%s",
        session_id,
        episode_graph_id,
        fact_graph_id,
        prior is not None and prior["object_hash"] != obj_hash,
    )

    return fact_graph_id
