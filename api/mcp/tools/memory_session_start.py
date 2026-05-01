"""api.mcp.tools.memory_session_start — Build initial session context.

Returns the most-salient recent Episodes, the active (non-superseded)
ExtractedFacts, and the most-mentioned ConceptEntities for the session.
This is the canonical "warm-up" call an agent makes at the start of a
turn so it can answer with prior context already in scope.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

from api.config import DEFAULT_TLP
from api.db import get_connection

logger = logging.getLogger(__name__)


@dataclass
class SessionContext:
    session_id: str
    started_at: str | None
    last_episode_at: str | None
    recent_episodes: list[dict[str, Any]] = field(default_factory=list)
    active_facts: list[dict[str, Any]] = field(default_factory=list)
    top_entities: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "started_at": self.started_at,
            "last_episode_at": self.last_episode_at,
            "recent_episodes": self.recent_episodes,
            "active_facts": self.active_facts,
            "top_entities": self.top_entities,
        }


async def tool_session_start(
    session_id: str,
    *,
    recent_n: int = 10,
    active_facts_n: int = 20,
    top_entities_n: int = 10,
    caller_identity: dict[str, Any] | None = None,
) -> SessionContext:
    """Return a snapshot of the session's current memory."""
    if not session_id:
        raise ValueError("session_id is required")

    caller = caller_identity or {"max_tlp": DEFAULT_TLP, "allowed_compartments": []}
    correlation_id = uuid.uuid4()

    async with get_connection(caller) as conn:
        counter_cur = await conn.execute(
            "select started_at, last_episode_at from memory_session_counters where session_id = %s",
            (session_id,),
        )
        counter = await counter_cur.fetchone()

        recent_cur = await conn.execute(
            """
            select episode_graph_id, salience, access_count, last_accessed_at
              from memory_episode_salience
             where session_id = %s
             order by salience desc
             limit %s
            """,
            (session_id, recent_n),
        )
        salience_rows = await recent_cur.fetchall()
        salient_ids = [int(r["episode_graph_id"]) for r in salience_rows]
        salience_by_id = {int(r["episode_graph_id"]): float(r["salience"]) for r in salience_rows}

        episode_payloads: list[dict[str, Any]] = []
        if salient_ids:
            cur = await conn.execute(
                """
                select * from ag_catalog.cypher('core_graph', $cypher$
                    match (e:Episode {session_id: $session_id})
                    where id(e) in $ids
                    return id(e) as id, e.sequence_no as seq,
                           e.content as content, e.source_kind as source_kind,
                           e.t_recorded as t_recorded
                $cypher$, %s) as (row agtype)
                """,
                (json.dumps({"session_id": session_id, "ids": salient_ids}),),
            )
            rows = await cur.fetchall()
            for r in rows:
                payload = r["row"]
                if isinstance(payload, dict):
                    gid = int(str(payload.get("id", "")).strip('"'))
                    episode_payloads.append(
                        {
                            "graph_id": gid,
                            "sequence_no": int(payload.get("seq") or 0),
                            "content": payload.get("content"),
                            "source_kind": payload.get("source_kind"),
                            "t_recorded": payload.get("t_recorded"),
                            "salience": salience_by_id.get(gid, 0.0),
                        }
                    )
            episode_payloads.sort(key=lambda r: r["salience"], reverse=True)

        active_cur = await conn.execute(
            """
            select i.fact_graph_id, i.subject_hash, i.predicate_hash, i.t_recorded
              from memory_extracted_fact_index i
              where i.t_superseded is null
                and exists (
                    select 1 from ag_catalog._ag_label_vertex v
                     where v.id = i.fact_graph_id
                )
              order by i.t_recorded desc
              limit %s
            """,
            (active_facts_n,),
        )
        active_rows = await active_cur.fetchall()
        active_facts = [
            {
                "fact_graph_id": int(r["fact_graph_id"]),
                "subject_hash": r["subject_hash"],
                "predicate_hash": r["predicate_hash"],
                "t_recorded": r["t_recorded"].isoformat() if r["t_recorded"] else None,
            }
            for r in active_rows
        ]

        entities: list[dict[str, Any]] = []
        cur = await conn.execute(
            """
            select * from ag_catalog.cypher('core_graph', $cypher$
                match (e:Episode {session_id: $session_id})-[:mentions]->(c:ConceptEntity)
                return c.canonical_key as ckey, c.entity_type as entity_type,
                       c.value as value, count(e) as mention_count
                order by mention_count desc
                limit $limit
            $cypher$, %s) as (row agtype)
            """,
            (json.dumps({"session_id": session_id, "limit": top_entities_n}),),
        )
        rows = await cur.fetchall()
        for r in rows:
            payload = r["row"]
            if isinstance(payload, dict):
                entities.append(
                    {
                        "canonical_key": payload.get("ckey"),
                        "entity_type": payload.get("entity_type"),
                        "value": payload.get("value"),
                        "mention_count": int(payload.get("mention_count") or 0),
                    }
                )

        await conn.execute(
            """
            insert into audit_log
                (entity_label, operation, actor, correlation_id)
            values (%s, %s, %s, %s)
            """,
            (
                "Session",
                "MEMORY_SESSION_START",
                caller.get("actor", "mcp"),
                correlation_id,
            ),
        )
        await conn.commit()

    ctx = SessionContext(
        session_id=session_id,
        started_at=counter["started_at"].isoformat() if counter and counter["started_at"] else None,
        last_episode_at=counter["last_episode_at"].isoformat()
        if counter and counter["last_episode_at"]
        else None,
        recent_episodes=episode_payloads,
        active_facts=active_facts,
        top_entities=entities,
    )

    logger.info(
        "session_start: session=%s episodes=%d facts=%d entities=%d correlation=%s",
        session_id,
        len(episode_payloads),
        len(active_facts),
        len(entities),
        correlation_id,
    )
    return ctx
