# Skill registry

## Concept

A skill is a named, versioned, composable MCP capability that combines one or
more Cypher query templates with result formatting, confidence tagging, and a
natural language description. Skills are what the AI agent calls. Query
templates are what skills use internally.

## Architecture

```
AI Agent
    │
    ▼
MCP Server (tool_execute_skill)
    │
    ▼
SkillRegistry.get_skill(name)
    │
    ▼
SkillBase.execute(params)
    │  calls cypher_query() one or more times
    ▼
SkillResult
    │  confidence, data, summary, gaps, sources
    ▼
AI Agent
```

## Implementing a new skill

1. Create a module in the appropriate domain subpackage under
   `api/mcp/skills/` (e.g., `api/mcp/skills/asset/my_skill.py`).

2. Create a class extending `SkillBase`:

```python
from api.mcp.skills.base import SkillBase, SkillResult
from api.mcp.tools.cypher_query import cypher_query

class MySkill(SkillBase):
    name = "my_skill"
    description = "What this skill does"
    version = "1.0.0"

    async def execute(self, params, caller_identity=None) -> SkillResult:
        rows = await cypher_query("my_template", params, caller_identity)
        return SkillResult(
            skill_name=self.name,
            confidence=1.0 if rows else 0.8,
            data=rows,
            summary=f"Found {len(rows)} result(s)",
            gaps=[] if rows else ["No data found"],
            sources=["layer_7_infrastructure"],
        )
```

3. The skill is auto-discovered at MCP server startup by the registry.

## Parameter schema format

Each Cypher template has a companion `.json` schema file:

```json
{
  "description": "What this query does",
  "parameters": {
    "param_name": {
      "type": "string",
      "required": true,
      "description": "What this parameter is"
    }
  },
  "returns": "list",
  "max_depth": 3,
  "estimated_ms": 150
}
```

## Confidence scoring convention

- Start at `1.0`
- Decrement by `0.1` for each empty sub-query result set
- Decrement by `0.1` for each stale evidence record
- Decrement by `0.2` if the primary entity is not found
- Never go below `0.0`

## Available skills

| Skill name                | Domain     | Description                                    |
| ------------------------- | ---------- | ---------------------------------------------- |
| `asset_full_summary`      | asset      | Complete asset profile across all domains       |
| `asset_compliance_status` | asset      | Compliance controls and evidence freshness      |
| `asset_vulnerabilities`   | asset      | CVEs affecting an asset                         |
| `asset_active_alerts`     | asset      | Firing alerts for an asset                      |
| `asset_security_events`   | asset      | Recent security events                          |
| `asset_topology`          | asset      | Infrastructure topology                         |
| `identity_access_map`     | identity   | Effective permissions (direct and inherited)    |
| `identity_audit_trail`    | identity   | Security events involving a principal           |
| `threat_actor_to_asset`   | threat     | Assets affected by a threat actor               |
| `alert_to_compliance_gap` | compliance | Compliance gaps created by an alert             |
