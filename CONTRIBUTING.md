# Contributing

## Code of conduct

This project follows a [Code of Conduct](CODE_OF_CONDUCT.md). By participating,
you are expected to uphold it.

## Development setup

### Prerequisites

- Python 3.12+
- Docker and Docker Compose
- `ruff` and `yamllint` (installed via `pip install -e ".[dev]"`)

### Getting started

```bash
# Clone and install
git clone https://github.com/rmednitzer/core-graph.git
cd core-graph
pip install -e ".[dev,test]"

# Start the local dev stack
make up

# Run migrations and seed data
make migrate
make seed

# Verify everything works
make test
```

### Local services

The dev stack (`make up`) starts:

| Service | Port | Purpose |
|---|---|---|
| PostgreSQL 16 (AGE + pgvector) | 5432 | Core database |
| NATS JetStream | 4222 | Message bus |
| Valkey | 6379 | Cache (session, rate limiting) |
| MinIO | 9000 | Evidence storage (WORM) |
| Prometheus | 9090 | Metrics collection |

### Running services locally

```bash
make serve          # REST API on :8000 (hot-reload)
make mcp            # MCP server
make graph-writer   # Ingest graph writer worker
make psql           # Interactive database shell
```

## Commits

This project uses [Conventional Commits](https://www.conventionalcommits.org/).

Scopes: `feat:`, `fix:`, `docs:`, `schema:`, `policy:`, `deploy:`, `test:`,
`skill:`

Examples:

- `schema: add bitemporal columns to threat_actor`
- `policy: restrict external_auditor to TLP:GREEN`
- `fix: parameterise Cypher query in entity_resolve`
- `skill: add asset_topology skill for network graph queries`

## Pull requests

- One concern per PR
- Smallest safe increment
- Schema changes require a new numbered migration file in `schema/migrations/`
- Policy changes require corresponding test updates in `tests/auth/`
- RLS changes require corresponding test updates in `tests/rls/`
- New ingest connectors must extend `AdapterBase` in `ingest/connectors/base.py`
- New MCP capabilities must be implemented as skills in `api/mcp/skills/`

## Testing

```bash
# Full test suite (unit + RLS enforcement)
make test

# Integration tests only (requires running Docker stack)
make integration-test

# Specific test file
pytest tests/skills/test_asset_skills.py -v

# Linting and validation
make lint
```

### Test organisation

| Directory | What it tests |
|---|---|
| `tests/schema/` | Migration numbering and SQL validity |
| `tests/rls/` | Row-Level Security enforcement (SQL-based) |
| `tests/auth/` | Cerbos policy decisions (YAML test cases) |
| `tests/ingest/` | Connector adapters, NER, entity resolution |
| `tests/integration/` | End-to-end flows (requires Docker stack) |
| `tests/skills/` | MCP skill registry and individual skills |
| `tests/taxii/` | TAXII 2.1 endpoint compliance |
| `tests/` (root) | Cypher safety, label validation, Merkle chain, DLQ |

### Writing tests

- Unit tests use `pytest` with `pytest-asyncio` for async code
- RLS tests are raw SQL files executed against the database
- Cerbos policy tests use the YAML test format in `tests/auth/`
- Integration tests are marked with `@pytest.mark.integration` and require
  the Docker stack running

## Code style

- **Python:** ruff for linting and formatting, type hints required, Python 3.12+
- **SQL:** lowercase keywords, 4-space indent, parameterised queries only
- **YAML:** 2-space indent
- **Markdown:** no trailing whitespace (except explicit line breaks)
- **Cypher:** query templates in `.cypher` files with companion `.json` parameter
  schemas. Labels validated via `validate_label()` before interpolation. No
  string concatenation.

## Security rules

- Never commit secrets, keys, or credentials
- All SQL must use parameterised queries
- Cypher labels must pass `validate_label()` before interpolation
- Never weaken RLS policies without explicit justification
- Never bypass Cerbos/SpiceDB authorization at the application layer

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Adding a new ingest connector

1. Create a new directory under `ingest/connectors/<name>/`
2. Extend `AdapterBase` from `ingest/connectors/base.py`
3. Implement the `fetch()` and `transform()` methods
4. Add configuration in a `config.py` module
5. Add unit tests in `tests/ingest/test_<name>_adapter.py`

## Adding a new MCP skill

1. Create a skill class extending `SkillBase` in `api/mcp/skills/<domain>/`
2. Add Cypher query templates in `api/mcp/skills/queries/` (`.cypher` + `.json`)
3. Register the skill in the skill registry
4. Add tests in `tests/skills/`
5. Document the skill in `docs/skills/README.md`

See [docs/skills/README.md](docs/skills/README.md) for the skill architecture.
