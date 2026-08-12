.PHONY: help up down migrate activate-app-role seed validate test lint typecheck clean reset psql serve mcp graph-writer enrichment-worker integration-test verify-chain verify-merkle stamp-merkle bench helm-lint helm-template helm-validate zarf-validate deploy-lint

# Database connection defaults (override via environment)
PGHOST   ?= localhost
PGPORT   ?= 5432
PGUSER   ?= cg_admin
PGPASSWORD ?= cg_dev_only
PGDATABASE ?= core_graph
# Dev-only. Matches deploy/docker/docker-compose.yml so `make migrate` against a
# pre-existing stack activates cg_app the same way a fresh initdb does.
CG_APP_PASSWORD ?= cg_dev_only_app

export PGHOST PGPORT PGUSER PGPASSWORD PGDATABASE

PSQL := psql -v ON_ERROR_STOP=1

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

up: ## Start local development stack (docker-compose)
	docker compose -f deploy/docker/docker-compose.yml up -d

down: ## Stop local development stack
	docker compose -f deploy/docker/docker-compose.yml down

migrate: ## Run database migrations
	@echo "==> Running migrations"
	@for f in $$(ls schema/migrations/*.sql | sort); do \
		echo "  -> Applying $$(basename $$f)"; \
		$(PSQL) -f "$$f"; \
	done
	@echo "==> Migrations complete"
	@$(MAKE) --no-print-directory activate-app-role

activate-app-role: ## Set the cg_app password so the API can connect (dev)
	@# Migration 038 creates cg_app without a password on purpose; setting one
	@# is what activates it, and belongs to the deployment rather than to a
	@# migration. deploy/docker/initdb.sh does this on a *first* container
	@# start. This target covers the other case: a stack whose pgdata volume
	@# predates the role, where initdb never re-runs and the API would sit in a
	@# connect-retry loop against a role with no password.
	@if [ -z "$(CG_APP_PASSWORD)" ]; then \
		echo "==> CG_APP_PASSWORD unset; skipping cg_app activation"; \
	else \
		echo "==> Activating cg_app"; \
		echo "alter role cg_app login password :'pw';" \
			| $(PSQL) -v pw="$(CG_APP_PASSWORD)" >/dev/null; \
	fi

seed: ## Load reference data (MITRE ATT&CK, STIX vocabularies, roles)
	@echo "==> Loading seed data"
	@for f in $$(ls schema/seed/*.sql 2>/dev/null | sort); do \
		echo "  -> Loading $$(basename $$f)"; \
		$(PSQL) -f "$$f"; \
	done
	@echo "==> Seed data loaded"

validate: ## Validate schema, Python, and policies
	@echo "==> Validating Python (ruff)"
	ruff check .
	ruff format --check .
	@echo "==> Validating YAML policies"
	yamllint -d relaxed policies/
	@echo "==> Checking migration numbering"
	@python3 scripts/validate.py
	@echo "==> All validations passed"

test: ## Run all tests
	@echo "==> Running pytest"
	pytest
	@echo "==> Running RLS enforcement tests"
	$(PSQL) -f tests/rls/test_tlp_enforcement.sql
	$(PSQL) -f tests/rls/test_edge_tlp.sql
	$(PSQL) -f tests/rls/test_iam_tlp_floor.sql
	$(PSQL) -f tests/rls/test_write_path.sql
	$(PSQL) -f tests/rls/test_stix_sdo_rls.sql
	$(PSQL) -f tests/rls/test_vector_tlp.sql
	$(PSQL) -f tests/rls/test_application_role.sql
	$(PSQL) -f tests/rls/test_clearance_roles.sql
	$(PSQL) -f tests/rls/test_readonly_clearances.sql
	@echo "==> All tests passed"

lint: validate ## Lint Python and SQL (alias for validate)

typecheck: ## Run mypy over the service packages (config in pyproject.toml)
	mypy

clean: ## Remove build artifacts and caches
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -name '*.pyc' -delete 2>/dev/null || true

reset: ## Drop and recreate database, rerun migrations and seeds
	@echo "==> Dropping database $(PGDATABASE)"
	dropdb --if-exists $(PGDATABASE)
	@echo "==> Creating database $(PGDATABASE)"
	createdb $(PGDATABASE)
	@$(MAKE) migrate
	@$(MAKE) seed
	@echo "==> Reset complete"

psql: ## Connect to local dev database interactively
	psql

serve: ## Run REST API locally via uvicorn
	uvicorn api.rest.main:app --reload --port 8000

mcp: ## Run the MCP server
	python -m api.mcp.server

graph-writer: ## Run the graph writer worker
	python -m ingest.graph_writer

enrichment-worker: ## Run the enrichment worker (ingest.* -> enriched.*)
	python -m ingest.enrichment_worker

integration-test: ## Run integration tests only
	CG_OIDC_ENABLED=false CG_DEV_MODE=true pytest -m integration -v

verify-chain: ## Run audit log hash chain verification
	python -m evidence.chain.verify

verify-merkle: ## Run Merkle root verification
	python -m evidence.chain.verify --merkle

stamp-merkle: ## Request RFC 3161 timestamps for unstamped Merkle roots
	python scripts/stamp_merkle_roots.py

bench: ## Run performance benchmarks
	python scripts/bench/bench_ner_extraction.py
	python scripts/bench/bench_graph_traversal.py
	python scripts/bench/bench_ingest_throughput.py

eval: ## Run the retrieval eval against the golden set
	python scripts/eval/run_retrieval_eval.py \
		--golden tests/eval/golden/retrieval_v1.jsonl \
		--report-md eval-report.md

drift: ## Run the embedding drift detector
	python scripts/bench/embedding_drift.py \
		--baseline tests/eval/baseline_embedding_dist.npz \
		--sample-size 10000

helm-lint: ## Lint Helm chart (lab + prod profiles)
	@echo "==> Linting Helm chart (lab)"
	helm lint deploy/k8s/helm
	@echo "==> Linting Helm chart (prod)"
	helm lint deploy/k8s/helm -f deploy/k8s/helm/values.yaml -f deploy/k8s/helm/values-prod.yaml

helm-template: ## Template Helm chart (lab + prod profiles)
	@echo "==> Templating Helm chart (lab)"
	helm template core-graph deploy/k8s/helm --debug > /dev/null
	@echo "==> Templating Helm chart (prod)"
	helm template core-graph deploy/k8s/helm -f deploy/k8s/helm/values.yaml -f deploy/k8s/helm/values-prod.yaml --debug > /dev/null

helm-validate: helm-lint helm-template ## Full Helm validation (lint + template)

zarf-validate: ## Validate zarf.yaml against Zarf schema
	@echo "==> Validating zarf.yaml"
	check-jsonschema --schemafile "https://raw.githubusercontent.com/zarf-dev/zarf/main/zarf.schema.json" zarf.yaml

deploy-lint: helm-lint zarf-validate ## Validate all deployment artifacts
