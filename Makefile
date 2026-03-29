.PHONY: help up down migrate seed validate test lint clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

up: ## Start local development stack (docker-compose)
	docker compose -f deploy/docker/docker-compose.yml up -d

down: ## Stop local development stack
	docker compose -f deploy/docker/docker-compose.yml down

migrate: ## Run database migrations
	@echo "TODO: implement migration runner"

seed: ## Load reference data (MITRE ATT&CK, STIX vocabularies, roles)
	@echo "TODO: implement seed loader"

validate: ## Validate schema and policies
	@echo "TODO: implement validation"

test: ## Run all tests
	@echo "TODO: implement test runner"

lint: ## Lint Python and SQL
	@echo "TODO: implement linting"

clean: ## Remove build artifacts and caches
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -name '*.pyc' -delete 2>/dev/null || true
