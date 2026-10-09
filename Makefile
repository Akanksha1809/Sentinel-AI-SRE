# Sentinel developer entry points. Run `make help` for the list.
SHELL := /bin/bash
COMPOSE ?= docker-compose -f deploy/compose/docker-compose.yml
PROM_IMAGE := prom/prometheus:v3.13.4
AM_IMAGE := prom/alertmanager:v0.34.1
ACTUATOR := http://127.0.0.1:8085
SECRETS := secrets

.DEFAULT_GOAL := help
.PHONY: help setup secrets images build up down clean wait ps logs \
        test test-unit test-integration lint fmt typecheck security check-monitoring check \
        dashboards token

help: ## Show targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n",$$1,$$2}'

# ---------------------------------------------------------------- setup
setup: ## Create the venv and install all workspace packages + dev tools
	uv sync --all-packages

secrets: ## Generate local secrets into ./secrets (idempotent)
	./scripts/gen-secrets.sh

dashboards: ## Regenerate Grafana dashboard JSON
	uv run python deploy/grafana/build_dashboards.py

# ---------------------------------------------------------------- stack
images: ## Build service images and both shop-api release images
	$(COMPOSE) --profile images build

build: images

up: secrets ## Start the stack and wait until it is ready
	$(COMPOSE) up -d
	@$(MAKE) --no-print-directory wait

down: ## Stop the stack (keeps volumes) and remove actuator-managed replicas
	-@docker ps -aq --filter label=sentinel.managed=true | xargs -r docker rm -f >/dev/null
	$(COMPOSE) down

clean: ## Stop the stack and delete all volumes
	-@docker ps -aq --filter label=sentinel.managed=true | xargs -r docker rm -f >/dev/null
	$(COMPOSE) down -v

wait: ## Block until all components report ready (timeout 180s)
	@./scripts/wait-ready.sh

ps: ## Show stack status and managed replicas
	@$(COMPOSE) ps --format 'table {{.Service}}\t{{.Status}}'
	@docker ps --filter label=sentinel.managed=true --format 'table {{.Names}}\t{{.Status}}\t{{.Label "sentinel.version"}}\t{{.Label "sentinel.config_revision"}}'

logs: ## Tail stack logs (SERVICE=name to filter)
	$(COMPOSE) logs -f --tail=100 $(SERVICE)

# ---------------------------------------------------------------- quality
test-unit: ## Unit + policy tests (no Docker needed)
	uv run pytest -m "not integration and not e2e and not ollama"

test-integration: ## Integration + API tests against real Postgres (needs Docker)
	uv run pytest -m integration

test: test-unit test-integration check-monitoring ## All tests (Docker needed for integration)

lint: ## Ruff lint + format check
	uv run ruff check .
	uv run ruff format --check .

fmt: ## Auto-format
	uv run ruff check --fix .
	uv run ruff format .

typecheck: ## mypy --strict
	uv run mypy src services/demo-app/src services/actuator/src services/loadgen/src

token: ## Create an API token: make token NAME=alice ROLE=responder
	$(COMPOSE) exec sentinel-api sentinel token create $(NAME) $(ROLE)

security: ## Bandit + pip-audit
	uv run bandit -q -c pyproject.toml -r src services/demo-app/src services/actuator/src services/loadgen/src
	uv export --all-packages --no-dev --no-emit-workspace --no-hashes -q -o /tmp/sentinel-reqs.txt && uv run pip-audit -r /tmp/sentinel-reqs.txt --progress-spinner off

check-monitoring: ## promtool check + rule unit tests, amtool config check
	docker run --rm -v "$(CURDIR)/deploy/prometheus":/w:ro -w /w --entrypoint promtool $(PROM_IMAGE) check config --syntax-only prometheus.yml
	docker run --rm -v "$(CURDIR)/deploy/prometheus":/w:ro -w /w --entrypoint promtool $(PROM_IMAGE) check rules rules/slo.yml rules/alerts.yml
	docker run --rm -v "$(CURDIR)/deploy/prometheus":/w:ro -w /w/tests --entrypoint promtool $(PROM_IMAGE) test rules rules_test.yml
	docker run --rm -v "$(CURDIR)/deploy/alertmanager":/w:ro --entrypoint amtool $(AM_IMAGE) check-config /w/alertmanager.yml

check: lint typecheck test security ## Everything CI runs (except e2e)
