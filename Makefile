PY ?= python3
VENV ?= .venv
BIN := $(VENV)/bin
PORT ?= 8765

.PHONY: venv install dev seed test test-pg lint fmt run run-http inspector example check docker-up docker-down clean

venv:
	$(PY) -m venv $(VENV)

install: venv
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -e ".[dev]"

dev: install seed

seed:
	$(BIN)/python scripts/seed_demo.py

test:
	$(BIN)/pytest

# Needs a disposable PostgreSQL, e.g. `docker compose up -d postgres`.
test-pg:
	TEST_DATABASE_URL=$${TEST_DATABASE_URL:-postgresql://shop:shop@localhost:5432/shop} $(BIN)/pytest -m postgres

lint:
	$(BIN)/ruff check src tests scripts examples
	$(BIN)/ruff format --check src tests scripts examples

fmt:
	$(BIN)/ruff format src tests scripts examples
	$(BIN)/ruff check --fix src tests scripts examples

run:
	$(BIN)/mcp-pg-analyst serve --transport stdio

run-http:
	$(BIN)/mcp-pg-analyst serve --transport http --port $(PORT)

# MCP Inspector UI (Node 18+): connect it to http://127.0.0.1:$(PORT)/mcp
inspector:
	npx -y @modelcontextprotocol/inspector

example:
	$(BIN)/python examples/client.py

check:
	@test -n "$(SQL)" || (echo 'usage: make check SQL="select ..."' && exit 2)
	$(BIN)/mcp-pg-analyst check "$(SQL)"

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down -v

clean:
	rm -rf .pytest_cache .ruff_cache build dist *.egg-info src/*.egg-info
	find . -name "__pycache__" -type d -prune -exec rm -rf {} +
