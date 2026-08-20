.PHONY: help install test cov lint sample demo clean

PY ?= python3
export PYTHONPATH := $(CURDIR)/src

help:
	@echo "make install  - install the package in editable mode with dev extras"
	@echo "make test     - run the test suite"
	@echo "make cov      - run tests with a coverage report"
	@echo "make lint     - run ruff"
	@echo "make sample   - generate the synthetic Case 029 profile in ./demo"
	@echo "make demo     - full pipeline: generate, acquire, verify, analyse, report"
	@echo "make clean    - remove generated artefacts"

install:
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest

cov:
	$(PY) -m pytest --cov=ffxforensics --cov-report=term-missing --cov-report=html

lint:
	$(PY) -m ruff check src tests

sample:
	$(PY) -m ffxforensics.cli sample demo/source --tz +01:00

demo:
	./scripts/run_case029.sh

clean:
	rm -rf demo .pytest_cache .coverage htmlcov .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
