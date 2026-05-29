VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
REQUIREMENTS := docker/requirements.txt

.PHONY: docker venv deps clean test test-integration test-deps

docker: deps
	$(PYTHON) docker/build.py -o docker-compose.yml

venv:
	@test -x $(PYTHON) || python3 -m venv $(VENV)

 deps: venv
	$(PIP) install --quiet --upgrade pip
	$(PIP) install --quiet -r $(REQUIREMENTS)

clean: deps
	$(PYTHON) docker/build.py --clean

test-deps: venv
	$(PIP) install --quiet -r requirements-test.txt

test: test-deps
	$(VENV)/bin/pytest tests/ -m "not integration" -v

test-integration: test-deps
	$(VENV)/bin/pytest tests/ -m integration -v --timeout=120
