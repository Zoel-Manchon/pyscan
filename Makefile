.PHONY: help install dev test lint typecheck audit check run lab clean \
        menu build tui sim watch sweep scan sniff dtest shell down

help:           ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

# ---- local development ----------------------------------------------------
install:        ## editable install (runtime deps only)
	pip install -e .

dev:            ## editable install + every development dependency
	pip install -e ".[dev,tui]"

test:           ## run the suite with the coverage gate
	pytest -q

lint:           ## ruff
	ruff check src/ tests/

typecheck:      ## mypy --strict
	mypy

audit:          ## static analysis + dependency CVE audit
	bandit -c pyproject.toml -r src/
	pip-audit --skip-editable

check: lint typecheck test audit  ## everything CI runs, locally

run:            ## demo scan against localhost
	pyscan scan 127.0.0.1 --top-ports 100

lab:            ## generate a practice capture, then replay it through the IDS
	pyscan lab capture.pcap
	pyscan monitor capture.pcap --hmi 10.10.30.10 --plc 10.10.30.21,10.10.40.7

clean:
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache .coverage coverage.xml
	find . -type d -name __pycache__ -exec rm -rf {} +

# ---- Docker Compose (menu driven) -----------------------------------------
DC ?= docker compose
RUN = $(DC) run --rm otkit

menu:           ## interactive menu: everything from one command
	bash otkit.sh

build:          ## build/refresh the all-in-one image
	$(DC) build

tui:            ## open the OT command centre
	$(RUN) pyscan monitor --tui

sim:            ## generate capture.pcap with an attack inside it
	$(RUN) pyscan lab capture.pcap

watch:          ## mini-IDS in the terminal  (IFACE=eth0 HMI=.. PLC=..)
	$(RUN) pyscan monitor --live --iface $(or $(IFACE),eth0) \
	  --hmi $(or $(HMI),10.10.30.10) --plc $(or $(PLC),10.10.30.21,10.10.40.7)

sweep:          ## pyscan inventory  (CIDR=10.10.30.0/24)
	$(RUN) pyscan sweep $(or $(CIDR),10.10.30.0/24) --max-rate 5

scan:           ## identify one host  (HOST=.. PORT=502 TYPE=modbus)
	$(RUN) pyscan scan $(HOST) -p $(or $(PORT),502) --type $(or $(TYPE),modbus) --max-rate 5

sniff:          ## live packet TUI  (IFACE=eth0)
	$(RUN) pyscan sniff --live --iface $(or $(IFACE),eth0) --tui

dtest:          ## run the suite inside the container
	$(DC) run --rm -v "$$(pwd)":/repo -w /repo otkit sh -c "pip install -e '.[dev]' -q && pytest -q"

shell:          ## shell inside the container
	$(RUN) bash

down:           ## clean up the compose containers
	$(DC) down
