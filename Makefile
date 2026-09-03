.PHONY: install dev test run clean menu build tui sim watch sweep scan sniff dtest shell down

# ---- Docker Compose (menu-driven) ----
DC ?= docker compose
RUN = $(DC) run --rm otkit

menu:           ## menu interactivo: lo hace TODO desde un solo comando
	bash otkit.sh

build:          ## construir/actualizar la imagen todo-en-uno
	$(DC) build

tui:            ## abrir el centro de mando (TUI)
	$(RUN) python ot_command.py

sim:            ## generar capture.pcap de ejemplo
	$(RUN) python otsim.py

watch:          ## mini-IDS CLI en vivo  (IFACE=eth0 HMI=.. PLC=..)
	$(RUN) python otwatch.py --iface $(or $(IFACE),eth0) --hmi $(or $(HMI),10.10.30.10) --plc $(or $(PLC),10.10.30.21,10.10.40.7)

sweep:          ## pyscan inventario  (CIDR=10.10.30.0/24)
	$(RUN) pyscan sweep $(or $(CIDR),10.10.30.0/24)

scan:           ## pyscan identificar host  (HOST=.. PORT=502 TYPE=modbus)
	$(RUN) pyscan scan $(HOST) -p $(or $(PORT),502) --type $(or $(TYPE),modbus) --max-rate 5

sniff:          ## pyscan sniff en vivo con TUI  (IFACE=eth0)
	$(RUN) pyscan sniff --live --iface $(or $(IFACE),eth0) --tui

dtest:          ## tests dentro del contenedor
	$(DC) run --rm -v "$$(pwd)":/repo -w /repo otkit pytest -q

shell:          ## shell dentro del contenedor
	$(RUN) bash

down:           ## limpiar contenedores del compose
	$(DC) down

# ---- desarrollo local (sin Docker) ----
install:        ## editable install (runtime deps)
	pip install -e .

dev:            ## editable install + test deps
	pip install -e ".[dev]"

test:           ## run the test suite (local)
	pytest -q

run:            ## demo scan against localhost (local)
	pyscan scan 127.0.0.1 --ports 1-1024

clean:
	rm -rf build dist *.egg-info .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
