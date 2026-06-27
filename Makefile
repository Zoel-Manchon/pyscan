.PHONY: install dev test run clean

install:        ## editable install (runtime deps)
	pip install -e .

dev:            ## editable install + test deps
	pip install -e ".[dev]"

test:           ## run the test suite
	pytest -q

run:            ## demo scan against localhost
	pyscan scan 127.0.0.1 --ports 1-1024

clean:
	rm -rf build dist *.egg-info .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} +
