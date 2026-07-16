SHELL := /bin/sh
PYTHON ?= python

.PHONY: test build verify quickstart

test:
	$(PYTHON) -m pytest -q

build:
	$(PYTHON) -m build

verify: test build
	$(PYTHON) scripts/verify_candidate.py

quickstart:
	$(PYTHON) examples/quickstart/python_quickstart.py
