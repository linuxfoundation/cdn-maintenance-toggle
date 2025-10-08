# Copyright The Linux Foundation and each contributor to LFX.
# SPDX-License-Identifier: MIT

.PHONY: all clean lint megalinter test

all:
	@echo 'no default: supported targets are "requirements.txt", "clean", "lint", and "megalinter"' >&2

clean:
	rm -Rf __pycache__ .venv .ruff_cache .mypy_cache megalinter-reports

lint:
	uv sync
	uv run ruff check
	uv run mypy *.py

megalinter:
	docker pull oxsecurity/megalinter-python:v7
	docker run --rm --platform linux/amd64 -v '$(CURDIR):/tmp/lint:rw' oxsecurity/megalinter-python:v7

test:
	@echo "No tests to run ... would you like to 'make lint'?" >&2

requirements.txt: pyproject.toml .license-header
	cat .license-header > requirements.txt
	uv pip compile pyproject.toml >> requirements.txt

fmt:
	uvx black *.py
	uvx isort *.py
