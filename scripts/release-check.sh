#!/usr/bin/env bash
set -euo pipefail

rm -rf dist
pytest --cov=aiegis --cov-report=term-missing --cov-fail-under=90
ruff check .
mypy src
python -m build
twine check dist/*
