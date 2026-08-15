.PHONY: help test lint check report clean

# Default target: show what's available.
help:
	@echo "Targets:"
	@echo "  test     - run pytest (offline; no Azure/OpenShift)"
	@echo "  lint     - run ruff + pyright + bash -n + shellcheck (skip if absent)"
	@echo "  check    - test + lint"
	@echo "  report   - generate vulnerability_report.html from existing CSVs"
	@echo "  clean    - remove generated CSVs, HTML, and Python caches"

test:
	pytest -q

lint:
	@echo "==> ruff"
	@ruff check .
	@echo "==> pyright"
	@if command -v pyright >/dev/null 2>&1; then pyright; else echo "(pyright not installed, skipping)"; fi
	@echo "==> bash -n"
	@bash -n defender.sh
	@bash -n check_ocp.sh
	@echo "==> shellcheck (warning+ severity; info/style are advisory)"
	@if command -v shellcheck >/dev/null 2>&1; then shellcheck --severity=warning defender.sh check_ocp.sh; else echo "(shellcheck not installed, skipping)"; fi

check: test lint

# Assumes resultado_cruzamento.csv and expanded.csv are already present in the
# working directory. Use for local iteration on report.py; the full pipeline
# (defender.sh + check_ocp.sh + expandcsv.py) needs live Azure/OpenShift.
report:
	python3 report.py

clean:
	rm -f vulnerable_images_report.csv blocked_images_report.csv
	rm -f resultado_cruzamento.csv expanded.csv vulnerability_report.html
	rm -f *.csv.tmp.*
	rm -rf __pycache__ tests/__pycache__ .pytest_cache .ruff_cache
