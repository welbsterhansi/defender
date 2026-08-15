.PHONY: help test lint check report pipeline-local smoke-real clean

# Default target: show what's available.
help:
	@echo "Targets (offline / safe by default):"
	@echo "  test            - run pytest (no Azure/OpenShift calls)"
	@echo "  lint            - run ruff + pyright + bash -n + shellcheck (skip if absent)"
	@echo "  check           - test + lint"
	@echo "  report          - generate vulnerability_report.html from existing CSVs"
	@echo "  pipeline-local  - run expandcsv.py + report.py against existing CSVs"
	@echo "  clean           - remove generated CSVs, HTML, and Python caches"
	@echo ""
	@echo "Targets that TOUCH real Azure/OpenShift (manual smoke only):"
	@echo "  smoke-real ACR_NAME=<acr>"
	@echo "                  - defender.sh report-only, critical band 9.8-10, no writes"
	@echo ""
	@echo "There is NO make target that block/unblock images or that mutates ACR."
	@echo "Those actions must be run by hand with explicit team approval."

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
	@bash -n scripts/benchmark-defender.sh
	@echo "==> shellcheck (warning+ severity; info/style are advisory)"
	@if command -v shellcheck >/dev/null 2>&1; then shellcheck --severity=warning defender.sh check_ocp.sh lib/logging.sh scripts/benchmark-defender.sh; else echo "(shellcheck not installed, skipping)"; fi

check: test lint

# Assumes resultado_cruzamento.csv and expanded.csv are already present in the
# working directory. Use for local iteration on report.py; the full pipeline
# (defender.sh + check_ocp.sh + expandcsv.py) needs live Azure/OpenShift.
report:
	python3 report.py

# Runs the two purely-local stages of the pipeline: expandcsv (needs
# resultado_cruzamento.csv + vulnerable_images_report.csv) then report.
# Use after a real defender.sh + check_ocp.sh run has produced the inputs.
pipeline-local:
	@test -f vulnerable_images_report.csv || { echo "Missing vulnerable_images_report.csv (run defender.sh first)"; exit 2; }
	@test -f resultado_cruzamento.csv     || { echo "Missing resultado_cruzamento.csv (run check_ocp.sh first)"; exit 2; }
	python3 expandcsv.py
	python3 report.py

# Manual smoke test: talks to REAL Azure via `az` (which must already be
# logged in). Tightest severity band and report-only mode — no side effects
# on the registry. Refuses to run without an explicit ACR name so nobody
# accidentally scans the wrong subscription.
#
# Usage: make smoke-real ACR_NAME=<your-acr>
smoke-real:
	@if [ -z "$(ACR_NAME)" ]; then \
	    echo "Error: ACR_NAME is required. Usage: make smoke-real ACR_NAME=<acr>"; \
	    exit 2; \
	fi
	@echo "This will call Azure Resource Graph. Report-only, min=9.8 max=10."
	@echo "Ctrl-C in the next 3s to cancel."
	@sleep 3
	./defender.sh --acr-name "$(ACR_NAME)" --min-score 9.8 --max-score 10

clean:
	rm -f vulnerable_images_report.csv blocked_images_report.csv
	rm -f resultado_cruzamento.csv expanded.csv vulnerability_report.html
	rm -f *.csv.tmp.*
	rm -rf logs/
	rm -rf __pycache__ tests/__pycache__ .pytest_cache .ruff_cache
