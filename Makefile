# airframe — wireless connectivity test automation and AI triage
#
# `make help` lists everything. `make verify` runs the whole pipeline end to end.

PY      := ./.venv/bin/python
PYTEST  := $(PY) -m pytest
CMAKE   := cmake
SIM_DIR := sim
SIM_BIN := $(SIM_DIR)/build/airframe-sim
JOBS    := 8

.DEFAULT_GOAL := help
.PHONY: help setup sim sim-test sim-asan test test-sim test-macos test-fast \
        corpus pcap kpi baseline ml triage mcp report lint typecheck clean verify

help: ## show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------- setup

setup: ## create the venv and install dependencies
	/opt/homebrew/bin/python3.13 -m venv .venv || python3 -m venv .venv
	$(PY) -m pip install --quiet --upgrade pip setuptools wheel
	$(PY) -m pip install --quiet -e ".[dev]"
	@echo "setup complete: $$($(PY) --version)"

# ---------------------------------------------------------------- C++ simulator

sim: ## build the C++ DUT simulator
	$(CMAKE) -S $(SIM_DIR) -B $(SIM_DIR)/build -DCMAKE_BUILD_TYPE=Debug
	$(CMAKE) --build $(SIM_DIR)/build -j$(JOBS)

sim-test: sim ## build and run the GoogleTest suite via ctest
	ctest --test-dir $(SIM_DIR)/build --output-on-failure -j$(JOBS)

sim-asan: ## build and run the C++ tests under ASan + UBSan
	$(CMAKE) -S $(SIM_DIR) -B $(SIM_DIR)/build-asan -DAIRFRAME_SANITIZE=ON
	$(CMAKE) --build $(SIM_DIR)/build-asan -j$(JOBS)
	./$(SIM_DIR)/build-asan/airframe_tests

# ---------------------------------------------------------------- Python tests

test: test-sim ## default: the full suite against the simulator

test-sim: ## run every test against the deterministic simulator
	$(PYTEST) --dut=sim

test-macos: ## run the real-hardware subset against this Mac's Wi-Fi
	$(PYTEST) --dut=macos

test-fast: ## skip slow and network-dependent tests
	$(PYTEST) --dut=sim -m "not slow and not network"

test-flaky: ## demonstrate flake recording: retry failures, record every attempt
	@rm -f /tmp/airframe_flake_demo_state
	$(PYTEST) demo --retries=3 -q --dut=sim
	@echo "\n--- what the store recorded ---"
	@$(PY) -m airframe.mcp.server --call flaky_tests

# ---------------------------------------------------------------- data

corpus: sim ## regenerate the capture/log corpus (deterministic)
	$(PY) scripts/build_corpus.py
	$(PY) -m airframe.pcap.synth --out data/pcaps

pcap: ## cross-validate our 802.11 dissector against tshark
	$(PY) -m airframe.pcap.tshark_check data/pcaps/*.pcap | tail -20

kpi: ## measure network KPIs against Indian endpoints
	$(PY) -m airframe.kpi.runner --check

kpi-quick: ## fast KPI run (4 endpoints)
	$(PY) -m airframe.kpi.runner --quick

baseline: ## rebuild KPI baselines from stored history
	$(PY) -m airframe.kpi.runner --baseline

# ---------------------------------------------------------------- analysis

logs: ## mine log templates from the corpus
	$(PY) -m airframe.logs.drain "data/logs/*.log"

ml: ## cluster failures and assess flakiness
	@echo "=== failure clustering ==="
	@$(PY) -m airframe.ml.cluster
	@echo "\n=== flaky-test analysis ==="
	@$(PY) -m airframe.ml.flaky

triage: ## LLM triage, scored against known injected faults
	$(PY) -m airframe.triage.agent --evaluate

providers: ## show which LLM providers are configured
	$(PY) -m airframe.triage.provider

mcp: ## list the MCP tools this rig exposes
	$(PY) -m airframe.mcp.server --list

report: ## build the HTML dashboard
	$(PY) -m airframe.report.html --open

# ---------------------------------------------------------------- quality

lint: ## ruff
	$(PY) -m ruff check src tests scripts

format: ## ruff --fix
	$(PY) -m ruff check --fix src tests scripts

typecheck: ## mypy
	$(PY) -m mypy

clean: ## remove build output and generated data
	rm -rf $(SIM_DIR)/build $(SIM_DIR)/build-asan
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	rm -rf data/db data/artifacts
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

# ---------------------------------------------------------------- everything

verify: ## the full pipeline, end to end
	@echo "=========== 1/9  C++ build + unit tests ==========="
	@$(MAKE) --no-print-directory sim-test
	@echo "\n=========== 2/9  determinism check ==========="
	@./$(SIM_BIN) --scenario wpa3 --fault FOURWAY_M3_TIMEOUT --seed 42 --pcap /tmp/af_a.pcap > /tmp/af_a.json
	@./$(SIM_BIN) --scenario wpa3 --fault FOURWAY_M3_TIMEOUT --seed 42 --pcap /tmp/af_b.pcap > /tmp/af_b.json
	@cmp /tmp/af_a.pcap /tmp/af_b.pcap && cmp /tmp/af_a.json /tmp/af_b.json \
		&& echo "  identical output for the same seed: PASS"
	@echo "\n=========== 3/9  pytest against the simulator ==========="
	@$(PYTEST) --dut=sim -q
	@echo "\n=========== 4/9  pytest against real macOS Wi-Fi ==========="
	@$(PYTEST) --dut=macos -q || echo "  (real hardware subset; skips are expected)"
	@echo "\n=========== 5/9  dissector vs tshark ==========="
	@$(PY) -m airframe.pcap.tshark_check data/pcaps/*.pcap 2>/dev/null | tail -3
	@echo "\n=========== 6/9  log template mining ==========="
	@$(PY) -m airframe.logs.drain "data/logs/*.log" 2>/dev/null | head -4
	@echo "\n=========== 7/9  failure clustering ==========="
	@$(PY) -m airframe.ml.cluster 2>/dev/null | head -5
	@echo "\n=========== 8/9  LLM triage vs ground truth ==========="
	@$(PY) -m airframe.triage.agent --evaluate 2>/dev/null | tail -4
	@echo "\n=========== 9/9  MCP server ==========="
	@$(PY) -m airframe.mcp.server --call rig_status 2>/dev/null | head -7
	@echo "\nVERIFY COMPLETE"
