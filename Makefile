# Capri CLI plus HackCulture KB tooling.

.PHONY: materialize validate validate-specs test check install

## install: symlink the `capri` command onto your PATH (~/.local/bin)
install:
	@mkdir -p $(HOME)/.local/bin
	@ln -sf $(CURDIR)/capri $(HOME)/.local/bin/capri
	@echo "linked $(HOME)/.local/bin/capri -> $(CURDIR)/capri"
	@echo "ensure ~/.local/bin is on your PATH, then run: capri setup"

## materialize: regenerate kb/<class>/*.yaml, kb/_index, and eval/manifests from the specs
materialize:
	python3 tools/materialize_kb.py

## validate: check the materialized kb/ tree, strict (CI default)
validate:
	python3 tools/validate_kb.py --strict

## validate-specs: check the condensed card blocks in the specs instead
validate-specs:
	python3 tools/validate_kb.py --from-specs --strict

## test: run all adversarial self-tests (KB validator + substrate + store + dispatch + findings/report)
test:
	python3 tests/test_validator.py
	python3 tests/test_substrate.py
	python3 tests/test_store.py
	python3 tests/test_dispatch.py
	python3 tests/test_findings_report.py
	python3 tests/test_loop.py
	python3 tests/test_planner.py
	python3 tests/test_roleio.py
	python3 tests/test_modelplane.py
	python3 tests/test_roles.py
	python3 tests/test_enrich.py
	python3 tests/test_bifrost.py
	python3 tests/test_tavily.py
	python3 tests/test_blackboard.py
	python3 tests/test_frontier.py
	python3 tests/test_sandbox.py
	python3 tests/test_adapters.py
	python3 tests/test_capabilities.py
	python3 tests/test_bind.py
	python3 tests/test_crawler.py
	python3 tests/test_sourcemap.py
	python3 tests/test_sinks.py
	python3 tests/test_session.py
	python3 tests/test_catalog.py
	python3 tests/test_modelplane_setup.py
	python3 tests/test_cli.py
	python3 tests/test_engagements_store.py
	python3 tests/test_reasoning_store.py
	python3 tests/test_report_render.py
	python3 tests/test_dashboard.py
	python3 tests/test_project_assessment.py
	python3 tests/test_mobile.py
	python3 tests/test_eval.py

## contract: validate the example engagement contract (HC-SUB-01 §4)
contract:
	python3 -m harness.substrate.contract harness/substrate/examples/engagement.example.yaml

## features: regenerate the Gherkin .feature files from the BR specs
features:
	python3 tools/gen_features.py

## check: everything CI runs (validate the tree + all self-tests)
check: validate test
