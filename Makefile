# HackCulture KB tooling. Pure standard library; no dependencies to install.

.PHONY: materialize validate validate-specs test check

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
	python3 tests/test_modelplane_setup.py

## contract: validate the example engagement contract (HC-SUB-01 §4)
contract:
	python3 -m harness.substrate.contract harness/substrate/examples/engagement.example.yaml

## features: regenerate the Gherkin .feature files from the BR specs
features:
	python3 tools/gen_features.py

## check: everything CI runs (validate the tree + all self-tests)
check: validate test
