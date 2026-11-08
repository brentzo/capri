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

## test: run all adversarial self-tests (KB validator + M0 substrate + M1 store)
test:
	python3 tests/test_validator.py
	python3 tests/test_substrate.py
	python3 tests/test_store.py

## contract: validate the example engagement contract (HC-SUB-01 §4)
contract:
	python3 -m harness.substrate.contract harness/substrate/examples/engagement.example.yaml

## features: regenerate the Gherkin .feature files from the BR specs
features:
	python3 tools/gen_features.py

## check: everything CI runs (validate the tree + all self-tests)
check: validate test
