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

## test: run the validator's adversarial self-tests (HC-KB-01 §12)
test:
	python3 tests/test_validator.py

## check: everything CI runs (validate the tree + self-tests)
check: validate test
