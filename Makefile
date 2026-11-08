# HackCulture KB tooling. Pure standard library; no dependencies to install.

.PHONY: validate validate-strict test check

## validate: run the HC-KB-01 card validator over the technique-card specs
validate:
	python3 tools/validate_kb.py

## validate-strict: also fail on UNRESOLVED taxonomy ids (the `# verify` surface)
validate-strict:
	python3 tools/validate_kb.py --strict

## test: run the validator's adversarial self-tests (HC-KB-01 §12)
test:
	python3 tests/test_validator.py

## check: everything CI runs
check: validate test
