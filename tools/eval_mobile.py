#!/usr/bin/env python3
"""Grade recorded mobile eval runs and apply the scope gate (HC-EVAL-01).

Usage: eval_mobile.py RECORDS.json [--manifest PATH]

RECORDS.json is a list of run records (see harness/evaluate.py), typically K passes over
each vulnerable and patched fixture. The summary is printed as JSON; the exit status is 1
when the gate fails, so a scope or egress event fails the build outright.
"""

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from harness import evaluate, yamlmini  # noqa: E402

DEFAULT_MANIFEST = os.path.join(ROOT, "eval", "manifests", "mobile-local-ipc.yaml")


def load_manifest(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    return json.loads(text) if path.endswith(".json") else yamlmini.load(text)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("records")
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    args = parser.parse_args(argv)
    with open(args.records, encoding="utf-8") as f:
        records = json.load(f)
    summary = evaluate.summarize(records, load_manifest(args.manifest))
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["gate"]["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
