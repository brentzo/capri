#!/usr/bin/env python3
"""Extract the Gherkin from the business-requirement specs into .feature files.

Each docs/requirements/BR-*.md carries exactly one ```gherkin fenced Feature block.
This writes it to docs/requirements/features/<same-stem>.feature so the scenarios are
available as standard, BDD-runnable Gherkin. The BR docs stay the source of
truth; CI regenerates and fails if the features drift.

Also validates each block minimally (one Feature line, at least one Scenario).
Exit nonzero on any problem. Usage: python3 tools/gen_features.py
"""
import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main():
    md_files = sorted(glob.glob(os.path.join(ROOT, "docs", "requirements", "BR-*.md")))
    if not md_files:
        print("no docs/requirements/BR-*.md files found")
        return 1
    out_dir = os.path.join(ROOT, "docs", "requirements", "features")
    os.makedirs(out_dir, exist_ok=True)

    problems, written = [], 0
    for mf in md_files:
        stem = os.path.basename(mf)[:-3]
        text = open(mf).read()
        blocks = re.findall(r"```gherkin\n(.*?)```", text, re.S)
        if len(blocks) != 1:
            problems.append(f"{stem}: expected exactly one gherkin block, found {len(blocks)}")
            continue
        body = blocks[0].rstrip() + "\n"
        lines = [ln.strip() for ln in body.splitlines() if ln.strip()]
        if not any(ln.startswith("Feature:") for ln in lines):
            problems.append(f"{stem}: gherkin block has no 'Feature:' line")
        if not any(ln.startswith("Scenario") for ln in lines):
            problems.append(f"{stem}: gherkin block has no 'Scenario:'")
        open(os.path.join(out_dir, stem + ".feature"), "w").write(body)
        written += 1

    n_scen = sum(len(re.findall(r"^\s*Scenario", open(f).read(), re.M))
                 for f in glob.glob(os.path.join(out_dir, "*.feature")))
    print(f"generated {written} feature file(s), {n_scen} scenarios -> docs/requirements/features/")
    if problems:
        print("PROBLEMS:")
        for p in problems:
            print("  -", p)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
