"""Run Capri's offline, read-only source assessment for a local project."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules" / "source"
ASSESSMENT_AREAS = ("committed-secrets", "database-rls", "edge-function-auth", "uploads")
EXCLUDES = (
    ".git", "node_modules", "dist", "build", ".output", "coverage", ".supabase",
    ".claude", ".scratch", "docs", "tests", "testing", "scripts/evaluation",
    ".env", ".env.*", "*.md", "*.test.*", "*.spec.*", "*.lock", "*.pdf", "*.png",
    "*.jpg", "*.jpeg", "*.webp",
)


def _default_report_path(project):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Path.home() / ".capri" / "reports" / f"{project.name}-source-{stamp}.json"


def _finding(result, project):
    extra = result.get("extra") or {}
    metadata = extra.get("metadata") or {}
    raw_path = Path(result.get("path", ""))
    if not raw_path.is_absolute():
        raw_path = project / raw_path
    try:
        relative = raw_path.resolve().relative_to(project).as_posix()
    except ValueError as error:
        raise RuntimeError("Semgrep returned a location outside the selected project") from error
    start = result.get("start") or {}
    rule_id = result.get("check_id", "unknown")
    if rule_id.startswith("rules.source."):
        rule_id = rule_id.removeprefix("rules.source.")
    return {
        "rule_id": rule_id,
        "category": metadata.get("category", "security-review"),
        "severity": str(extra.get("severity", "INFO")).upper(),
        "confidence": metadata.get("confidence", "medium"),
        "message": extra.get("message", "Review this security pattern."),
        "location": {"path": relative, "line": start.get("line"), "column": start.get("col")},
    }


def assess_source(project, *, output=None, scanner=None, find_scanner=shutil.which):
    """Scan source with Capri-owned local rules and write a snippet-free local report."""
    project = Path(project).expanduser().resolve()
    if not project.is_dir():
        raise ValueError("selected project path is not a directory")
    if not RULES.is_dir() or not any(RULES.glob("*.yaml")):
        raise RuntimeError("Capri's local source rule pack is missing")

    scanner_path = find_scanner("semgrep")
    if not scanner_path:
        raise RuntimeError("Semgrep CLI was not found; install it locally, then retry")

    report_path = Path(output).expanduser().resolve() if output else _default_report_path(project).resolve()
    try:
        report_path.relative_to(project)
    except ValueError:
        pass
    else:
        raise ValueError("report output must be outside the selected project")

    command = [str(scanner_path), "scan", "--config", str(RULES), "--metrics=off",
               "--disable-version-check", "--json", "--quiet"]
    for pattern in EXCLUDES:
        command.extend(("--exclude", pattern))
    command.append(str(project))
    environment = os.environ.copy()
    environment["SEMGREP_SEND_METRICS"] = "off"
    run = scanner or subprocess.run
    try:
        completed = run(command, cwd=ROOT, capture_output=True, text=True,
                        encoding="utf-8", errors="replace", timeout=300, env=environment,
                        check=False)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("local source assessment exceeded its five-minute limit") from error
    if completed.returncode != 0:
        raise RuntimeError(f"local Semgrep scan failed with exit status {completed.returncode}")
    try:
        raw = json.loads(completed.stdout)
    except (TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("local Semgrep scan returned invalid JSON") from error
    if raw.get("errors"):
        raise RuntimeError("local Semgrep scan was incomplete; review the scanner configuration")

    findings = [_finding(item, project) for item in raw.get("results", [])]
    findings.sort(key=lambda item: (item["location"]["path"], item["location"]["line"] or 0, item["rule_id"]))
    report = {
        "schema_version": 1,
        "project": project.name,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source_assessment": {
            "status": "complete",
            "scanner": "Semgrep with Capri local rules",
            "ruleset": "capri-source-1",
            "areas_reviewed": list(ASSESSMENT_AREAS),
            "findings_by_area": {
                area: sum(item["category"] == area for item in findings)
                for area in ASSESSMENT_AREAS
            },
            "findings": findings,
            "finding_count": len(findings),
            "source_sent_to_model_provider": False,
        },
        "runtime_assessment": {
            "status": "not_run",
            "reason": "This Capri build can only run its built-in demo target dynamically.",
        },
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report, report_path


def main(argv=None):
    parser = argparse.ArgumentParser(prog="capri source", description="Assess a local project's source without executing it.")
    parser.add_argument("--project", required=True, help="local project root")
    parser.add_argument("--output", help="report file outside the selected project (defaults to ~/.capri/reports)")
    args = parser.parse_args(argv)
    try:
        report, path = assess_source(args.project, output=args.output)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"source assessment failed: {error}", file=sys.stderr)
        return 1
    source = report["source_assessment"]
    print(f"source assessment complete: {source['finding_count']} finding(s)")
    print(f"report: {path}")
    print("runtime assessment: not run (current Capri runner targets its built-in demo)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
