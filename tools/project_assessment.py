"""Run Capri's offline, read-only source assessment for a local project."""
import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

from tools.dependencies import assess_dependencies
from tools.dependencies.trivy import update_database
from tools.project_snapshot import create_snapshot

ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules" / "source"
ASSESSMENT_AREAS = ("committed-secrets", "database-rls", "edge-function-auth", "uploads")
EXCLUDES = (
    ".git", "node_modules", "dist", "build", ".output", "coverage", ".supabase",
    ".claude", ".scratch", "docs", "tests", "testing", "scripts/evaluation",
    ".env", ".env.*", "*.md", "*.test.*", "*.spec.*", "*.pdf", "*.png",
    "*.jpg", "*.jpeg", "*.webp",
)


def _default_report_path(project):
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return Path.home() / ".capri" / "reports" / f"{project.name}-source-{stamp}.json"


def _finding(result, snapshot):
    extra = result.get("extra") or {}
    metadata = extra.get("metadata") or {}
    raw_path = Path(result.get("path", ""))
    if not raw_path.is_absolute():
        raw_path = snapshot / raw_path
    try:
        relative = raw_path.resolve().relative_to(snapshot).as_posix()
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


def assess_source(project, *, output=None, scanner=None, find_scanner=shutil.which, now=None):
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
               "--max-target-bytes=50MB",
               "--disable-version-check", "--json", "--quiet"]
    for pattern in EXCLUDES:
        command.extend(("--exclude", pattern))
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith("SEMGREP_")}
    environment["SEMGREP_SEND_METRICS"] = "off"
    run = scanner or subprocess.run
    with create_snapshot(project, EXCLUDES) as snapshot_info:
        snapshot = snapshot_info.root
        command.append(str(snapshot))
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

        dependency_results = [item for item in raw.get("results", [])
                              if ((item.get("extra") or {}).get("metadata") or {}).get("category") == "dependency-hygiene"]
        findings = [_finding(item, snapshot) for item in raw.get("results", [])
                    if item not in dependency_results]
        dependencies = assess_dependencies(snapshot, dependency_results, run, find_scanner,
                                           project=snapshot, oversize=snapshot_info.oversize,
                                           now=now, cwd=ROOT)
        path_reasons = [f"Windows path limit prevented scanning: {path}"
                        for path in snapshot_info.path_limited]
    findings.sort(key=lambda item: (item["location"]["path"], item["location"]["line"] or 0, item["rule_id"]))
    report = {
        "schema_version": 2,
        "project": project.name,
        "created_at": datetime.now(UTC).isoformat(),
        "source_assessment": {
            "status": "partial" if path_reasons else "complete",
            "reasons": path_reasons,
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
        "dependency_assessment": dependencies,
        "runtime_assessment": {
            "status": "not_run",
            "reason": "This Capri build can only run its built-in demo target dynamically.",
        },
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report, report_path


def main(argv=None, *, scanner=None, find_scanner=shutil.which):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "update-db":
        try:
            return update_database(scanner or subprocess.run, find_scanner, cwd=ROOT)
        except (OSError, RuntimeError, ValueError) as error:
            print(f"source update-db failed: {error}", file=sys.stderr)
            return 1
    parser = argparse.ArgumentParser(prog="capri source", description="Assess a local project's source without executing it.")
    parser.add_argument("--project", required=True, help="local project root")
    parser.add_argument("--output", help="report file outside the selected project (defaults to ~/.capri/reports)")
    args = parser.parse_args(argv)
    try:
        report, path = assess_source(args.project, output=args.output, scanner=scanner,
                                     find_scanner=find_scanner)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"source assessment failed: {error}", file=sys.stderr)
        return 1
    source = report["source_assessment"]
    print(f"source assessment {source['status']}: {source['finding_count']} finding(s)")
    for key, label in (("vulnerable_dependencies", "vulnerable dependencies"),
                       ("dependency_hygiene", "dependency hygiene")):
        area = report["dependency_assessment"][key]
        print(f"{label}: {area['status']} ({area['finding_count']} finding(s))")
    print(f"report: {path}")
    print("runtime assessment: not run (current Capri runner targets its built-in demo)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
