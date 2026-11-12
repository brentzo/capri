"""Offline Trivy readiness, database update and finding mapping."""
import json
import os
import re
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

MIN_VERSION = (0, 75, 0)


def cache_dir():
    return Path.home() / ".capri" / "trivy"


def _environment():
    return {key: value for key, value in os.environ.items() if not key.startswith("TRIVY_")}


def _invoke(run, command, *, cwd):
    return run(command, cwd=cwd, capture_output=True, text=True, encoding="utf-8",
               errors="replace", timeout=300, env=_environment(), check=False)


def _version_tuple(value):
    numbers = value.split("-", 1)[0].split(".")
    return tuple(int(part) for part in numbers)


def _read_updated_at(metadata):
    value = metadata["UpdatedAt"]
    value = re.sub(r"\.(\d{6})\d+", r".\1", value)
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("Trivy database update time must include a timezone")
    return parsed.astimezone(UTC)


def readiness(run, find_tool, *, now=None, cwd):
    path = find_tool("trivy")
    if not path:
        return None, None, "Trivy not found"
    try:
        result = _invoke(run, [str(path), "version", "-f", "json"], cwd=cwd)
        if result.returncode:
            return None, None, "Trivy version command failed"
        version_data = json.loads(result.stdout)
        version = version_data.get("Version", "")
        if _version_tuple(version) < MIN_VERSION:
            return version, None, "Trivy 0.75.0 or newer is required"
    except subprocess.TimeoutExpired:
        return None, None, "Trivy version check timed out"
    except OSError:
        return None, None, "Trivy could not be started"
    except (ValueError, TypeError, json.JSONDecodeError):
        return None, None, "Trivy returned an invalid version"
    metadata_path = cache_dir() / "db" / "metadata.json"
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        updated = _read_updated_at(metadata)
    except (OSError, KeyError, ValueError, TypeError, json.JSONDecodeError):
        return version, None, "Trivy vulnerability database not found or invalid; run `capri source update-db`"
    now = (now or datetime.now(UTC)).astimezone(UTC)
    age = now - updated
    return version, {"updated_at": updated.isoformat(), "version": metadata.get("Version"),
                     "age_days": age.days, "stale": age > timedelta(days=7)}, None


def update_database(run, find_tool, *, cwd):
    path = find_tool("trivy")
    if not path:
        raise RuntimeError("Trivy CLI was not found; install Trivy 0.75.0 or newer")
    try:
        version_run = _invoke(run, [str(path), "version", "-f", "json"], cwd=cwd)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("could not run Trivy version check; Trivy 0.75.0 or newer is required") from error
    if version_run.returncode:
        raise RuntimeError("could not read Trivy version; Trivy 0.75.0 or newer is required")
    try:
        version = json.loads(version_run.stdout).get("Version", "")
        if _version_tuple(version) < MIN_VERSION:
            raise RuntimeError(f"Trivy {version} is too old; Trivy 0.75.0 or newer is required")
    except (ValueError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("Trivy returned an invalid version; Trivy 0.75.0 or newer is required") from error
    command = [str(path), "image", "--download-db-only", "--cache-dir", str(cache_dir()),
               "--disable-telemetry", "--skip-version-check", "--config", ""]
    try:
        result = _invoke(run, command, cwd=cwd)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("Trivy vulnerability database download failed") from error
    if result.returncode:
        raise RuntimeError("Trivy vulnerability database download failed")
    try:
        metadata = json.loads((cache_dir() / "db" / "metadata.json").read_text(encoding="utf-8"))
        updated = _read_updated_at(metadata)
    except (OSError, KeyError, ValueError, TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("Trivy download finished but database metadata is missing or invalid") from error
    print(f"Trivy vulnerability database updated at {updated.isoformat()}")
    return 0


def scan(snapshot, run, trivy, *, cwd):
    command = [str(trivy), "fs", str(snapshot), "--scanners", "vuln", "--pkg-types", "library",
               "--include-dev-deps", "--list-all-pkgs", "--format", "json", "--quiet",
               "--offline-scan", "--skip-db-update", "--skip-java-db-update", "--skip-check-update",
               "--skip-version-check", "--disable-telemetry", "--cache-dir", str(cache_dir()),
               "--config", "", "--ignorefile", ""]
    result = _invoke(run, command, cwd=cwd)
    if result.returncode:
        raise RuntimeError(f"Trivy scan failed with exit status {result.returncode}")
    try:
        return json.loads(result.stdout), command
    except (TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("Trivy scan returned invalid JSON") from error


def map_results(data, snapshot, path_map=None):
    ecosystems = {"npm": "npm", "pnpm": "npm", "yarn": "npm", "bun": "npm",
                  "cocoapods": "cocoapods", "swift": "swiftpm", "pub": "pub", "gradle": "gradle"}
    findings = []
    counts = {name: 0 for name in ecosystems.values()}
    returned_paths = set()
    for result in data.get("Results", []):
        ecosystem = ecosystems.get(str(result.get("Type", "")).lower())
        if not ecosystem or result.get("Class") != "lang-pkgs":
            continue
        target = str(result.get("Target", "")).replace("\\", "/")
        target_path = Path(target)
        if target_path.is_absolute():
            try:
                target = target_path.resolve().relative_to(snapshot.resolve()).as_posix()
            except ValueError:
                continue
        returned_paths.add(target)
        packages = {item.get("ID"): item for item in result.get("Packages", []) if item.get("ID")}
        counts[ecosystem] += len(packages)
        for vuln in result.get("Vulnerabilities", []) or []:
            package = packages.get(vuln.get("PkgID"), {})
            package_name = package.get("PkgName") or vuln.get("PkgName")
            version = package.get("InstalledVersion") or vuln.get("InstalledVersion")
            ids = list(dict.fromkeys([vuln.get("VulnerabilityID", "")] + (vuln.get("VendorIDs") or [])))
            ids = [value for value in ids if value]
            location = {"path": target, "line": None}
            locations = package.get("Locations") or []
            if locations:
                location["line"] = locations[0].get("StartLine")
            version_kind = "resolved"
            scope = "dev" if package.get("Dev") else "runtime"
            declared = re.search(r"(?:^|/)\.capri-declared/(\d+)/gradle\.lockfile$", target.replace("\\", "/"))
            if declared and path_map:
                source = path_map.get((declared.group(1), package_name, version))
                if source:
                    location, scope = source[0], source[1]
                    version_kind = "declared"
            fixed = [item.strip() for item in str(vuln.get("FixedVersion") or "").split(",") if item.strip()]
            for advisory in ids:
                findings.append({"ecosystem": ecosystem, "package": package_name, "version": version,
                                 "version_kind": version_kind, "scope": scope, "advisory_ids": ids,
                                 "severity": str(vuln.get("Severity", "UNKNOWN")).upper(),
                                 "fixed_versions": fixed or None, "title": vuln.get("Title"),
                                 "advisory_url": vuln.get("PrimaryURL"), "location": location,
                                 "reachability": "present in lockfile, reachability not checked"})
    seen = set()
    unique = []
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    for finding in sorted(findings, key=lambda item: (rank.get(item["severity"], 5), item["ecosystem"],
                                                       item["location"]["path"], item["package"] or "")):
        key = (finding["location"]["path"], finding["package"], finding["version"], tuple(finding["advisory_ids"]))
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique, counts, returned_paths
