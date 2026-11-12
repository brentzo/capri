"""Private dependency assessment behind one public report-producing function."""
import json
import re
import subprocess
import sys
import tomllib
import urllib.parse
from pathlib import Path

from tools.dependencies import catalog, gradle, readers, trivy

_PUBLIC_REGISTRIES = {"registry.npmjs.org", "registry.yarnpkg.com"}


def _overall(ecosystems):
    """An area is complete only if every present ecosystem is, and not_run only if none ran."""
    present = {value["status"] for value in ecosystems.values() if value["status"] != "not_applicable"}
    if not present:
        return "not_applicable"
    if len(present) == 1:
        return present.pop()
    return "partial"


def _finding(rule, ecosystem, severity, confidence, message, technique, path, line=1):
    return {"rule_id": rule, "category": "dependency-hygiene", "ecosystem": ecosystem,
            "severity": severity, "confidence": confidence, "message": message,
            "related_technique": technique,
            "location": {"path": path, "line": line, "column": None}}


def _registry_entry(entry):
    if entry.get("local"):
        return False
    raw = entry.get("raw")
    resolution = raw.get("resolution", "") if isinstance(raw, dict) else ""
    source = str(entry.get("resolved") or resolution).lower()
    return not source.startswith(("git+", "git:", "file:", "link:", "workspace:", "portal:"))


def _dependency_confusion(path, relative, entries, project):
    private = {}
    for entry in entries:
        package = entry.get("name", "")
        if not package.startswith("@") or "/" not in package:
            continue
        resolved = entry.get("resolved", "")
        host = urllib.parse.urlparse(resolved).hostname
        if host and host not in _PUBLIC_REGISTRIES:
            scope = package.split("/", 1)[0]
            private.setdefault(scope, []).append((host, entry["line"]))
    if not private:
        return []
    root = path.parent
    ancestors = []
    current = root
    while current == project or project in current.parents:
        ancestors.append(current)
        if current == project:
            break
        current = current.parent
    scope_pins = {}
    for ancestor in ancestors:
        for config_name in (".npmrc", ".yarnrc", ".yarnrc.yml"):
            config = ancestor / config_name
            if not config.is_file():
                continue
            text = config.read_text(encoding="utf-8", errors="replace")
            if config_name == ".npmrc":
                for scope, url in re.findall(r"(?m)^\s*(@[\w.-]+):registry\s*=\s*(\S+)", text):
                    scope_pins[scope] = urllib.parse.urlparse(url).hostname
            elif config_name == ".yarnrc":
                for scope, url in re.findall(r'["\'](@[\w.-]+):registry["\']\s+["\']([^"\']+)', text):
                    scope_pins[scope] = urllib.parse.urlparse(url).hostname
            else:
                current_scope = None
                for line in text.splitlines():
                    match = re.match(r"^\s{2}([\w.-]+):\s*$", line)
                    if match:
                        current_scope = "@" + match.group(1)
                    match = re.match(r"^\s+ npmRegistryServer:\s*['\"]?([^'\"\s]+)", line)
                    if match and current_scope:
                        scope_pins[current_scope] = urllib.parse.urlparse(match.group(1)).hostname
    results = []
    for scope, hosts in private.items():
        if any(scope_pins.get(scope) != host for host, _ in hosts):
            results.append(_finding("source.deps.npm-dependency-confusion", "npm", "ERROR", "medium",
                                    f"Scoped package {scope} resolves from a registry that is not pinned for this scope.",
                                    "KB-SUPPLY-DEP-CONFUSION-001", relative,
                                    min(line for _, line in hosts)))
    return results


def _manifest_findings(path, relative, project, lockfiles):
    data = json.loads(path.read_text(encoding="utf-8"))
    maps = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
    dependencies = [(name, version) for section in maps for name, version in (data.get(section) or {}).items()]
    results = []
    if dependencies and not any((parent / lockfile.name).exists() for parent in [path.parent, *path.parents]
                                if parent == project or project in parent.parents for lockfile in lockfiles):
        results.append(_finding("source.deps.manifest-without-lockfile", "npm", "WARNING", "high",
                                "Dependency manifest has no lockfile in this directory or an ancestor.",
                                "KB-SUPPLY-LOCKFILE-TAMPER-001", relative))
    for name, value in dependencies:
        value = str(value).strip()
        if value in ("", "*", "latest", "x") or (re.search(r"(?:^|\|\|)\s*>=?\s*\S+", value) and not re.search(r"<", value)):
            results.append(_finding("source.deps.npm-loose-range", "npm", "WARNING", "high",
                                    f"Dependency {name} uses an open version range.",
                                    "KB-SUPPLY-LOCKFILE-TAMPER-001", relative))
        if value.startswith(("git+", "git:", "github:", "gitlab:", "bitbucket:", "http:", "https:")) or re.fullmatch(r"[^/@\s]+/[^/@\s]+", value):
            results.append(_finding("source.deps.npm-non-registry-source", "npm", "WARNING", "medium",
                                    f"Dependency {name} uses a non-registry source.",
                                    "KB-SUPPLY-DEP-CONFUSION-001", relative))
        if value.startswith(("file:", "link:")):
            target = (path.parent / value.split(":", 1)[1]).resolve()
            if project not in target.parents and target != project:
                results.append(_finding("source.deps.npm-non-registry-source", "npm", "WARNING", "medium",
                                        f"Dependency {name} points outside the project tree.",
                                        "KB-SUPPLY-DEP-CONFUSION-001", relative))
    return results


def _paired_lock(manifest, lockfiles, project, ecosystem):
    parent = manifest.parent
    while parent == project or project in parent.parents:
        if any(lock.parent == parent for lock in lockfiles):
            return True
        if parent == project:
            break
        parent = parent.parent
    if ecosystem == "swiftpm":
        app_names = {manifest.parent.name, manifest.parent.parent.name}
        return any(any(part.endswith((".xcodeproj", ".xcworkspace")) and part.rsplit(".", 1)[0] in app_names
                       for part in lock.parts) for lock in lockfiles)
    return False


def _gradle_roots(files, snapshot):
    manifests = [path for path, ecosystem, kind in files if ecosystem == "gradle" and kind == "manifest"]
    roots = set()
    for manifest in manifests:
        ancestors = []
        current = manifest.parent
        while current == snapshot or snapshot in current.parents:
            ancestors.append(current)
            if current == snapshot:
                break
            current = current.parent
        settings = [parent for parent in ancestors
                    if (parent / "settings.gradle").exists() or (parent / "settings.gradle.kts").exists()]
        if settings:
            roots.add(max(settings, key=lambda item: len(item.parts)))
        else:
            build_roots = [parent for parent in ancestors
                           if (parent / "build.gradle").exists() or (parent / "build.gradle.kts").exists()]
            roots.add(min(build_roots, key=lambda item: len(item.parts)) if build_roots else manifest.parent)
    return sorted(roots)


def assess_dependencies(snapshot, semgrep_results, run, find_tool, *, project, oversize=None, now=None, cwd):
    """Return dependency coverage and findings without sending the inventory anywhere."""
    files = catalog.discover(snapshot)
    hygiene_findings = []
    hygiene_reasons = {name: [] for name in catalog.ECOSYSTEMS}
    oversize_paths = set((oversize or {}).keys())
    for relative in (oversize or {}):
        kind = catalog.FILES.get(Path(relative).name)
        if kind:
            files.append((snapshot / relative, *kind))
        elif Path(relative).name.endswith(".lockfile"):
            files.append((snapshot / relative, "gradle", "lockfile"))
    files.sort(key=lambda item: item[0].as_posix())
    by_ecosystem = {name: [item for item in files if item[1] == name] for name in catalog.ECOSYSTEMS}
    for path, ecosystem, kind in files:
        relative = path.relative_to(snapshot).as_posix()
        if relative in oversize_paths:
            hygiene_reasons[ecosystem].append(f"file exceeds 50 MB: {relative}")
            continue
        if ecosystem == "npm" and kind == "manifest":
            try:
                hygiene_findings.extend(_manifest_findings(path, relative, project, [item[0] for item in by_ecosystem["npm"] if item[2] == "lockfile"]))
            except (OSError, UnicodeError, ValueError, TypeError, AttributeError) as error:
                hygiene_reasons[ecosystem].append(f"could not parse {relative}: {type(error).__name__}")
        if ecosystem == "gradle" and path.name == "libs.versions.toml":
            try:
                tomllib.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
                hygiene_reasons[ecosystem].append(f"could not parse {relative}: {type(error).__name__}")
        if kind == "manifest" and ecosystem in ("cocoapods", "swiftpm", "pub"):
            locks = [lock[0] for lock in by_ecosystem[ecosystem] if lock[2] == "lockfile"]
            if not _paired_lock(path, locks, snapshot, ecosystem):
                confidence = "medium" if ecosystem in ("swiftpm", "pub") else "high"
                hygiene_findings.append(_finding(f"source.deps.{ecosystem}-manifest-without-lockfile", ecosystem,
                                                "WARNING", confidence, "Dependency manifest has no lockfile.",
                                                "KB-SUPPLY-LOCKFILE-TAMPER-001", relative))
        if ecosystem == "npm" and path.name == "bun.lockb" and not (path.parent / "bun.lock").exists():
            hygiene_findings.append(_finding("source.deps.bun-binary-lockfile", ecosystem, "INFO", "high",
                                            "Binary bun.lockb cannot be assessed; migrate to text bun.lock.",
                                            "KB-SUPPLY-LOCKFILE-TAMPER-001", relative))
    gradle_locks = [path for path, ecosystem, kind in files if ecosystem == "gradle" and kind == "lockfile"]
    for root in _gradle_roots(files, snapshot):
        locked = any(root in lock.parents or root == lock.parent for lock in gradle_locks)
        if not locked:
            candidates = [path for path, ecosystem, kind in files
                          if ecosystem == "gradle" and kind == "manifest" and root in path.parents]
            manifest = next((path for path in candidates
                             if path.name in ("settings.gradle", "settings.gradle.kts")), None)
            manifest = manifest or next((path for path in candidates
                                         if path.name in ("build.gradle", "build.gradle.kts")), None) or root
            relative = manifest.relative_to(snapshot).as_posix()
            hygiene_findings.append(_finding("source.deps.gradle-manifest-without-lockfile", "gradle", "WARNING", "high",
                                            "Gradle root has no gradle.lockfile.",
                                            "KB-SUPPLY-LOCKFILE-TAMPER-001", relative))
    for path, ecosystem, kind in files:
        if path.relative_to(snapshot).as_posix() in oversize_paths:
            continue
        if kind != "lockfile" or path.name == "bun.lockb":
            continue
        relative = path.relative_to(snapshot).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
            entries = readers.read_lockfile(path, text)
            if ecosystem == "npm":
                missing = [entry for entry in entries if not entry.get("integrity") and _registry_entry(entry)]
                if missing:
                    hygiene_findings.append(_finding("source.deps.npm-missing-integrity", ecosystem, "WARNING", "medium",
                                                    f"{len(missing)} lockfile entries have no integrity hash.",
                                                    "KB-SUPPLY-LOCKFILE-TAMPER-001", relative, missing[0]["line"]))
                scripted = [entry for entry in entries if entry.get("install")]
                if scripted:
                    hygiene_findings.append(_finding("source.deps.npm-install-script", ecosystem, "INFO", "low",
                                                    f"{len(scripted)} packages run install scripts.",
                                                    "KB-SUPPLY-POSTINSTALL-001", relative, scripted[0]["line"]))
            if path.name in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "bun.lock"):
                hygiene_findings.extend(_dependency_confusion(path, relative, entries, snapshot))
        except (OSError, UnicodeError, json.JSONDecodeError, readers.LockfileParseError, AttributeError) as error:
            detail = str(error) if isinstance(error, readers.LockfileParseError) else type(error).__name__
            hygiene_reasons[ecosystem].append(f"could not parse {relative}: {detail}")
    for result in semgrep_results:
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        raw = Path(result.get("path", ""))
        if not raw.is_absolute():
            raw = snapshot / raw
        try:
            relative = raw.resolve().relative_to(snapshot).as_posix()
        except ValueError:
            continue
        ecosystem = metadata.get("ecosystem", "npm")
        finding = _finding(result.get("check_id", "source.deps.unknown").removeprefix("rules.source."), ecosystem,
                           str(extra.get("severity", "WARNING")).upper(), metadata.get("confidence", "medium"),
                           extra.get("message", "Review this dependency hygiene pattern."),
                           metadata.get("related_technique", "KB-SUPPLY-DEP-CONFUSION-001"), relative,
                           (result.get("start") or {}).get("line") or 1)
        hygiene_findings.append(finding)

    if not files:
        empty = {name: {"status": "not_applicable", "reasons": [], "package_count": None}
                 for name in catalog.ECOSYSTEMS}
        return {
            "vulnerable_dependencies": {"status": "not_applicable", "reasons": [], "scanner": None,
                                         "database": None, "ecosystems": empty, "findings": [], "finding_count": 0},
            "dependency_hygiene": {"status": "not_applicable", "reasons": [], "ecosystems": empty,
                                   "findings": hygiene_findings, "finding_count": len(hygiene_findings)},
            "dependency_inventory_sent_to_network": False,
        }
    hygiene_ecosystems = {}
    vulnerable_ecosystems = {}
    for name, ecosystem_files in by_ecosystem.items():
        if not ecosystem_files:
            status, reasons = "not_applicable", []
        elif hygiene_reasons[name]:
            status, reasons = "partial", sorted(set(hygiene_reasons[name]))
        else:
            status, reasons = "complete", []
        hygiene_ecosystems[name] = {"status": status, "reasons": reasons, "package_count": None}

    version, database, gate_reason = trivy.readiness(run, find_tool, now=now, cwd=cwd)
    trivy_findings = []
    counts = {name: 0 for name in catalog.ECOSYSTEMS}
    returned = set()
    scan_error = None
    trivy_path = find_tool("trivy") if not gate_reason else None
    declared_map = gradle.synthesize(snapshot, files) if not gate_reason else {}
    if not gate_reason:
        try:
            data, _ = trivy.scan(snapshot, run, trivy_path, cwd=cwd)
            trivy_findings, counts, returned = trivy.map_results(data, snapshot, declared_map)
            if database["stale"]:
                print("warning: Trivy vulnerability database is older than 7 days", file=sys.stderr)
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            scan_error = str(error)
    else:
        print(f"warning: vulnerable dependency assessment not run: {gate_reason}", file=sys.stderr)
    if scan_error:
        print(f"warning: vulnerable dependency assessment not run: {scan_error}", file=sys.stderr)
    for name, ecosystem_files in by_ecosystem.items():
        if not ecosystem_files:
            status, reasons = "not_applicable", []
        elif gate_reason or scan_error:
            status, reasons = "not_run", [gate_reason or scan_error]
        else:
            lockfiles = [path for path, eco, kind in files if eco == name and kind == "lockfile"]
            assessable = [path for path in lockfiles if path.name != "bun.lockb" and str(path.relative_to(snapshot)).replace("\\", "/") in returned]
            declared_returned = name == "gradle" and any(target.startswith(".capri-declared/") for target in returned)
            unavailable = []
            if not lockfiles and name != "gradle":
                unavailable.append("no assessable lockfile")
            for path in lockfiles:
                relative = path.relative_to(snapshot).as_posix()
                if relative in oversize_paths:
                    unavailable.append(f"file exceeds 50 MB: {relative}")
            if any(path.name == "bun.lockb" for path in lockfiles) and not any(path.name == "bun.lock" for path in lockfiles):
                unavailable.append("binary bun.lockb is not assessable")
            if name == "gradle" and declared_map:
                unavailable.append("declared versions only; transitive dependencies not covered")
            elif name == "gradle" and any(item[1] == "gradle" and item[2] == "manifest" for item in files) and not lockfiles:
                unavailable.append("no gradle.lockfile and no exact declared versions (versions come from Gradle plugins or variables); add a gradle.lockfile to cover Android dependencies")
            if declared_returned:
                assessable.append(snapshot / ".capri-declared" / "gradle.lockfile")
            elif name == "gradle" and declared_map:
                unavailable.append("scanner returned no packages for declared Gradle versions")
            if lockfiles and not assessable:
                unavailable.append("scanner returned no packages for lockfile")
            if assessable and not unavailable:
                status, reasons = "complete", []
            elif assessable:
                status, reasons = "partial", unavailable
            elif lockfiles and any(path.name != "bun.lockb" and path.exists() and path.stat().st_size
                                   and path.relative_to(snapshot).as_posix() not in oversize_paths for path in lockfiles):
                status, reasons = "partial", unavailable or [f"scanner returned no packages for {lockfiles[0].relative_to(snapshot).as_posix()}"]
            elif name == "gradle" and declared_map:
                status, reasons = "partial", unavailable
            else:
                status, reasons = "not_run", unavailable or ["no assessable lockfile"]
        vulnerable_ecosystems[name] = {"status": status, "reasons": reasons, "package_count": None}
    for name, item in vulnerable_ecosystems.items():
        if item["status"] != "not_applicable":
            item["package_count"] = counts.get(name, 0) if item["status"] != "not_run" else None
    hygiene = {"status": _overall(hygiene_ecosystems), "reasons": sorted({reason for value in hygiene_ecosystems.values() for reason in value["reasons"]}),
               "ecosystems": hygiene_ecosystems, "findings": hygiene_findings, "finding_count": len(hygiene_findings)}
    vulnerable = {"status": _overall(vulnerable_ecosystems),
                  "reasons": sorted({f"{name}: {reason}" for name, item in vulnerable_ecosystems.items() for reason in item["reasons"]}),
                  "scanner": {"name": "trivy", "version": version},
                  "database": database, "ecosystems": vulnerable_ecosystems,
                  "findings": trivy_findings, "finding_count": len(trivy_findings)}
    return {"vulnerable_dependencies": vulnerable, "dependency_hygiene": hygiene,
            "dependency_inventory_sent_to_network": False}
