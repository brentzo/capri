import json
import shutil
import subprocess
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.project_assessment import assess_source
from tools.project_assessment import main as assessment_main


def test_source_assessment_uses_only_local_rules_and_redacts_snippets():
    with tempfile.TemporaryDirectory() as directory:
        project = Path(directory) / "project"
        project.mkdir()
        (project / "src.ts").write_text(
            'const token = "do-not-report-this-secret";\n', encoding="utf-8"
        )
        report_path = Path(directory) / "report.json"
        invocation = {}

        def scanner(command, **kwargs):
            invocation["command"] = command
            invocation["kwargs"] = kwargs
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps(
                    {
                        "results": [
                            {
                                "check_id": "rules.source.source.secrets.hardcoded-credential",
                                "path": str(Path(command[-1]) / "src.ts"),
                                "start": {"line": 1, "col": 1},
                                "end": {"line": 1, "col": 46},
                                "extra": {
                                    "severity": "ERROR",
                                    "message": "Hardcoded credential",
                                    "lines": 'const token = "do-not-report-this-secret";',
                                    "metadata": {
                                        "category": "committed-secrets",
                                        "confidence": "medium",
                                    },
                                },
                            }
                        ],
                        "errors": [],
                    }
                ),
                stderr="",
            )

        result, returned_path = assess_source(
            project,
            output=report_path,
            scanner=scanner,
            find_scanner=lambda name: "semgrep" if name == "semgrep" else None,
        )
        serialized = report_path.read_text(encoding="utf-8")
        command = invocation["command"]

        assert result["source_assessment"]["status"] == "complete"
        assert "committed-secrets" in result["source_assessment"]["areas_reviewed"]
        assert result["source_assessment"]["findings_by_area"]["committed-secrets"] == 1
        assert returned_path == report_path.resolve()
        assert (
            result["source_assessment"]["findings"][0]["rule_id"]
            == "source.secrets.hardcoded-credential"
        )
        assert result["source_assessment"]["findings"][0]["location"] == {
            "path": "src.ts",
            "line": 1,
            "column": 1,
        }
        assert "do-not-report-this-secret" not in serialized
        assert "--metrics=off" in command
        assert "--disable-version-check" in command
        assert "--config" in command and str(ROOT / "rules" / "source") in command
        assert "--json" in command
        assert "--exclude" in command and ".env.*" in command
        assert ".claude" in command and "*.md" in command
        assert Path(command[-1]) != project
        assert "--max-target-bytes=50MB" in command
        assert invocation["kwargs"]["timeout"] > 0
        assert not (project / ".capri").exists()


def test_source_assessment_rejects_report_inside_project():
    with tempfile.TemporaryDirectory() as directory:
        project = Path(directory) / "project"
        project.mkdir()
        try:
            assess_source(
                project,
                output=project / "report.json",
                scanner=lambda *_a, **_k: None,
                find_scanner=lambda _: "semgrep",
            )
        except ValueError as error:
            assert "outside the selected project" in str(error)
        else:
            raise AssertionError("report path inside the project must be refused")


def test_source_assessment_fails_cleanly_without_local_semgrep():
    with tempfile.TemporaryDirectory() as directory:
        project = Path(directory) / "project"
        project.mkdir()
        try:
            assess_source(
                project, scanner=lambda *_a, **_k: None, find_scanner=lambda _: None
            )
        except RuntimeError as error:
            assert "Semgrep CLI was not found" in str(error)
        else:
            raise AssertionError("missing scanner must stop before the scan")


def test_source_assessment_accepts_any_project_layout():
    with tempfile.TemporaryDirectory() as directory:
        project = Path(directory) / "any-app"
        (project / "lib").mkdir(parents=True)
        (project / "lib" / "main.dart").write_text("void main() {}\n", encoding="utf-8")
        empty_scan = lambda command, **_k: subprocess.CompletedProcess(
            command, 0, stdout=json.dumps({"results": [], "errors": []}), stderr=""
        )
        result, _ = assess_source(
            project,
            output=Path(directory) / "report.json",
            scanner=empty_scan,
            find_scanner=lambda name: "semgrep" if name == "semgrep" else None,
        )
        assert result["project"] == "any-app"
        assert result["source_assessment"]["status"] == "complete"
        assert result["source_assessment"]["ruleset"] == "capri-source-1"


def test_source_assessment_scans_a_clean_snapshot_and_preserves_relative_locations():
    with tempfile.TemporaryDirectory() as directory:
        project = Path(directory) / "project"
        project.mkdir()
        source = project / "src.ts"
        source.write_text('const token = "planted-secret";\n', encoding="utf-8")
        (project / ".gitignore").write_text("src.ts\n", encoding="utf-8")
        (project / ".semgrepignore").write_text("src.ts\n", encoding="utf-8")
        (project / ".trivyignore").write_text("CVE-2026-0001\n", encoding="utf-8")
        (project / "trivy.yaml").write_text("ignore-unfixed: true\n", encoding="utf-8")
        (project / "osv-scanner.toml").write_text("[scanner]\n", encoding="utf-8")
        (project / ".env.private").write_text("PRIVATE=must-not-copy\n", encoding="utf-8")
        output = Path(directory) / "report.json"
        call = {}

        def scanner(command, **kwargs):
            snapshot = Path(command[-1])
            call["snapshot"] = snapshot
            assert snapshot != project
            assert (snapshot / "src.ts").read_text(encoding="utf-8") == source.read_text(encoding="utf-8")
            assert not (snapshot / ".gitignore").exists()
            assert not (snapshot / ".semgrepignore").exists()
            assert not (snapshot / ".trivyignore").exists()
            assert not (snapshot / "trivy.yaml").exists()
            assert not (snapshot / "osv-scanner.toml").exists()
            assert not (snapshot / ".env.private").exists()
            assert "--max-target-bytes=50MB" in command
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps({
                    "results": [{
                        "check_id": "rules.source.source.secrets.hardcoded-credential",
                        "path": str(snapshot / "src.ts"),
                        "start": {"line": 1, "col": 1},
                        "extra": {"severity": "ERROR", "message": "Hardcoded credential",
                                  "lines": 'const token = "planted-secret";',
                                  "metadata": {"category": "committed-secrets", "confidence": "medium"}},
                    }],
                    "errors": [],
                }),
                stderr="",
            )

        report, _ = assess_source(project, output=output, scanner=scanner,
                                  find_scanner=lambda name: "semgrep" if name == "semgrep" else None)
        assert report["source_assessment"]["findings"][0]["location"]["path"] == "src.ts"
        assert not call["snapshot"].exists()
        assert set(project.iterdir()) == {source, project / ".gitignore", project / ".semgrepignore",
                                          project / ".trivyignore", project / "trivy.yaml",
                                          project / "osv-scanner.toml", project / ".env.private"}


def test_source_assessment_removes_snapshot_after_scanner_failure():
    with tempfile.TemporaryDirectory() as directory:
        project = Path(directory) / "project"
        project.mkdir()
        (project / "src.ts").write_text("const safe = true;\n", encoding="utf-8")
        snapshot = {}

        def scanner(command, **_kwargs):
            snapshot["path"] = Path(command[-1])
            raise subprocess.TimeoutExpired(command, 1)

        try:
            assess_source(project, output=Path(directory) / "report.json", scanner=scanner,
                          find_scanner=lambda _: "semgrep")
        except RuntimeError as error:
            assert "five-minute limit" in str(error)
        else:
            raise AssertionError("scanner timeout must fail the assessment")
        assert not snapshot["path"].exists()


def test_windows_path_limit_is_reported_as_partial_coverage():
    with tempfile.TemporaryDirectory() as directory:
        project = Path(directory) / "project"
        project.mkdir()
        (project / "source.ts").write_text("const safe = true;\n", encoding="utf-8")
        with patch("tools.project_snapshot.IS_WINDOWS", True), \
                patch("tools.project_snapshot.WINDOWS_PATH_LIMIT", 10):
            report, _ = assess_source(
                project, output=Path(directory) / "report.json",
                scanner=lambda command, **_kwargs: subprocess.CompletedProcess(
                    command, 0, stdout='{"results":[],"errors":[]}', stderr=""),
                find_scanner=lambda name: "semgrep" if name == "semgrep" else None,
            )
        assert report["source_assessment"]["status"] == "partial"
        assert "source.ts" in report["source_assessment"]["reasons"][0]


def test_real_semgrep_matches_each_source_and_dependency_rule_once():
    with tempfile.TemporaryDirectory() as directory:
        project = Path(directory) / "fixture"
        (project / "web").mkdir(parents=True)
        (project / "uploads").mkdir()
        (project / ".gitignore").write_text("web/secrets.ts\n", encoding="utf-8")
        (project / ".semgrepignore").write_text("web/secrets.ts\n", encoding="utf-8")
        (project / "web" / "secrets.ts").write_text(
            'const api_key = "abcd1234567890secret";\nconst safe = process.env.API_KEY;\n'
            'const service_role_key = "private";\nconst anon_key = "public";\n', encoding="utf-8")
        (project / "database.sql").write_text(
            "alter table public.items disable row level security;\n"
            "alter table public.safe enable row level security;\n"
            "create policy open on public.items using (true);\n"
            "create policy scoped on public.safe using (auth.uid() = owner_id);\n"
            "create function unsafe() returns void security definer as $$ select 1; $$ language sql;\n"
            "create function safe() returns void security definer set search_path = public as $$ select 1; $$ language sql;\n",
            encoding="utf-8")
        (project / "config.toml").write_text("verify_jwt = false\nverify_jwt = true\n", encoding="utf-8")
        (project / "uploads" / "UploadHandler.ts").write_text(
            "const bytes = await request.arrayBuffer();\nconst text = await request.text();\n", encoding="utf-8")
        (project / ".npmrc").write_text("registry=http://registry.example.test\n", encoding="utf-8")
        (project / ".yarnrc.yml").write_text('npmRegistryServer: "https://registry.example.test"\n', encoding="utf-8")
        (project / "Podfile").write_text(
            "pod 'Floating', :git => 'https://example.test/repo.git'\n"
            "pod 'Pinned', :git => 'https://example.test/repo.git', :tag => '1.0'\n", encoding="utf-8")
        (project / "Package.resolved").write_text(
            '{"pins":[{"identity":"moving","state":{"branch":"main"}},'
            '{"identity":"fixed","state":{"branch":null}}]}\n', encoding="utf-8")
        (project / "pubspec.lock").write_text(
            "packages:\n  moving:\n    dependency: direct main\n    source: git\n"
            "  fixed:\n    dependency: transitive\n    source: hosted\n", encoding="utf-8")
        (project / "build.gradle").write_text(
            "implementation 'org.example:dynamic:1.+'\n"
            "implementation 'org.example:fixed:1.2.3'\n"
            "maven { url 'http://repo.example.test' }\n"
            "maven { url 'https://repo.example.test' }\n"
            "mavenLocal()\n", encoding="utf-8")
        (project / "libs.versions.toml").write_text(
            '[versions]\nrelease = "latest.release"\nfixed = "1.2.3"\n', encoding="utf-8")
        scanner = shutil.which("semgrep")
        if not scanner:
            raise AssertionError("Semgrep 1.180.0 is required for the real rule fixtures")
        report, _ = assess_source(
            project, output=Path(directory) / "report.json",
            find_scanner=lambda name: scanner if name == "semgrep" else None,
        )
        matches = report["source_assessment"]["findings"] + report["dependency_assessment"]["dependency_hygiene"]["findings"]
        counts = {}
        for item in matches:
            counts[item["rule_id"]] = counts.get(item["rule_id"], 0) + 1
        expected = {
            "source.secrets.hardcoded-credential", "source.database.rls-disabled",
            "source.database.unrestricted-policy", "source.database.definer-search-path",
            "source.edge.manual-auth-required", "source.edge.service-role-in-client",
            "source.upload.server-validation-review", "source.deps.npm-http-registry",
            "source.deps.pod-git-unpinned", "source.deps.swiftpm-branch-pin",
            "source.deps.pub-git-or-path", "source.deps.gradle-dynamic-version",
            "source.deps.gradle-http-repository", "source.deps.gradle-maven-local",
        }
        assert expected <= set(counts), f"missing Semgrep rule matches: {counts}"
        assert all(counts[rule] == (2 if rule == "source.deps.gradle-dynamic-version" else 1)
                   for rule in expected), counts


def test_dependency_confusion_only_flags_unpinned_private_scopes():
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        project = base / "project"
        project.mkdir()
        (project / "package.json").write_text('{"dependencies":{"@private/pkg":"1","@pinned/pkg":"1","@types/react":"1"}}', encoding="utf-8")
        (project / ".npmrc").write_text("@pinned:registry=https://packages.example.test/\n", encoding="utf-8")
        (project / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 1,
            "dependencies": {
                "@private/pkg": {"version": "1.0.0", "resolved": "https://private.example.test/pkg.tgz", "integrity": "sha512-a"},
                "@pinned/pkg": {"version": "1.0.0", "resolved": "https://packages.example.test/pkg.tgz", "integrity": "sha512-b"},
                "@types/react": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/react.tgz", "integrity": "sha512-c"},
            },
        }), encoding="utf-8")
        semgrep = shutil.which("semgrep")
        if not semgrep:
            raise AssertionError("Semgrep 1.180.0 is required for dependency-confusion fixtures")
        report, _ = assess_source(project, output=base / "report.json",
                                  find_scanner=lambda name: semgrep if name == "semgrep" else None)
        confusion = [item for item in report["dependency_assessment"]["dependency_hygiene"]["findings"]
                     if item["rule_id"] == "source.deps.npm-dependency-confusion"]
        assert len(confusion) == 1, report["dependency_assessment"]["dependency_hygiene"]["findings"]
        assert confusion[0]["location"]["path"] == "package-lock.json"
        assert "@private" in confusion[0]["message"]


def test_text_lockfile_readers_handle_yarn_pnpm_bun_and_report_parse_gaps():
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        project = base / "project"
        project.mkdir()
        (project / "package.json").write_text('{"dependencies":{"sample":"^1.0.0"}}', encoding="utf-8")
        (project / "yarn.lock").write_text(
            'sample@^1.0.0:\n  version "1.0.0"\n  resolved "https://registry.yarnpkg.com/sample.tgz"\n  integrity sha512-ok\n',
            encoding="utf-8")
        (project / "pnpm-lock.yaml").write_text(
            "lockfileVersion: '9.0'\npackages:\n  sample@1.0.0:\n    resolution: {tarball: https://registry.npmjs.org/sample.tgz}\n    requiresBuild: true\n",
            encoding="utf-8")
        (project / "bun.lock").write_text(
            '{"packages":{"comma,name":["comma,name@1.0.0","https://registry.npmjs.org/a.tgz",{},],}}\n',
            encoding="utf-8")
        (project / "package-lock.json").write_text('{"lockfileVersion":99,"packages":{}}', encoding="utf-8")

        def scanner(command, **_kwargs):
            return subprocess.CompletedProcess(command, 0, stdout='{"results":[],"errors":[]}', stderr="")

        report, _ = assess_source(project, output=base / "report.json", scanner=scanner,
                                  find_scanner=lambda name: "semgrep" if name == "semgrep" else None)
        area = report["dependency_assessment"]["dependency_hygiene"]
        assert area["ecosystems"]["npm"]["status"] == "partial", area
        assert any("unknown lockfile version 99" in reason for reason in area["ecosystems"]["npm"]["reasons"]), area
        findings = area["findings"]
        missing = [item for item in findings if item["rule_id"] == "source.deps.npm-missing-integrity"]
        assert {item["location"]["path"] for item in missing} == {"bun.lock", "pnpm-lock.yaml"}, findings
        install = [item for item in findings if item["rule_id"] == "source.deps.npm-install-script"]
        assert len(install) == 1 and install[0]["location"]["path"] == "pnpm-lock.yaml", findings


def test_recorded_real_trivy_outputs_cover_each_supported_ecosystem():
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        home = base / "home"
        metadata = home / ".capri" / "trivy" / "db" / "metadata.json"
        metadata.parent.mkdir(parents=True)
        metadata.write_text('{"Version":2,"UpdatedAt":"2026-11-10T19:01:23Z"}', encoding="utf-8")
        fixtures = ROOT / "tests" / "fixtures" / "dependency-assessment"
        for ecosystem in ("npm", "cocoapods", "swiftpm", "pub", "gradle"):
            def runner(command, _ecosystem=ecosystem, **_kwargs):
                if command[0] == "semgrep":
                    return subprocess.CompletedProcess(command, 0, stdout='{"results":[],"errors":[]}', stderr="")
                if "version" in command:
                    return subprocess.CompletedProcess(command, 0, stdout='{"Version":"0.75.0"}', stderr="")
                recorded = (fixtures / f"trivy-results-{_ecosystem}.json").read_text(encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, stdout=recorded, stderr="")

            with patch.object(Path, "home", return_value=home):
                report, _ = assess_source(
                    fixtures / ecosystem, output=base / f"{ecosystem}.report.json", scanner=runner,
                    find_scanner=lambda name: {"semgrep": "semgrep", "trivy": "trivy"}.get(name),
                )
            area = report["dependency_assessment"]["vulnerable_dependencies"]
            assert area["ecosystems"][ecosystem]["status"] == "complete"
            assert area["ecosystems"][ecosystem]["package_count"] == 1
            assert all(item["ecosystem"] == ecosystem for item in area["findings"])


def test_recorded_mixed_and_nested_workspace_scans_keep_lockfiles_separate():
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        home = base / "home"
        metadata = home / ".capri" / "trivy" / "db" / "metadata.json"
        metadata.parent.mkdir(parents=True)
        metadata.write_text('{"Version":2,"UpdatedAt":"2026-11-10T19:01:23Z"}', encoding="utf-8")
        fixtures = ROOT / "tests" / "fixtures" / "dependency-assessment"
        for fixture in ("mixed", "monorepo"):
            def runner(command, _fixture=fixture, **_kwargs):
                if command[0] == "semgrep":
                    return subprocess.CompletedProcess(command, 0, stdout='{"results":[],"errors":[]}', stderr="")
                if "version" in command:
                    return subprocess.CompletedProcess(command, 0, stdout='{"Version":"0.75.0"}', stderr="")
                return subprocess.CompletedProcess(
                    command, 0,
                    stdout=(fixtures / f"trivy-results-{_fixture}.json").read_text(encoding="utf-8"), stderr="",
                )

            with patch.object(Path, "home", return_value=home):
                report, _ = assess_source(
                    fixtures / fixture, output=base / f"{fixture}.report.json", scanner=runner,
                    find_scanner=lambda name: {"semgrep": "semgrep", "trivy": "trivy"}.get(name),
                )
            area = report["dependency_assessment"]["vulnerable_dependencies"]
            if fixture == "mixed":
                assert area["status"] == "partial", area
                assert area["ecosystems"]["npm"]["status"] == "complete", area
                assert area["ecosystems"]["cocoapods"]["status"] == "complete", area
                assert area["ecosystems"]["gradle"]["status"] == "partial", area
            else:
                assert area["status"] == "complete", area
                assert area["ecosystems"]["npm"]["status"] == "complete", area
                paths = {item["location"]["path"] for item in area["findings"]}
                assert any(path.startswith("apps/web/") for path in paths), paths
                assert any(path.startswith("apps/mobile/") for path in paths), paths


def test_stale_trivy_database_warns_without_downgrading_coverage():
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        home = base / "home"
        metadata = home / ".capri" / "trivy" / "db" / "metadata.json"
        metadata.parent.mkdir(parents=True)
        metadata.write_text('{"Version":2,"UpdatedAt":"2026-11-01T00:00:00Z"}', encoding="utf-8")
        fixture = ROOT / "tests" / "fixtures" / "dependency-assessment" / "npm"

        def runner(command, **_kwargs):
            if command[0] == "semgrep":
                return subprocess.CompletedProcess(command, 0, stdout='{"results":[],"errors":[]}', stderr="")
            if "version" in command:
                return subprocess.CompletedProcess(command, 0, stdout='{"Version":"0.75.0"}', stderr="")
            return subprocess.CompletedProcess(
                command, 0, stdout=(ROOT / "tests" / "fixtures" / "dependency-assessment" /
                                    "trivy-results-npm.json").read_text(encoding="utf-8"), stderr="",
            )

        warnings = StringIO()
        with patch.object(Path, "home", return_value=home), redirect_stderr(warnings):
            report, _ = assess_source(
                fixture, output=base / "report.json", scanner=runner,
                find_scanner=lambda name: {"semgrep": "semgrep", "trivy": "trivy"}.get(name),
                now=__import__("datetime").datetime(2026, 11, 11, tzinfo=__import__("datetime").timezone.utc),
            )
        vulnerable = report["dependency_assessment"]["vulnerable_dependencies"]
        assert vulnerable["status"] == "complete"
        assert vulnerable["database"]["stale"] is True
        assert "older than 7 days" in warnings.getvalue()


def test_dependency_assessment_reports_hygiene_and_offline_trivy_advisories():
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        project = base / "project"
        project.mkdir()
        (project / "package.json").write_text(json.dumps({
            "dependencies": {"lodash": "*", "remote": "github:owner/repo", "local": "file:../outside"},
        }), encoding="utf-8")
        (project / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"},
                         "node_modules/scripted": {"version": "1.2.3", "integrity": "sha512-x",
                                                     "hasInstallScript": True}},
        }), encoding="utf-8")
        metadata = base / ".capri" / "trivy" / "db" / "metadata.json"
        metadata.parent.mkdir(parents=True)
        metadata.write_text('{"Version": 2, "UpdatedAt": "2026-11-10T06:00:00.123456789Z"}', encoding="utf-8")
        calls = []

        def runner(command, **kwargs):
            calls.append((command, kwargs))
            if command[0] == "semgrep":
                return subprocess.CompletedProcess(command, 0, stdout='{"results":[],"errors":[]}', stderr="")
            if command[1:3] == ["version", "-f"]:
                return subprocess.CompletedProcess(command, 0, stdout='{"Version":"0.75.0"}', stderr="")
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps({"Results": [{
                "Class": "lang-pkgs", "Type": "npm", "Target": "package-lock.json",
                "Packages": [{"ID": "pkg:npm/lodash@4.17.20", "PkgName": "lodash",
                              "InstalledVersion": "4.17.20", "Locations": [{"StartLine": 4}], "Dev": False}],
                "Vulnerabilities": [{"PkgID": "pkg:npm/lodash@4.17.20", "VulnerabilityID": "CVE-2021-23337",
                                     "VendorIDs": ["GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"],
                                     "Severity": "HIGH", "FixedVersion": "4.17.21", "Title": "Command injection",
                                     "PrimaryURL": "https://example.test/advisory"}],
            }]}), stderr="")

        with patch.object(Path, "home", return_value=base):
            report, _ = assess_source(
                project, output=base / "report.json", scanner=runner,
                find_scanner=lambda name: {"semgrep": "semgrep", "trivy": "trivy"}.get(name),
                now=__import__("datetime").datetime(2026, 11, 11, tzinfo=__import__("datetime").timezone.utc),
            )
        dependency = report["dependency_assessment"]
        assert report["schema_version"] == 2
        assert dependency["dependency_inventory_sent_to_network"] is False
        assert dependency["vulnerable_dependencies"]["ecosystems"]["npm"]["status"] == "complete"
        assert dependency["vulnerable_dependencies"]["ecosystems"]["npm"]["package_count"] == 1
        finding = dependency["vulnerable_dependencies"]["findings"][0]
        assert finding["location"] == {"path": "package-lock.json", "line": 4}
        assert finding["advisory_ids"] == ["CVE-2021-23337", "GHSA-35jh-r3h4-6jhm"]
        assert finding["fixed_versions"] == ["4.17.21"]
        hygiene_ids = {item["rule_id"] for item in dependency["dependency_hygiene"]["findings"]}
        assert {"source.deps.npm-loose-range", "source.deps.npm-non-registry-source",
                "source.deps.npm-missing-integrity", "source.deps.npm-install-script"} <= hygiene_ids
        serialized = (base / "report.json").read_text(encoding="utf-8")
        assert "node_modules/scripted" not in serialized
        assert "package-lock.json" in serialized and "4.17.20" in serialized
        trivy_call = next(command for command, _ in calls if len(command) > 1 and command[1] == "fs")
        assert {"--scanners", "vuln", "--pkg-types", "library", "--include-dev-deps", "--list-all-pkgs",
                "--offline-scan", "--skip-db-update", "--skip-java-db-update", "--skip-check-update",
                "--skip-version-check", "--disable-telemetry", "--ignorefile"} <= set(trivy_call)
        scan_environment = next(kwargs["env"] for command, kwargs in calls if len(command) > 1 and command[1] == "fs")
        assert not any(key.startswith("TRIVY_") for key in scan_environment)


def test_trivy_scan_failure_warns_and_marks_vulnerable_coverage_not_run():
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        project = base / "project"
        project.mkdir()
        (project / "package.json").write_text('{"dependencies":{"lodash":"4.17.20"}}', encoding="utf-8")
        (project / "package-lock.json").write_text(
            '{"lockfileVersion":3,"packages":{"":{"dependencies":{"lodash":"4.17.20"}},'
            '"node_modules/lodash":{"version":"4.17.20"}}}', encoding="utf-8")
        metadata = base / ".capri" / "trivy" / "db" / "metadata.json"
        metadata.parent.mkdir(parents=True)
        metadata.write_text('{"Version":2,"UpdatedAt":"2026-11-10T00:00:00Z"}', encoding="utf-8")

        def runner(command, **kwargs):
            if command[0] == "semgrep":
                return subprocess.CompletedProcess(command, 0, stdout='{"results":[],"errors":[]}', stderr="")
            if command[1:3] == ["version", "-f"]:
                return subprocess.CompletedProcess(command, 0, stdout='{"Version":"0.75.0"}', stderr="")
            return subprocess.CompletedProcess(command, 2, stdout="", stderr="scanner failed")

        warnings = StringIO()
        with patch.object(Path, "home", return_value=base), redirect_stderr(warnings):
            report, _ = assess_source(
                project, output=base / "report.json", scanner=runner,
                find_scanner=lambda name: {"semgrep": "semgrep", "trivy": "trivy"}.get(name),
            )

        vulnerable = report["dependency_assessment"]["vulnerable_dependencies"]
        assert vulnerable["status"] == "not_run"
        assert "Trivy scan failed with exit status 2" in vulnerable["reasons"][0]
        assert "warning: vulnerable dependency assessment not run: Trivy scan failed with exit status 2" in warnings.getvalue()


def test_update_db_uses_the_capri_cache_and_accepts_suffixed_versions():
    with tempfile.TemporaryDirectory() as directory:
        home = Path(directory)
        metadata = home / ".capri" / "trivy" / "db" / "metadata.json"
        calls = []

        def runner(command, **kwargs):
            calls.append((command, kwargs))
            if "version" in command:
                return subprocess.CompletedProcess(command, 0, stdout='{"Version":"0.76.0-rc1"}', stderr="")
            metadata.parent.mkdir(parents=True, exist_ok=True)
            metadata.write_text('{"UpdatedAt":"2026-11-11T00:00:00.123456789Z"}', encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        output = StringIO()
        with patch.object(Path, "home", return_value=home), redirect_stdout(output):
            result = assessment_main(["update-db"], scanner=runner,
                                     find_scanner=lambda name: "trivy" if name == "trivy" else None)
        assert result == 0
        assert "2026-11-11T00:00:00.123456+00:00" in output.getvalue()
        command, kwargs = calls[1]
        assert command[1:3] == ["image", "--download-db-only"]
        assert str(home / ".capri" / "trivy") in command
        assert "--disable-telemetry" in command and "--skip-version-check" in command
        assert "--config" in command and command[command.index("--config") + 1] == ""
        assert not any(key.startswith("TRIVY_") for key in kwargs["env"])


def test_gradle_declared_versions_map_to_manifest_and_keep_partial_coverage():
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        project = base / "android"
        project.mkdir()
        build = project / "build.gradle"
        build.write_text(
            "dependencies {\n"
            "  implementation 'org.example:app:1.2.3'\n"
            "  testImplementation 'org.example:testlib:2.0.0'\n"
            "  implementation 'org.example:dynamic:1.+'\n"
            "}\n", encoding="utf-8")
        metadata = base / ".capri" / "trivy" / "db" / "metadata.json"
        metadata.parent.mkdir(parents=True)
        metadata.write_text('{"Version":2,"UpdatedAt":"2026-11-11T00:00:00Z"}', encoding="utf-8")
        observed = {}

        def runner(command, **kwargs):
            if command[0] == "semgrep":
                return subprocess.CompletedProcess(command, 0, stdout='{"results":[],"errors":[]}', stderr="")
            if "version" in command:
                return subprocess.CompletedProcess(command, 0, stdout='{"Version":"0.75.0"}', stderr="")
            snapshot = Path(command[2])
            lock = snapshot / ".capri-declared" / "1" / "gradle.lockfile"
            observed["lock"] = lock.read_text(encoding="utf-8")
            packages = [
                {"ID": "pkg:maven/org.example/app@1.2.3", "PkgName": "org.example:app",
                 "InstalledVersion": "1.2.3", "Locations": [{"StartLine": 1}]},
                {"ID": "pkg:maven/org.example/testlib@2.0.0", "PkgName": "org.example:testlib",
                 "InstalledVersion": "2.0.0", "Locations": [{"StartLine": 2}]},
            ]
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps({"Results": [{
                "Class": "lang-pkgs", "Type": "gradle", "Target": ".capri-declared/1/gradle.lockfile",
                "Packages": packages, "Vulnerabilities": [
                    {"PkgID": packages[0]["ID"], "VulnerabilityID": "CVE-2026-0001", "Severity": "CRITICAL"},
                    {"PkgID": packages[1]["ID"], "VulnerabilityID": "CVE-2026-0002", "Severity": "HIGH"},
                ],
            }]}), stderr="")

        with patch.object(Path, "home", return_value=base):
            report, _ = assess_source(project, output=base / "report.json", scanner=runner,
                                      find_scanner=lambda name: {"semgrep": "semgrep", "trivy": "trivy"}.get(name))
        findings = report["dependency_assessment"]["vulnerable_dependencies"]["findings"]
        assert "org.example:app:1.2.3=compileClasspath,runtimeClasspath" in observed["lock"]
        assert "org.example:testlib:2.0.0=testCompileClasspath,testRuntimeClasspath" in observed["lock"]
        assert findings[0]["location"] == {"path": "build.gradle", "line": 2}
        assert findings[0]["version_kind"] == "declared" and findings[0]["scope"] == "runtime"
        assert findings[1]["location"] == {"path": "build.gradle", "line": 3}
        assert findings[1]["version_kind"] == "declared" and findings[1]["scope"] == "dev"
        gradle_coverage = report["dependency_assessment"]["vulnerable_dependencies"]["ecosystems"]["gradle"]
        assert gradle_coverage["status"] == "partial"
        assert "declared versions only; transitive dependencies not covered" in gradle_coverage["reasons"]
        assert not (project / ".capri-declared").exists()


def _link_directory(link, target):
    """Create the platform's directory link: a junction on Windows, a symlink elsewhere."""
    if sys.platform == "win32":
        import _winapi
        _winapi.CreateJunction(str(target), str(link))
    else:
        link.symlink_to(target, target_is_directory=True)


def _empty_scan(seen):
    def scanner(command, **_kwargs):
        seen["snapshot"] = Path(command[-1])
        seen["files"] = sorted(p.relative_to(seen["snapshot"]).as_posix()
                               for p in seen["snapshot"].rglob("*") if p.is_file())
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps({"results": [], "errors": []}),
                                           stderr="")
    return scanner


def test_a_broken_directory_link_is_skipped_not_fatal():
    with tempfile.TemporaryDirectory() as directory:
        project = Path(directory) / "project"
        project.mkdir()
        (project / "app.ts").write_text("const ok = true;\n", encoding="utf-8")
        gone = Path(directory) / "gone"
        gone.mkdir()
        _link_directory(project / ".codegraph", gone)
        gone.rmdir()                                      # the link now points nowhere
        seen = {}
        report, _ = assess_source(project, output=Path(directory) / "report.json",
                                  scanner=_empty_scan(seen), find_scanner=lambda _: "semgrep")
        assert report["source_assessment"]["status"] == "complete"
        assert seen["files"] == ["app.ts"]


def test_a_directory_link_out_of_the_project_is_never_followed():
    with tempfile.TemporaryDirectory() as directory:
        project = Path(directory) / "project"
        project.mkdir()
        (project / "app.ts").write_text("const ok = true;\n", encoding="utf-8")
        outside = Path(directory) / "outside"
        outside.mkdir()
        (outside / "leak.ts").write_text('const apiKey = "outside-project-secret";\n', encoding="utf-8")
        _link_directory(project / "linked", outside)
        seen = {}
        assess_source(project, output=Path(directory) / "report.json",
                      scanner=_empty_scan(seen), find_scanner=lambda _: "semgrep")
        assert seen["files"] == ["app.ts"]


def test_android_native_build_output_is_not_copied():
    with tempfile.TemporaryDirectory() as directory:
        project = Path(directory) / "project"
        native = project / "android" / "app" / ".cxx" / "Debug"
        native.mkdir(parents=True)
        (native / "build.ninja").write_text("rule cc", encoding="utf-8")
        (project / "app.ts").write_text("const ok = true;", encoding="utf-8")
        seen = {}
        assess_source(project, output=Path(directory) / "report.json",
                      scanner=_empty_scan(seen), find_scanner=lambda _: "semgrep")
        assert seen["files"] == ["app.ts"]


def test_source_assessment_rejects_a_path_that_is_not_a_directory():
    with tempfile.TemporaryDirectory() as directory:
        try:
            assess_source(
                Path(directory) / "missing",
                scanner=lambda *_a, **_k: None,
                find_scanner=lambda _: "semgrep",
            )
        except ValueError as error:
            assert "not a directory" in str(error)
        else:
            raise AssertionError("a missing project path must be refused")


def test_mixed_coverage_reads_partial_and_says_how_to_cover_gradle():
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        project = base / "project"
        (project / "android" / "app").mkdir(parents=True)
        (project / "package.json").write_text(json.dumps({"dependencies": {"lodash": "^4.17.20"}}),
                                              encoding="utf-8")
        (project / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {"": {}, "node_modules/lodash": {"version": "4.17.20", "integrity": "sha512-x",
                                                         "resolved": "https://registry.npmjs.org/lodash.tgz"}},
        }), encoding="utf-8")
        (project / "android" / "settings.gradle").write_text("include ':app'", encoding="utf-8")
        (project / "android" / "app" / "build.gradle").write_text(
            'dependencies {\n    implementation("com.facebook.react:react-android")\n}\n', encoding="utf-8")
        metadata = base / ".capri" / "trivy" / "db" / "metadata.json"
        metadata.parent.mkdir(parents=True)
        metadata.write_text('{"Version": 2, "UpdatedAt": "2026-11-10T06:00:00Z"}', encoding="utf-8")

        def runner(command, **_kwargs):
            if command[0] == "semgrep":
                return subprocess.CompletedProcess(command, 0, stdout='{"results":[],"errors":[]}', stderr="")
            if command[1:3] == ["version", "-f"]:
                return subprocess.CompletedProcess(command, 0, stdout='{"Version":"0.75.0"}', stderr="")
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps({"Results": [{
                "Class": "lang-pkgs", "Type": "npm", "Target": "package-lock.json",
                "Packages": [{"ID": "pkg:npm/lodash@4.17.20", "PkgName": "lodash",
                              "InstalledVersion": "4.17.20", "Locations": [{"StartLine": 4}], "Dev": False}],
                "Vulnerabilities": [{"PkgID": "pkg:npm/lodash@4.17.20", "VulnerabilityID": "CVE-2021-23337",
                                     "Severity": "HIGH", "FixedVersion": "4.17.21"}],
            }]}), stderr="")

        with patch.object(Path, "home", return_value=base):
            report, _ = assess_source(
                project, output=base / "report.json", scanner=runner,
                find_scanner=lambda name: {"semgrep": "semgrep", "trivy": "trivy"}.get(name),
                now=__import__("datetime").datetime(2026, 11, 11, tzinfo=__import__("datetime").timezone.utc),
            )
        area = report["dependency_assessment"]["vulnerable_dependencies"]
        assert area["ecosystems"]["npm"]["status"] == "complete", area
        assert area["ecosystems"]["gradle"]["status"] == "not_run", area
        assert area["status"] == "partial", area
        assert area["finding_count"] == 1
        gradle_reason = " ".join(area["ecosystems"]["gradle"]["reasons"])
        assert "gradle.lockfile" in gradle_reason and "plugins" in gradle_reason, gradle_reason


def test_coverage_is_not_run_only_when_no_ecosystem_ran():
    with tempfile.TemporaryDirectory() as directory:
        base = Path(directory)
        project = base / "project"
        project.mkdir()
        (project / "package.json").write_text(json.dumps({"dependencies": {"lodash": "^4.17.20"}}),
                                              encoding="utf-8")
        (project / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {"": {}}}),
                                                   encoding="utf-8")

        def runner(command, **_kwargs):
            return subprocess.CompletedProcess(command, 0, stdout='{"results":[],"errors":[]}', stderr="")

        report, _ = assess_source(project, output=base / "report.json", scanner=runner,
                                  find_scanner=lambda name: "semgrep" if name == "semgrep" else None)
        area = report["dependency_assessment"]["vulnerable_dependencies"]
        assert area["ecosystems"]["npm"]["status"] == "not_run", area
        assert area["status"] == "not_run", area


def main():
    tests = [
        value for name, value in sorted(globals().items()) if name.startswith("test_")
    ]
    failed = 0
    for test in tests:
        try:
            test()
            print(f"  ok   {test.__name__}")
        except AssertionError as error:
            failed += 1
            print(f"  FAIL {test.__name__}: {error}")
        except Exception as error:  # noqa: BLE001
            failed += 1
            print(f"  ERR  {test.__name__}: {type(error).__name__}: {error}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
