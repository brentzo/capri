import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.project_assessment import assess_source


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
                                "path": str(project / "src.ts"),
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
            find_scanner=lambda _: "semgrep",
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
        assert str(project) in command
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
            find_scanner=lambda _: "semgrep",
        )
        assert result["project"] == "any-app"
        assert result["source_assessment"]["status"] == "complete"
        assert result["source_assessment"]["ruleset"] == "capri-source-1"


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
