import io
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cli import terminal


def test_original_banner_renders_without_color_by_default():
    banner = terminal.render_banner()
    assert "██████╗ █████╗ ██████╗" in banner
    assert "\033[" not in banner
    assert banner.splitlines()[0].strip()


def test_print_banner_keeps_plain_output_uncolored():
    output = io.StringIO()
    terminal.print_banner("MODEL SETUP", "Choose two providers.", stream=output)
    assert "MODEL SETUP" in output.getvalue()
    assert "\033[" not in output.getvalue()
    assert "██████╗ █████╗ ██████╗" in output.getvalue()


def test_command_uses_a_windows_friendly_invocation_on_windows():
    expected = "python .\\capri setup" if sys.platform == "win32" else "capri setup"
    assert terminal.command("setup") == expected


def _load_capri():
    import importlib.machinery
    import importlib.util
    loader = importlib.machinery.SourceFileLoader("capri_cli", str(ROOT / "capri"))
    spec = importlib.util.spec_from_loader("capri_cli", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _run_with_engagement_forbidden(argv):
    """Call `capri <argv>` in-process; fail loudly if it would start an engagement.

    Output is redirected, so stdout is not a terminal and `capri run` takes its plain path,
    which always goes through `tools.run_engagement.main`."""
    from contextlib import redirect_stderr, redirect_stdout
    from unittest.mock import patch

    capri = _load_capri()

    def forbidden(*_args, **_kwargs):
        raise AssertionError(f"capri {' '.join(argv)} started an engagement")

    out, err = io.StringIO(), io.StringIO()
    with patch.object(capri, "_prepare_ui_runtime", return_value=None), \
            patch("tools.run_engagement.main", forbidden), \
            redirect_stdout(out), redirect_stderr(err):
        try:
            code = capri.main(argv)
        except SystemExit as exit_:
            code = exit_.code
    return code, out.getvalue(), err.getvalue()


def test_run_help_prints_usage_instead_of_starting_an_engagement():
    for flag in ("--help", "-h"):
        code, out, _ = _run_with_engagement_forbidden(["run", flag])
        assert code == 0, (flag, code)
        assert "capri run" in out and "--plain" in out, out


def test_run_rejects_unknown_arguments_instead_of_starting_an_engagement():
    code, _, err = _run_with_engagement_forbidden(["run", "--target", "sidequest"])
    assert code == 2, code
    assert "unrecognized arguments" in err, err


def test_run_summary_says_which_role_ran_out_of_credit_and_how_to_fix_it():
    from tools import run_engagement
    lines = run_engagement.model_stop_lines({("verifier", "provider_out_of_credit"): 3,
                                             ("operator", "budget_exhausted"): 1})
    assert len(lines) == 2, lines
    operator_line, verifier_line = lines
    assert "operator" in operator_line and "token budget" in operator_line, operator_line
    assert "verifier" in verifier_line and "3" in verifier_line, verifier_line
    assert "out of credit" in verifier_line and "capri setup" in verifier_line, verifier_line


def test_run_summary_is_silent_when_no_role_stopped():
    from tools import run_engagement
    assert run_engagement.model_stop_lines({}) == []


def test_a_live_run_caps_every_role_output_so_a_small_balance_still_serves():
    import os
    import types
    from unittest.mock import patch

    from harness.store import db
    from tools import run_engagement
    env = {"HC_VK_OPERATOR": "op-secret", "HC_VK_VERIFIER": "ver-secret",
           "HC_OPERATOR_ROUTE": "openai/gpt-4o-mini",
           "HC_VERIFIER_ROUTE": "openrouter/anthropic/claude-haiku-5.5"}
    with patch.dict(os.environ, env):
        operator, verifier, _ = run_engagement.build_roles(
            db.connect(), types.SimpleNamespace(model_budget=1000, id="eng-cap"))
    caps = {role: vk.max_output_tokens for role, vk in operator.plane.vkeys.items()}
    assert caps == {"operator": run_engagement.MAX_OUTPUT_TOKENS,
                    "verifier": run_engagement.MAX_OUTPUT_TOKENS}, caps
    assert 0 < run_engagement.MAX_OUTPUT_TOKENS <= 16384


def test_a_second_run_is_refused_without_touching_the_live_range():
    # Regression: a second `capri run` provisioned over the range of the run already in
    # progress, and its cleanup deleted that run's network mid-engagement.
    import tempfile as tempfile_module
    from unittest.mock import patch

    from harness.sandbox import rangelock
    from tools import run_engagement

    class LiveRange:
        network = "hc-range"

        def __init__(self, **_kwargs):
            pass

        def provision(self, _engagement):
            raise AssertionError("provisioned over a live range")

        def teardown(self):
            raise AssertionError("tore down a live range")

    lines = []
    with tempfile.TemporaryDirectory() as lock_dir, \
            patch.object(tempfile_module, "tempdir", lock_dir):
        live = rangelock.RangeLock("hc-range").acquire()
        try:
            with patch.object(run_engagement, "DockerSandbox", LiveRange), \
                    patch.object(run_engagement.shutil, "which", return_value="docker"):
                code = run_engagement.main(progress=lines.append)
        finally:
            live.release()
    assert code == 1, (code, lines)
    assert any("already running" in line for line in lines), lines


def test_help_shows_branded_commands_and_windows_invocation():
    result = subprocess.run([sys.executable, str(ROOT / "capri"), "help"],
                            cwd=ROOT, capture_output=True, text=True,
                            encoding="utf-8", check=True)
    assert "Commands" in result.stdout
    assert "gateway destroy" in result.stdout
    assert "source --project <path>" in result.stdout
    assert ("python .\\capri setup" if sys.platform == "win32" else "capri setup") in result.stdout


def test_gateway_env_remains_shell_usable_without_a_banner():
    with tempfile.TemporaryDirectory() as state_dir:
        (Path(state_dir) / ".env").write_text(
            "VK_OPERATOR=test-operator\nVK_VERIFIER=test-verifier\n", encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(ROOT / "capri"), "gateway", "--dir", state_dir,
             "--port", "8099", "env"],
            cwd=ROOT, capture_output=True, text=True, check=True)
    assert result.stdout.startswith("export HC_BIFROST_URL=")
    assert "CAPRI" not in result.stdout


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
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
