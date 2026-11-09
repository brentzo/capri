import io
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import terminal


def test_banner_renders_without_color_by_default():
    banner = terminal.render_banner()
    assert banner.isascii()
    assert "\033[" not in banner
    assert banner.splitlines()[0].strip()


def test_print_banner_keeps_plain_output_ascii():
    output = io.StringIO()
    terminal.print_banner("MODEL SETUP", "Choose two providers.", stream=output)
    assert "MODEL SETUP" in output.getvalue()
    assert "\033[" not in output.getvalue()
    assert output.getvalue().isascii()


def test_command_uses_a_windows_friendly_invocation_on_windows():
    expected = "python .\\capri setup" if sys.platform == "win32" else "capri setup"
    assert terminal.command("setup") == expected


def test_help_shows_branded_commands_and_windows_invocation():
    result = subprocess.run([sys.executable, str(ROOT / "capri"), "help"],
                            cwd=ROOT, capture_output=True, text=True, check=True)
    assert "Commands" in result.stdout
    assert "gateway destroy" in result.stdout
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
