"""Shared, dependency-free styling for Capri's terminal commands."""
import os
import sys

ART = """\
  ____     _     ____    ____    ___
 / ___|   / \\   |  _ \\  |  _ \\  |_ _|
| |      / _ \\  | |_) | | |_) |  | |
| |___  / ___ \\ |  __/  |  _ <   | |
 \\____|/_/   \\_\\|_|     |_| \\_\\ |___|"""


def render_banner(*, color=False):
    art = "\n".join("  " + line for line in ART.splitlines())
    return f"\033[36m{art}\033[0m" if color else art


def print_banner(title, subtitle=None, *, stream=None):
    stream = stream or sys.stdout
    color = stream.isatty() and not os.environ.get("NO_COLOR")
    bold, dim, reset = ("\033[1m", "\033[2m", "\033[0m") if color else ("", "", "")
    stream.write("\n" + render_banner(color=color) + "\n\n")
    stream.write(f"  {bold}{title}{reset}\n")
    if subtitle:
        stream.write(f"  {dim}{subtitle}{reset}\n")
    stream.write("\n")


def command(subcommand):
    prefix = "python .\\capri" if os.name == "nt" else "capri"
    return f"{prefix} {subcommand}".rstrip()
