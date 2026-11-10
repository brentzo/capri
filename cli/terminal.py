"""Shared, dependency-free styling for Capri's terminal commands."""
import os
import sys

ART = """\
 ██████╗ █████╗ ██████╗ ██████╗ ██╗
██╔════╝██╔══██╗██╔══██╗██╔══██╗██║
██║     ███████║██████╔╝██████╔╝██║
██║     ██╔══██║██╔═══╝ ██╔══██╗██║
╚██████╗██║  ██║██║     ██║  ██║██║
 ╚═════╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝"""


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


def rich_console():
    """Return Rich's terminal-aware console when the optional CLI UI deps are available."""
    try:
        from rich.console import Console
    except ImportError:
        return None
    return Console()


def print_status(message, *, style="cyan", stream=None):
    """Print one colored status line, falling back cleanly for plain environments."""
    try:
        from rich.text import Text
    except ImportError:
        (stream or sys.stdout).write(message + "\n")
        return
    console = rich_console()
    if console is None:
        (stream or sys.stdout).write(message + "\n")
        return
    console.print(Text(message, style=style))
