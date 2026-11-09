#!/usr/bin/env python3
"""Capri model setup - a terminal UI to pick your models and start the gateway.

This is the native, no-browser way a self-hoster configures the model plane on their
own machine. It offers the providers from the catalog Capri owns (`tools/catalog.py`)
as one list of models grouped by provider: choose a model for the Operator and a
different-provider model for the Verifier (the finder never verifies on its own model),
give your API keys with no echo, and it brings the Bifrost gateway up
(`tools/modelplane.py`) - Bifrost stays invisible.

    capri setup            # full-screen TUI where the terminal supports it
    capri setup --plain    # line-by-line prompts (and the automatic fallback)

Navigation in the full-screen UI: ↑/↓ move, Enter selects, Esc steps back (and quits
from the first screen), q quits. The UI uses the standard-library `curses`, which ships
on macOS and Linux; where it is absent (notably Windows) or the output is not a
terminal, setup falls back to plain prompts. No third-party dependency either way. Keys
are read with no echo and written only into the gateway's env, never printed or logged.
"""
import argparse
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tools import catalog, modelplane, terminal                     # noqa: E402

try:
    import curses
except ImportError:                                                 # e.g. Windows
    curses = None


def _state_dir(args):
    return modelplane.state_dir(types.SimpleNamespace(dir=args.dir))


def _launch(args, op, ver, keys, progress):
    """Build the pairing, merge in the keys, and bring the gateway up. `op`/`ver` are
    (provider, model); `keys` is {key_env: value}."""
    try:
        plane = modelplane.build_plane(op, ver)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    sd = _state_dir(args)
    env = modelplane.load_env(sd)
    env.update({k: v for k, v in keys.items() if v})
    missing = modelplane.missing_provider_keys(env, plane)
    if missing:
        providers = [catalog.label(s["provider"]) for s in plane.values()
                     if s["key_env"] in missing]
        return {"ok": False, "error": "API keys required for: " + ", ".join(providers)}
    if not modelplane.have_docker():
        return {"ok": False, "error": "Docker was not found. Install Docker Desktop "
                "(or set HC_CONTAINER=podman), then run setup again."}
    return modelplane.bring_up(sd, plane, env, port=args.port, progress=progress)


def _run_command_hint():
    return terminal.command("run")


# --- full-screen curses UI -------------------------------------------------------

C_TITLE, C_SEL, C_DIM, C_OK, C_WARN, C_KEY = 1, 2, 3, 4, 5, 6


def _init_colors():
    if not curses.has_colors():
        return
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(C_TITLE, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(C_SEL, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(C_DIM, -1, -1)
    curses.init_pair(C_OK, curses.COLOR_GREEN, -1)
    curses.init_pair(C_WARN, curses.COLOR_YELLOW, -1)
    curses.init_pair(C_KEY, curses.COLOR_CYAN, -1)


def _cp(n):
    return curses.color_pair(n) if curses.has_colors() else 0


def _safe(stdscr, y, x, text, attr=0):
    h, w = stdscr.getmaxyx()
    if 0 <= y < h and x < w:
        try:
            stdscr.addstr(y, x, text[:w - x - 1], attr)
        except curses.error:
            pass


def _header(stdscr, state):
    stdscr.erase()
    w = stdscr.getmaxyx()[1]
    title = f" CAPRI / MODEL SETUP   {state.get('step', '')}"
    _safe(stdscr, 0, 0, title.ljust(w), _cp(C_TITLE) | curses.A_BOLD)
    _safe(stdscr, 2, 2, "Operator", curses.A_BOLD)
    _safe(stdscr, 2, 12, _role_summary(state, "operator"), _cp(C_DIM))
    _safe(stdscr, 3, 2, "Verifier", curses.A_BOLD)
    _safe(stdscr, 3, 12, _role_summary(state, "verifier"), _cp(C_DIM))
    _safe(stdscr, 4, 2, "─" * max(0, w - 4), _cp(C_DIM))


def _role_summary(state, role):
    r = state.get(role) or {}
    if not r.get("provider"):
        return "not selected"
    return f"{catalog.label(r['provider'])} / {r.get('model') or '?'}"


def _row(stdscr, y, w, label, selected):
    prefix = "›" if selected else " "
    attr = _cp(C_SEL) | curses.A_BOLD if selected else _cp(C_DIM)
    _safe(stdscr, y, 2, f"{prefix} {label}".ljust(w - 4), attr)


def _clear_below(stdscr, top):
    for y in range(top, stdscr.getmaxyx()[0]):
        stdscr.move(y, 0)
        stdscr.clrtoeol()


def _footer(stdscr, text):
    _safe(stdscr, stdscr.getmaxyx()[0] - 1, 2, text, _cp(C_DIM))


# -- a scrollable list of all models, grouped by provider --

def _rows_for(exclude):
    rows = []
    for p in catalog.providers():
        if p == exclude:
            continue
        rows.append(("header", p, None))
        for m in catalog.models(p):
            rows.append(("model", p, m))
        rows.append(("other", p, None))
    return rows


def _next_selectable(rows, start, step):
    i = start
    while 0 <= i < len(rows):
        if rows[i][0] != "header":
            return i
        i += step
    return None


def _model_picker(stdscr, state, role, exclude=None):
    """Return ('ok', provider, model) | ('back', None, None) | ('quit', None, None)."""
    rows = _rows_for(exclude)
    sel = _next_selectable(rows, 0, 1)
    top = 0
    note = f"  (not {catalog.label(exclude)})" if exclude else ""
    while True:
        _header(stdscr, state)
        h, w = stdscr.getmaxyx()
        _clear_below(stdscr, 6)
        _safe(stdscr, 6, 2, f"Choose the {role.title()} model{note}", curses.A_BOLD)
        list_top, visible = 8, max(1, stdscr.getmaxyx()[0] - 9)
        if sel < top:
            top = sel
        elif sel >= top + visible:
            top = sel - visible + 1
        # keep a group's header on screen with its first item, so scrolling back to the
        # very top never clips the provider header above the selected model
        if visible > 1 and sel > 0 and rows[sel - 1][0] == "header":
            top = min(top, sel - 1)
        for ri in range(top, min(len(rows), top + visible)):
            kind, prov, model = rows[ri]
            y = list_top + (ri - top)
            if kind == "header":
                _safe(stdscr, y, 2, catalog.label(prov).upper(), _cp(C_KEY) | curses.A_BOLD)
            else:
                _row(stdscr, y, w, f"  {model}" if kind == "model" else "  + other model…",
                     ri == sel)
        _footer(stdscr, "↑↓ move · Enter select · Esc back · q quit")
        stdscr.refresh()
        ch = stdscr.getch()
        if ch in (curses.KEY_UP, ord("k")):
            sel = _next_selectable(rows, sel - 1, -1) or sel
        elif ch in (curses.KEY_DOWN, ord("j")):
            sel = _next_selectable(rows, sel + 1, 1) or sel
        elif ch in (curses.KEY_ENTER, 10, 13):
            kind, prov, model = rows[sel]
            if kind == "model":
                return "ok", prov, model
            typed = _input(stdscr, state, f"Type the {role.title()} model for {catalog.label(prov)}")
            if typed:
                return "ok", prov, typed
        elif ch == 27:
            return "back", None, None
        elif ch == ord("q"):
            return "quit", None, None


def _input(stdscr, state, prompt, *, mask=False, default=""):
    """One-line editor; returns the string, or None on Esc. Enter on empty keeps
    `default`; masked input echoes dots."""
    buf = [] if mask else list(default)
    while True:
        _header(stdscr, state)
        h, w = stdscr.getmaxyx()
        _clear_below(stdscr, 6)
        _safe(stdscr, 6, 2, prompt, curses.A_BOLD)
        if default and not mask:
            _safe(stdscr, 7, 2, f"(Enter keeps {default})", _cp(C_DIM))
        shown = ("•" * len(buf)) if mask else "".join(buf)
        _safe(stdscr, 9, 2, "> ", _cp(C_KEY))
        _safe(stdscr, 9, 4, shown + " ")
        _footer(stdscr, "Enter accept · Esc back")
        try:
            stdscr.move(9, min(4 + len(shown), w - 2))
        except curses.error:
            pass
        stdscr.refresh()
        ch = stdscr.getch()
        if ch in (curses.KEY_ENTER, 10, 13):
            text = "".join(buf)
            return text if text else default
        if ch == 27:
            return None
        if ch in (curses.KEY_BACKSPACE, 127, 8):
            if buf:
                buf.pop()
        elif 32 <= ch < 127:
            buf.append(chr(ch))


def _menu(stdscr, state, prompt, items):
    """Simple vertical menu; returns an index, or None on Esc."""
    idx = 0
    while True:
        _header(stdscr, state)
        w = stdscr.getmaxyx()[1]
        _clear_below(stdscr, 6)
        _safe(stdscr, 6, 2, prompt, curses.A_BOLD)
        for i, label in enumerate(items):
            _row(stdscr, 8 + i, w, label, i == idx)
        _footer(stdscr, "↑↓ move · Enter select · Esc back")
        stdscr.refresh()
        ch = stdscr.getch()
        if ch in (curses.KEY_UP, ord("k")):
            idx = (idx - 1) % len(items)
        elif ch in (curses.KEY_DOWN, ord("j")):
            idx = (idx + 1) % len(items)
        elif ch in (curses.KEY_ENTER, 10, 13):
            return idx
        elif ch == 27:
            return None


def _key_step(stdscr, state, role):
    r = state[role]
    key = _input(stdscr, state,
                 f"{catalog.label(r['provider'])} API key for the {role}  (hidden)",
                 mask=True, default=r.get("key", ""))
    if key is None:
        return "back"
    r["key"] = key
    return "ok"


def _confirm_and_launch(stdscr, state, args):
    choice = _menu(stdscr, state, "Start the gateway with these two models?",
                   ["Start", "Back", "Quit"])
    if choice is None or choice == 1:
        return "back", None
    if choice == 2:
        return "quit", None
    op, ver = state["operator"], state["verifier"]

    def progress(msg):
        _header(stdscr, state)
        _clear_below(stdscr, 6)
        _safe(stdscr, 6, 2, "Starting the gateway", curses.A_BOLD)
        _safe(stdscr, 8, 4, msg + " …", _cp(C_KEY))
        stdscr.refresh()

    res = _launch(args, (op["provider"], op["model"]), (ver["provider"], ver["model"]),
                  {catalog.key_env(op["provider"]): op.get("key", ""),
                   catalog.key_env(ver["provider"]): ver.get("key", "")}, progress)
    _show_result(stdscr, state, res)
    return "done", res


def _show_result(stdscr, state, res):
    _header(stdscr, state)
    _clear_below(stdscr, 6)
    if res["ok"]:
        _safe(stdscr, 6, 2, "✓ Gateway healthy.", _cp(C_OK) | curses.A_BOLD)
        _safe(stdscr, 8, 4, f"Operator  {res['routes']['operator']}", _cp(C_DIM))
        _safe(stdscr, 9, 4, f"Verifier  {res['routes']['verifier']}", _cp(C_DIM))
        _safe(stdscr, 11, 2, "Run an engagement with:", curses.A_BOLD)
        _safe(stdscr, 12, 4, _run_command_hint(), _cp(C_KEY))
    else:
        _safe(stdscr, 6, 2, "✗ Could not start the gateway.", _cp(C_WARN) | curses.A_BOLD)
        _safe(stdscr, 8, 4, res["error"], _cp(C_DIM))
    _footer(stdscr, "press any key to exit")
    stdscr.refresh()
    stdscr.getch()


def _run_curses(stdscr, args):
    curses.curs_set(0)
    stdscr.keypad(True)
    _init_colors()
    state = {"operator": {}, "verifier": {}}
    steps = ("op_model", "op_key", "ver_model", "ver_key", "confirm")
    i = 0
    while 0 <= i < len(steps):
        step = steps[i]
        state["step"] = f"{i + 1}/5  {step.replace('_', ' ').upper()}"
        if step == "op_model":
            action, prov, model = _model_picker(stdscr, state, "operator")
            if action == "ok":
                state["operator"].update(provider=prov, model=model)
        elif step == "ver_model":
            action, prov, model = _model_picker(stdscr, state, "verifier",
                                                exclude=state["operator"]["provider"])
            if action == "ok":
                state["verifier"].update(provider=prov, model=model)
        elif step == "op_key":
            action = _key_step(stdscr, state, "operator")
        elif step == "ver_key":
            action = _key_step(stdscr, state, "verifier")
        else:
            action, res = _confirm_and_launch(stdscr, state, args)
            if action == "done":
                return res
        if action == "quit":
            return None
        i += -1 if action == "back" else 1       # Esc on the first screen falls out = quit
    return None


# --- plain line-by-line flow (fallback, and --plain) -----------------------------

def _flat_choices(exclude=None):
    choices = []
    for p in catalog.providers():
        if p == exclude:
            continue
        for m in catalog.models(p):
            choices.append((p, m))
        choices.append((p, None))                # "type a model"
    return choices


def _choose_role_plain(role, *, exclude=None):
    import getpass
    choices = _flat_choices(exclude)
    step = 1 if role == "operator" else 2
    print(f"\nStep {step}/2 · Choose {role.title()} model" +
          (f" (provider must differ from {catalog.label(exclude)})" if exclude else ""))
    last = None
    for i, (p, m) in enumerate(choices, 1):
        if p != last:
            print(f"  {catalog.label(p)}:")
            last = p
        print(f"    {i:2}) {m if m else '(type a model name)'}")
    while True:
        raw = input("  > ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(choices):
            provider, model = choices[int(raw) - 1]
            break
        print("  pick a number from the list.")
    if model is None:
        model = input(f"  {catalog.label(provider)} model: ").strip()
    key = getpass.getpass(f"  {catalog.label(provider)} API key for the {role} (hidden): ").strip()
    return {"provider": provider, "model": model, "key": key}


def _run_plain(args):
    terminal.print_banner("MODEL SETUP", "Choose two providers. Operator and Verifier must differ.")
    op = _choose_role_plain("operator")
    ver = _choose_role_plain("verifier", exclude=op["provider"])
    print("\nStarting the gateway …")
    res = _launch(args, (op["provider"], op["model"]), (ver["provider"], ver["model"]),
                  {catalog.key_env(op["provider"]): op["key"],
                   catalog.key_env(ver["provider"]): ver["key"]},
                  lambda m: print(f"  {m} …"))
    if res["ok"]:
        print(f"\n✓ Gateway healthy.  operator={res['routes']['operator']}  "
              f"verifier={res['routes']['verifier']}")
        print("Run an engagement with:\n  " + _run_command_hint())
        return res
    print("\n✗ Could not start the gateway:", res["error"])
    if res.get("logs"):
        print(res["logs"])
    return res


def main(argv=None):
    p = argparse.ArgumentParser(description="Capri model setup (pick models, start the gateway).")
    p.add_argument("--dir", help="state dir (default ~/.hackculture/modelplane)")
    p.add_argument("--port", type=int, default=modelplane.DEFAULT_PORT, help="localhost port")
    p.add_argument("--plain", action="store_true", help="line-by-line prompts, no full-screen UI")
    args = p.parse_args(argv)

    use_tui = curses is not None and sys.stdin.isatty() and sys.stdout.isatty() and not args.plain
    if use_tui:
        try:
            res = curses.wrapper(_run_curses, args)
        except curses.error:
            res = _run_plain(args)            # a terminal too small or unusual: fall back
    else:
        res = _run_plain(args)
    return 0 if (res and res.get("ok")) else 1


if __name__ == "__main__":
    sys.exit(main())
