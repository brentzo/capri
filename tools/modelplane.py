#!/usr/bin/env python3
"""Stand up the Bifrost model-plane gateway from a chosen provider pairing (HC-MODEL-01).

The harness drives commercial models through one Bifrost gateway, with a virtual key
per role so no role ever holds a provider key (`harness/modelplane.py`). That gateway is
infrastructure, the way Docker is for the sandbox, and it runs on the user's own
machine - no cloud account. This module owns the mechanics of bringing it up from a
pairing (which provider/model is the Operator, which is the Verifier) chosen from the
catalog Capri owns (`tools/catalog.py`). The interactive way to choose that pairing and
drop in keys is the setup TUI (`cli/setup.py`); this module is what it calls, and it
also exposes a plain CLI (`up`/`keys`/`env`/`status`/`down`/`destroy`).

The one step that is never automated, by design, is the user supplying their own
provider API keys. Those are secrets: they are read with no echo, written straight into
the gateway's env, and never committed, printed, or passed as process arguments.

State (the generated config, the chosen pairing, and the `.env` holding the keys and
virtual keys) lives outside the repo, under ~/.hackculture/modelplane by default, so
secrets never land in a working tree. Override with --dir or HC_MODELPLANE_DIR. The
gateway binds to 127.0.0.1 only, so the keys it holds are never exposed on the network.

Requires Docker (or set HC_CONTAINER=podman). This is an ops tool, not part of the
harness runtime; the harness itself stays dependency-free and talks to a gateway URL.
"""
import argparse
import getpass
import json
import os
import pathlib
import secrets
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cli import terminal                                              # noqa: E402
from tools import catalog                                             # noqa: E402

IMAGE = "maximhq/bifrost:latest"
SEED_IMAGE = "alpine:3.20"           # tiny, root, only used to seed config + perms
CONTAINER = os.environ.get("HC_GATEWAY_NAME", "hc-bifrost")
VOLUME = os.environ.get("HC_GATEWAY_VOLUME", "hc-bifrost-data")
DEFAULT_PORT = 8099


# --- the operator/verifier pairing ----------------------------------------------

def role_entry(provider, model=None):
    """A pairing role entry from a catalog provider (and optional model override)."""
    return {"provider": provider, "model": model or catalog.default_model(provider),
            "key_env": catalog.key_env(provider)}


# The default pairing when the user has not chosen one: a diverse, proven pair drawn
# from the catalog (Operator on DeepSeek, Verifier on OpenAI), providers disjoint.
DEFAULT_PLANE = {"operator": role_entry("deepseek"), "verifier": role_entry("openai")}


def build_plane(operator, verifier):
    """A pairing from (provider, model) picks for each role, validated against the
    catalog's one invariant: both known, and on different providers (HC-MODEL-01 §4)."""
    reason = catalog.validate_pairing(operator[0], verifier[0])
    if reason:
        raise ValueError(reason)
    return {"operator": role_entry(*operator), "verifier": role_entry(*verifier)}


# --- pure helpers (no Docker; unit-tested in tests/test_modelplane_setup.py) -----

def plane_routes(plane=DEFAULT_PLANE):
    """role -> Bifrost model route, e.g. {'operator': 'deepseek/deepseek-chat'}."""
    return {role: f"{s['provider']}/{s['model']}" for role, s in plane.items()}


def build_bifrost_config(plane=DEFAULT_PLANE):
    """The Bifrost gateway config (providers + per-role virtual keys) as a dict. Every
    credential is an `env.VAR` reference, never a literal secret, and the structure
    encodes the diversity invariant: one provider per virtual key, the two disjoint."""
    providers, vkeys = {}, []
    for role, s in plane.items():
        prov, model, key_id = s["provider"], s["model"], f"key-{s['provider']}"
        providers[prov] = {"keys": [{"id": key_id, "name": prov, "weight": 1.0,
                                     "models": [model], "value": f"env.{s['key_env']}"}]}
        vkeys.append({"id": f"vk-{role}", "name": f"vk-{role}", "is_active": True,
                      "value": f"env.VK_{role.upper()}",
                      "provider_configs": [{"provider": prov, "key_ids": [key_id],
                                            "allowed_models": [model], "weight": 1.0}]})
    return {"providers": providers, "governance": {"virtual_keys": vkeys}}


_VK_ABBR = {"operator": "op", "verifier": "ver"}


def new_vkeys(plane=DEFAULT_PLANE):
    """Fresh per-role gateway virtual-key secrets. The `sk-bf-` prefix is what Bifrost
    accepts as a caller-supplied key verbatim."""
    return {f"VK_{role.upper()}": f"sk-bf-{_VK_ABBR.get(role, role)}-{secrets.token_hex(16)}"
            for role in plane}


def env_keys(plane=DEFAULT_PLANE):
    """The ordered keys of the gateway .env: provider keys first, then virtual keys."""
    return [s["key_env"] for s in plane.values()] + [f"VK_{r.upper()}" for r in plane]


def parse_env(text):
    """Parse a KEY=VALUE .env file into a dict, ignoring blanks and # comments."""
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def render_env(env, plane=DEFAULT_PLANE):
    """Render the gateway .env, with a header that warns it holds secrets."""
    lines = ["# hackculture model-plane gateway secrets - DO NOT COMMIT.",
             "# Provider keys are pay-as-you-go API keys (not chat subscriptions).",
             f"# Routes: {', '.join(f'{r}={route}' for r, route in plane_routes(plane).items())}"]
    for k in env_keys(plane):
        lines.append(f"{k}={env.get(k, '')}")
    return "\n".join(lines) + "\n"


def missing_provider_keys(env, plane=DEFAULT_PLANE):
    """Provider key env names whose value is still empty (gateway cannot route them)."""
    return [s["key_env"] for s in plane.values() if not env.get(s["key_env"], "").strip()]


# --- state on disk --------------------------------------------------------------

def state_dir(args):
    d = getattr(args, "dir", None) or os.environ.get("HC_MODELPLANE_DIR") or str(
        pathlib.Path.home() / ".hackculture" / "modelplane")
    return pathlib.Path(d)


def load_env(sd):
    f = sd / ".env"
    return parse_env(f.read_text()) if f.exists() else {}


def save_env(sd, env, plane=DEFAULT_PLANE):
    sd.mkdir(parents=True, exist_ok=True)
    f = sd / ".env"
    f.write_text(render_env(env, plane))
    try:
        os.chmod(f, 0o600)              # secrets: owner-only
    except OSError:
        pass                            # best effort (e.g. Windows)


def save_plane(sd, plane):
    sd.mkdir(parents=True, exist_ok=True)
    (sd / "plane.json").write_text(json.dumps(plane, indent=2) + "\n")


def load_plane(sd):
    """The pairing this gateway was last brought up with, or the default."""
    f = sd / "plane.json"
    if f.exists():
        try:
            p = json.loads(f.read_text())
            if isinstance(p, dict) and {"operator", "verifier"} <= set(p):
                return p
        except (ValueError, OSError):
            pass
    return DEFAULT_PLANE


# --- Docker ops -----------------------------------------------------------------

def container_cmd():
    return os.environ.get("HC_CONTAINER", "docker")


def have_docker():
    import shutil
    return shutil.which(container_cmd()) is not None


def _run(args, **kw):
    kw.setdefault("check", False)
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    return subprocess.run([container_cmd(), *args], **kw)


def _health(name):
    r = _run(["inspect", "--format", "{{if .State.Health}}{{.State.Health.Status}}"
              "{{else}}{{.State.Status}}{{end}}", name])
    return r.stdout.strip() if r.returncode == 0 else "absent"


def _wait_healthy(name, *, timeout, sleep=time.sleep):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        h = _health(name)
        if h == "healthy":
            return True
        if h in ("absent", "exited", "dead"):
            return False
        sleep(2)
    return _health(name) == "healthy"


def _current_port():
    r = _run(["port", CONTAINER, "8080"])
    if r.returncode == 0 and ":" in r.stdout:
        try:
            return int(r.stdout.strip().rsplit(":", 1)[1])
        except ValueError:
            return None
    return None


def bring_up(sd, plane, env, *, port, progress=lambda m: None):
    """Generate the gateway config from a pairing, seed it into a Docker-managed volume
    (over stdin, group-0 writable so Bifrost can write its stores), run the container on
    127.0.0.1:port, and wait for health. Headless and result-returning so the setup TUI
    and the CLI share one path. Returns {ok, routes?, error?, logs?}."""
    missing = missing_provider_keys(env, plane)
    if missing:
        return {"ok": False, "error": "missing provider API keys: " + ", ".join(missing)}
    save_plane(sd, plane)
    for k, v in new_vkeys(plane).items():
        env.setdefault(k, v)                        # mint once; never rotate silently
    for s in plane.values():
        env.setdefault(s["key_env"], "")
    save_env(sd, env, plane)
    config_text = json.dumps(build_bifrost_config(plane), indent=2) + "\n"
    (sd / "config.json").write_text(config_text)

    progress("creating the data volume")
    _run(["volume", "create", VOLUME])
    # Seed config over stdin (not a host bind mount, so it survives Docker Desktop file
    # sharing and odd /tmp setups) and make the dir group-0 writable so the gateway
    # (uid 1000, gid 0) can create its config.db / logs.db.
    progress("seeding the gateway config")
    seed = _run(["run", "--rm", "-i", "-v", f"{VOLUME}:/data", SEED_IMAGE, "sh", "-c",
                 "cat > /data/config.json && chmod 0775 /data && chmod 0664 /data/config.json"],
                input=config_text)
    if seed.returncode != 0:
        return {"ok": False, "error": f"could not seed the gateway config: {seed.stderr.strip()}"}

    progress("starting the gateway")
    _run(["rm", "-f", CONTAINER])
    run = _run(["run", "-d", "--name", CONTAINER, "-p", f"127.0.0.1:{port}:8080",
                "--env-file", str(sd / ".env"), "-v", f"{VOLUME}:/app/data",
                "--restart", "unless-stopped", IMAGE])
    if run.returncode != 0:
        return {"ok": False, "error": f"could not start the gateway: {run.stderr.strip()}"}

    progress("waiting for the gateway to report healthy")
    if not _wait_healthy(CONTAINER, timeout=60):
        return {"ok": False, "error": "the gateway did not report healthy in time",
                "logs": _run(["logs", "--tail", "15", CONTAINER]).stdout}
    return {"ok": True, "routes": plane_routes(plane)}


# --- plain CLI (the TUI in cli/setup.py is the interactive way) ------------------

def up(args):
    if not have_docker():
        sys.exit(f"{container_cmd()} not found. Install Docker, or set HC_CONTAINER=podman.")
    sd = state_dir(args)
    plane = load_plane(sd)                           # persisted choice, else the default
    res = bring_up(sd, plane, load_env(sd), port=args.port,
                   progress=lambda message: terminal.print_status(f"›  {message} …"))
    if not res["ok"]:
        terminal.print_status(f"Gateway did not come up: {res['error']}", style="bold red")
        if res.get("logs"):
            print(res["logs"])
        sys.exit(1)
    r = res["routes"]
    terminal.print_status(f"✓ Gateway healthy on 127.0.0.1:{args.port}", style="bold green")
    terminal.print_status(f"Operator  {r['operator']}  ·  Verifier  {r['verifier']}", style="cyan")
    print("run an engagement with:  " + terminal.command("run"))


def keys(args):
    if not have_docker():
        sys.exit(f"{container_cmd()} not found.")
    sd = state_dir(args)
    plane, env = load_plane(sd), load_env(sd)
    if not env:
        sys.exit("gateway not set up yet; run: " + terminal.command("setup"))
    terminal.print_status("Update provider API keys · input is hidden", style="bold cyan")
    for role, s in plane.items():
        shown = "set" if env.get(s["key_env"], "").strip() else "unset"
        val = getpass.getpass(f"  {s['key_env']} for {role} ({s['provider']}, {shown}): ").strip()
        if val:
            env[s["key_env"]] = val
    save_env(sd, env, plane)
    terminal.print_status("✓ Keys saved. Restarting the gateway…", style="bold green")
    args.port = args.port or _current_port() or DEFAULT_PORT
    up(args)


def runtime_env(sd, port=None):
    """The HC_* handles the runner reads, or None if the gateway is not set up yet.
    `capri run` sets these in-process so there is no manual export dance."""
    plane, env = load_plane(sd), load_env(sd)
    if not env.get("VK_OPERATOR") or not env.get("VK_VERIFIER"):
        return None
    port = port or _current_port() or DEFAULT_PORT
    routes = plane_routes(plane)
    return {"HC_BIFROST_URL": f"http://127.0.0.1:{port}",
            "HC_VK_OPERATOR": env["VK_OPERATOR"], "HC_VK_VERIFIER": env["VK_VERIFIER"],
            "HC_OPERATOR_ROUTE": routes["operator"], "HC_VERIFIER_ROUTE": routes["verifier"]}


def print_env(args):
    e = runtime_env(state_dir(args), args.port or None)
    if e is None:
        sys.exit("gateway not set up yet; run: " + terminal.command("setup"))
    for k, v in e.items():
        print(f"export {k}={v}")


def status(args):
    if not have_docker():
        sys.exit(f"{container_cmd()} not found.")
    sd = state_dir(args)
    plane, env = load_plane(sd), load_env(sd)
    health = _health(CONTAINER)
    port = _current_port()
    console = terminal.rich_console()
    if console:
        from rich.table import Table
        from rich.text import Text

        console.print(Text(f"Gateway  {CONTAINER}  ·  {health}",
                           style="bold green" if health == "healthy" else "bold yellow"))
        console.print(Text(f"Address  {f'127.0.0.1:{port}' if port else 'not running'}",
                           style="cyan"))
        table = Table(box=None, show_header=True, padding=(0, 2))
        table.add_column("ROLE", style="bold cyan")
        table.add_column("PROVIDER / MODEL")
        table.add_column("API KEY")
        for role, settings in plane.items():
            configured = bool(env.get(settings["key_env"], "").strip())
            table.add_row(Text(role.title()), Text(f"{settings['provider']} / {settings['model']}"),
                          Text("set" if configured else "unset",
                               style="green" if configured else "bold red"))
        console.print(table)
        console.print(Text(f"State  {sd}", style="dim"))
        return
    print(f"state dir: {sd}")
    print(f"container: {CONTAINER}  health: {health}")
    print(f"port: {port if port else '(not running)'}")
    for role, s in plane.items():
        print(f"  {role:8} -> {s['provider']}/{s['model']:16} key {s['key_env']}: "
              f"{'set' if env.get(s['key_env'], '').strip() else 'UNSET'}")


def down(args):
    if not have_docker():
        sys.exit(f"{container_cmd()} not found.")
    _run(["rm", "-f", CONTAINER])
    terminal.print_status(f"✓ Stopped {CONTAINER}. Data volume and keys are kept.", style="bold green")


def destroy(args):
    if not have_docker():
        sys.exit(f"{container_cmd()} not found.")
    _run(["rm", "-f", CONTAINER])
    _run(["volume", "rm", VOLUME])
    terminal.print_status(f"✓ Removed {CONTAINER} and volume {VOLUME}.", style="bold green")
    terminal.print_status(f"Provider keys remain in {state_dir(args) / '.env'}.", style="yellow")


def main(argv=None):
    p = argparse.ArgumentParser(description="Bring up the Bifrost model-plane gateway. "
                                "For interactive setup, run capri setup.")
    p.add_argument("--dir", help="state dir (default ~/.hackculture/modelplane)")
    p.add_argument("--port", type=int, default=0, help=f"localhost port (default {DEFAULT_PORT})")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("up", "keys", "env", "status", "down", "destroy"):
        sub.add_parser(name)
    args = p.parse_args(argv)
    if args.cmd == "up" and not args.port:
        args.port = DEFAULT_PORT
    if args.cmd != "env":                # keep this output directly shell-usable
        terminal.print_banner(f"GATEWAY / {args.cmd.upper()}")
    return {"up": up, "keys": keys, "env": print_env, "status": status,
            "down": down, "destroy": destroy}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
