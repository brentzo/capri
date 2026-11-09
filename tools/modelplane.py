#!/usr/bin/env python3
"""Bring the Bifrost model-plane gateway up with one command (HC-MODEL-01).

The harness drives commercial models through one Bifrost gateway, with a virtual
key per role so no role ever holds a provider key (`harness/modelplane.py`). That
gateway is infrastructure, the way Docker is for the sandbox, and it comes up the
same way the sandbox does: one command, standard library only, no cloud account.

    python3 tools/modelplane.py up        generate config, mint virtual keys, run
    python3 tools/modelplane.py keys      paste your own provider keys (prompted, silent)
    python3 tools/modelplane.py env       print the exports the runner reads
    python3 tools/modelplane.py status    health, and whether provider keys are set
    python3 tools/modelplane.py down      stop the gateway (keeps keys and data)
    python3 tools/modelplane.py destroy   stop and wipe the data volume

The one step that is not automated, by design, is the developer supplying their own
provider API keys. Those are secrets: `keys` reads them straight into the gateway's
env with no echo, and they are never committed, printed, or passed as process
arguments. Everything else - the config, the per-role virtual keys, the container,
the permissions - is generated here so a new developer runs two commands, not ten.

State (the generated config and the `.env` holding the keys and virtual keys) lives
outside the repo, under ~/.hackculture/modelplane by default, so secrets never land
in a working tree. Override with --dir or HC_MODELPLANE_DIR. The gateway binds to
127.0.0.1 only, so the provider keys it holds are never exposed on the network.

Requires Docker (or set HC_CONTAINER=podman). This is an ops tool, not part of the
harness runtime; the harness itself stays dependency-free and talks to whatever
gateway URL it is handed. See infra/modelplane/README.md.
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
import urllib.error
import urllib.request

IMAGE = "maximhq/bifrost:latest"
SEED_IMAGE = "alpine:3.20"           # tiny, root, only used to seed config + perms
# Name and data volume, overridable so a host can run more than one gateway.
CONTAINER = os.environ.get("HC_GATEWAY_NAME", "hc-bifrost")
VOLUME = os.environ.get("HC_GATEWAY_VOLUME", "hc-bifrost-data")
DEFAULT_PORT = 8099

# One diverse operator/verifier pairing (HC-MODEL-01 §4): distinct providers, so the
# finder never verifies on the finder's model. This table is the single source of
# truth for the gateway config, the virtual keys, and the routes the runner exports.
PLANE = {
    "operator": {"provider": "deepseek", "model": "deepseek-chat", "key_env": "DEEPSEEK_API_KEY"},
    "verifier": {"provider": "openai",   "model": "gpt-4o-mini",   "key_env": "OPENAI_API_KEY"},
}


# --- pure helpers (no Docker; unit-tested in tests/test_modelplane_setup.py) -----

def plane_routes():
    """role -> Bifrost model route, e.g. {'operator': 'deepseek/deepseek-chat'}. The
    runner passes these verbatim as the model field; the role's virtual key governs
    that each may reach only its own provider."""
    return {role: f"{s['provider']}/{s['model']}" for role, s in PLANE.items()}


def build_bifrost_config():
    """The Bifrost gateway config (providers + per-role virtual keys) as a dict.

    Each provider key and each virtual-key value is an `env.VAR` reference, so the
    real secrets live only in the gateway's env, never in this committed config. The
    structure encodes the diversity invariant: a virtual key is bound to exactly one
    provider, and the operator's and verifier's providers are disjoint by table."""
    providers, vkeys = {}, []
    for role, s in PLANE.items():
        prov, model, key_id = s["provider"], s["model"], f"key-{s['provider']}"
        providers[prov] = {"keys": [{"id": key_id, "name": prov, "weight": 1.0,
                                     "models": [model], "value": f"env.{s['key_env']}"}]}
        vkeys.append({"id": f"vk-{role}", "name": f"vk-{role}", "is_active": True,
                      "value": f"env.VK_{role.upper()}",
                      "provider_configs": [{"provider": prov, "key_ids": [key_id],
                                            "allowed_models": [model], "weight": 1.0}]})
    return {"providers": providers, "governance": {"virtual_keys": vkeys}}


_VK_ABBR = {"operator": "op", "verifier": "ver"}


def new_vkeys():
    """Fresh per-role gateway virtual-key secrets. The `sk-bf-` prefix is what Bifrost
    accepts as a caller-supplied key verbatim (without it the gateway generates its
    own and we would not know the value)."""
    return {f"VK_{role.upper()}": f"sk-bf-{_VK_ABBR.get(role, role)}-{secrets.token_hex(16)}"
            for role in PLANE}


def env_keys():
    """The ordered keys of the gateway .env: provider keys first, then virtual keys."""
    return [s["key_env"] for s in PLANE.values()] + [f"VK_{r.upper()}" for r in PLANE]


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


def render_env(env):
    """Render the gateway .env, with a header that warns it holds secrets."""
    lines = ["# hackculture model-plane gateway secrets - DO NOT COMMIT.",
             "# Provider keys are pay-as-you-go API keys (not chat subscriptions);",
             "# set them with: python3 tools/modelplane.py keys",
             f"# Routes: {', '.join(f'{r}={route}' for r, route in plane_routes().items())}"]
    for k in env_keys():
        lines.append(f"{k}={env.get(k, '')}")
    return "\n".join(lines) + "\n"


def missing_provider_keys(env):
    """Provider key env names whose value is still empty (gateway cannot route them)."""
    return [s["key_env"] for s in PLANE.values() if not env.get(s["key_env"], "").strip()]


# --- state on disk --------------------------------------------------------------

def state_dir(args):
    d = args.dir or os.environ.get("HC_MODELPLANE_DIR") or str(
        pathlib.Path.home() / ".hackculture" / "modelplane")
    return pathlib.Path(d)


def load_env(sd):
    f = sd / ".env"
    return parse_env(f.read_text()) if f.exists() else {}


def save_env(sd, env):
    sd.mkdir(parents=True, exist_ok=True)
    f = sd / ".env"
    f.write_text(render_env(env))
    try:
        os.chmod(f, 0o600)              # secrets: owner-only
    except OSError:
        pass                            # best effort (e.g. Windows)


# --- Docker ops -----------------------------------------------------------------

def container_cmd():
    return os.environ.get("HC_CONTAINER", "docker")


def _run(args, **kw):
    kw.setdefault("check", False)
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    return subprocess.run([container_cmd(), *args], **kw)


def _require_docker():
    import shutil
    if shutil.which(container_cmd()) is None:
        sys.exit(f"{container_cmd()} not found. Install Docker, or set HC_CONTAINER=podman.")


def _health(name):
    r = _run(["inspect", "--format", "{{if .State.Health}}{{.State.Health.Status}}"
              "{{else}}{{.State.Status}}{{end}}", name])
    return r.stdout.strip() if r.returncode == 0 else "absent"


def up(args):
    _require_docker()
    sd = state_dir(args)
    env = load_env(sd)
    for k, v in new_vkeys().items():
        env.setdefault(k, v)                        # mint once; never rotate silently
    for s in PLANE.values():
        env.setdefault(s["key_env"], "")
    save_env(sd, env)
    config_text = json.dumps(build_bifrost_config(), indent=2) + "\n"
    (sd / "config.json").write_text(config_text)    # on-disk copy for the dev to inspect

    _run(["volume", "create", VOLUME])
    # Seed the named volume with config.json and make its dir group-0 writable, so the
    # gateway (which runs as uid 1000, gid 0) can create its config.db / logs.db. The
    # seed container is root; this is what lets a non-root developer run the gateway
    # without any host chgrp. The config is piped in over stdin rather than bind-mounted
    # from the host, so seeding never depends on the Docker daemon being able to see a
    # host path - which is exactly what breaks on Docker Desktop file sharing and on
    # odd /tmp setups. Only the Docker-managed volume is mounted.
    seed = _run(["run", "--rm", "-i", "-v", f"{VOLUME}:/data", SEED_IMAGE, "sh", "-c",
                 "cat > /data/config.json && chmod 0775 /data && chmod 0664 /data/config.json"],
                input=config_text)
    if seed.returncode != 0:
        sys.exit(f"failed to seed gateway config:\n{seed.stderr.strip()}")

    _run(["rm", "-f", CONTAINER])
    run = _run(["run", "-d", "--name", CONTAINER,
                "-p", f"127.0.0.1:{args.port}:8080",
                "--env-file", str(sd / ".env"),
                "-v", f"{VOLUME}:/app/data", "--restart", "unless-stopped", IMAGE])
    if run.returncode != 0:
        sys.exit(f"failed to start the gateway:\n{run.stderr.strip()}")

    print(f"starting the gateway on 127.0.0.1:{args.port} ...")
    if not _wait_healthy(CONTAINER, timeout=60):
        print("gateway did not report healthy in time; recent logs:")
        print(_run(["logs", "--tail", "15", CONTAINER]).stdout)
        sys.exit(1)
    print("gateway healthy.")
    _print_next_steps(sd, args, env)


def _wait_healthy(name, *, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        h = _health(name)
        if h == "healthy":
            return True
        if h in ("absent", "exited", "dead"):
            return False
        time.sleep(2)
    return _health(name) == "healthy"


def _print_next_steps(sd, args, env):
    missing = missing_provider_keys(env)
    if missing:
        print("\nnext: set your provider API keys (prompted, not echoed):")
        print("    python3 tools/modelplane.py keys")
        print(f"    (still unset: {', '.join(missing)})")
    else:
        print("\nprovider keys are set. Before a live run, export the gateway handles:")
        print('    eval "$(python3 tools/modelplane.py env)"')
        print("    sudo -E python3 tools/run_engagement.py")


def keys(args):
    _require_docker()
    sd = state_dir(args)
    env = load_env(sd)
    if not env:
        sys.exit("gateway not set up yet; run: python3 tools/modelplane.py up")
    print("Paste each provider API key (input is hidden). Press Enter to leave one unchanged.")
    for role, s in PLANE.items():
        name = s["key_env"]
        shown = "set" if env.get(name, "").strip() else "unset"
        val = getpass.getpass(f"  {name} for {role} ({s['provider']}, currently {shown}): ").strip()
        if val:
            env[name] = val
    save_env(sd, env)
    still = missing_provider_keys(env)
    if still:
        print(f"note: still unset: {', '.join(still)} (the gateway cannot route those).")
    print("keys written (values not shown). Restarting the gateway ...")
    args.port = args.port or _current_port() or DEFAULT_PORT
    up(args)


def _current_port():
    r = _run(["port", CONTAINER, "8080"])
    if r.returncode == 0 and ":" in r.stdout:
        try:
            return int(r.stdout.strip().rsplit(":", 1)[1])
        except ValueError:
            return None
    return None


def print_env(args):
    sd = state_dir(args)
    env = load_env(sd)
    if not env.get("VK_OPERATOR") or not env.get("VK_VERIFIER"):
        sys.exit("gateway not set up yet; run: python3 tools/modelplane.py up")
    port = args.port or _current_port() or DEFAULT_PORT
    print(f"export HC_BIFROST_URL=http://127.0.0.1:{port}")
    print(f"export HC_VK_OPERATOR={env['VK_OPERATOR']}")
    print(f"export HC_VK_VERIFIER={env['VK_VERIFIER']}")


def status(args):
    _require_docker()
    sd = state_dir(args)
    env = load_env(sd)
    print(f"state dir: {sd}")
    print(f"container: {CONTAINER}  health: {_health(CONTAINER)}")
    port = _current_port()
    print(f"port: {port if port else '(not running)'}")
    for role, s in PLANE.items():
        name = s["key_env"]
        print(f"  {role:8} -> {s['provider']}/{s['model']:16} key {name}: "
              f"{'set' if env.get(name, '').strip() else 'UNSET'}")
    reachable = "no"
    if port:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=3) as r:
                reachable = "yes" if r.status < 500 else f"status {r.status}"
        except (urllib.error.URLError, OSError):
            reachable = "no"
    print(f"gateway reachable on localhost: {reachable}")


def down(args):
    _require_docker()
    _run(["rm", "-f", CONTAINER])
    print(f"stopped {CONTAINER} (data volume and keys kept; `up` brings it back).")


def destroy(args):
    _require_docker()
    _run(["rm", "-f", CONTAINER])
    _run(["volume", "rm", VOLUME])
    print(f"removed {CONTAINER} and volume {VOLUME}. The .env (keys) is kept; "
          f"delete {state_dir(args) / '.env'} to remove the secrets too.")


def main(argv=None):
    p = argparse.ArgumentParser(description="Bring up the Bifrost model-plane gateway.")
    p.add_argument("--dir", help="state dir for config and .env (default ~/.hackculture/modelplane)")
    p.add_argument("--port", type=int, default=0, help=f"localhost port (default {DEFAULT_PORT})")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("up", "keys", "env", "status", "down", "destroy"):
        sub.add_parser(name)
    args = p.parse_args(argv)
    if args.cmd in ("up",) and not args.port:
        args.port = DEFAULT_PORT
    return {"up": up, "keys": keys, "env": print_env, "status": status,
            "down": down, "destroy": destroy}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
