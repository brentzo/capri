#!/usr/bin/env python3
"""Choose diverse Operator and Verifier models and start the Bifrost gateway."""
import argparse
import getpass
import sys

from cli import terminal
from tools import catalog, modelplane


def _launch(args, op, ver, keys, progress):
    """Validate the pairing and keys before starting the local gateway."""
    try:
        plane = modelplane.build_plane(op, ver)
    except ValueError as error:
        return {"ok": False, "error": str(error)}
    sd = modelplane.state_dir(args)
    env = modelplane.load_env(sd)
    env.update({key: value for key, value in keys.items() if value})
    missing = modelplane.missing_provider_keys(env, plane)
    if missing:
        providers = [catalog.label(role["provider"]) for role in plane.values()
                     if role["key_env"] in missing]
        return {"ok": False, "error": "API keys required for: " + ", ".join(providers)}
    if not modelplane.have_docker():
        return {"ok": False, "error": "Docker was not found. Install Docker Desktop "
                "(or set HC_CONTAINER=podman), then run setup again."}
    return modelplane.bring_up(sd, plane, env, port=args.port, progress=progress)


def _run_command_hint():
    return terminal.command("run")


def model_choices(exclude_provider=None):
    choices = []
    for provider in catalog.providers():
        if provider == exclude_provider:
            continue
        choices.extend((provider, model) for model in catalog.models(provider))
        choices.append((provider, None))
    return choices


def _choose_role_plain(role, *, exclude=None, step=1):
    choices = model_choices(exclude)
    print(f"\nStep {step}/4 · Choose {role.title()} model" +
          (f" (provider must differ from {catalog.label(exclude)})" if exclude else ""))
    previous = None
    for index, (provider, model) in enumerate(choices, 1):
        if provider != previous:
            print(f"  {catalog.label(provider)}:")
            previous = provider
        print(f"    {index:2}) {model if model else '(type a model name)'}")
    while True:
        raw = input("  > ").strip()
        if raw.isdigit() and 1 <= int(raw) <= len(choices):
            provider, model = choices[int(raw) - 1]
            break
        print("  pick a number from the list.")
    if model is None:
        model = input(f"  {catalog.label(provider)} model: ").strip()
    return {"provider": provider, "model": model}


def _run_plain(args):
    terminal.print_banner("MODEL SETUP", "Choose two providers. Operator and Verifier must differ.")
    operator = _choose_role_plain("operator", step=1)
    print("\nStep 2/4 · Enter the Operator API key (input is hidden)")
    operator["key"] = getpass.getpass(f"  {catalog.label(operator['provider'])} API key: ").strip()
    verifier = _choose_role_plain("verifier", exclude=operator["provider"], step=3)
    print("\nStep 4/4 · Enter the Verifier API key (input is hidden)")
    verifier["key"] = getpass.getpass(f"  {catalog.label(verifier['provider'])} API key: ").strip()
    print("\nSelected pairing")
    print(f"  Operator  {catalog.label(operator['provider'])} / {operator['model']}")
    print(f"  Verifier  {catalog.label(verifier['provider'])} / {verifier['model']}")
    print("\nStarting the gateway …")
    result = _launch(args, (operator["provider"], operator["model"]),
                     (verifier["provider"], verifier["model"]),
                     {catalog.key_env(operator["provider"]): operator["key"],
                      catalog.key_env(verifier["provider"]): verifier["key"]},
                     lambda message: print(f"  {message} …"))
    if result["ok"]:
        print(f"\n✓ Gateway healthy.  operator={result['routes']['operator']}  "
              f"verifier={result['routes']['verifier']}")
        print("Run an engagement with:\n  " + _run_command_hint())
    else:
        print("\n✗ Could not start the gateway:", result["error"])
        if result.get("logs"):
            print(result["logs"])
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Choose models and start the Bifrost gateway.")
    parser.add_argument("--dir", help="state dir (default ~/.hackculture/modelplane)")
    parser.add_argument("--port", type=int, default=modelplane.DEFAULT_PORT, help="localhost port")
    parser.add_argument("--plain", action="store_true", help="use line-by-line prompts")
    args = parser.parse_args(argv)
    if args.plain or not (sys.stdin.isatty() and sys.stdout.isatty()):
        result = _run_plain(args)
    else:
        from cli.setup_tui import SetupApp

        result = SetupApp(args).run()
    return 0 if (result and result.get("ok")) else 1


if __name__ == "__main__":
    sys.exit(main())
