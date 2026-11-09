# Model-plane gateway (HC-MODEL-01)

The harness drives commercial models through one [Bifrost](https://github.com/maximhq/bifrost) gateway, with a virtual key per role so no role ever holds a provider key.
This directory is the host-side setup for that gateway.
Like the sandbox range, it is self-hosted: Docker and two API keys, no cloud account.

The harness Python stays dependency-free and only ever talks to a gateway URL.
`tools/modelplane.py` (standard library only, cross-platform) is the one command that stands the gateway up.

## Quickstart

From the repo root, on a host with Docker:

```sh
python3 tools/modelplane.py up        # generate config, mint virtual keys, run the gateway
python3 tools/modelplane.py keys      # paste your OpenAI and DeepSeek keys (hidden input)
python3 tools/modelplane.py status    # health, routes, and whether keys are set
```

Then point an engagement at it:

```sh
eval "$(python3 tools/modelplane.py env)"   # exports HC_BIFROST_URL / HC_VK_OPERATOR / HC_VK_VERIFIER
sudo -E python3 tools/run_engagement.py     # -E so the exports survive sudo
```

`run_engagement.py` runs the Operator on DeepSeek and the Verifier on OpenAI through the gateway.
With no gateway configured it falls back to deterministic stand-ins, so the substrate and dispatch path still run on a host without model access.

## The one manual step, by design

Supplying your own provider API keys is the only step that is not automated, because they are secrets.
`keys` reads them with no echo and writes them straight into the gateway's env; they are never committed, printed, or passed as process arguments.
Use pay-as-you-go API keys (an OpenAI key and a DeepSeek key), not a chat subscription.

Everything else is generated for you: the Bifrost config, a fresh per-role virtual key, the container, and the volume permissions.

## What `up` does

- Generates the Bifrost config from one table in `tools/modelplane.py`: two providers (OpenAI, DeepSeek) and two virtual keys (`vk-operator` bound to DeepSeek, `vk-verifier` bound to OpenAI).
  The config carries only `env.VAR` references, never a literal secret, and the operator and verifier providers are disjoint by construction, so the finder never verifies on the finder's model.
- Mints a per-role virtual-key secret (`sk-bf-...`) once and stores it, so the harness and the gateway share a handle the operator never has to see.
- Seeds a Docker-managed named volume with the config over the container's stdin, not a host bind mount, so seeding never depends on the daemon seeing a host path (which is what breaks on Docker Desktop file sharing and some `/tmp` setups), and makes the volume dir group-0 writable so the gateway (which runs as uid 1000, gid 0) can create its `config.db` and `logs.db`.
- Runs the container bound to `127.0.0.1` only, so the provider keys it holds are never exposed on the network, and waits for the container to report healthy.

## Where state lives

Config and the `.env` that holds the keys and virtual keys live under `~/.hackculture/modelplane`, outside the repo, so no secret reaches a working tree.
Override with `--dir` or `HC_MODELPLANE_DIR`.
Avoid a path under `/tmp`: some hosts give the Docker daemon a private `/tmp`, so a state dir there is invisible to the container.

## Commands

| command   | what it does                                                        |
|-----------|---------------------------------------------------------------------|
| `up`      | generate config, mint virtual keys, run the gateway, wait for health |
| `keys`    | read the provider keys (hidden) and restart                          |
| `env`     | print the `export` lines the runner reads                            |
| `status`  | show health, routes, key state, and localhost reachability          |
| `down`    | stop and remove the container, keeping the keys and data             |
| `destroy` | stop and remove the container and its data volume                   |

Flags: `--dir` (state dir), `--port` (localhost port, default 8099).
Environment: `HC_CONTAINER` (`docker` or `podman`), `HC_GATEWAY_NAME` and `HC_GATEWAY_VOLUME` (to run more than one gateway on a host).

## Notes

The gateway is an external service (a Docker image), the same way the sandbox range is Docker plus nftables.
That is consistent with the zero-dependency rule, which is about the harness runtime: the harness code is standard library only and is handed a gateway URL, the way the sandbox adapter is handed a command runner.

Model and provider choice per role is a cost-versus-capability question (HC-MODEL-01 §14); the only fixed requirement is that the operator and verifier sit on disjoint providers, which the generated config guarantees.
To change the pairing, edit the `PLANE` table in `tools/modelplane.py` and re-run `up`.
