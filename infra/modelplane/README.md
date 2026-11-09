# Model-plane gateway (HC-MODEL-01)

The harness drives commercial models through one [Bifrost](https://github.com/maximhq/bifrost) gateway, with a virtual key per role so no role ever holds a provider key.
This directory is the host-side setup for that gateway.
Like the sandbox range, it is self-hosted and runs on your own machine: Docker and two API keys, no cloud account.

The harness Python stays dependency-free and only ever talks to a gateway URL.
`capri setup` configures the gateway; `tools/setup.py` (standard library only) is the terminal UI behind it, and `tools/modelplane.py` is the mechanics it drives.

## Quickstart

On a machine with Docker:

```sh
make install     # once: puts the `capri` command on your PATH
capri setup      # pick your Operator and Verifier models, drop in keys, start the gateway
capri run        # run an engagement with the models you chose
```

`capri setup` is a terminal UI: it shows a catalog of providers as one list of models grouped by provider, you pick a model for the Operator and a different-provider model for the Verifier (the finder never verifies on its own model), and it reads your API keys with no echo and starts the gateway.
`capri run` loads the gateway handles into its own environment, so there is no manual export step.
With no gateway configured, a run falls back to deterministic stand-ins, so the substrate and dispatch path still work on a host without model access.

## The one manual step, by design

Supplying your own provider API keys is the only step that is not automated, because they are secrets.
The setup UI reads them with no echo and writes them straight into the gateway's env; they are never committed, printed, or passed as process arguments.
Use pay-as-you-go API keys, not a chat subscription.

Everything else is generated for you: the Bifrost config, a fresh per-role virtual key, the container, and the volume permissions.

## The provider catalog

`tools/catalog.py` is the catalog Capri owns: the single-API-key providers Bifrost supports (OpenAI, Anthropic, Gemini, DeepSeek, Mistral, Cohere, Groq, Cerebras, xAI, Perplexity, OpenRouter, Nebius, Hugging Face, Replicate), each with its Bifrost identifier, the env var its key lives in, and a few suggested models.
It is the one place to edit to add a provider or adjust a model list, and it is what the setup UI offers and what the gateway config is generated from.
Multi-field providers (Bedrock, Vertex, Azure, Databricks) and self-hosted ones (Ollama, vLLM, SGL) need extra fields and are a separate path.

## What the setup does underneath

- Generates the Bifrost config from the pairing you chose: one provider block and one virtual key per role, bound to that provider.
  The config carries only `env.VAR` references, never a literal secret, and the operator and verifier providers are disjoint by construction.
- Mints a per-role virtual-key secret (`sk-bf-...`) once and stores it, so the harness and the gateway share a handle you never have to see.
- Seeds a Docker-managed named volume with the config over the container's stdin, not a host bind mount, so seeding never depends on the daemon seeing a host path (which is what breaks on Docker Desktop file sharing and some `/tmp` setups), and makes the volume dir group-0 writable so the gateway (which runs as uid 1000, gid 0) can create its `config.db` and `logs.db`.
- Runs the container bound to `127.0.0.1` only, so the provider keys it holds are never exposed on the network, and waits for the container to report healthy.

## Where state lives

The config, the chosen pairing, and the `.env` that holds the keys and virtual keys live under `~/.hackculture/modelplane`, outside the repo, so no secret reaches a working tree.
Override with `--dir` or `HC_MODELPLANE_DIR`.
Avoid a path under `/tmp`: some hosts give the Docker daemon a private `/tmp`, so a state dir there is invisible to the container.

## The gateway CLI

`capri gateway <cmd>` manages the running gateway:

| command   | what it does                                               |
|-----------|-----------------------------------------------------------|
| `status`  | show health, routes, key state, and localhost reachability |
| `env`     | print the `export` lines the runner reads                  |
| `keys`    | re-enter the provider keys (hidden) and restart            |
| `up`      | bring the gateway up from the saved pairing                |
| `down`    | stop and remove the container, keeping the keys and data   |
| `destroy` | stop and remove the container and its data volume          |

Environment: `HC_CONTAINER` (`docker` or `podman`), `HC_GATEWAY_NAME` and `HC_GATEWAY_VOLUME` (to run more than one gateway on a host).

## Notes

The gateway is an external service (a Docker image), the same way the sandbox range is Docker plus nftables.
That is consistent with the zero-dependency rule, which is about the harness runtime: the harness code is standard library only and is handed a gateway URL, the way the sandbox adapter is handed a command runner.

Model and provider choice per role is a cost-versus-capability question (HC-MODEL-01 §14); the only fixed requirement is that the operator and verifier sit on different providers, which the catalog and the generated config guarantee.
To change the pairing, run `capri setup` again; to add a provider, edit `tools/catalog.py`.
