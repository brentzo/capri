# Sandbox range infrastructure (HC-SUB-01)

This directory holds the host-side pieces of the self-hosted Docker sandbox backend.
The harness Python stays stdlib-only; the range itself is Docker plus an nftables
scope guard, which the `harness/sandbox/docker.py` adapter drives over `docker` and
`nsenter`.

## What runs where

The harness runs on the range host (the operator host), as root, because installing
the scope guard into the attacker container's network namespace needs `nsenter`.
The range is one `--internal` Docker network (no route off the host, so no egress by
construction) holding:

- one attacker container, where tool adapters run, with no `NET_ADMIN` and no network
  tooling, so the agent can neither reach an out-of-scope host nor reconfigure the
  guard;
- one target container per in-scope host, pinned to an IP the adapter assigns.

The scope guard is an nftables ruleset the host installs into the attacker netns:
default-deny egress, allowing only the pinned in-scope IPs on their allowed ports.

## Build the golden node image

```sh
docker build -t hc-node:golden -f Dockerfile.node .
```

## Prove it (guard proof, G1 scope + G2 no-egress)

```sh
sudo python3 ../../tools/sandbox_selftest.py
```

It provisions a throwaway range, runs the four §8.1 assertions from inside the
attacker container (internet dropped, public DNS refused, in-range out-of-scope
dropped, pinned in-scope allowed), prints each, and tears the range down.

## No nested virtualization required

This backend needs only Docker and nftables, so it runs on any commodity Linux host
and inside Docker Desktop's Linux VM on macOS/Windows. Stronger escape-containment
(G4) via gVisor or a separate gateway host plugs in behind the same `Sandbox`
interface; the snapshot round-trip (G3), escape-attempt (G4), and kill-switch (G5)
drills are the following slices, and until all five guarantees prove, the harness
stays in passive-only.
