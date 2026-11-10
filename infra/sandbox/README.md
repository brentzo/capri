# Sandbox range infrastructure (HC-SUB-01)

This directory holds the images for the self-hosted Docker sandbox backend.
The harness stays standard-library-only and drives the range through Docker.
No host `nsenter` binary or root shell is required, so the same flow works from Linux
and Windows with Docker Desktop.

## What runs where

The range is one `--internal` Docker network (no route off the host, so no egress by
construction) holding:

- one attacker container, where tool adapters run, with no `NET_ADMIN` and no network
  tooling, so the agent can neither reach an out-of-scope host nor reconfigure the
  guard;
- one target container per in-scope host, pinned to an IP the adapter assigns.

The scope guard is an nftables ruleset installed by a short-lived `hc-guard:golden`
helper that joins the attacker's network namespace. The helper drops every capability
then adds only `NET_ADMIN`, applies the ruleset from stdin, and exits. The attacker
never receives that capability or the `nft` binary.

## Build the range images

Run from the repository root:

```sh
docker build -t hc-node:golden -f infra/sandbox/Dockerfile.node infra/sandbox
docker build -t hc-attacker:golden -f infra/sandbox/Dockerfile.attacker infra/sandbox
docker build -t hc-guard:golden -f infra/sandbox/Dockerfile.guard infra/sandbox
```

## Prove it (guard proof, G1 scope + G2 no-egress)

```sh
uv run --project . python tools/sandbox_selftest.py
```

It provisions a throwaway range, runs the four §8.1 assertions from inside the
attacker container (internet dropped, public DNS refused, in-range out-of-scope
dropped, pinned in-scope allowed), prints each, and tears the range down.

## No nested virtualization required

This backend needs Docker and its Linux container runtime, so it runs on commodity
Linux hosts and Docker Desktop on Windows/macOS. Stronger escape-containment
(G4) via gVisor is auto-detected when the host offers the `runsc` runtime, and the
snapshot round-trip (G3), escape-attempt (G4), and kill-switch (G5) drills are
implemented on this backend. `proofs_pass` runs all five, and the harness leaves
passive-only only when every guarantee holds.
