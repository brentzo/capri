# hackculture

An autonomous penetration-testing agent harness for authorized, scoped engagements.
The orchestrator is code and owns the control loop; the model roles only ever propose actions, and the harness decides what actually runs.

## Non-negotiables

The harness core and its tests use only the Python 3.12 standard library.
The CLI may use Textual and Rich for terminal UI; pin those dependencies in `pyproject.toml` and `uv.lock`.
SQLite stands in for the production Postgres, and a content-addressed filesystem blob store stands in for object storage.
Do not reach for a dependency or a running service to make something easier; the self-contained, egress-denied posture is the whole point of the design.

The specs under `docs/specs/` are the source of truth.
`make materialize` regenerates `kb/` and `eval/`; `make features` regenerates `docs/requirements/features/`.
CI fails if either tree drifts from the specs, so regenerate and commit instead of hand-editing a generated file.

## Build and test

`make check` runs the strict KB validator plus every test suite, and it must be green before you commit.
Tests live in `tests/` and share one runner convention: a `main()` collects every `test_*` function and prints `  ok  ` / `FAIL` lines and an `N/N passed` total.
When you add a suite, wire it into both the `test:` target in `Makefile` and the step list in `.github/workflows/validate.yml`.
CI runs each test file by name and will not discover a new one on its own.

## Finish a milestone

A slice is not done until the docs match the code.
Add an implementation-pointer paragraph to the relevant spec under `docs/specs/`, a short section in `harness/README.md`, and one dated line at the bottom of the `SPEC.md` decision log.

## Git workflow

Do not merge branches or create merge commits.
When bringing upstream changes into the current branch, rebase onto its upstream instead.
Use `git pull --rebase --autostash` to update a branch while preserving local work.
Do not rebase commits that are already published or shared, and do not force-push unless the user explicitly asks.
This repository sets `pull.rebase=true`, `pull.autostash=true`, and `rebase.autoStash=true` in its local Git config.

## Commit messages

Start the subject with a Conventional Commits type and a colon: `feat`, `fix`, `docs`, `refactor`, `test`, `perf`, `chore`, `build`, or `ci`.
`feat` is a new capability, `fix` a bug fix, `chore` tooling or meta work, and so on.
Do not add a scope; we do not want the old area-prefix style like `harness:` or `kb:`.

After the type, write what the change does, verb-led and in plain language a teammate can skim in six months and understand.
Good: `feat: add the control loop that runs an engagement end to end`.
Bad: `harness: outer control loop`, which is a scope followed by a noun that names a thing without saying what changed.

No internal handles anywhere in the subject: no `HC-...` spec ids, no `§4` section numbers, and no `(parenthetical)` tag on the end.
Those are cross-reference codes for the specs, not information for someone reading `git log`, and they read as noise.
If a spec reference genuinely helps, say it in the body as a plain phrase, not a code.

The body carries the why, and the what that the diff cannot show on its own.
Do not list files, paths, or line numbers that are already visible in the diff.
Do not use an em dash; use a plain dash.
Do not add a `Co-Authored-By` trailer.
A commit-message hook rejects anything over 500 bytes, so keep the body to a few tight sentences.

## Ship

One focused commit per milestone, straight to `main`.
Push, then confirm the run went green with `gh-axi run list` before you treat the slice as shipped.
Brent reviews on the remote (currently `github.com/brentzo/luna`; the name is temporary).
