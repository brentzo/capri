"""Sandbox substrate: the backend-agnostic interface and the passive-only default.

The harness never trusts a model to keep a run safe; it trusts the substrate
(HC-SUB-01 §3). A `Sandbox` backend provisions an isolated range, proves the five
guarantees with startup self-tests (§8), and exposes the §10 interface the control
loop drives. Until every proof passes, the harness stays in passive-only and runs no
active tool call, so a backend that cannot prove containment is treated as absent,
never trusted (§3, §9).

This module defines that interface, a `PassiveOnlySandbox` that proves nothing (the
safe default when no range is up), the guard-proof assertion model (§8.1), and a
default subprocess command runner the real backends shell through. The Docker backend
is in `docker.py`.
"""
import collections

RunResult = collections.namedtuple("RunResult", "rc out err")


class SandboxError(Exception):
    """A substrate operation failed; the harness stays fail-closed (§5.4, §11)."""


class Sandbox:
    """The §10 interface every backend implements. The control loop calls
    `proofs_pass` to decide whether it may leave passive-only, and `snapshot`/
    `restore` around tier>=2 actions (§6.3). The base raises, so a half-built backend
    fails loudly rather than silently skipping a guarantee."""

    def provision(self, engagement):
        """Stand up the range for an engagement; return a descriptor dict."""
        raise NotImplementedError

    def snapshot(self):
        """Snapshot current range state; return a snapshot id (§6.3, G3)."""
        raise NotImplementedError

    def restore(self, snapshot_id):
        """Restore the range to a snapshot; return True (§6.3, G3)."""
        raise NotImplementedError

    def guard_proof(self):
        """Run the §8.1 guard proof (G1 scope, G2 no-egress) from inside the range;
        return `{"pass": bool, "assertions": [...]}`."""
        raise NotImplementedError

    def proofs_pass(self):
        """Run every §8 self-test and return True only if all five guarantees hold.
        This is the gate for leaving passive-only (§9)."""
        raise NotImplementedError

    def kill(self):
        """Freeze and tear down the range (§6.4, G5); return True."""
        raise NotImplementedError


# §8.1 guard-proof assertions, named so a failure says which guarantee broke.
_GUARD_CHECKS = (
    ("internet_tcp_dropped", "a TCP connection to the internet canary is dropped"),
    ("public_dns_refused", "a public DNS lookup is refused"),
    ("in_range_out_of_scope_dropped", "an in-range out-of-scope host is unreachable"),
    ("in_scope_target_allowed", "a pinned in-scope target on an allowed port connects"),
)


def guard_proof_result(*, internet_reachable, public_dns_resolves,
                       out_of_scope_reachable, in_scope_reachable):
    """Evaluate the four §8.1 assertions from observed reachability. All four must
    hold; a single failure names the assertion and fails the proof, so the caller
    can log which guarantee broke (§8.1) and stay fail-closed."""
    got = (not internet_reachable, not public_dns_resolves,
           not out_of_scope_reachable, in_scope_reachable)
    assertions = [{"name": name, "describes": desc, "ok": ok}
                  for (name, desc), ok in zip(_GUARD_CHECKS, got)]
    return {"pass": all(got), "assertions": assertions}


class PassiveOnlySandbox(Sandbox):
    """The safe default: no range, nothing proven, so the harness stays passive-only
    (§9). Every proof fails closed and the active-only operations refuse, which is
    exactly the posture a torn-down or never-provisioned sandbox must present."""

    reason = "no sandbox provisioned"

    def provision(self, engagement):
        return {"range_id": None, "mode": "passive-only", "reason": self.reason}

    def snapshot(self):
        raise SandboxError("passive-only: snapshots require a provisioned range")

    def restore(self, snapshot_id):
        raise SandboxError("passive-only: restore requires a provisioned range")

    def guard_proof(self):
        return {"pass": False, "assertions": [], "reason": self.reason}

    def proofs_pass(self):
        return False

    def kill(self):
        return True


def default_run(argv, *, input=None, timeout=30):
    """Run a command and capture its output, as `RunResult`. Stdlib subprocess only;
    the real backends inject this and the tests inject a stub, so no Docker or root is
    needed to exercise the provisioning and proof logic."""
    import subprocess
    try:
        p = subprocess.run(list(argv), input=input, capture_output=True, text=True,
                           timeout=timeout)
    except subprocess.TimeoutExpired as e:
        return RunResult(124, e.stdout or "", f"timeout after {timeout}s")
    except OSError as e:
        return RunResult(127, "", str(e))
    return RunResult(p.returncode, p.stdout, p.stderr)
