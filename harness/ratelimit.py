"""Per-target rate limit and run-action budget (HC-AGENT-01 §5.2 guard 4, §8).

The fourth `dispatch()` guard. One token bucket per target, shared across every
worker hitting that target (§8), plus a run-level action budget. Both come from
the engagement contract's `policy.rate`. The clock is injectable so tests are
deterministic. This is the network/run limit; the per-virtual-key model-plane
rate limit is separate and lives in Bifrost (HC-AGENT-01 §6).
"""
import time


class RateLimiter:
    def __init__(self, max_rps_per_target, max_actions_per_run=None, burst=None,
                 now=time.monotonic):
        self.rate = float(max_rps_per_target)
        self.burst = float(burst if burst is not None else max_rps_per_target)
        self.max_actions = max_actions_per_run
        self._now = now
        self._buckets = {}          # target -> [tokens, last_ts]
        self.actions = 0            # executed actions this run

    @classmethod
    def from_engagement(cls, eng, now=time.monotonic):
        r = eng.rate or {}
        return cls(r.get("max_rps_per_target", 10), r.get("max_actions_per_run"), now=now)

    def check(self, target):
        """Return ('allow', None) or ('deny', reason). Consumes a token on allow.

        reason is 'budget_exhausted' (run action cap) or 'rate_limited' (per-target)."""
        if self.max_actions is not None and self.actions >= self.max_actions:
            return "deny", "budget_exhausted"
        t = self._now()
        tokens, last = self._buckets.get(target, (self.burst, t))
        tokens = min(self.burst, tokens + (t - last) * self.rate)
        if tokens < 1.0:
            self._buckets[target] = (tokens, t)
            return "deny", "rate_limited"
        self._buckets[target] = (tokens - 1.0, t)
        self.actions += 1
        return "allow", None
