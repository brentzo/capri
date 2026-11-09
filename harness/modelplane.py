"""Bifrost model plane (HC-MODEL-01).

All generative traffic goes through one virtual key per role; no role holds a
provider key of its own. This module is the policy around every model call -
provider routing, the provider-diversity invariant, hierarchical budgets, the
semantic cache, fallback, per-vkey rate, and audit logging - as pure standard
library. The actual Bifrost HTTP client is infrastructure and is injected as a
`transport`, the same way tool adapters and the sandbox are injected into
`dispatch()` and the loop; tests drive the plane with a deterministic stub
transport.

The injected transport is the only thing that knows provider credentials:

    transport.complete(provider, messages, metadata) -> object with
        .text .model .tokens_in .tokens_out .latency_ms
    raising ProviderDown(provider) when that provider cannot serve.

The plane calls it with a provider it chose from the role's vkey, so a role can
never name a provider or hold a key (§13.1). What the plane enforces:

- Provider diversity (§4): vk-operator and vk-verifier resolve to disjoint
  providers, asserted at construction; a violating config fails closed before any
  run, which is finder-is-not-verifier at the model plane.
- Budgets (§5): per-vkey child budgets under an engagement parent; a breach fails
  closed (PlaneStop), and because roles hold no keys there is nothing to fall
  through to.
- Cache (§7): on for Planner/Reporter prose, off for Operator/Verifier so a cached
  response never drives a live action; namespaced per engagement.
- Fallback (§10): Planner/Reporter fall back freely, the Operator only within its
  own provider set, the Verifier not at all (pinned) so it never verifies on the
  Operator's provider.
- MCP boundary (§8): only vk-enrich may carry brokered tools; any other vkey with
  mcp_tools fails the config. Pentest tools never flow through here - dispatch() is
  the only path to the sandbox.
- Observability (§9): every call and every stop is an append-only audit row tying
  the model turn to its engagement and action.
"""
import hashlib
import json
import time

from harness.ratelimit import RateLimiter
from harness.store import audit

# Roles whose output is stable prose and may be cached (§7); the others must not be.
_CACHEABLE_DEFAULT = frozenset({"planner", "reporter", "enrich"})
# Only the enrichment vkey may be brokered MCP tools (§8).
_TOOL_BROKER_ROLE = "enrich"


class PlaneConfigError(Exception):
    """A config that cannot be served safely; raised at construction, fail closed."""


class ProviderDown(Exception):
    """A transport signals that one provider cannot serve; the plane applies the
    vkey's fallback policy."""

    def __init__(self, provider):
        super().__init__(provider)
        self.provider = provider


class PlaneStop(Exception):
    """The role must stop (§5, §10): budget, rate, or no provider left. The caller
    turns this into a role that gives up, never a fall-through to a provider."""

    def __init__(self, reason, role):
        super().__init__(f"{role}: {reason}")
        self.reason = reason
        self.role = role


class VirtualKey:
    """One role's binding: a provider set, a cache policy, a fallback policy, a
    child budget, a per-vkey rate, and any brokered MCP tools (enrich only)."""
    __slots__ = ("role", "vkey", "providers", "cache", "fallback", "budget",
                 "rate", "mcp_tools")

    def __init__(self, role, providers, *, cache=False, fallback="free",
                 budget=None, rate=None, mcp_tools=()):
        self.role = role
        self.vkey = f"vk-{role}"
        self.providers = tuple(providers)
        self.cache = cache
        self.fallback = fallback        # "free" | "within_set" | "none"
        self.budget = budget            # child budget in cost units, or None
        self.rate = rate                # per-vkey requests/sec, or None
        self.mcp_tools = tuple(mcp_tools)


class Completion:
    __slots__ = ("text", "role", "vkey", "provider", "model", "tokens_in",
                 "tokens_out", "cost", "cache_hit", "latency_ms")

    def __init__(self, *, text, role, vkey, provider, model, tokens_in, tokens_out,
                 cost, cache_hit, latency_ms):
        self.text = text
        self.role = role
        self.vkey = vkey
        self.provider = provider
        self.model = model
        self.tokens_in = tokens_in
        self.tokens_out = tokens_out
        self.cost = cost
        self.cache_hit = cache_hit
        self.latency_ms = latency_ms


def _cost(tokens_in, tokens_out):
    """Default cost model: one unit per token. A deployment swaps a price map in;
    the policy (fail closed on breach) does not depend on the unit."""
    return int(tokens_in) + int(tokens_out)


class ModelPlane:
    def __init__(self, vkeys, transport, conn, engagement_id, *,
                 engagement_budget=None, clock=time.monotonic):
        self.vkeys = {vk.role: vk for vk in vkeys}
        self.transport = transport
        self.conn = conn
        self.engagement_id = engagement_id
        self.engagement_budget = engagement_budget
        self._clock = clock
        self._cache = {}                            # (eng, role, hash) -> Completion
        self._spend = {role: 0 for role in self.vkeys}
        self._total = 0
        self._rate = {vk.role: RateLimiter(vk.rate, now=clock)
                      for vk in vkeys if vk.rate is not None}
        self._validate_config()

    # --- startup invariants (§4, §8, fail closed) -----------------------
    def _validate_config(self):
        for role, vk in self.vkeys.items():
            if vk.mcp_tools and role != _TOOL_BROKER_ROLE:
                raise PlaneConfigError(
                    f"{vk.vkey} may not broker MCP tools; only vk-{_TOOL_BROKER_ROLE} may")
        self.assert_provider_diversity()

    def assert_provider_diversity(self):
        """operator ∩ verifier providers must be empty (§4, §13.2)."""
        op, ver = self.vkeys.get("operator"), self.vkeys.get("verifier")
        if op and ver and set(op.providers) & set(ver.providers):
            raise PlaneConfigError(
                "vk-operator and vk-verifier share a provider; diversity invariant "
                "violated (finder must not verify on the finder's model)")
        return "ok", None

    # --- the one call path (§12) ----------------------------------------
    def call(self, role, messages, metadata=None):
        """Serve one model turn for `role`, or raise PlaneStop if it must stop.

        A role names itself, never a provider; the plane resolves its vkey, applies
        budget / rate / cache / fallback, logs the turn, and returns a Completion."""
        metadata = metadata or {}
        vk = self.vkeys.get(role)
        if vk is None:
            raise PlaneConfigError(f"unknown role {role!r}; every call carries a role vkey")

        if self._cacheable(vk):
            cached = self._cache.get(self._cache_key(role, messages))
            if cached is not None:
                hit = self._as_cache_hit(cached)
                self._log(vk, hit, metadata, decision="cache_hit")
                return hit

        if role in self._rate:
            verdict, reason = self._rate[role].check(role)
            if verdict != "allow":
                self._stop(vk, "rate_limited", metadata)

        # Budget fails closed before serving: an already-exhausted vkey (or the
        # engagement parent) has nothing to fall through to (§5).
        if vk.budget is not None and self._spend[role] >= vk.budget:
            self._stop(vk, "budget_exhausted", metadata)
        if self.engagement_budget is not None and self._total >= self.engagement_budget:
            self._stop(vk, "engagement_budget_exhausted", metadata)

        comp = self._serve(vk, messages, metadata)
        if self._cacheable(vk):
            self._cache[self._cache_key(role, messages)] = comp
        return comp

    def _serve(self, vk, messages, metadata):
        order = (vk.providers[:1] if vk.fallback == "none" else vk.providers)
        for provider in order:
            try:
                raw = self.transport.complete(provider, messages, metadata)
            except ProviderDown:
                continue                            # fallback within the ordered set
            cost = _cost(raw.tokens_in, raw.tokens_out)
            self._spend[vk.role] += cost
            self._total += cost
            comp = Completion(text=raw.text, role=vk.role, vkey=vk.vkey,
                              provider=provider, model=raw.model,
                              tokens_in=raw.tokens_in, tokens_out=raw.tokens_out,
                              cost=cost, cache_hit=False, latency_ms=raw.latency_ms)
            self._log(vk, comp, metadata, decision="served")
            return comp
        # The Verifier reaches here with its single pinned provider down and never
        # falls back onto the Operator's provider (§10): the lead stays unverified.
        self._stop(vk, "provider_unavailable", metadata)

    # --- helpers --------------------------------------------------------
    def _cacheable(self, vk):
        return vk.cache and vk.role in _CACHEABLE_DEFAULT

    @staticmethod
    def _as_cache_hit(comp):
        """A served-from-cache turn is the stored completion flagged cache_hit and
        charged nothing (§7): the provider was never called again."""
        return Completion(text=comp.text, role=comp.role, vkey=comp.vkey,
                          provider=comp.provider, model=comp.model,
                          tokens_in=comp.tokens_in, tokens_out=comp.tokens_out,
                          cost=0, cache_hit=True, latency_ms=0)

    def _cache_key(self, role, messages):
        digest = hashlib.sha256(
            json.dumps(messages, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        return (self.engagement_id, role, digest)   # namespaced per engagement (§7)

    def _log(self, vk, comp, metadata, *, decision):
        audit.record(self.conn, self.engagement_id, vk.vkey, "model_call",
                     decision=decision, reason=f"{comp.provider}/{comp.model}",
                     correlation_id=metadata.get("correlation_id"),
                     detail={"role": vk.role, "vkey": vk.vkey, "provider": comp.provider,
                             "model": comp.model, "tokens_in": comp.tokens_in,
                             "tokens_out": comp.tokens_out, "cache_hit": comp.cache_hit,
                             "latency_ms": comp.latency_ms})

    def _stop(self, vk, reason, metadata):
        audit.record(self.conn, self.engagement_id, vk.vkey, "model_stop",
                     decision=reason, correlation_id=metadata.get("correlation_id"),
                     detail={"role": vk.role, "vkey": vk.vkey})
        raise PlaneStop(reason, vk.role)

    # --- config sketch (§11) --------------------------------------------
    @classmethod
    def from_config(cls, config, transport, conn, engagement_id, *, clock=time.monotonic):
        """Build a plane from the HC-MODEL-01 §11 config shape. A config that
        violates the diversity or MCP invariant fails closed here, at startup."""
        vks = config.get("virtual_keys", {})
        budgets = (config.get("budgets") or {}).get("engagement", {})
        role_budgets = budgets.get("children", {}) if isinstance(budgets.get("children"), dict) else {}
        vkeys = []
        for vkid, spec in vks.items():
            role = vkid[3:] if vkid.startswith("vk-") else vkid
            vkeys.append(VirtualKey(
                role, spec.get("providers", []), cache=spec.get("cache", False),
                fallback=spec.get("fallback", "free"), rate=spec.get("rate"),
                budget=role_budgets.get(vkid), mcp_tools=spec.get("mcp_tools", ())))
        return cls(vkeys, transport, conn, engagement_id,
                   engagement_budget=budgets.get("limit"), clock=clock)
