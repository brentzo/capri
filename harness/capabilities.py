"""Capability registry: which concrete tool adapter executes each KB technique.

A technique card (HC-KB-01) expresses its probe at a conceptual level - its `probe_steps`
name a tool like `custom.authz_probe` - while the dispatcher runs concrete reviewed
adapters (`idor`, `sqli`, ...). This registry is the reviewed bridge between the two: it
maps a card id to the adapter that implements the technique and the arguments that drive
it against a target, so the model proposes a probe the dispatcher can actually run. The
conceptual tool name is not enough on its own (for example `custom.authz_probe` covers
both object-level and function-level authorization, which are two different adapters), so
the mapping is keyed by card id.

A card with no entry here has no runnable implementation yet: it still loads into the full
KB and the report validator still knows it, but the live runner does not hunt it, so the
harness degrades gracefully rather than proposing a tool the dispatcher would deny. The
probe arguments are the one place a target's shape (its endpoints and parameters) is
configured; a later slice derives them from recon instead of naming them here.
"""

# card id -> (concrete dispatcher tool, probe arguments). A card is listed only when the
# adapter proves the technique the card actually describes; the timing-oracle SQLi variant
# (KB-WEB-INJ-SQLI-002), for instance, is not mapped to the boolean `sqli` adapter.
CAPABILITIES = {
    "KB-WEB-INJ-SQLI-001": ("sqli", {"path": "/item", "sqli_param": "id"}),
    "KB-WEB-AUTH-IDOR-001": ("idor", {"path": "/account", "id_param": "id",
                                      "login_path": "/login", "own_id": "1"}),
    "KB-WEB-AUTH-BFLA-001": ("bfla", {"path": "/admin", "login_path": "/login",
                                      "login_user": "1"}),
    "KB-WEB-AUTH-JWT-001": ("jwt", {"path": "/account", "params": {"id": "1"}}),
    "KB-WEB-INJ-SSTI-001": ("ssti", {"path": "/greet", "param": "name"}),
    "KB-WEB-PROTO-CORS-001": ("cors", {"path": "/api/data"}),
    "KB-WEB-INJ-PATH-001": ("path", {"path": "/download", "param": "file"}),
    "KB-WEB-INJ-CMDI-001": ("cmdi", {"path": "/ping", "param": "host", "delay_s": 5}),
    "KB-WEB-CACHE-POISON-001": ("cache", {"path": "/promo"}),
    "KB-WEB-SESS-FIX-001": ("sess", {"path": "/portal", "login_path": "/portal/login",
                                     "me_path": "/portal/me", "login_user": "1"}),
    "KB-WEB-INJ-SSRF-001": ("ssrf", {"path": "/fetch", "param": "url"}),
    "KB-CLIENT-REDIRECT-OPEN-001": ("redirect", {"path": "/redirect", "param": "url"}),
}


def implemented(card_id):
    """Whether the harness has a runnable adapter for this technique."""
    return card_id in CAPABILITIES


def runnable_index(kb_index):
    """Project a KB index into just the cards the harness can hunt, each with a concrete
    probe step attached in place of its conceptual one.

    The returned cards keep the real card's id, version, applicability, preconditions,
    success signal, and severity, so the planner, the deterministic signal rule, and the
    report validator all see the genuine technique; only the `probe_steps` are replaced
    with the adapter tool and arguments the dispatcher runs. Cards with no capability are
    left out."""
    out = {}
    for (cid, ver), card in kb_index.items():
        cap = CAPABILITIES.get(cid)
        if cap is None:
            continue
        tool, args = cap
        intent = ((card.get("probe_steps") or [{}])[0]).get("intent") or tool
        runnable = dict(card)
        runnable["probe_steps"] = [{"tool": tool, "intent": intent, **args}]
        out[(cid, ver)] = runnable
    return out
