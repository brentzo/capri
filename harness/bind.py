"""Recon-derived probe-argument binding (HC-AGENT-01 §5.3).

The capability registry gives each runnable card a probe step whose argument values may
be templates like ``{asset.path}`` or ``{asset.param}``. This module resolves those
templates against an asset's recon facts, so the probe is routed at the endpoints and
parameters recon actually discovered on the target rather than at literals baked into the
registry.

A whole-string template (the value is exactly ``{name}``) resolves to the fact's value,
keeping its type; an inline template substitutes ``str(fact)`` into the surrounding text.
A step that carries no templates is returned unchanged, so cards still holding literal
args keep working. A template that references a fact the asset does not carry cannot be
routed over that asset: ``bind_probe_args`` returns ``None`` and the caller skips the pair,
which is what keeps a recon-derived card from firing against an asset that lacks the
endpoint facts it needs.
"""
import re

# A template token: {dotted.fact.name}. Fact names are flat keys that may contain dots,
# matching the blackboard fact namespace recon writes (e.g. "asset.path").
_TEMPLATE = re.compile(r"\{([A-Za-z_][\w.]*)\}")


class _Unresolved(Exception):
    """A template referenced a fact the asset does not carry."""


def _subst(value, facts):
    """Resolve any templates in a probe-step value against facts, recursively."""
    if isinstance(value, str):
        whole = _TEMPLATE.fullmatch(value)
        if whole:                                   # keep the fact's native type
            key = whole.group(1)
            if key not in facts or facts[key] is None:
                raise _Unresolved(key)
            return facts[key]

        def repl(mo):
            key = mo.group(1)
            if key not in facts or facts[key] is None:
                raise _Unresolved(key)
            return str(facts[key])

        return _TEMPLATE.sub(repl, value)
    if isinstance(value, dict):
        return {k: _subst(v, facts) for k, v in value.items()}
    if isinstance(value, list):
        return [_subst(v, facts) for v in value]
    return value


def step_has_templates(step):
    """Whether a probe step carries any ``{template}`` argument value."""
    try:
        return _subst(step, {}) != step
    except _Unresolved:
        return True


def bind_probe_args(card, facts):
    """Specialize a runnable card's probe step to one asset's recon facts.

    Returns a copy of ``card`` whose first probe step has its argument templates resolved
    from ``facts``. A step with no templates yields the card unchanged. When a template
    references a fact the asset does not carry, the card cannot be routed over this asset
    and the function returns ``None``.
    """
    steps = card.get("probe_steps") or []
    if not steps:
        return card
    step = steps[0]
    try:
        bound = _subst(step, facts)
    except _Unresolved:
        return None
    if bound == step:
        return card                                 # literal step: nothing to specialize
    out = dict(card)
    out["probe_steps"] = [bound, *steps[1:]]
    return out
