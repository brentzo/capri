"""Framework detection for source-aware recon (HC-AGENT-01).

Routes the source tree to the matching extractor, the way REA routes an artifact to the
right analysis. Each adapter answers `detects(source_root)`; the first that does wins. New
stacks (Express, FastAPI, Rails) are added by registering another adapter here, never by
touching the probe-routing spine downstream.
"""
from harness.sourcemap import react_router

# Ordered: the first adapter whose detects() is true handles the tree.
_ADAPTERS = [
    ("react-router", react_router),
]


def detect(source_root):
    """Return (framework_id, adapter_module) for the source tree, or (None, None)."""
    for name, adapter in _ADAPTERS:
        try:
            if adapter.detects(source_root):
                return name, adapter
        except Exception:  # noqa: BLE001 - a malformed tree is "not this framework", not fatal
            continue
    return None, None
