"""Surface extraction entry point (HC-AGENT-01 recon).

`extract_surface(source_root)` detects the app's framework and returns the deterministic
surface map the recon phase projects into endpoint-as-asset entries. The map shape matches
what `harness.recon.project_surface` already consumes (an `endpoints` list of
`{path, method, params, ...}`), so the probe-routing spine is unchanged; only the source of
the surface differs. An unrecognized tree returns an empty surface with its framework set to
`None`, an honest "nothing extracted" rather than a guess.
"""
import os

from harness.sourcemap.detect import detect


def extract_surface(source_root):
    """Return `{framework, source_root, endpoints:[...]}` extracted from the app's source.

    `endpoints` each carry `path`, `method` (and `methods`), `params`, `path_params`, `auth`,
    `kind` (page/resource/layout) and `handler_file`. An app whose framework is not recognized
    yields `{"framework": None, "endpoints": []}`."""
    source_root = os.path.abspath(source_root)
    framework, adapter = detect(source_root)
    if adapter is None:
        return {"framework": None, "source_root": source_root, "endpoints": []}
    surface = adapter.extract(source_root)
    surface.setdefault("framework", framework)
    surface.setdefault("source_root", source_root)
    surface.setdefault("endpoints", [])
    return surface
