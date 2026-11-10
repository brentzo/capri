"""React Router v7 file-based (`flatRoutes`) surface adapter (HC-AGENT-01 recon).

Routes come from filenames, deterministically: `@react-router/fs-routes` decodes each file
in `app/routes/` into a URL path by a fixed convention, so the route list and path params
need no parser at all. Per module, a comment-stripped pattern scan reads the named exports
(`loader` -> GET, `action` -> a mutation, `default` -> a page vs a resource route), the input
taps (`searchParams.get`, `formData`/`formText`, `request.json` fields; path params come from
the filename), and an auth flag (a `requireSession`/`requireSupportActor` call, or membership
in the `_dashboard` subtree whose middleware gates the whole thing). A handler whose inputs the
scan cannot resolve keeps an empty param list; its route is still reported. No code is executed.
"""
import os
import re

# Colocated helpers that live under app/routes/ but are not routes.
_NON_ROUTE = (".server.ts", ".server.tsx", ".client.ts", ".client.tsx",
              ".test.ts", ".test.tsx", ".spec.ts", ".spec.tsx", ".d.ts", ".css")

_AUTH_CALLS = ("requireSession", "requireSupportActor", "requireSupportApiActor",
               "requireAuth", "requireUser", "requireFeatureWriteAccess")

# Input taps: each captures a parameter name a handler reads from the request.
_TAPS = (
    re.compile(r"searchParams\.get\(\s*['\"]([^'\"]+)['\"]"),            # ?name=
    re.compile(r"\.get\(\s*['\"]([^'\"]+)['\"]\s*\)"),                    # formData/body .get('name')
    re.compile(r"\b(?:formText|entryText|formNumber|formBool|bodyText|formFile)"
               r"\(\s*\w+\s*,\s*['\"]([^'\"]+)['\"]"),                    # formText(form, 'name')
)
_HAS_JSON_BODY = re.compile(r"\brequest\.json\(\)|\bparseJsonBody\(")


def detects(source_root):
    """Whether this adapter handles the tree: a React Router app whose routes are file-based."""
    pkg = _read(os.path.join(source_root, "package.json"))
    if "@react-router/dev" not in pkg and "react-router" not in pkg:
        return False
    routes_ts = (_read(os.path.join(source_root, "app", "routes.ts"))
                 + _read(os.path.join(source_root, "app", "routes.tsx")))
    if "flatRoutes" in routes_ts:
        return True
    return os.path.isdir(os.path.join(source_root, "app", "routes"))


def extract(source_root):
    """Return `{framework, source_root, endpoints:[...]}` for a flat-routes app."""
    routes_dir = os.path.join(source_root, "app", "routes")
    endpoints = []
    for route_id, handler_file in _iter_route_modules(routes_dir):
        src = _strip_comments(_read(handler_file))
        path, path_params, index = _decode_route_id(route_id)
        methods = []
        if _has_export(src, "loader"):
            methods.append("GET")
        if _has_export(src, "action"):
            methods.append("POST")
        has_default = bool(re.search(r"\bexport\s+default\b", src))
        kind = "page" if has_default else ("resource" if methods else "layout")
        params = _scan_params(src)
        endpoints.append({
            "path": path,
            "method": "GET" if "GET" in methods or not methods else methods[0],
            "methods": methods,
            "params": params,
            "path_params": path_params,
            "auth": _is_auth(src, route_id),
            "kind": kind,
            "index": index,
            "has_json_body": bool(_HAS_JSON_BODY.search(src)),
            "handler_file": os.path.relpath(handler_file, source_root),
        })
    endpoints.sort(key=lambda e: (e["path"], e["handler_file"]))
    return {"framework": "react-router", "source_root": source_root, "endpoints": endpoints}


# --- route module discovery -------------------------------------------------

def _iter_route_modules(routes_dir):
    """Yield (route_id, absolute_file) for each route: a flat file `X.tsx`, or a folder
    `X/route.tsx`. The route id is the file/folder name without the extension."""
    if not os.path.isdir(routes_dir):
        return
    for name in sorted(os.listdir(routes_dir)):
        full = os.path.join(routes_dir, name)
        if os.path.isfile(full):
            if name.startswith(".") or any(name.endswith(s) for s in _NON_ROUTE):
                continue
            if name.endswith((".tsx", ".ts", ".jsx", ".js")):
                yield name.rsplit(".", 1)[0], full
        elif os.path.isdir(full):
            for route_file in ("route.tsx", "route.ts", "route.jsx", "route.js"):
                cand = os.path.join(full, route_file)
                if os.path.isfile(cand):
                    yield name, cand
                    break


# --- filename -> URL path (the flat-routes convention) ----------------------

def _split_segments(route_id):
    """Split a route id on '.' , but never on a '.' inside a [...] escape."""
    segs, buf, depth = [], [], 0
    for ch in route_id:
        if ch == "[":
            depth += 1
            buf.append(ch)
        elif ch == "]":
            depth = max(0, depth - 1)
            buf.append(ch)
        elif ch == "." and depth == 0:
            segs.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    segs.append("".join(buf))
    return [s for s in segs if s != ""]


def _unescape(seg):
    """Replace [x] escapes with their literal content (so `[.]` -> `.`)."""
    return re.sub(r"\[(.*?)\]", lambda m: m.group(1), seg)


def _decode_route_id(route_id):
    """Decode a flat-route id into (url_path, path_params, is_index)."""
    path_segs, path_params, index = [], [], False
    for seg in _split_segments(route_id):
        if seg == "_index":
            index = True
            continue
        if seg.startswith("_"):                       # pathless layout: no URL segment
            continue
        core = seg[:-1] if seg.endswith("_") else seg  # trailing '_' only de-nests
        if core.startswith("$"):
            name = core[1:]
            if name == "":
                path_segs.append("*")                 # splat / catch-all
            else:
                path_segs.append(":" + name)
                path_params.append(name)
        else:
            path_segs.append(_unescape(core))
    path = "/" + "/".join(path_segs)
    return path, path_params, index


# --- handler scanning -------------------------------------------------------

def _strip_comments(src):
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    src = re.sub(r"(^|[^:])//[^\n]*", r"\1", src)      # keep the char before // (avoids eating http:)
    return src


def _has_export(src, name):
    if re.search(rf"\bexport\s+(?:async\s+)?(?:function|const|let|var)\s+{name}\b", src):
        return True
    return bool(re.search(rf"\bexport\s*\{{[^}}]*\b{name}\b[^}}]*\}}", src))


def _scan_params(src):
    found = []
    for rx in _TAPS:
        found.extend(rx.findall(src))
    # drop obvious non-params that the generic .get() tap can catch (header reads, cookies)
    out = sorted({p for p in found if p and not p.lower() in ("cookie", "authorization")})
    return out


def _is_auth(src, route_id):
    if route_id.startswith("_dashboard"):
        return True
    return any(call in src for call in _AUTH_CALLS)


def _read(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""
