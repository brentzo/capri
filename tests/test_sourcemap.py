"""Source-aware surface extraction (HC-AGENT-01 recon): the React Router flat-routes adapter
and its projection into endpoint-assets. Pure unit tests over a fixture route tree, no Docker,
no network, no models. Routes decode from filenames deterministically and a comment-stripped
scan reads each handler's exports, input taps and auth gate; `project_surface` then turns the
extracted surface into the same `{asset: facts}` the probe-routing spine already consumes."""
import atexit
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness import bind, recon
from harness.sourcemap import extract_surface
from harness.sourcemap.detect import detect

# --- a minimal React Router flat-routes app, written once and shared (read-only) -----------

_PKG = '{"dependencies": {"@react-router/dev": "^7.0.0", "react-router": "^7.0.0"}}'
_ROUTES_TS = (
    "import { flatRoutes } from '@react-router/fs-routes';\n"
    "export default flatRoutes();\n"
)

# filename -> handler source. Each exercises a decode rule and/or a scan rule.
_ROUTE_FILES = {
    # index route: '/', a GET loader reading one query param, no auth.
    "_index.tsx": (
        "export async function loader({ request }) {\n"
        "  const q = new URL(request.url).searchParams.get('q');\n"
        "  return { q }; // http://example not a comment-eater trap\n"
        "}\n"
        "export default function Home() { return null; }\n"
    ),
    # resource route with a path param and several query params, auth-gated by a call.
    "api.accounts.$id.transactions.tsx": (
        "export async function loader({ request, params }) {\n"
        "  await requireSession(request);\n"
        "  const url = new URL(request.url);\n"
        "  const search = url.searchParams.get('search');\n"
        "  const type = url.searchParams.get('type');\n"
        "  return json({ id: params.id, search, type });\n"
        "}\n"
    ),
    # _dashboard subtree: pathless prefix, auth by subtree membership; page + a mutation.
    "_dashboard.settings.tsx": (
        "export async function action({ request }) {\n"
        "  const form = await request.formData();\n"
        "  const name = formText(form, 'displayName');\n"
        "  return { name };\n"
        "}\n"
        "export default function Settings() { return null; }\n"
    ),
    # trailing-underscore de-nest plus a $param: '/posts/:slug/edit'.
    "posts.$slug_.edit.tsx": (
        "export async function loader() { return null; }\n"
        "export default function Edit() { return null; }\n"
    ),
    # bracket escape: '[report.pdf]' is one literal segment, the dot not a separator.
    "files.[report.pdf].tsx": (
        "export async function loader() { return new Response('pdf'); }\n"
    ),
    # a non-route colocated helper: must be ignored, not decoded into a route.
    "api.accounts.$id.transactions.server.ts": (
        "export function requireSession() {}\n"
    ),
}
# a folder-form route: app/routes/widgets/route.tsx -> '/widgets'.
_FOLDER_ROUTE = ("widgets", "route.tsx",
                 "export async function loader() { return null; }\n"
                 "export default function Widgets() { return null; }\n")


def _build_fixture():
    root = tempfile.mkdtemp(prefix="hc-sourcemap-")
    with open(os.path.join(root, "package.json"), "w") as fh:
        fh.write(_PKG)
    app = os.path.join(root, "app")
    routes = os.path.join(app, "routes")
    os.makedirs(routes)
    with open(os.path.join(app, "routes.ts"), "w") as fh:
        fh.write(_ROUTES_TS)
    for name, src in _ROUTE_FILES.items():
        with open(os.path.join(routes, name), "w") as fh:
            fh.write(src)
    folder = os.path.join(routes, _FOLDER_ROUTE[0])
    os.makedirs(folder)
    with open(os.path.join(folder, _FOLDER_ROUTE[1]), "w") as fh:
        fh.write(_FOLDER_ROUTE[2])
    return root


_ROOT = _build_fixture()
atexit.register(shutil.rmtree, _ROOT, True)


def _by_path(surface):
    return {e["path"]: e for e in surface["endpoints"]}


# --- detection ----------------------------------------------------------------

def test_detect_identifies_react_router():
    name, adapter = detect(_ROOT)
    assert name == "react-router" and adapter is not None


def test_unrecognized_tree_yields_empty_surface():
    empty = tempfile.mkdtemp(prefix="hc-empty-")
    try:
        surface = extract_surface(empty)
        assert surface["framework"] is None and surface["endpoints"] == []
    finally:
        shutil.rmtree(empty, True)


# --- filename -> URL path decoding --------------------------------------------

def test_all_routes_decode_to_expected_paths():
    paths = set(_by_path(extract_surface(_ROOT)))
    assert paths == {
        "/", "/api/accounts/:id/transactions", "/settings",
        "/posts/:slug/edit", "/files/report.pdf", "/widgets",
    }


def test_colocated_server_helper_is_not_a_route():
    # the .server.ts sibling must not appear as its own route
    handlers = [e["handler_file"] for e in extract_surface(_ROOT)["endpoints"]]
    assert not any(h.endswith(".server.ts") for h in handlers)


def test_index_route_is_flagged():
    assert _by_path(extract_surface(_ROOT))["/"]["index"] is True


def test_path_params_are_recovered():
    eps = _by_path(extract_surface(_ROOT))
    assert eps["/api/accounts/:id/transactions"]["path_params"] == ["id"]
    assert eps["/posts/:slug/edit"]["path_params"] == ["slug"]


# --- handler scanning: methods, kind, params, auth ----------------------------

def test_loader_is_get_and_default_export_is_a_page():
    home = _by_path(extract_surface(_ROOT))["/"]
    assert home["methods"] == ["GET"] and home["kind"] == "page"


def test_action_plus_default_is_a_page_with_a_mutation():
    settings = _by_path(extract_surface(_ROOT))["/settings"]
    assert "POST" in settings["methods"] and settings["kind"] == "page"  # has a default export


def test_resource_route_without_default_export():
    tx = _by_path(extract_surface(_ROOT))["/api/accounts/:id/transactions"]
    assert tx["kind"] == "resource" and tx["methods"] == ["GET"]


def test_query_params_are_scanned():
    tx = _by_path(extract_surface(_ROOT))["/api/accounts/:id/transactions"]
    assert tx["params"] == ["search", "type"]


def test_form_tap_param_is_scanned():
    settings = _by_path(extract_surface(_ROOT))["/settings"]
    assert settings["params"] == ["displayName"]


def test_requirecall_marks_route_auth_gated():
    tx = _by_path(extract_surface(_ROOT))["/api/accounts/:id/transactions"]
    assert tx["auth"] is True


def test_dashboard_subtree_is_auth_gated_by_membership():
    assert _by_path(extract_surface(_ROOT))["/settings"]["auth"] is True


def test_unauthed_route_is_not_flagged():
    assert _by_path(extract_surface(_ROOT))["/"]["auth"] is False


# --- projection into endpoint-assets ------------------------------------------

def test_query_param_projects_to_a_concrete_probeable_asset():
    model = recon.phase_source_recon(_ROOT, host="t1.sandbox.local", addr="10.90.0.4", port=8080)
    a = model["t1::/api/accounts/1/transactions?search"]
    assert a["asset.path"] == "/api/accounts/1/transactions"   # :id concretized for the probe
    assert a["asset.param"] == "search" and a["asset.params"] == ["search"]
    assert a["asset.auth_required"] is True and a["open_ports"] == [8080]


def test_path_param_projects_to_a_path_injection_asset():
    model = recon.phase_source_recon(_ROOT, host="t1.sandbox.local", addr="10.90.0.4", port=8080)
    a = model["t1::/api/accounts/:id/transactions$id"]
    assert a["asset.inject_in"] == "path" and a["asset.path_param"] == "id"
    assert a["asset.path_template"] == "/api/accounts/{id}/transactions"
    assert "asset.param" not in a                               # query cards must not bind it


def test_query_injection_card_binds_a_query_asset_but_skips_a_path_asset():
    model = recon.phase_source_recon(_ROOT, host="t1.sandbox.local", addr="10.90.0.4", port=8080)
    card = {"id": "KB-TEST", "version": "1.0.0",
            "probe_steps": [{"tool": "sqli", "intent": "baseline",
                             "path": "{asset.path}", "sqli_param": "{asset.param}"}]}
    bound = bind.bind_probe_args(card, model["t1::/api/accounts/1/transactions?search"])
    assert bound["probe_steps"][0]["sqli_param"] == "search"
    assert bind.bind_probe_args(card, model["t1::/api/accounts/:id/transactions$id"]) is None


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"  ok   {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"  FAIL {t.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"  ERR  {t.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
