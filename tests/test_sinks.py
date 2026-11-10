"""Per-handler sink reachability (HC-AGENT-01 recon, Slice B): the analyzer that decides which
parameters are worth probing, and the applicability gate it feeds. Pure unit tests over source
strings and a small fixture route tree; no Docker, no network, no models. The classifier marks a
parameter risky only where the source shows a request value reaching a sink unsafely, so a
well-parameterized layer stays clean and the injection cards' fan-out collapses onto the few
real candidates."""
import atexit
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from harness import predicates, recon
from harness.sourcemap import extract_surface, sinks

# --- classify_file: one handler's source, judged on its own text ----------------------------

def _sql(src):
    return sinks.classify_file(src)["sqli"]


def test_parameterized_query_is_safe():
    src = ("import { getPool } from '@/lib/db.server';\n"
           "const q = new URL(request.url).searchParams.get('q');\n"
           "const params = []; const push = v => { params.push(v); return '$'+params.length; };\n"
           "getPool().query(`SELECT * FROM t WHERE name = ${push(q)}`, params);\n")
    assert _sql(src) == "safe"


def test_value_inlined_in_a_string_literal_is_risky():
    src = ("const q = new URL(request.url).searchParams.get('q');\n"
           "pool.query(`SELECT * FROM t WHERE name = '${q}'`);\n")
    assert _sql(src) == "risky"


def test_request_value_inlined_unquoted_is_risky():
    src = ("const sort = new URL(request.url).searchParams.get('sort');\n"
           "pool.query(`SELECT * FROM t ORDER BY ${sort}`);\n")
    assert _sql(src) == "risky"


def test_allow_listed_order_column_is_safe():
    src = ("const COLS = { name: 'name', date: 'created_at' };\n"
           "const sort = new URL(request.url).searchParams.get('sort');\n"
           "const col = COLS[sort] || 'name';\n"
           "pool.query(`SELECT * FROM t ORDER BY ${col}`);\n")
    assert _sql(src) == "safe"


def test_manual_placeholder_and_constants_are_safe():
    src = ("const COLUMNS = 'a, b, c';\n"
           "const idParam = `$${params.length}`;\n"
           "pool.query(`SELECT ${COLUMNS} FROM t WHERE id = ${idParam}`);\n")
    assert _sql(src) == "safe"


def test_no_query_call_is_absent():
    assert _sql("export async function loader() { return json({ ok: true }); }") == "absent"


def test_fs_path_from_request_is_risky_else_safe():
    risky = ("import { readFileSync } from 'fs';\n"
             "const name = new URL(request.url).searchParams.get('name');\n"
             "readFileSync('/data/' + name);\n")
    safe = ("import { readFileSync } from 'fs';\n"
            "const JWK = process.env.JWK_PATH;\n"
            "readFileSync(JWK, 'utf8');\n")
    assert sinks.classify_file(risky)["path"] == "risky"
    assert sinks.classify_file(safe)["path"] == "safe"
    assert sinks.classify_file("const x = 1;")["path"] == "absent"


def test_command_injection_requires_child_process_and_taint():
    risky = ("import { execSync } from 'child_process';\n"
             "const host = new URL(request.url).searchParams.get('host');\n"
             "execSync('ping ' + host);\n")
    const = ("import { execSync } from 'child_process';\n"
             "execSync('uptime');\n")
    regexp = "const m = /(\\d+)/.exec(line);"      # RegExp.exec, not a shell
    assert sinks.classify_file(risky)["cmdi"] == "risky"
    assert sinks.classify_file(const)["cmdi"] == "safe"
    assert sinks.classify_file(regexp)["cmdi"] == "absent"


def test_ssti_eval_of_request_is_risky():
    risky = ("const tpl = new URL(request.url).searchParams.get('tpl');\n"
             "return eval(tpl);\n")
    assert sinks.classify_file(risky)["ssti"] == "risky"
    assert sinks.classify_file("const y = eval('1+1');")["ssti"] == "absent"   # constant


# --- the import graph and the cross-file closure --------------------------------------------

_PKG = '{"dependencies": {"@react-router/dev": "^7.0.0", "react-router": "^7.0.0"}}'
_ROUTES_TS = "import { flatRoutes } from '@react-router/fs-routes';\nexport default flatRoutes();\n"
_ROUTE_FILES = {
    # parameterized -> safe, no sink_risk
    "safe.tsx": (
        "import { getPool } from '@/providers/db.server';\n"
        "export async function loader({ request }) {\n"
        "  const q = new URL(request.url).searchParams.get('q');\n"
        "  const params = []; const push = v => { params.push(v); return '$'+params.length; };\n"
        "  return getPool().query(`SELECT * FROM t WHERE name = ${push(q)}`, params);\n"
        "}\nexport default function S() { return null; }\n"),
    # value inlined in a string literal -> risky sqli
    "sqli.tsx": (
        "import { getPool } from '@/providers/db.server';\n"
        "export async function loader({ request }) {\n"
        "  const q = new URL(request.url).searchParams.get('q');\n"
        "  return getPool().query(`SELECT * FROM t WHERE name = '${q}'`);\n"
        "}\nexport default function Q() { return null; }\n"),
    # sink lives in an imported module -> the closure must reach it
    "crossfile.tsx": (
        "import { listBad } from '@/providers/bad.server';\n"
        "export async function loader({ request }) {\n"
        "  const term = new URL(request.url).searchParams.get('term');\n"
        "  return listBad(term);\n"
        "}\nexport default function C() { return null; }\n"),
    # fs path from a request value -> risky path
    "pathtrav.tsx": (
        "import { readFileSync } from 'fs';\n"
        "export async function loader({ request }) {\n"
        "  const name = new URL(request.url).searchParams.get('name');\n"
        "  return new Response(readFileSync('/data/' + name));\n"
        "}\nexport default function P() { return null; }\n"),
}
_PROVIDERS = {
    "db.server.ts": "import pg from 'pg';\nlet pool;\nexport function getPool() { return pool; }\n",
    "bad.server.ts": (
        "import { getPool } from '@/providers/db.server';\n"
        "export function listBad(term) {\n"
        "  return getPool().query(`SELECT * FROM t WHERE x = '${term}'`);\n"
        "}\n"),
}


def _build_fixture():
    root = tempfile.mkdtemp(prefix="hc-sinks-")
    with open(os.path.join(root, "package.json"), "w") as fh:
        fh.write(_PKG)
    app = os.path.join(root, "app")
    os.makedirs(os.path.join(app, "routes"))
    os.makedirs(os.path.join(app, "providers"))
    with open(os.path.join(app, "routes.ts"), "w") as fh:
        fh.write(_ROUTES_TS)
    for name, src in _ROUTE_FILES.items():
        with open(os.path.join(app, "routes", name), "w") as fh:
            fh.write(src)
    for name, src in _PROVIDERS.items():
        with open(os.path.join(app, "providers", name), "w") as fh:
            fh.write(src)
    return root


_ROOT = _build_fixture()
atexit.register(shutil.rmtree, _ROOT, True)


def test_import_graph_resolves_alias_and_drops_externals():
    graph, _content = sinks.build_import_graph(_ROOT)
    cross = os.path.join(_ROOT, "app", "routes", "crossfile.tsx")
    bad = os.path.join(_ROOT, "app", "providers", "bad.server.ts")
    assert bad in graph[cross]                              # `@/providers/bad.server` resolved
    path_route = os.path.join(_ROOT, "app", "routes", "pathtrav.tsx")
    assert graph[path_route] == set()                       # `fs` is external, an opaque leaf


def test_closure_reaches_a_sink_in_an_imported_module():
    graph, content = sinks.build_import_graph(_ROOT)
    cross = os.path.join(_ROOT, "app", "routes", "crossfile.tsx")
    assert sinks.analyze_handler(cross, graph, content) == ["sqli"]   # risk found across the import


# --- extract_surface + project_surface annotations ------------------------------------------

def _surface():
    return {e["path"]: e for e in extract_surface(_ROOT)["endpoints"]}


def test_extract_surface_tags_each_handler():
    eps = _surface()
    assert eps["/safe"]["sink_analyzed"] is True and eps["/safe"]["sink_risk"] == []
    assert eps["/sqli"]["sink_risk"] == ["sqli"]
    assert eps["/crossfile"]["sink_risk"] == ["sqli"]
    assert eps["/pathtrav"]["sink_risk"] == ["path"]


def test_projected_assets_carry_the_sink_facts():
    model = recon.phase_source_recon(_ROOT, host="t1.sandbox.local", addr="10.90.0.4", port=8080)
    safe = model["t1::/safe?q"]
    assert safe["asset.sink_analyzed"] is True and safe["asset.sink_risk"] == []
    risky = model["t1::/sqli?q"]
    assert risky["asset.sink_risk"] == ["sqli"]


# --- the applicability gate (the exact clauses materialized into the injection cards) --------

_SQLI_GATE = "matches(asset.sink_risk, /sqli/) || !exists(asset.sink_analyzed)"
_PATH_GATE = ("matches(asset.sink_risk, /path/) || !exists(asset.sink_analyzed)"
              " && matches(asset.params, /file|path|name|template/)")


def test_sqli_gate_skips_safe_source_asset_and_holds_on_risky():
    model = recon.phase_source_recon(_ROOT, host="t1.sandbox.local", addr="10.90.0.4", port=8080)
    assert not predicates.evaluate(_SQLI_GATE, model["t1::/safe?q"])      # safe -> fan-out cut
    assert predicates.evaluate(_SQLI_GATE, model["t1::/sqli?q"])          # risky -> probed


def test_gate_falls_back_to_param_presence_for_black_box_assets():
    # a crawl-derived asset carries no sink analysis; the clause must keep the old behavior
    bb = {"asset.type": "http_endpoint", "asset.params": ["file"], "asset.param": "file"}
    assert predicates.evaluate(_SQLI_GATE, bb)          # sqli card still applies (no analysis)
    assert predicates.evaluate(_PATH_GATE, bb)          # path card applies on the param name


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
