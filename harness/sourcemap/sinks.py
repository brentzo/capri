"""Per-handler sink reachability analysis (HC-AGENT-01 recon, Slice B).

Slice A enumerates every route and parameter; this decides which parameters are worth
probing, by reading how a handler's *reachable* source uses its sinks. A route's taps and its
sinks usually live in different files (route -> facade -> provider), so the analysis follows
each handler's imports across the app's own source and classifies the sinks that whole closure
can reach. The verdict is attached to every parameter of the handler: a handler that can reach
an unsafe sink of a class flags all of its parameters for that class, so no parameter that
could reach it is skipped. It over-approximates per parameter (a handler with one unsafe sink
flags them all, and a shared helper module flags every handler that imports it), which keeps
the analysis deterministic and tractable; per-parameter taint tracing is a later refinement.

Each file in the closure is classified against its *own* text: a SQL template's interpolations
are judged where the template is written, so a parameter named `pageSize` in one module cannot
poison a different module's `${q.pageSize}`. The classifier is precision-favoring, which is
what the fan-out goal needs: it reports a sink risky only where the source actually shows a
request value reaching the sink unsafely, at the cost of missing a value laundered through
several indirections. The sink and safe-primitive patterns are grounded in a real React Router
+ node-postgres app; an unfamiliar safe idiom reads as risky (conservative), and new idioms are
added to the classifiers rather than worked around. Only the four classes that map to the
injection technique cards are computed in v1: SQL injection, path traversal, OS command
injection, and server-side template injection. SSRF, open redirect and IDOR are a follow-up.

Deterministic and standard-library only: the same source always yields the same verdict.
"""
import os
import json
import re

from harness.sourcemap.react_router import _read, _strip_comments

_SRC_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mts", ".cts", ".mjs", ".cjs")

# The request-input vocabulary: an expression that mentions any of these reads untrusted
# input. The `params.` branch is a route path param (`params.id`); it excludes array
# operations so a SQL builder's own `params` parameter array (`params.length`,
# `params.push(...)`) is not mistaken for request input.
_PARAMS_ARRAY_OPS = (r"length|push|pop|shift|unshift|splice|slice|concat|map|join|indexOf"
                     r"|forEach|filter|reduce|includes|find|some|every|flat|fill|sort"
                     r"|reverse|keys|values|entries")
_TAINT = re.compile(
    # framework-neutral web/React Router request inputs
    r"\bsearchParams\b|\bparams\.(?!(?:" + _PARAMS_ARRAY_OPS + r")\b)[A-Za-z_$]"
    r"|\brequest\.(?:json|formData|url|text|body|arrayBuffer)\b|\breq\.(?:query|params|body)\b"
    r"|\bformData\s*\(|\bgetRequestURL\b|\bgetQuery\s*\("
    # common app-defined form helpers (extend here per project, not worked around)
    r"|\bformText\b|\bformNumber\b|\bformBool\b|\bformFile\b|\bentryText\b|\bbodyText\b"
    r"|\btoStringValue\b|\brequireValue\b"
)
# A value read from a request-bound container (`form.get('x')`, where the receiver was assigned
# from formData()/searchParams). Catches the generic form-read idiom without an app helper name.
_CONTAINER_ASSIGN = re.compile(r"\bformData\s*\(|\bsearchParams\b|\bURLSearchParams\b|new\s+URL\s*\(")
_CONTAINER_GET = re.compile(r"([A-Za-z_$][\w$]*)\.(?:get|getAll)\s*\(")

# ---------------------------------------------------------------------------
# Import graph: route each import specifier to a file inside the app's own tree.
# ---------------------------------------------------------------------------

# A string specifier that follows `from`, a side-effect `import`, `import(` or `require(`.
_IMPORT_RE = re.compile(r"""\b(?:from|import|require)\s*\(?\s*['"]([^'"]+)['"]""")


def _resolve_file(base):
    """Resolve a module base path (no extension, or a directory) to a concrete source file."""
    for ext in _SRC_EXTS:
        if os.path.isfile(base + ext):
            return base + ext
    if os.path.isfile(base):
        return base
    for ext in _SRC_EXTS:
        idx = os.path.join(base, "index" + ext)
        if os.path.isfile(idx):
            return idx
    return None


def _strip_jsonc(text):
    """Make a tsconfig/jsconfig (JSONC) parseable: drop comments and trailing commas."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"(^|[^:])//[^\n]*", r"\1", text)
    return re.sub(r",(\s*[}\]])", r"\1", text)


def _load_aliases(source_root):
    """The import aliases this project declares, as `[(prefix, [target_dirs])]`.

    Read from `tsconfig.json`/`jsconfig.json` `compilerOptions.paths` (resolved against
    `baseUrl`), so a project that aliases `~/`, `@app/` or `@/ -> ./src/*` resolves as well as
    one using `@/ -> ./app/*`. When no config declares paths, fall back to the common `@/ ->
    app/` convention if an `app/` directory exists, so a config-less app still resolves. A `*`
    wildcard in a key or target is treated as a prefix."""
    cfg = {}
    for name in ("tsconfig.json", "jsconfig.json"):
        p = os.path.join(source_root, name)
        if os.path.isfile(p):
            try:
                cfg = json.loads(_strip_jsonc(_read(p)))
            except (ValueError, OSError):
                cfg = {}
            break
    co = cfg.get("compilerOptions", {}) if isinstance(cfg, dict) else {}
    base_dir = os.path.normpath(os.path.join(source_root, co.get("baseUrl", ".") or "."))
    aliases = []
    for key, targets in (co.get("paths", {}) or {}).items():
        prefix = key[:-1] if key.endswith("*") else key
        dirs = [os.path.normpath(os.path.join(base_dir, (t[:-1] if t.endswith("*") else t)))
                for t in (targets or []) if isinstance(t, str)]
        if prefix and dirs:
            aliases.append((prefix, dirs))
    if not aliases and os.path.isdir(os.path.join(source_root, "app")):
        aliases.append(("@/", [os.path.join(source_root, "app")]))
    return aliases


def _resolve(spec, importer_file, aliases):
    """Resolve one import specifier to an in-tree file, or None for external/bare packages."""
    if spec.startswith("."):
        base = os.path.normpath(os.path.join(os.path.dirname(importer_file), spec))
        return _resolve_file(base)
    for prefix, dirs in aliases:                    # project path aliases (tsconfig `paths`)
        if spec.startswith(prefix):
            rest = spec[len(prefix):]
            for base in dirs:
                hit = _resolve_file(os.path.join(base, rest))
                if hit:
                    return hit
            return None
    return None                                     # bare package: external, an opaque leaf


# Directories that never hold the app's own first-party source.
_SKIP_DIRS = {"node_modules", ".git", "dist", "build", "out", ".next", ".turbo",
              "coverage", "tmp", ".cache", "public", "vendor"}


def build_import_graph(source_root):
    """Scan the project's source once and return `(graph, content)`.

    `graph[abs_file]` is the set of in-tree files it imports; `content[abs_file]` is its
    comment-stripped source, cached so the closure scan never re-reads a file. The whole project
    tree is walked (not just `app/`), with build/output directories skipped, so a module imported
    from `src/` or `lib/` is still part of the closure. External and unresolvable imports are
    dropped (opaque leaves), so the closure stays inside the project's own code - which is where
    its sink call sites are written even when the driver (pg, react-router) is third-party.
    """
    aliases = _load_aliases(source_root)
    graph, content = {}, {}
    for root, dirs, files in os.walk(source_root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith(".")]
        for name in files:
            if not name.endswith(_SRC_EXTS):
                continue
            f = os.path.join(root, name)
            src = _strip_comments(_read(f))
            content[f] = src
            deps = set()
            for m in _IMPORT_RE.finditer(src):
                r = _resolve(m.group(1), f, aliases)
                if r:
                    deps.add(r)
            graph[f] = deps
    return graph, content


def reachable_files(handler_file, graph, _cap=800):
    """The handler plus every in-tree module it transitively imports. Finite (in-tree only);
    `_cap` guards a pathological graph."""
    handler_file = os.path.abspath(handler_file)
    seen, stack = set(), [handler_file]
    while stack and len(seen) < _cap:
        f = stack.pop()
        if f in seen:
            continue
        seen.add(f)
        for dep in graph.get(f, ()):
            if dep not in seen:
                stack.append(dep)
    return seen


# ---------------------------------------------------------------------------
# Light expression helpers. Each operates on ONE file's source, so same-named
# variables in different files never cross-contaminate (no full dataflow).
# ---------------------------------------------------------------------------

def _assignment_rhs(name, src):
    """Right-hand sides of `const/let/var NAME = RHS` and destructured `const { .. NAME .. }
    = RHS` within one file. One level only, deliberately."""
    n = re.escape(name)
    out = re.findall(r"(?:const|let|var)\s+" + n + r"\s*=\s*([^\n;]+)", src)
    out += re.findall(r"(?:const|let|var)\s*\{[^}]*\b" + n + r"\b[^}]*\}\s*=\s*([^\n;]+)", src)
    return out


def _call_arg(src, start):
    """The text of the first argument of a call, reading from just after its `(`."""
    depth, buf = 0, []
    for ch in src[start:start + 800]:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif ch == "," and depth == 0:
            break
        buf.append(ch)
    return "".join(buf)


def _reads_request(text, src):
    """Whether an expression reads request input: the taint vocabulary directly, or `x.get('..')`
    on a receiver assigned from a request-bound container (`formData()`, `searchParams`)."""
    if _TAINT.search(text):
        return True
    for recv in _CONTAINER_GET.findall(text):
        if any(_CONTAINER_ASSIGN.search(rhs) for rhs in _assignment_rhs(recv, src)):
            return True
    return False


def _arg_tainted(arg, src):
    """Whether a call argument carries request input, directly or one same-file assignment back."""
    if _reads_request(arg, src):
        return True
    for name in set(re.findall(r"[A-Za-z_$][\w$]*", arg)):
        if any(_reads_request(rhs, src) for rhs in _assignment_rhs(name, src)):
            return True
    return False


def _template_literals(src):
    return re.findall(r"`([^`]*)`", src, re.S)


# ---------------------------------------------------------------------------
# SQL injection: a request value reaches a SQL statement un-parameterized.
# ---------------------------------------------------------------------------

_QUERY_CALL = re.compile(r"\.query\s*\(")
# A real SQL statement, not a fragment or a prose template that merely holds a keyword.
_SQL_ANCHOR = re.compile(
    r"\bSELECT\b[\s\S]*?\bFROM\b|\bINSERT\s+INTO\b|\bUPDATE\b[\s\S]*?\bSET\b|\bDELETE\s+FROM\b",
    re.I)
_PUSH = re.compile(r"\bpush\s*\(")


def _in_string_literal(tpl, pos):
    """Whether character `pos` of a template sits inside a `'...'` or `"..."` SQL string
    literal. A value interpolated there is being inlined into the query text as data, which is
    the injection the parameter placeholder exists to prevent. Approximate (no escape
    handling), which is adequate for ranking."""
    quote = None
    for ch in tpl[:pos]:
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
    return quote is not None


def _classify_sql(src):
    """SQL injection risk: a value reaches a statement either inlined into a string literal or
    as a request-derived expression, rather than as a `$N` parameter.

    A `push(...)` or `$${...}` interpolation is a placeholder and never risky. An interpolation
    inside a SQL string literal (`'${x}'`, `LIKE '%${x}%'`) is a raw value inlined into the query
    text, which is risky whatever its origin - it is exactly what a parameter prevents. An
    unquoted interpolation (a column, a clause, a clamped `LIMIT ${n}`) is risky only when it is
    request-derived in this same file. This keeps a well-parameterized layer clean while
    catching both the classic quoted-value injection and a request value inlined elsewhere; it
    can miss a value laundered through several indirections, the precision/recall trade the
    fan-out goal calls for."""
    if not _QUERY_CALL.search(src):
        return "absent"
    for t in _template_literals(src):
        if not _SQL_ANCHOR.search(t):
            continue
        for m in re.finditer(r"\$\{([^{}]*)\}", t):
            if m.start() > 0 and t[m.start() - 1] == "$":
                continue                            # `$${...}` renders a literal $N placeholder
            expr = m.group(1)
            if _PUSH.search(expr):
                continue                            # parameterized value
            if _in_string_literal(t, m.start()) or _arg_tainted(expr, src):
                return "risky"
    return "safe"


# ---------------------------------------------------------------------------
# Path / file: a filesystem path built from request input.
# ---------------------------------------------------------------------------

_FS_SINK = re.compile(
    r"\b(?:readFileSync|readFile|createReadStream|writeFile|writeFileSync|createWriteStream"
    r"|appendFile|appendFileSync|unlink|realpath|realpathSync|openSync|readdir|readdirSync)"
    r"\s*\(|\bpath\.(?:join|resolve|normalize)\s*\(")


def _classify_path(src):
    found = False
    for m in _FS_SINK.finditer(src):
        found = True
        if _arg_tainted(_call_arg(src, m.end()), src):
            return "risky"
    return "safe" if found else "absent"


# ---------------------------------------------------------------------------
# OS command injection: a child_process call whose command carries request input.
# ---------------------------------------------------------------------------

_CP_IMPORT = re.compile(r"['\"](?:node:)?child_process['\"]")
_CP_CALL = re.compile(r"\b(?:spawn|spawnSync|exec|execSync|execFile|execFileSync|fork)\s*\(")


def _classify_cmdi(src):
    if not _CP_IMPORT.search(src):
        return "absent"                             # a bare `.exec(` without it is RegExp.exec
    for m in _CP_CALL.finditer(src):
        if _arg_tainted(_call_arg(src, m.end()), src):
            return "risky"
    return "safe"


# ---------------------------------------------------------------------------
# Server-side template injection: input rendered by a string template engine or eval.
# ---------------------------------------------------------------------------

_SSTI_SINK = re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(")
_SSTI_ENGINE = re.compile(r"\b(?:handlebars|pug|nunjucks|ejs|mustache|eta|liquidjs)\b")
_ENGINE_RENDER = re.compile(r"\.(?:render|compile|renderString)\s*\(")


def _classify_ssti(src):
    for m in _SSTI_SINK.finditer(src):
        if _arg_tainted(_call_arg(src, m.end()), src):
            return "risky"
    if _SSTI_ENGINE.search(src):
        for m in _ENGINE_RENDER.finditer(src):
            if _arg_tainted(_call_arg(src, m.end()), src):
                return "risky"
    return "absent"


_CLASSIFIERS = {
    "sqli": _classify_sql,
    "path": _classify_path,
    "cmdi": _classify_cmdi,
    "ssti": _classify_ssti,
}
_RANK = {"absent": 0, "safe": 1, "risky": 2}


def classify_file(src):
    """Return `{class: "absent"|"safe"|"risky"}` for one file's source."""
    return {tag: fn(src) for tag, fn in _CLASSIFIERS.items()}


def analyze_handler(handler_file, graph, content):
    """The sorted list of sink classes a handler can reach *unsafely* (its `sink_risk`).

    Each reachable file is classified against its own text; a class is risky for the handler if
    any reachable file is risky for it. An empty list means every class was absent or safe
    across the closure; the handler was still analyzed, which the caller records so a skipped
    card is distinguished from an unanalyzed (black-box) one.
    """
    agg = {tag: "absent" for tag in _CLASSIFIERS}
    for f in reachable_files(handler_file, graph):
        src = content.get(f)
        if not src:
            continue
        for tag, verdict in classify_file(src).items():
            if _RANK[verdict] > _RANK[agg[tag]]:
                agg[tag] = verdict
    return sorted(tag for tag, verdict in agg.items() if verdict == "risky")
