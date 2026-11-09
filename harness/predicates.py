"""Blackboard predicate evaluator (HC-KB-01 §4).

Evaluates the applicability / severity predicate DSL against a flat facts dict,
using the same grammar the validator checks (tools/validate_kb.py check_dsl):
dotted identifiers, string / number / regex literals, the comparisons
== != < > <= >= and `in`, the functions exists() and matches(), and the boolean
operators ! && ||. A bare identifier is true when its fact is truthy.

Facts are plain data from the run's blackboard; the evaluator only compares
values and never executes anything, so an untrusted fact value cannot do more
than compare unequal. An unknown identifier is missing, not an error: it is
falsey on its own and never equal to a literal, so a predicate over facts that
were not gathered simply does not fire.
"""
import re

_TOKEN = re.compile(r"""
    \s+
  | "(?:[^"\\]|\\.)*"
  | '(?:[^'\\]|\\.)*'
  | /(?:[^/\\]|\\.)*/
  | \d+(?:\.\d+)?
  | ==|!=|<=|>=|&&|\|\||[<>]
  | !
  | \bin\b
  | [()]
  | ,
  | [A-Za-z_][A-Za-z0-9_.]*(?:\[\*\])?
""", re.VERBOSE)

_CMP = {"==", "!=", "<", ">", "<=", ">=", "in"}
_MISSING = object()


class PredicateError(ValueError):
    pass


class _Ident:
    __slots__ = ("name",)

    def __init__(self, name):
        self.name = name


def _tokenize(expr):
    toks, pos, n = [], 0, len(expr)
    while pos < n:
        m = _TOKEN.match(expr, pos)
        if not m or m.end() == pos:
            raise PredicateError(f"unparseable near {expr[pos:pos + 20]!r}")
        pos = m.end()
        t = m.group().strip()
        if t:
            toks.append(t)
    return toks


def _unquote(t):
    return re.sub(r"\\(.)", r"\1", t[1:-1])


class _Parser:
    def __init__(self, toks, facts):
        self.toks, self.i, self.facts = toks, 0, facts

    def _peek(self):
        return self.toks[self.i] if self.i < len(self.toks) else None

    def _next(self):
        t = self._peek()
        self.i += 1
        return t

    def _expect(self, t):
        if self._next() != t:
            raise PredicateError(f"expected {t!r}")

    def parse(self):
        v = self._or()
        if self._peek() is not None:
            raise PredicateError(f"trailing tokens from {self._peek()!r}")
        return v

    def _or(self):
        v = self._and()
        while self._peek() == "||":
            self._next()
            v = self._and() or v           # evaluate RHS (no short-circuit side effects)
        return bool(v)

    def _and(self):
        v = self._not()
        while self._peek() == "&&":
            self._next()
            r = self._not()
            v = bool(v) and bool(r)
        return bool(v)

    def _not(self):
        if self._peek() == "!":
            self._next()
            return not self._not()
        return self._atom()

    def _atom(self):
        t = self._peek()
        if t == "(":
            self._next()
            v = self._or()
            self._expect(")")
            return bool(v)
        # function call (exists / matches) stands alone as a boolean atom
        if t is not None and re.match(r"^[A-Za-z_]", t) and self._lookahead_is_call():
            return self._call()
        # otherwise a value, optionally compared to another value
        left = self._value()
        op = self._peek()
        if op in _CMP:
            self._next()
            return self._compare(op, left, self._value())
        return self._truthy(left)

    def _lookahead_is_call(self):
        return self.i + 1 < len(self.toks) and self.toks[self.i + 1] == "("

    def _call(self):
        name = self._next()
        self._expect("(")
        args = [self._value()]
        while self._peek() == ",":
            self._next()
            args.append(self._value())
        self._expect(")")
        if name == "exists":
            key = args[0].name if isinstance(args[0], _Ident) else args[0]
            return self.facts.get(key, _MISSING) is not _MISSING and self.facts.get(key) is not None
        if name == "matches":
            val = self._resolve(args[0])
            pat = args[1] if isinstance(args[1], str) else str(args[1])
            if val is _MISSING or val is None:
                return False
            return re.search(pat, str(val)) is not None
        raise PredicateError(f"disallowed function {name!r} (only exists/matches)")

    def _value(self):
        t = self._next()
        if t is None:
            raise PredicateError("unexpected end of expression")
        if t[0] in "\"'":
            return _unquote(t)
        if t[0] == "/":
            return t[1:-1]                      # regex body, used by matches()
        if re.fullmatch(r"\d+(\.\d+)?", t):
            return float(t) if "." in t else int(t)
        if t in ("true", "false", "null"):
            return {"true": True, "false": False, "null": None}[t]
        if re.match(r"^[A-Za-z_]", t):
            return _Ident(t[:-3] if t.endswith("[*]") else t)
        raise PredicateError(f"unexpected token {t!r}")

    def _resolve(self, v):
        if isinstance(v, _Ident):
            return self.facts.get(v.name, _MISSING)
        return v

    def _truthy(self, v):
        r = self._resolve(v)
        return False if r is _MISSING else bool(r)

    def _compare(self, op, left, right):
        l, r = self._resolve(left), self._resolve(right)
        if op == "in":
            try:
                return l in r
            except TypeError:
                return False
        if op == "==":
            return l == r
        if op == "!=":
            return l != r
        if l is _MISSING or r is _MISSING:
            return False
        try:
            return {"<": l < r, ">": l > r, "<=": l <= r, ">=": l >= r}[op]
        except TypeError:
            return False


def evaluate(expr, facts=None):
    """Return the boolean value of `expr` over `facts` (default empty)."""
    if not isinstance(expr, str) or not expr.strip():
        raise PredicateError("empty predicate")
    return _Parser(_tokenize(expr), facts or {}).parse()


_NON_FACT = {"exists", "matches", "true", "false", "null", "in"}


def identifiers(expr):
    """The dotted fact names a predicate reads, with any `[*]` suffix dropped.

    Literals, numbers, keywords, and the exists/matches function names are left
    out, so the result is exactly the facts the predicate depends on. Used to
    trace an objective's required facts back through the blackboard (HC-OBJ-01
    §9). A malformed expression yields the empty set rather than raising."""
    if not isinstance(expr, str) or not expr.strip():
        return set()
    try:
        toks = _tokenize(expr)
    except PredicateError:
        return set()
    out = set()
    for t in toks:
        if re.match(r"^[A-Za-z_]", t) and t not in _NON_FACT:
            out.add(t[:-3] if t.endswith("[*]") else t)
    return out
