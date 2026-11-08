"""Minimal YAML-subset loader (standard library only).

Supports the subset the HackCulture harness authors by hand: block mappings,
block sequences, inline flow mappings `{ ... }` and sequences `[ ... ]`,
quoted and bare scalars (int / float / bool / null / str), and `#` comments.
It is intentionally small and strict, not a general YAML parser; it raises
YamlError on anything it does not understand, which keeps contract parsing
fail-closed (HC-SUB-01 §4.2).
"""


class YamlError(ValueError):
    pass


# --------------------------------------------------------------------------
# scalars
# --------------------------------------------------------------------------
def _scalar(tok):
    t = tok.strip()
    if t == "" or t == "~" or t == "null":
        return None
    if len(t) >= 2 and t[0] == t[-1] and t[0] in "'\"":
        return t[1:-1]
    low = t.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    try:
        return int(t)
    except ValueError:
        pass
    try:
        return float(t)
    except ValueError:
        pass
    return t


# --------------------------------------------------------------------------
# flow collections: { k: v, ... } and [ a, b, ... ]
# --------------------------------------------------------------------------
def _split_top(s):
    """Split on top-level commas, honoring quotes and nested brackets."""
    items, cur, depth, q = [], "", 0, None
    for c in s:
        if q:
            cur += c
            if c == q:
                q = None
        elif c in "'\"":
            q = c
            cur += c
        elif c in "{[":
            depth += 1
            cur += c
        elif c in "}]":
            depth -= 1
            cur += c
        elif c == "," and depth == 0:
            items.append(cur)
            cur = ""
        else:
            cur += c
    if cur.strip():
        items.append(cur)
    return [x for x in items if x.strip() != ""] if items or cur.strip() else []


def _split_kv(item):
    """Split `key: value` at the first top-level colon."""
    depth, q = 0, None
    for i, c in enumerate(item):
        if q:
            if c == q:
                q = None
        elif c in "'\"":
            q = c
        elif c in "{[":
            depth += 1
        elif c in "}]":
            depth -= 1
        elif c == ":" and depth == 0:
            return item[:i], item[i + 1:]
    raise YamlError(f"expected 'key: value' in flow mapping, got: {item.strip()!r}")


def _flow(tok):
    t = tok.strip()
    if t.startswith("{"):
        if not t.endswith("}"):
            raise YamlError(f"unbalanced flow mapping: {t!r}")
        out = {}
        for item in _split_top(t[1:-1]):
            k, v = _split_kv(item)
            out[str(_scalar(k))] = _value(v.strip())
        return out
    if t.startswith("["):
        if not t.endswith("]"):
            raise YamlError(f"unbalanced flow sequence: {t!r}")
        return [_value(x.strip()) for x in _split_top(t[1:-1])]
    raise YamlError(f"not a flow collection: {t!r}")


def _value(tok):
    t = tok.strip()
    if t[:1] in "{[":
        return _flow(t)
    return _scalar(t)


# --------------------------------------------------------------------------
# block structure (indentation based)
# --------------------------------------------------------------------------
def _strip_comment(line):
    res, q = [], None
    for c in line:
        if q:
            res.append(c)
            if c == q:
                q = None
        elif c in "'\"":
            q = c
            res.append(c)
        elif c == "#":
            break
        else:
            res.append(c)
    return "".join(res).rstrip()


def _prepare(text):
    rows = []
    for n, raw in enumerate(text.splitlines(), 1):
        if "\t" in raw.split("#")[0]:
            raise YamlError(f"line {n}: tabs are not allowed for indentation")
        line = _strip_comment(raw)
        if line.strip() == "":
            continue
        indent = len(line) - len(line.lstrip(" "))
        rows.append((indent, line.strip(), n))
    return rows


def _parse_block(rows, i, indent):
    """Parse rows[i:] at the given indent into a dict or list; return (value, i)."""
    if rows[i][1].startswith("- "):
        seq = []
        while i < len(rows) and rows[i][0] == indent and rows[i][1].startswith("- "):
            item = rows[i][1][2:].strip()
            if item.startswith("{") or item.startswith("["):
                seq.append(_flow(item))
                i += 1
            elif ":" in item:
                # a mapping whose first pair is on the dash line; gather any
                # deeper-indented continuation lines into the same mapping
                block = [(indent + 2, item, rows[i][2])]
                j = i + 1
                while j < len(rows) and rows[j][0] > indent:
                    block.append(rows[j])
                    j += 1
                val, _ = _parse_block(block, 0, indent + 2)
                seq.append(val)
                i = j
            else:
                seq.append(_scalar(item))
                i += 1
        return seq, i

    out = {}
    while i < len(rows) and rows[i][0] == indent:
        line = rows[i][1]
        if ":" not in line:
            raise YamlError(f"line {rows[i][2]}: expected 'key:' mapping, got {line!r}")
        key, rest = _split_kv(line)
        key = str(_scalar(key))
        rest = rest.strip()
        if rest != "":
            out[key] = _value(rest)
            i += 1
        else:
            # nested block at a deeper indent
            if i + 1 < len(rows) and rows[i + 1][0] > indent:
                child_indent = rows[i + 1][0]
                val, i = _parse_block(rows, i + 1, child_indent)
                out[key] = val
            else:
                out[key] = None
                i += 1
    return out, i


def load(text):
    rows = _prepare(text)
    if not rows:
        return None
    base = rows[0][0]
    val, i = _parse_block(rows, 0, base)
    if i != len(rows):
        raise YamlError(f"line {rows[i][2]}: unexpected indentation or trailing content")
    return val
