"""Small standard-library readers for package-manager lockfiles."""
import json
import re

MAX_FILE_BYTES = 50 * 1024 * 1024


class LockfileParseError(ValueError):
    pass


def _strip_jsonc_commas(text):
    output = []
    quoted = escaped = False
    for index, char in enumerate(text):
        if quoted:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
            output.append(char)
        elif char == ",":
            following = index + 1
            while following < len(text) and text[following].isspace():
                following += 1
            if following == len(text) or text[following] not in "]}":
                output.append(char)
        else:
            output.append(char)
    return "".join(output)


def _line_for(text, key):
    escaped = json.dumps(key)[1:-1]
    match = re.search(r'^\s*"' + re.escape(escaped) + r'"\s*:\s*\{', text, re.MULTILINE)
    return text.count("\n", 0, match.start()) + 1 if match else 1


def _blocks(text, indent, field_indent):
    entries = []
    current = None
    in_pnpm_packages = True
    for number, line in enumerate(text.splitlines(), 1):
        if indent != 0 and line.strip() == "packages:":
            in_pnpm_packages = True
            continue
        if indent != 0 and line and not line.startswith(" ") and line.strip() != "packages:":
            in_pnpm_packages = False
        if not in_pnpm_packages:
            continue
        leading = len(line) - len(line.lstrip(" "))
        if leading == indent and line.rstrip().endswith(":") and line.strip() != "packages:":
            current = {"header": line.strip()[:-1], "line": number, "fields": {}}
            entries.append(current)
        elif current is not None and leading == field_indent:
            match = re.match(r'([^ :]+)\s*:?[ \t]+(".*?"|\{.*\}|[^#]+?)\s*$', line.strip())
            if match:
                current["fields"][match.group(1)] = match.group(2).strip('"')
    return entries


def read_lockfile(path, text):
    name = path.name
    if name in ("package-lock.json", "npm-shrinkwrap.json"):
        data = json.loads(text)
        if not isinstance(data, dict):
            raise LockfileParseError("npm lockfile must be a JSON object")
        version = data.get("lockfileVersion", 1)
        entries = []
        if version in (2, 3):
            packages = data.get("packages") or {}
            if not isinstance(packages, dict):
                raise LockfileParseError("npm packages field must be an object")
            for key, package in packages.items():
                if not key or not isinstance(package, dict):
                    continue
                entries.append({"name": key.rsplit("node_modules/", 1)[-1], "line": _line_for(text, key),
                                "integrity": package.get("integrity"), "local": bool(package.get("link") or package.get("inBundle")),
                                "install": bool(package.get("hasInstallScript")), "resolved": package.get("resolved", ""),
                                "raw": package})
        elif version == 1:
            def visit(items, prefix=""):
                if not isinstance(items or {}, dict):
                    raise LockfileParseError("npm dependencies field must be an object")
                for package_name, package in (items or {}).items():
                    if not isinstance(package, dict):
                        continue
                    entries.append({"name": package_name, "line": _line_for(text, package_name),
                                    "integrity": package.get("integrity"), "local": bool(package.get("inBundle")),
                                    "install": bool(package.get("hasInstallScript")), "resolved": package.get("resolved", ""),
                                    "raw": package})
                    visit(package.get("dependencies"))
            visit(data.get("dependencies"))
        else:
            raise LockfileParseError(f"unknown lockfile version {version}")
        return entries
    if name == "bun.lock":
        data = json.loads(_strip_jsonc_commas(text))
        if not isinstance(data, dict):
            raise LockfileParseError("bun lockfile must be a JSON object")
        entries = []
        packages = data.get("packages") or {}
        if not isinstance(packages, dict):
            raise LockfileParseError("bun packages field must be an object")
        for package_name, value in packages.items():
            if not isinstance(value, list):
                raise LockfileParseError("bun package entry must be an array")
            entries.append({"name": package_name, "line": _line_for(text, package_name),
                            "integrity": value[3] if len(value) > 3 else None,
                            "local": value[1] in ("workspace:", "file:", "link:") if len(value) > 1 else False,
                            "install": False, "raw": value,
                            "resolved": value[1] if len(value) > 1 else ""})
        return entries
    if name == "yarn.lock":
        berry = "__metadata:" in text
        entries = _blocks(text, 0, 2)
        entries = [entry for entry in entries if entry["header"] != "__metadata"]
        if text.strip() and not entries and not berry:
            raise LockfileParseError("no yarn lockfile entries found")
        for entry in entries:
            fields = entry["fields"]
            entry.update(name=entry["header"], integrity=fields.get("checksum" if berry else "integrity"),
                         local=any(fields.get("resolution", "").startswith(prefix)
                                   for prefix in ("workspace:", "link:", "portal:")),
                         install=False, raw=fields, resolved=fields.get("resolved", ""))
        return entries
    if name == "pnpm-lock.yaml":
        entries = _blocks(text, 2, 4)
        if "packages:" in text and not entries:
            raise LockfileParseError("no pnpm package entries found")
        for entry in entries:
            fields = entry["fields"]
            resolution = fields.get("resolution", "")
            entry.update(name=entry["header"], integrity=(re.search(r"integrity:\s*([^,}]+)", resolution) or [None, None])[1],
                         local=fields.get("link", "") == "true", install=fields.get("requiresBuild") == "true",
                         raw=fields, resolved=resolution)
        return entries
    if name == "Package.resolved":
        data = json.loads(text)
        if not isinstance(data, dict):
            raise LockfileParseError("Package.resolved must be a JSON object")
        pins = data.get("pins") or (data.get("object") or {}).get("pins") or []
        if not isinstance(pins, list):
            raise LockfileParseError("Package.resolved pins field must be an array")
        if any(not isinstance(pin, dict) for pin in pins):
            raise LockfileParseError("Package.resolved pin must be an object")
        return [{"name": pin.get("identity") or pin.get("package"), "line": _line_for(text, pin.get("identity", "")),
                 "integrity": (pin.get("state") or {}).get("revision"), "local": False, "install": False,
                 "raw": pin} for pin in pins]
    return []
