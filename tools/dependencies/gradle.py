"""Read literal Gradle dependency versions without running Gradle."""
import re
import tomllib

_COORDINATE = re.compile(r'^\s*(\w+)\s*\(?\s*["\']([\w.\-]+):([\w.\-]+):([^"\'@:$\s]+)(?::[^"\'@]+)?(?:@\w+)?["\']')
_MAP = re.compile(r'group\s*:\s*["\']([^"\']+)["\']\s*,\s*name\s*:\s*["\']([^"\']+)["\']\s*,\s*version\s*:\s*["\']([^"\']+)["\']')


def _exact(value):
    return isinstance(value, str) and not any(token in value for token in ("$", "+", "[", "(", ",", "latest."))


def _version(value, versions):
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        ref = value.get("ref")
        if ref:
            return versions.get(ref)
    return None


def _catalog(path, relative, versions_by_file):
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    versions = data.get("versions", {})
    values = []
    for alias, library in (data.get("libraries") or {}).items():
        group = artifact = version = None
        if isinstance(library, str):
            parts = library.split(":")
            if len(parts) == 3:
                group, artifact, version = parts
        elif isinstance(library, dict):
            module = library.get("module", "")
            if ":" in module:
                group, artifact = module.split(":", 1)
            else:
                group, artifact = library.get("group"), library.get("name")
            version_data = library.get("version", library.get("version.ref"))
            version = _version(version_data, versions)
        if group and artifact and _exact(version):
            line = next((number for number, row in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
                         if re.match(r"\s*" + re.escape(alias) + r"\s*=", row)), 1)
            values.append((group, artifact, version, relative, line, "runtime"))
    return values


def synthesize(snapshot, files):
    manifests = [(path, path.relative_to(snapshot).as_posix()) for path, ecosystem, kind in files
                 if ecosystem == "gradle" and kind == "manifest"]
    roots = {}
    for path, relative in manifests:
        ancestors = []
        directory = path.parent
        while directory == snapshot or snapshot in directory.parents:
            ancestors.append(directory)
            if directory == snapshot:
                break
            directory = directory.parent
        settings = [root for root in ancestors if any((root / name).exists()
                                                       for name in ("settings.gradle", "settings.gradle.kts"))]
        if settings:
            directory = max(settings, key=lambda root: len(root.parts))
        else:
            builds = [root for root in ancestors if any((root / name).exists()
                                                        for name in ("build.gradle", "build.gradle.kts"))]
            directory = min(builds, key=lambda root: len(root.parts)) if builds else path.parent
        roots.setdefault(directory, []).append((path, relative))
    output_map = {}
    index = 0
    for root, root_manifests in roots.items():
        if any(root.rglob("gradle.lockfile")) or any(root.glob("gradle/dependency-locks/*.lockfile")):
            continue
        declarations = []
        for path, relative in root_manifests:
            if path.name == "libs.versions.toml":
                try:
                    declarations.extend(_catalog(path, relative, {}))
                except (OSError, UnicodeError, tomllib.TOMLDecodeError):
                    continue
            elif path.suffix in (".gradle", ".kts"):
                try:
                    lines = path.read_text(encoding="utf-8").splitlines()
                except (OSError, UnicodeError):
                    continue
                for number, line in enumerate(lines, 1):
                    match = _COORDINATE.search(line)
                    if match:
                        config, group, artifact, version = match.groups()
                    else:
                        match = _MAP.search(line)
                        if not match:
                            continue
                        group, artifact, version = match.groups()
                        config = line.lstrip().split("(", 1)[0].split(" ", 1)[0]
                    if _exact(version):
                        scope = "dev" if config.startswith(("test", "androidTest")) else "runtime"
                        declarations.append((group, artifact, version, relative, number, scope))
        if not declarations:
            continue
        index += 1
        target = snapshot / ".capri-declared" / str(index) / "gradle.lockfile"
        target.parent.mkdir(parents=True, exist_ok=True)
        lock_lines = []
        for group, artifact, version, relative, line, scope in declarations:
            configuration = "testCompileClasspath,testRuntimeClasspath" if scope == "dev" else "compileClasspath,runtimeClasspath"
            lock_lines.append(f"{group}:{artifact}:{version}={configuration}")
            output_map[(str(index), f"{group}:{artifact}", version)] = (
                {"path": relative, "line": line}, scope, relative)
        target.write_text("\n".join(lock_lines) + "\n", encoding="utf-8")
    return output_map
