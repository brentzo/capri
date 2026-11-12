"""Recognized project files for local dependency assessment."""

FILES = {
    "package.json": ("npm", "manifest"),
    "package-lock.json": ("npm", "lockfile"),
    "npm-shrinkwrap.json": ("npm", "lockfile"),
    "pnpm-lock.yaml": ("npm", "lockfile"),
    "yarn.lock": ("npm", "lockfile"),
    "bun.lock": ("npm", "lockfile"),
    "bun.lockb": ("npm", "lockfile"),
    ".npmrc": ("npm", "registry-config"),
    ".yarnrc": ("npm", "registry-config"),
    ".yarnrc.yml": ("npm", "registry-config"),
    "Podfile": ("cocoapods", "manifest"),
    "Podfile.lock": ("cocoapods", "lockfile"),
    "Package.swift": ("swiftpm", "manifest"),
    "Package.resolved": ("swiftpm", "lockfile"),
    "pubspec.yaml": ("pub", "manifest"),
    "pubspec.lock": ("pub", "lockfile"),
    "build.gradle": ("gradle", "manifest"),
    "build.gradle.kts": ("gradle", "manifest"),
    "settings.gradle": ("gradle", "manifest"),
    "settings.gradle.kts": ("gradle", "manifest"),
    "libs.versions.toml": ("gradle", "manifest"),
    "gradle.lockfile": ("gradle", "lockfile"),
}
ECOSYSTEMS = ("npm", "cocoapods", "swiftpm", "pub", "gradle")


def discover(snapshot):
    found = []
    for path in snapshot.rglob("*"):
        if not path.is_file():
            continue
        kind = FILES.get(path.name)
        if kind:
            found.append((path, *kind))
        elif path.name.endswith(".lockfile") and "dependency-locks" in path.parts:
            found.append((path, "gradle", "lockfile"))
    return sorted(found, key=lambda item: item[0].as_posix())
