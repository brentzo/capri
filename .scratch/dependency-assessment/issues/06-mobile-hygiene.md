# 06: Mobile hygiene: CocoaPods, SwiftPM, Pub, Gradle

**What to build:** the dependency hygiene area covers the mobile ecosystems.
Semgrep rules report pods taken from git without a tag or commit, Swift packages pinned to a branch, Pub git or path dependencies, Gradle dynamic versions, `http://` Gradle repositories and `mavenLocal()`.
Manifest-to-lockfile pairing extends to `Podfile`, `Package.swift`, `pubspec.yaml` and Gradle roots, including `Package.resolved` inside Xcode project and workspace folders.
Missing-lockfile confidence is medium for SwiftPM and Pub because libraries conventionally omit lockfiles.
Mobile ecosystems get real hygiene coverage statuses.
Spec: Technical Design > "Semgrep hygiene rules" (pod, swiftpm, pub, gradle rows), "Algorithm: pairing manifests with lockfiles" (Gradle root rule), "Recognised files".

**Blocked by:** 02 (Run real Semgrep in CI), 03 (Tracer bullet: dependency section)

**Status:** ready-for-agent

- [ ] Every new rule has a matching and a non-matching fixture line, tested with real Semgrep, at the severity and confidence in the spec's table.
- [ ] `pod 'X', :git => '...'` without `:tag`/`:commit` (both hash syntaxes) is reported; with either pin it is not.
- [ ] SwiftPM `"branch": "main"` is reported; `"branch": null` is not.
- [ ] Gradle `+` and `latest.release` versions are reported in build scripts and version catalogs; exact versions are not.
- [ ] A Gradle root with no `gradle.lockfile` (or `gradle/dependency-locks/*.lockfile`) under it gets the missing-lockfile finding once, at the settings or top-level build script.
- [ ] `Package.resolved` under `*.xcodeproj/.../swiftpm/` counts as the lockfile for the app.
- [ ] Each finding carries ecosystem and `related_technique`.
- [ ] HC-PROJ-02 updated; `make check` green.
