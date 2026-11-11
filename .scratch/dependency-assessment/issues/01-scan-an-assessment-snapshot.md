# 01: Scan an assessment snapshot so a project can't hide files from the source rules

**What to build:** `capri source` stops pointing Semgrep at the project directory.
It walks the project once, copies only the files its exclude policy accepts into a temporary assessment snapshot outside the project, scans the snapshot, maps results back to project-relative paths, and always deletes the snapshot.
A project's own `.semgrepignore`, `.gitignore` or scanner config can no longer hide files or change scanner behaviour.
The source report is otherwise unchanged.
Spec: `.scratch/dependency-assessment/spec.md`, Technical Design > "Discovery walk and assessment snapshot" and "Security and privacy invariants".

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] Regression test first: a fixture project whose `.semgrepignore` and `.gitignore` list files containing a planted credential still reports every planted credential; the test fails on the current code before the fix.
- [ ] The scanner receives a snapshot directory that contains no `.semgrepignore`, `.gitignore`, `.trivyignore`, `trivy.yaml`, `trivy.yml` or `osv-scanner.toml`, and no excluded private env files.
- [ ] Findings keep project-relative paths and line numbers identical to scanning the project directly.
- [ ] The snapshot is removed after a successful run and after a failed run (scanner error, timeout, invalid JSON).
- [ ] No file or directory is created inside the project during an assessment.
- [ ] Symlinked files and directories are skipped and never followed; a symlink pointing outside the project is not read.
- [ ] A file over 50 MB is not copied; a snapshot over 2 GB stops the run with a clear message naming the limit.
- [ ] Semgrep runs with `--max-target-bytes` raised to 50 MB, metrics and version check off, and an environment with user `SEMGREP_*` variables removed except metrics-off.
- [ ] Verified end to end with real Semgrep on a fixture project outside the repo.
- [ ] HC-PROJ-01 and `harness/README.md` describe the snapshot; `SPEC.md` decision log gets a dated line; `make check` green.
