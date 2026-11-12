"""Build a private, bounded copy of the files Capri is allowed to assess."""
import fnmatch
import os
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_SNAPSHOT_BYTES = 2 * 1024 * 1024 * 1024
# Leave room below MAX_PATH for a separator and the Windows terminating NUL.
WINDOWS_PATH_LIMIT = 250
IS_WINDOWS = os.name == "nt"
DROP_FILES = {".semgrepignore", ".gitignore", ".trivyignore", ".trivyignore.yaml",
              "trivy.yaml", "trivy.yml", "osv-scanner.toml"}
DROP_DIRS = {".git", "node_modules", "dist", "build", ".output", "coverage", ".supabase",
             ".claude", ".scratch", "docs", "tests", "testing", "Pods", ".dart_tool",
             ".gradle", ".build", "DerivedData", ".cxx"}


@dataclass
class AssessmentSnapshot:
    root: Path
    oversize: dict[str, int]
    path_limited: list[str]
    skipped: int


@contextmanager
def create_snapshot(project: Path, excludes: tuple[str, ...]):
    """Yield a temporary snapshot, preserving relative paths and never following links."""
    temporary = tempfile.TemporaryDirectory(prefix="capri-snapshot-")
    root = Path(temporary.name).resolve()
    try:
        root.relative_to(project)
    except ValueError:
        pass
    else:
        temporary.cleanup()
        raise RuntimeError("temporary assessment snapshot must be outside the selected project")

    destination = root / "project"
    destination.mkdir()
    oversize = {}
    path_limited = []
    skipped = 0
    total = 0

    def ignore_file(relative):
        return relative.name in DROP_FILES or any(
            fnmatch.fnmatch(relative.name, pattern)
            for pattern in excludes if "/" not in pattern and pattern != "*.lock"
        )

    try:
        for current, directories, filenames in os.walk(project, followlinks=False,
                                                        onerror=lambda error: (_ for _ in ()).throw(error)):
            current_path = Path(current)
            relative_dir = current_path.relative_to(project)
            retained = []
            for dirname in directories:
                entry = current_path / dirname
                relative = (relative_dir / dirname).as_posix()
                excluded = dirname in DROP_DIRS
                excluded |= any(fnmatch.fnmatch(relative, pattern.rstrip("/"))
                                for pattern in excludes if "/" in pattern and not pattern.startswith("*."))
                if IS_WINDOWS and len(str(destination / relative)) >= WINDOWS_PATH_LIMIT:
                    path_limited.append(relative)
                    skipped += 1
                    continue
                # Windows junctions are directory links that is_symlink() does not report;
                # pruning both here keeps the walk inside the project and off dangling links.
                if entry.is_symlink() or entry.is_junction() or excluded:
                    skipped += 1
                else:
                    retained.append(dirname)
            directories[:] = retained
            for filename in filenames:
                source = current_path / filename
                relative = relative_dir / filename
                relative_posix = relative.as_posix()
                if ignore_file(relative) or source.is_symlink():
                    skipped += 1
                    continue
                target = destination / relative
                if IS_WINDOWS and len(str(target)) >= WINDOWS_PATH_LIMIT:
                    path_limited.append(relative_posix)
                    skipped += 1
                    continue
                try:
                    info = source.lstat()
                except OSError:
                    skipped += 1
                    continue
                if not stat.S_ISREG(info.st_mode):
                    skipped += 1
                    continue
                if info.st_size > MAX_FILE_BYTES:
                    oversize[relative_posix] = info.st_size
                    continue
                if total + info.st_size > MAX_SNAPSHOT_BYTES:
                    raise RuntimeError("assessment snapshot exceeds the 2 GB limit")
                target.parent.mkdir(parents=True, exist_ok=True)
                copied = 0
                with source.open("rb") as input_file, target.open("wb") as output_file:
                    while chunk := input_file.read(1024 * 1024):
                        copied += len(chunk)
                        if copied > MAX_FILE_BYTES or total + copied > MAX_SNAPSHOT_BYTES:
                            raise RuntimeError("assessment snapshot exceeds the 2 GB limit")
                        output_file.write(chunk)
                total += copied
        yield AssessmentSnapshot(destination, oversize, path_limited, skipped)
    finally:
        temporary.cleanup()
