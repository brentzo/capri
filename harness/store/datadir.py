"""Local data directory for a self-hosted run history (HC-REPORT-01 §2).

A live run used to open an in-memory database and a throwaway blob directory, so
nothing survived the process. For the operator to browse past runs, a run persists
to a per-user data directory: `~/.capri/` by default, overridable with the
`HC_DATA_DIR` environment variable or an explicit argument (tests point it at a
temp dir). The directory holds `engagements.db` (the SQLite store) and `blobs/`
(the content-addressed evidence store). Standard library only.
"""
import os

ENV_VAR = "HC_DATA_DIR"
DEFAULT = "~/.capri"


def base(override=None):
    """Return the data directory, creating it if absent. Precedence: an explicit
    override, then `$HC_DATA_DIR`, then `~/.capri`."""
    path = override or os.environ.get(ENV_VAR) or os.path.expanduser(DEFAULT)
    os.makedirs(path, exist_ok=True)
    return path


def db_path(override=None):
    """Path to the engagements SQLite file inside the data directory."""
    return os.path.join(base(override), "engagements.db")


def blob_root(override=None):
    """Path to the evidence blob store inside the data directory, created if absent."""
    root = os.path.join(base(override), "blobs")
    os.makedirs(root, exist_ok=True)
    return root
