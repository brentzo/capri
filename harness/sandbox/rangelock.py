"""One engagement per sandbox range at a time, across processes (HC-SUB-01 §10).

A range is a set of named Docker resources (`hc-range`, its attacker, its targets),
and provisioning tears down any range of that name first so a range a crashed run
left behind is cleaned up. A range another live run is using looks exactly the same,
so without this lock a second run destroyed the first one's range mid-engagement.

The lock is an OS file lock, held from before provisioning until after teardown. The
OS drops it when the holder exits, cleanly or not, so a crashed run never blocks the
next one and stale-range cleanup keeps working. It lives beside the range's callers,
not inside `DockerSandbox`, because the backend's tests build many same-named fake
ranges in one process.
"""

import os
import sys
import tempfile

from harness.sandbox.base import SandboxError


class RangeBusy(SandboxError):
    """Another live engagement holds the range; nothing was provisioned or torn down."""


class RangeLock:
    def __init__(self, range_name, *, lock_dir=None):
        self.range_name = range_name
        self.path = os.path.join(
            lock_dir or tempfile.gettempdir(), f"capri-{range_name}.lock"
        )
        self._handle = None

    def acquire(self):
        """Hold the range for this process, or raise RangeBusy. Returns self."""
        handle = open(self.path, "a+b")
        try:
            _lock(handle)
        except OSError:
            handle.close()
            raise RangeBusy(
                f"another engagement is already running on sandbox range {self.range_name!r}; "
                "let it finish or stop it, then run again"
            ) from None
        self._handle = handle
        return self

    def release(self):
        if self._handle is None:
            return
        try:
            _unlock(self._handle)
        finally:
            self._handle.close()
            self._handle = None


if sys.platform == "win32":
    import msvcrt

    def _lock(handle):
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)

    def _unlock(handle):
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def _lock(handle):
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(handle):
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
