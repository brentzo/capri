"""Content-addressed blob store (HC-DATA-01 §3).

The default blob backend: raw request/response bodies and pcaps are keyed by the
sha256 of their content, so identical payloads collapse to one object and every
blob is write-once. A `blob://<sha256>` URI embeds the hash, so integrity is
checkable without a side table. A lightweight S3-compatible server (Garage or
SeaweedFS) can be swapped behind this same put/get interface if an S3 API is
ever required; MinIO is excluded (its community edition was archived in 2026).
"""
import hashlib
import os

SCHEME = "blob://"


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


class BlobStore:
    """A write-once content-addressed store rooted at a filesystem directory."""

    def __init__(self, root):
        self.root = root
        os.makedirs(root, exist_ok=True)

    def _path(self, digest):
        # shard by the first two bytes so no single directory grows unbounded
        return os.path.join(self.root, digest[:2], digest[2:4], digest)

    @staticmethod
    def _digest(uri):
        if not isinstance(uri, str) or not uri.startswith(SCHEME):
            raise ValueError(f"not a blob URI: {uri!r}")
        return uri[len(SCHEME):]

    def put(self, data):
        """Store bytes, return their `blob://<sha256>` URI. Identical content
        dedups to the same URI and is never rewritten."""
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("blob data must be bytes")
        data = bytes(data)
        digest = sha256_hex(data)
        path = self._path(digest)
        if not os.path.exists(path):          # write-once; same content => same path
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = f"{path}.{os.getpid()}.tmp"
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, path)             # atomic publish
            os.chmod(path, 0o444)             # immutable to accidental writes
        return SCHEME + digest

    def get(self, uri):
        with open(self._path(self._digest(uri)), "rb") as f:
            return f.read()

    def exists(self, uri):
        try:
            return os.path.exists(self._path(self._digest(uri)))
        except ValueError:
            return False

    def verify(self, uri):
        """True if the stored bytes still hash to the URI's digest."""
        digest = self._digest(uri)
        try:
            return sha256_hex(self.get(uri)) == digest
        except FileNotFoundError:
            return False
