"""The fixed-action Android deep-link probe adapter."""
import re
import secrets
import time
import urllib.parse

from harness.mobile.apk import MobileError
from harness.mobile.protocol import MOBILE_TARGET

# `am start -W` returns when the activity is up, but the app makes its callback from a
# background thread after that, and a cold emulator can be slow. Waiting a bounded time
# keeps a real hit from being missed without letting a silent app stall the run.
CALLBACK_WAIT_S = 15.0
CALLBACK_POLL_S = 0.5


class DeepLinkProbe:
    """Only invokes manifest-discovered links with a harness-created range callback."""

    def __init__(self, package, links, *, adb, collaborator, collab_addr, expected_source,
                 monotonic=time.monotonic, sleep=time.sleep):
        self.package = package
        self.links = {link["id"]: link for link in links}
        self.adb = adb
        self.collaborator = collaborator
        self.collab_addr = collab_addr
        self.expected_source = expected_source
        self._monotonic = monotonic
        self._sleep = sleep

    def _await_callback(self, nonce):
        """Poll the collaborator log until a line carries this nonce from the emulator's
        address, or the deadline passes. Only that pair is a success signal."""
        deadline = self._monotonic() + CALLBACK_WAIT_S
        while True:
            for line in (self.collaborator() or "").splitlines():
                fields = line.rsplit(maxsplit=1)
                if (len(fields) == 2 and fields[0] == f"/{nonce}"
                        and fields[1] == self.expected_source):
                    return True
            if self._monotonic() >= deadline:
                return False
            self._sleep(CALLBACK_POLL_S)

    @staticmethod
    def bind_asset(facts, request):
        if facts.get("asset.type") == "mobile_app":
            request["target"] = MOBILE_TARGET
            request["port"] = 0
            request["args"] = {"link_id": facts.get("asset.mobile_link_id")}

    def run(self, req):
        args = req.get("args") or {}
        link_id = args.get("link_id")
        link = self.links.get(link_id) if isinstance(link_id, str) else None
        if link is None or not self.collab_addr or not self.collaborator:
            return {"status": "error", "parsed": {"error": "unknown_link"},
                    "request_bytes": b"mobile deep-link", "response_bytes": b"",
                    "deterministic_signals": {"hit": False, "confidence": 0.0}}
        if (not re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]{0,31}", link["scheme"])
                or not re.fullmatch(r"(?:[A-Za-z0-9.-]{1,253})?", link["host"])
                or not re.fullmatch(r"/[A-Za-z0-9._~/%-]*", link["path"])):
            return {"status": "error", "parsed": {"error": "unsupported_link_syntax"},
                    "request_bytes": b"mobile deep-link", "response_bytes": b"",
                    "deterministic_signals": {"hit": False, "confidence": 0.0}}
        nonce = "hc" + secrets.token_hex(12)
        callback = f"http://{self.collab_addr}/{nonce}"
        url = urllib.parse.urlunsplit((link["scheme"], link["host"], link["path"],
                                       urllib.parse.urlencode({"url": callback}), ""))
        cleared = self.adb(["shell", "pm", "clear", self.package])
        if cleared.rc != 0 or "success" not in (cleared.out or "").lower():
            raise MobileError("could not reset the Android app to its clean baseline")
        launched = self.adb(["shell", "am", "start", "-W", "-a",
                             "android.intent.action.VIEW", "-c",
                             "android.intent.category.BROWSABLE", "-d", url,
                             self.package])
        hit = launched.rc == 0 and self._await_callback(nonce)
        return {"status": "ok" if hit else "error",
                "parsed": {"package": self.package, "link_id": link["id"],
                           "launch_succeeded": launched.rc == 0, "oob_fired": hit},
                "request_bytes": url.encode("utf-8"),
                "response_bytes": f"oob={hit}".encode("ascii"),
                "deterministic_signals": {"hit": hit, "oob_fired": hit,
                                           "confidence": 0.95 if hit else 0.0}}
