"""Runnable capability mappings owned by the mobile harness."""
from harness.mobile.protocol import MOBILE_TOOL

CAPABILITIES = {
    "KB-MOBILE-LINK-DEEPLINK-001": (MOBILE_TOOL, {"link_id": "{asset.mobile_link_id}"}),
}
