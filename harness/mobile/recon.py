"""Mobile reconnaissance: audit the APK identity, project asset facts, run the static assessment."""

from harness.mobile.sandbox import ANDROID_EMULATOR_IMAGE
from harness.mobile.static import assess, exported_components
from harness.store import audit


def mobile_recon(conn, engagement_id, inventory):
    """Return (target model, static assessment) for an APK inventory.

    Records the exact build under test in the audit log, so every later result is tied to
    a package, version, signing certificate and APK digest."""
    audit.record(
        conn,
        engagement_id,
        "harness",
        "mobile_apk_inventory",
        decision="ok",
        detail={
            "package": inventory["package"],
            "version_name": inventory["version"]["name"],
            "version_code": inventory["version"]["code"],
            "sha256": inventory["sha256"],
            "signing_sha256": inventory.get("signing_sha256"),
            "emulator_image": ANDROID_EMULATOR_IMAGE,
            "component_count": len(inventory["components"]),
            "deep_link_count": len(inventory["deep_links"]),
        },
    )
    return _project(inventory), assess(inventory)


def _project(inventory):
    """Project APK facts into an app asset and one asset per supported deep link."""
    package = inventory["package"]
    core = {
        "host": "mobile-app",
        "addr": "mobile-app",
        "reachable": True,
        "asset.type": "mobile_app",
        "mobile_app": True,
        "has_deep_link": False,
        "mobile.package": package,
        "mobile.sha256": inventory["sha256"],
        "mobile.components": inventory["components"],
        "mobile.permissions": inventory["permissions"],
        "mobile.sdk": inventory["sdk"],
        "mobile.application": inventory["application"],
    }
    app = {**core, "asset.backup_allowed": inventory["application"]["allow_backup"]}
    exposed = [c["name"] for c in exported_components(inventory)]
    if exposed:  # exists() is true even for an empty list
        app.update({"asset.exported_components": exposed, "exported_component": True})
    model = {"mobile-app": app}
    for link in inventory["deep_links"]:
        model[f"mobile-app::{link['id']}"] = {
            **core,
            "has_deep_link": True,
            "asset.has_deep_link": True,
            "asset.mobile_link_id": link["id"],
            "mobile.component": link["component"],
            "mobile.link_filter_index": link["filter_index"],
            "mobile.link_scheme": link["scheme"],
            "mobile.link_host": link["host"],
            "mobile.link_path": link["path"],
        }
    return model
