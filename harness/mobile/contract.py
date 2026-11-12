"""Validation for the mobile target declaration in an engagement contract."""

ANDROID_APP_KEYS = {"apk"}


def normalize_android_app(app):
    if not isinstance(app, dict):
        return None
    return {"apk": app.get("apk")}


def validate_android_app(app, errors):
    """Validate the operator-supplied APK declaration; the file is checked before provisioning."""
    if app is None:
        return
    if not isinstance(app, dict):
        errors.append("engagement.android_app must be a mapping when present")
        return
    unknown = sorted(set(app) - ANDROID_APP_KEYS)
    if unknown:
        errors.append(f"engagement.android_app has unsupported key(s): {', '.join(unknown)}")
    apk = app.get("apk")
    if not isinstance(apk, str) or not apk.strip():
        errors.append("engagement.android_app.apk must be a non-empty path string")
