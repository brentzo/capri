#!/usr/bin/env python3
"""Android APK inventory and controlled deep-link adapter tests (HC-MOB-01)."""
import os
import sys
import tempfile
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from harness.mobile import (ANDROID_EMULATOR_IMAGE, DeepLinkProbe, MobileError,
                            inventory_manifest, inspect_apk)  # noqa: E402
from harness.substrate import contract, scope  # noqa: E402
from harness.recon import project_mobile_inventory  # noqa: E402
from harness.sandbox.base import RunResult, SandboxError  # noqa: E402
from harness.sandbox.docker import DockerSandbox, android_guard_ruleset  # noqa: E402
from harness import capabilities, kb, ratelimit, roleio  # noqa: E402
from harness.dispatch import Dispatcher  # noqa: E402
from harness.loop import Loop, phase_threat_model  # noqa: E402
from harness.planner import DeterministicPlanner  # noqa: E402
from harness.store import blobstore, db, findings  # noqa: E402

ANDROID = "http://schemas.android.com/apk/res/android"
MANIFEST = f'''<manifest xmlns:android="{ANDROID}" package="com.example.canary">
  <uses-permission android:name="android.permission.INTERNET" />
  <application>
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="capri" android:host="open" android:path="/fetch" />
      </intent-filter>
    </activity>
    <service android:name="Worker" android:exported="false" />
  </application>
</manifest>'''
MOBILE_CONTRACT = """
engagement:
  id: mobile-only
  authorized_by: test
  window: { start: 2026-11-12T00:00, end: 2026-11-13T00:00 }
  max_blast_tier: 1
  android_app: { apk: tests/fixtures/mobile/canary.apk }
scope: {}
"""


def test_manifest_inventory_normalizes_components_and_browsable_links():
    result = inventory_manifest(MANIFEST)
    assert result["package"] == "com.example.canary"
    assert result["permissions"] == ["android.permission.INTERNET"]
    assert result["components"] == [
        {"name": "com.example.canary.MainActivity", "type": "activity", "exported": True},
        {"name": "com.example.canary.Worker", "type": "service", "exported": False},
    ]
    assert result["deep_links"] == [{"id": "link-0001", "component": "com.example.canary.MainActivity",
                                     "filter_index": 0, "scheme": "capri", "host": "open",
                                     "path": "/fetch"}]


def test_manifest_inventory_rejects_malformed_or_package_less_xml():
    for text in ("<manifest", "<manifest><application /></manifest>"):
        try:
            inventory_manifest(text)
        except MobileError:
            continue
        raise AssertionError("invalid manifest was accepted")


def test_manifest_inventory_skips_link_data_that_could_escape_the_fixed_intent():
    bad = MANIFEST.replace('android:scheme="capri"', 'android:scheme="capri;touch"')
    assert inventory_manifest(bad)["deep_links"] == []


def test_mobile_only_engagement_is_valid_and_scope_uses_a_virtual_target():
    eng, errors = contract.parse(MOBILE_CONTRACT)
    assert not errors, errors
    assert eng.android_app == {"apk": "tests/fixtures/mobile/canary.apk"}
    assert scope.scope_validate(eng, "mobile-app", 0, allow_mobile=True) == ("allow", None)
    assert scope.scope_validate(eng, "10.90.0.4", 8080, allow_mobile=True)[0] == "deny"
    assert scope.scope_validate(eng, "mobile-app", 0)[0] == "deny"


def test_mobile_contract_rejects_unsupported_or_empty_apk_declarations():
    for decl in ("android_app: {apk: ''}", "android_app: {apk: a.apk, shell: true}"):
        text = MOBILE_CONTRACT.replace("android_app: { apk: tests/fixtures/mobile/canary.apk }", decl)
        _, errors = contract.parse(text)
        assert any("engagement.android_app" in error for error in errors), errors


def test_mobile_recon_has_one_app_asset_and_one_asset_per_manifest_link():
    inventory = {**inventory_manifest(MANIFEST), "sha256": "a" * 64}
    model = project_mobile_inventory(inventory)
    assert model["mobile-app"]["asset.type"] == "mobile_app"
    assert model["mobile-app::link-0001"]["asset.mobile_link_id"] == "link-0001"
    assert model["mobile-app::link-0001"]["asset.has_deep_link"] is True
    assert model["mobile-app::link-0001"]["mobile.sha256"] == "a" * 64
    pairs = phase_threat_model(model, capabilities.runnable_index(kb.load()))
    assert [(p.asset, p.technique_id) for p in pairs] == [
        ("mobile-app::link-0001", "KB-MOBILE-LINK-DEEPLINK-001")]


def test_android_guard_drops_unscoped_egress_and_only_allows_attacker_adb_ingress():
    rules = android_guard_ruleset("hc_android", "10.90.0.2",
                                  [("10.90.0.8", [443, 8443]), ("10.90.0.3", [8080])])
    assert "policy drop" in rules
    assert "ip daddr 10.90.0.8 tcp dport { 443, 8443 } accept" in rules
    assert "ip daddr 10.90.0.3 tcp dport { 8080 } accept" in rules
    assert "ip saddr 10.90.0.2 tcp dport 5555 accept" in rules
    assert "ip saddr 10.90.0.4" not in rules
    replacement = android_guard_ruleset("hc_android", "10.90.0.2", [], replace=True)
    assert replacement.startswith("delete table inet hc_android\n")


def test_android_provision_fails_closed_before_docker_on_unsupported_host():
    class Runner:
        calls = []

        def __call__(self, argv, **kwargs):
            self.calls.append(argv)
            return RunResult(0, "", "")

    runner = Runner()
    sandbox = DockerSandbox(run=runner)
    eng, errors = contract.parse(MOBILE_CONTRACT)
    assert not errors, errors
    with patch("harness.sandbox.docker.sys.platform", "win32"), \
            patch("harness.sandbox.docker.os.path.exists", return_value=False):
        try:
            sandbox.provision(eng)
        except SandboxError as exc:
            assert "Linux Docker host with /dev/kvm" in str(exc)
        else:
            raise AssertionError("mobile provision started without Linux KVM")
    assert runner.calls == [], runner.calls
    assert ANDROID_EMULATOR_IMAGE.endswith("sha256:e78ac1816acef59e40285e90003acd490ef54bb3242ed088afa31bc982577050")


def test_deep_link_finding_passes_dispatch_and_independent_verification():
    mobile_contract = MOBILE_CONTRACT.replace(
        "id: mobile-only", "id: mobile-loop").replace(
            "2026-11-13T00:00", "2026-11-13T23:59")
    eng, errors = contract.parse(mobile_contract)
    assert not errors, errors
    inventory = {**inventory_manifest(MANIFEST), "sha256": "b" * 64}
    target_model = project_mobile_inventory(inventory)
    mobile_kb = {key: card for key, card in capabilities.runnable_index(kb.load()).items()
                 if key[0] == "KB-MOBILE-LINK-DEEPLINK-001"}

    class Adapter:
        local_mobile_target = True

        def run(self, req):
            assert req["target"] == "mobile-app" and req["port"] == 0
            assert req["args"] == {"link_id": "link-0001"}
            return {"status": "ok", "parsed": {"oob_fired": True},
                    "request_bytes": b"fixed Android VIEW intent",
                    "response_bytes": b"range-local callback",
                    "deterministic_signals": {"hit": True, "confidence": 0.95}}

    class Sandbox:
        def proofs_pass(self):
            return True

        def guard_proof(self):
            return {"pass": True}

        def snapshot(self):
            return "clean"

        def restore(self, snapshot):
            assert snapshot == "golden"

    class Operator:
        def begin(self, pair, facts):
            return SimpleNamespace(id="mobile-operator", step=0)

        def propose_next(self, session, card, context):
            if session.step:
                return None
            session.step += 1
            return roleio.emit({"tool": "mobile", "intent": "invoke_deeplink",
                                "target": "mobile-app", "port": 0,
                                "args": {"link_id": "link-0001"}})

    class Verifier:
        def begin(self):
            return SimpleNamespace(id="mobile-verifier", step=0, disproved=False)

        def propose_next(self, session, inp, context):
            if session.step:
                return None
            session.step += 1
            step = inp["steps"][-1]
            return roleio.emit({**step, "intent": "reproduce"})

    with tempfile.TemporaryDirectory() as root:
        conn = db.connect()
        dispatcher = Dispatcher(conn, blobstore.BlobStore(root), eng, {"mobile": Adapter()},
                                ratelimit.RateLimiter(1000, now=lambda: 0.0))
        result = Loop(conn, eng, kb_index=mobile_kb, dispatcher=dispatcher,
                      sandbox=Sandbox(), planner=DeterministicPlanner(mobile_kb),
                      operator=Operator(), verifier=Verifier()).run(target_model)
        confirmed = findings.confirmed(conn, eng.id)
    assert result.valid, result.errors
    assert len(confirmed) == 1
    assert confirmed[0]["technique_id"] == "KB-MOBILE-LINK-DEEPLINK-001"
    assert confirmed[0]["found_by"] == "mobile-operator"
    assert confirmed[0]["verified_by"] == "mobile-verifier"


def test_inspect_apk_copies_hashes_and_removes_the_temporary_container_copy():
    commands = []

    def run(argv):
        commands.append(argv)
        if argv[1:3] == ["exec", "attacker"] and "apkanalyzer" in argv:
            return SimpleNamespace(rc=0, out=MANIFEST, err="")
        return SimpleNamespace(rc=0, out="", err="")

    fd, path = tempfile.mkstemp(suffix=".apk")
    try:
        with os.fdopen(fd, "wb") as apk:
            apk.write(b"apk-fixture")
        result = inspect_apk(path, "attacker", run=run)
    finally:
        os.unlink(path)
    assert result["sha256"] == "3934be6f0ca5c6c3efc3576bb846f79a8512db715c6a8103b034cb29e676fd8e"
    assert commands[0][:2] == ["docker", "cp"]
    assert commands[-1][-3:] == ["rm", "-f", "/tmp/hc-mobile.apk"]


def test_deep_link_probe_uses_fixed_intent_and_only_accepts_nonce_from_expected_source():
    invocations, logs = [], []
    result_ref = {}

    def adb(args):
        invocations.append(args)
        return SimpleNamespace(rc=0, out="Success", err="")

    def collaborator():
        args = next(args for args in invocations if "-d" in args)
        result_ref["url"] = args[args.index("-d") + 1]
        callback = parse_qs(urlparse(result_ref["url"]).query)["url"][0]
        nonce = urlparse(callback).path.lstrip("/")
        return f"/{nonce} 10.90.0.4" if nonce else ""

    probe = DeepLinkProbe("com.example.canary", inventory_manifest(MANIFEST)["deep_links"],
                          adb=adb, collaborator=collaborator, collab_addr="10.90.0.3:8080",
                          expected_source="10.90.0.4")
    result = probe.run({"args": {"link_id": "link-0001"}})
    assert result["deterministic_signals"]["hit"] is True
    assert invocations[0] == ["shell", "pm", "clear", "com.example.canary"]
    launch = invocations[1]
    assert launch[:7] == ["shell", "am", "start", "-W", "-a", "android.intent.action.VIEW", "-c"]
    callback = parse_qs(urlparse(launch[launch.index("-d") + 1]).query)["url"][0]
    assert callback.startswith("http://10.90.0.3:8080/")
    assert "arbitrary" not in str(launch)


def test_deep_link_probe_rejects_unknown_manifest_link():
    probe = DeepLinkProbe("com.example.canary", [], adb=lambda args: None,
                          collaborator=lambda: "", collab_addr="10.90.0.3:8080",
                          expected_source="10.90.0.4")
    assert probe.run({"args": {"link_id": "caller-controlled"}})["deterministic_signals"]["hit"] is False


def test_deep_link_probe_stops_if_app_data_reset_does_not_succeed():
    def adb(args):
        return SimpleNamespace(rc=0, out="Failed", err="")

    probe = DeepLinkProbe("com.example.canary", inventory_manifest(MANIFEST)["deep_links"],
                          adb=adb, collaborator=lambda: "", collab_addr="10.90.0.3:8080",
                          expected_source="10.90.0.4")
    try:
        probe.run({"args": {"link_id": "link-0001"}})
    except MobileError as exc:
        assert "reset" in str(exc)
    else:
        raise AssertionError("probe launched without a clean app baseline")


def test_callback_source_must_match_the_emulator_ip_exactly():
    invocations = []

    def adb(args):
        invocations.append(args)
        return SimpleNamespace(rc=0, out="Success", err="")

    def collaborator():
        launch = next(args for args in invocations if "-d" in args)
        url = launch[launch.index("-d") + 1]
        nonce = urlparse(parse_qs(urlparse(url).query)["url"][0]).path.lstrip("/")
        return f"/{nonce} 10.90.0.40"

    probe = DeepLinkProbe("com.example.canary", inventory_manifest(MANIFEST)["deep_links"],
                          adb=adb, collaborator=collaborator, collab_addr="10.90.0.3:8080",
                          expected_source="10.90.0.4")
    assert probe.run({"args": {"link_id": "link-0001"}})["deterministic_signals"]["hit"] is False


def test_android_guard_and_public_adb_key_precede_apk_inspection_and_install():
    calls = []

    class Runner:
        def __call__(self, argv, **kwargs):
            calls.append((argv, kwargs))
            if argv[-3:] == ["shell", "getprop", "sys.boot_completed"]:
                return SimpleNamespace(rc=0, out="1", err="")
            if argv[-2:] == ["path", "com.example.canary"]:
                return SimpleNamespace(rc=0, out="package:/data/app/canary.apk", err="")
            return SimpleNamespace(rc=0, out="Success", err="")

    sandbox = DockerSandbox(run=Runner())
    sandbox.attacker = "attacker"
    sandbox.android = "android"
    with patch.object(sandbox, "_read_file", return_value="public-adb-key") as read_key, \
            patch("harness.sandbox.docker.inspect_apk",
                  side_effect=lambda *args, **kwargs: calls.append(("APK_INSPECT", {})) or
                  {**inventory_manifest(MANIFEST), "sha256": "c" * 64}):
        sandbox._start_android("canary.apk", "10.90.0.4", "10.90.0.2")

    assert read_key.call_args.args[1].endswith(".pub")
    emulator_run = next(argv for argv, _ in calls
                        if isinstance(argv, list) and "ADBKEY_PUB=public-adb-key" in argv)
    assert "ADBKEY=public-adb-key" not in emulator_run
    guard_index = next(i for i, (argv, _) in enumerate(calls)
                       if isinstance(argv, list) and "nft" in argv)
    inspect_index = next(i for i, (argv, _) in enumerate(calls) if argv == "APK_INSPECT")
    assert guard_index < inspect_index


def test_baseline_restore_fails_when_pm_clear_reports_failure():
    sandbox = DockerSandbox(run=lambda argv, **kwargs: RunResult(0, "", ""))
    sandbox.mobile_inventory = {"package": "com.example.canary"}
    sandbox._adb = lambda args, **kwargs: SimpleNamespace(rc=0, out="Failed", err="")
    try:
        sandbox._reset_mobile_app()
    except SandboxError as exc:
        assert "clean baseline" in str(exc)
    else:
        raise AssertionError("failed Android reset was treated as successful")


def main():
    count = 0
    for name, test in sorted(globals().items()):
        if name.startswith("test_") and callable(test):
            try:
                test()
                print(f"  ok  {name}")
            except Exception as exc:
                print(f"FAIL  {name}: {exc}")
                raise
            count += 1
    print(f"{count}/{count} passed")


if __name__ == "__main__":
    main()
