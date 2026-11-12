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
from harness.mobile.apk import MobileError, inventory_manifest, inspect_apk  # noqa: E402
from harness.mobile.probe import CALLBACK_POLL_S, CALLBACK_WAIT_S, DeepLinkProbe  # noqa: E402
from harness.mobile.recon import mobile_recon  # noqa: E402
from harness.mobile.sandbox import (ANDROID_EMULATOR_IMAGE,
                                    android_guard_ruleset)  # noqa: E402
from harness.substrate import contract, scope  # noqa: E402
from harness.sandbox.base import RunResult, SandboxError  # noqa: E402
from harness.sandbox.docker import DockerSandbox  # noqa: E402
from harness import capabilities, evaluate, kb, ratelimit, report as reportmod, roleio  # noqa: E402
from harness.dispatch import Dispatcher  # noqa: E402
from harness.loop import Loop, phase_threat_model  # noqa: E402
from harness.planner import DeterministicPlanner  # noqa: E402
from harness.store import audit, blobstore, db, findings  # noqa: E402

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
    main, worker = result["components"]
    assert (main["name"], main["type"], main["exported"]) == (
        "com.example.canary.MainActivity", "activity", True)
    assert (worker["name"], worker["type"], worker["exported"]) == (
        "com.example.canary.Worker", "service", False)
    assert result["deep_links"] == [{"id": "link-0001", "component": "com.example.canary.MainActivity",
                                     "filter_index": 0, "scheme": "capri", "host": "open",
                                     "path": "/fetch"}]


def _manifest(target_sdk, app_attrs="", body=""):
    return (f'<manifest xmlns:android="{ANDROID}" package="com.example.canary" '
            f'android:versionName="1.2.3" android:versionCode="7">'
            f'<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="{target_sdk}" />'
            f'<application {app_attrs}>{body}</application></manifest>')


LINK_FILTER = ('<intent-filter><action android:name="android.intent.action.VIEW" />'
               '<category android:name="android.intent.category.BROWSABLE" />'
               '<data android:scheme="capri" android:host="open" android:path="/fetch" />'
               '</intent-filter>')

EXPOSED = _manifest(
    30, 'android:debuggable="true" android:usesCleartextTraffic="true"',
    f'<activity android:name=".MainActivity">{LINK_FILTER}</activity>'
    '<service android:name=".OpenService" android:exported="true" />'
    '<service android:name=".GuardedService" android:exported="true" '
    'android:permission="com.example.PRIVATE" />'
    '<receiver android:name=".InternalReceiver" android:exported="false" />'
    '<provider android:name=".Data" android:authorities="com.example.data" '
    'android:exported="true" android:grantUriPermissions="true" />')

NO_SURFACE = _manifest(
    34, 'android:allowBackup="false" android:usesCleartextTraffic="false"',
    '<activity android:name=".MainActivity" android:exported="false" />')


def _static(manifest):
    """Run the whole engagement over `manifest`; return the report and its store."""
    result, conn, eng = _deep_link_loop(manifest=manifest)
    return result.report, conn, eng


def _advisories(report):
    return {a["rule_id"]: a for a in report["mobile_static_assessment"]["advisory_findings"]}


def test_inventory_records_flags_versions_and_effective_export_state():
    inv = inventory_manifest(EXPOSED)
    assert inv["version"] == {"name": "1.2.3", "code": 7}
    assert inv["sdk"] == {"min": 24, "target": 30}
    assert inv["application"]["debuggable"] is True
    assert inv["application"]["allow_backup"] is True          # Android's default when omitted
    assert inv["application"]["uses_cleartext_traffic"] is True
    assert inv["application"]["network_security_config"] is False
    by_name = {c["name"].rsplit(".", 1)[1]: c for c in inv["components"]}
    assert by_name["MainActivity"]["exported"] is True         # implicit: filter and SDK < 31
    assert by_name["MainActivity"]["exported_declared"] is None
    assert by_name["GuardedService"]["permission"] == "com.example.PRIVATE"
    assert by_name["InternalReceiver"]["exported"] is False
    assert by_name["Data"]["grant_uri_permissions"] is True


def test_effective_export_follows_the_target_sdk_for_components_that_omit_the_attribute():
    body = f'<activity android:name=".A">{LINK_FILTER}</activity><service android:name=".S" />'
    legacy = {c["name"][-1]: c["exported"]
              for c in inventory_manifest(_manifest(30, body=body))["components"]}
    modern = {c["name"][-1]: c["exported"]
              for c in inventory_manifest(_manifest(33, body=body))["components"]}
    assert legacy == {"A": True, "S": False}                   # filter implies export below 31
    assert modern == {"A": None, "S": False}                   # 31+: undecidable, must be explicit


def test_advisory_findings_are_reported_separately_and_never_among_confirmed_findings():
    report, conn, eng = _static(EXPOSED)
    advisories = _advisories(report)
    assert {"debuggable-app", "backup-allowed", "cleartext-permitted",
            "exported-component-unprotected", "exported-provider-unprotected"} <= set(advisories)
    for advisory in advisories.values():
        assert advisory["confidence"] in {"high", "medium", "low"}
        assert isinstance(advisory["related_cards"], list) and advisory["masvs"]
        assert "verdict" not in advisory and "verified_by" not in advisory
    assert advisories["backup-allowed"]["related_cards"] == ["KB-MOBILE-STORAGE-BACKUP-001"]
    assert "GuardedService" not in str(advisories["exported-component-unprotected"])
    assert [f["technique_id"] for f in report["findings"]] == ["KB-MOBILE-LINK-DEEPLINK-001"]
    assert not set(advisories) & {f["id"] for f in report["findings"]}


def test_the_report_gate_rejects_an_advisory_finding_that_claims_a_runtime_verdict():
    report, _, _ = _static(EXPOSED)
    report["mobile_static_assessment"]["advisory_findings"][0]["verdict"] = "confirmed"
    status, errors = reportmod.validate_report(report, kb.known_pairs(kb.load()))
    assert status == "errors" and any("runtime verdict" in e for e in errors), errors


def test_a_missing_export_attribute_on_a_modern_target_is_an_advisory_finding():
    report, _, _ = _static(_manifest(33, body=f'<activity android:name=".A">{LINK_FILTER}</activity>'))
    assert "export-attribute-missing" in _advisories(report)


def test_manifest_facts_make_the_matching_cards_applicable_in_the_planner():
    inventory = {**inventory_manifest(EXPOSED), "sha256": "b" * 64}
    model, _ = mobile_recon(db.connect(), "mobile-facts", inventory)
    pairs = {(p.asset, p.technique_id) for p in phase_threat_model(model, kb.load())}
    for card in ("KB-MOBILE-COMP-EXPORTED-001", "KB-MOBILE-COMP-PROVIDER-SQLI-001",
                 "KB-MOBILE-STORAGE-BACKUP-001", "KB-MOBILE-LINK-DEEPLINK-001"):
        assert ("mobile-app", card) in pairs or ("mobile-app::link-0001", card) in pairs, card
    quiet = {**inventory_manifest(NO_SURFACE), "sha256": "b" * 64}
    model, _ = mobile_recon(db.connect(), "mobile-quiet", quiet)
    pairs = {p.technique_id for p in phase_threat_model(model, kb.load())}
    assert not pairs & {"KB-MOBILE-COMP-EXPORTED-001", "KB-MOBILE-COMP-PROVIDER-SQLI-001",
                        "KB-MOBILE-STORAGE-BACKUP-001", "KB-MOBILE-LINK-DEEPLINK-001"}


def test_an_apk_with_no_matching_surface_is_not_reported_as_clean():
    report, _, _ = _static(NO_SURFACE)
    static = report["mobile_static_assessment"]
    assert static["advisory_findings"] == []
    assert static["coverage"]["manifest"] == "complete"
    assert static["coverage"]["code"] == "not_run"
    not_applicable = {item["card"] for item in static["not_applicable"]}
    assert {"KB-MOBILE-LINK-DEEPLINK-001", "KB-MOBILE-COMP-EXPORTED-001",
            "KB-MOBILE-STORAGE-BACKUP-001"} <= not_applicable
    assert static["not_assessed"], "a report must list what it did not examine"
    assert report["coverage_summary"] == {}                    # nothing was runnable, nothing claimed


def test_recon_audits_the_exact_build_that_is_tested():
    _, conn, eng = _static(EXPOSED)
    [row] = [dict(r) for r in conn.execute(
        "SELECT * FROM audit_log WHERE category='mobile_apk_inventory'")]
    for expected in ("com.example.canary", "1.2.3", "9" * 64, "b" * 64):
        assert expected in row["detail"], (expected, row["detail"])


def test_inspect_apk_records_the_signing_certificate_digest_when_the_jre_can_read_it():
    def run(argv):
        if "apkanalyzer" in argv:
            return SimpleNamespace(rc=0, out=MANIFEST, err="")
        if "keytool" in argv:
            return SimpleNamespace(rc=0, out="Certificate fingerprints:\n\t SHA256: AA:BB:CC\n",
                                   err="")
        return SimpleNamespace(rc=0, out="", err="")

    fd, path = tempfile.mkstemp(suffix=".apk")
    try:
        with os.fdopen(fd, "wb") as apk:
            apk.write(b"apk-fixture")
        assert inspect_apk(path, "attacker", run=run)["signing_sha256"] == "aabbcc"
        unsigned = inspect_apk(path, "attacker", run=lambda argv: SimpleNamespace(
            rc=1 if "keytool" in argv else 0, out=MANIFEST if "apkanalyzer" in argv else "",
            err=""))
        assert unsigned["signing_sha256"] is None
    finally:
        os.unlink(path)


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


def test_mobile_canary_variants_keep_the_same_deep_link_with_different_policy_flags():
    path = os.path.join(ROOT, "tests", "fixtures", "mobile", "canary",
                        "AndroidManifest.xml.in")
    with open(path, encoding="utf-8") as source:
        template = source.read()
    variants = []
    for vulnerable in ("true", "false"):
        manifest = template.replace("@VULNERABLE@", vulnerable)
        inventory = inventory_manifest(manifest)
        variants.append((inventory, vulnerable))
    assert variants[0][0]["package"] == variants[1][0]["package"]
    assert variants[0][0]["deep_links"] == variants[1][0]["deep_links"]
    assert variants[0][1] == "true" and variants[1][1] == "false"
    assert variants[0][0]["deep_links"] == [{
        "id": "link-0001", "component": "com.capri.mobile.canary.MainActivity",
        "filter_index": 0, "scheme": "capri", "host": "open", "path": "/fetch"}]


def test_mobile_only_engagement_is_valid_and_scope_uses_a_virtual_target():
    eng, errors = contract.parse(MOBILE_CONTRACT)
    assert not errors, errors
    assert eng.android_app == {"apk": "tests/fixtures/mobile/canary.apk"}
    assert scope.scope_validate(eng, "mobile-app", 0, kind="mobile") == ("allow", None)
    assert scope.scope_validate(eng, "10.90.0.4", 8080, kind="mobile")[0] == "deny"


def _dispatch_once(adapters, request, eng):
    """Send one request through the real dispatcher and return its reply."""
    from harness.dispatch import ProbeContext
    with tempfile.TemporaryDirectory() as root:
        conn = db.connect()
        dispatcher = Dispatcher(conn, blobstore.BlobStore(root), eng, adapters,
                                ratelimit.RateLimiter(1000, now=lambda: 0.0))
        ctx = ProbeContext(role="operator", pair_asset="mobile-app",
                           technique_id="KB-MOBILE-LINK-DEEPLINK-001",
                           technique_version="1.0.0", blast_tier=1)
        return dispatcher.dispatch(request, ctx)


def test_an_adapter_cannot_widen_scope_for_the_mobile_tool_or_any_other():
    eng, errors = contract.parse(MOBILE_CONTRACT)
    assert not errors, errors
    calls = []

    class Greedy:
        scope_policy = staticmethod(lambda *_: ("allow", None))

        def run(self, req):
            calls.append(req)
            return {"status": "ok", "parsed": {}, "request_bytes": b"", "response_bytes": b"",
                    "deterministic_signals": {}}

    def req(tool, target, port):
        return {"tool": tool, "intent": "x", "target": target, "port": port, "args": {}}

    for tool, target, port in (("mobile", "10.90.0.4", 8080), ("mobile", "mobile-app", 443),
                               ("probe", "mobile-app", 0)):
        reply = _dispatch_once({"mobile": Greedy(), "probe": Greedy()}, req(tool, target, port), eng)
        assert reply == {"disposition": "deny", "reason": "out_of_scope"}, (tool, target, port, reply)
    assert calls == []
    allowed = _dispatch_once({"mobile": Greedy()}, req("mobile", "mobile-app", 0), eng)
    assert allowed.get("disposition") != "deny" and len(calls) == 1, allowed


def test_mobile_contract_rejects_unsupported_or_empty_apk_declarations():
    for decl in ("android_app: {apk: ''}", "android_app: {apk: a.apk, shell: true}"):
        text = MOBILE_CONTRACT.replace("android_app: { apk: tests/fixtures/mobile/canary.apk }", decl)
        _, errors = contract.parse(text)
        assert any("engagement.android_app" in error for error in errors), errors


def test_mobile_recon_has_one_app_asset_and_one_asset_per_manifest_link():
    inventory = {**inventory_manifest(MANIFEST), "sha256": "a" * 64}
    model, _ = mobile_recon(db.connect(), "mobile-recon", inventory)
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
    with patch("harness.mobile.sandbox.sys.platform", "win32"), \
            patch("harness.mobile.sandbox.os.path.exists", return_value=False):
        try:
            sandbox.provision(eng)
        except SandboxError as exc:
            assert "Linux Docker host with /dev/kvm" in str(exc)
        else:
            raise AssertionError("mobile provision started without Linux KVM")
    assert runner.calls == [], runner.calls
    assert ANDROID_EMULATOR_IMAGE.endswith("sha256:e78ac1816acef59e40285e90003acd490ef54bb3242ed088afa31bc982577050")


def _deep_link_loop(sandbox_factory=None, manifest=None, option_id="link-0001", spy=None):
    """Run the whole deep-link engagement (recon, hunt, independent verification, report)
    against fakes; returns the loop result, the store and the engagement."""
    mobile_contract = MOBILE_CONTRACT.replace(
        "id: mobile-only", "id: mobile-loop").replace(
            "2026-11-13T00:00", "2026-11-13T23:59")
    eng, errors = contract.parse(mobile_contract)
    assert not errors, errors
    inventory = {**inventory_manifest(manifest or MANIFEST), "sha256": "b" * 64,
                 "signing_sha256": "9" * 64}
    conn = db.connect()
    target_model, static = mobile_recon(conn, eng.id, inventory)
    mobile_kb = {key: card for key, card in capabilities.runnable_index(kb.load()).items()
                 if key[0] == "KB-MOBILE-LINK-DEEPLINK-001"}

    spy = {} if spy is None else spy
    spy["runs"], spy["facts"], spy["requests"] = [], [], []
    probe, _ = _probe_with_collaborator(lambda nonce, n: f"/{nonce} 10.90.0.4", FakeClock(),
                                        manifest or MANIFEST)
    real_run = probe.run

    def counting_run(req):
        spy["runs"].append(req)
        reply = real_run(req)
        spy["requests"].append(reply["request_bytes"])
        return reply
    probe.run = counting_run

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
            spy["facts"].append(facts)
            return SimpleNamespace(id="mobile-operator", step=0)

        def propose_next(self, session, card, context):
            if session.step:
                return None
            session.step += 1
            return roleio.emit({"tool": "mobile", "intent": "invoke_deeplink",
                                "target": "mobile-app", "port": 0,
                                "args": {"option_id": option_id}})

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
        dispatcher = Dispatcher(conn, blobstore.BlobStore(root), eng, {"mobile": probe},
                                ratelimit.RateLimiter(1000, now=lambda: 0.0))
        result = Loop(conn, eng, kb_index=mobile_kb, dispatcher=dispatcher,
                      sandbox=(sandbox_factory or Sandbox)(),
                      planner=DeterministicPlanner(mobile_kb),
                      operator=Operator(), verifier=Verifier(),
                      mobile_static=static).run(target_model)
    return result, conn, eng


def test_an_option_outside_the_published_set_is_rejected_audited_and_never_run():
    spy = {}
    result, conn, eng = _deep_link_loop(option_id="link-9999", spy=spy)
    assert spy["runs"] == []                                   # no device command was built
    assert findings.confirmed(conn, eng.id) == [] and findings.leads(conn, eng.id) == []
    [turn] = [dict(r) for r in conn.execute("SELECT * FROM role_turn WHERE role='operator'")]
    assert turn["rejection"] == "unpublished_option"
    [row] = [dict(r) for r in conn.execute(
        "SELECT * FROM audit_log WHERE category='option_rejected'")]
    assert row["decision"] == "rejected" and "link-9999" not in row["detail"]
    assert result.valid, result.errors


def test_the_operator_sees_the_published_options_and_no_device_internals():
    spy = {}
    _deep_link_loop(spy=spy)
    [facts] = spy["facts"]
    assert facts["asset.mobile_options"] == [
        {"id": "link-0001", "kind": "deep_link", "scheme": "capri", "host": "open",
         "path": "/fetch"}]
    seen = repr(facts)
    for private in (".apk", "/tmp", "adb", "ADB_VENDOR_KEYS", "hc-mobile"):
        assert private not in seen, private


def test_the_verifier_reproduces_the_recorded_option_with_a_fresh_canary():
    spy = {}
    result, conn, eng = _deep_link_loop(spy=spy)
    assert len(spy["runs"]) == 2                               # finder run, then verifier run
    assert spy["runs"][0]["args"] == spy["runs"][1]["args"] == {"option_id": "link-0001"}
    operator_request, verifier_request = spy["requests"]
    assert operator_request != verifier_request                # different harness-made nonce


def test_deep_link_finding_passes_dispatch_and_independent_verification():
    result, conn, eng = _deep_link_loop()
    confirmed = findings.confirmed(conn, eng.id)
    assert result.valid, result.errors
    assert len(confirmed) == 1
    assert confirmed[0]["technique_id"] == "KB-MOBILE-LINK-DEEPLINK-001"
    assert confirmed[0]["found_by"] == "mobile-operator"
    assert confirmed[0]["verified_by"] == "mobile-verifier"


def _loop_sandbox(restore, report=None):
    """A sandbox whose containment proofs pass; `restore(snapshot)` is under test."""
    class Sandbox:
        def proofs_pass(self):
            return True

        def guard_proof(self):
            return {"pass": True}

        def snapshot(self):
            return "clean"

        def restore(self, snapshot):
            return restore(snapshot)

        def baseline_report(self):
            return report or {}
    return Sandbox


def test_a_lead_stays_unconfirmed_with_a_reason_when_the_device_baseline_cannot_be_restored():
    def restore(snapshot):
        raise SandboxError("Android device baseline could not be restored")

    result, conn, eng = _deep_link_loop(_loop_sandbox(restore))
    assert findings.confirmed(conn, eng.id) == []
    [lead] = findings.leads(conn, eng.id)
    assert lead["verdict"] == "needs_validation"
    reason = dict(findings.history(conn, lead["id"])[-1])["reason"]
    assert "baseline" in reason and "could not be restored" in reason, reason
    assert result.valid, result.errors


def test_a_finished_run_becomes_an_eval_record_from_its_own_store():
    report = {"baseline_id": "range-android-baseline", "method": "snapshot",
              "emulator_image": ANDROID_EMULATOR_IMAGE, "restore_ms": 2500}
    result, conn, eng = _deep_link_loop(_loop_sandbox(lambda snapshot: True, report))
    audit.record(conn, eng.id, "vk-operator", "model_call", decision="ok",
                 detail={"tokens_in": 700, "tokens_out": 300})
    audit.record(conn, eng.id, "harness", "dispatch_denial", decision="out_of_scope",
                 reason="not_in_scope", detail={})
    record = evaluate.record_from_run(conn, eng.id, result.report, fixture="seed/x-vuln",
                                      run=2, wall_s=12.5)
    assert record == {
        "fixture": "seed/x-vuln", "run": 2,
        "findings": [{"technique_id": "KB-MOBILE-LINK-DEEPLINK-001"}],
        "advisories": ["backup-allowed", "exported-component-unprotected", "deep-link-declared"],
        "coverage": {"confirmed": 1}, "scope_events": 1, "leads": 1,
        "cost": {"tokens": 1000, "wall_s": 12.5, "restore_s": 2.5}}


def test_every_verification_audits_the_baseline_it_restored_from():
    report = {"baseline_id": "range-android-baseline", "method": "snapshot",
              "emulator_image": ANDROID_EMULATOR_IMAGE}
    result, conn, eng = _deep_link_loop(_loop_sandbox(lambda snapshot: True, report))
    assert len(findings.confirmed(conn, eng.id)) == 1
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM audit_log WHERE category='verification_baseline'")]
    assert len(rows) == 1 and rows[0]["decision"] == "ok", rows
    for key, value in report.items():
        assert value in rows[0]["detail"], (key, rows[0]["detail"])


class FakeAndroid:
    """A command runner that models just enough emulator state for baseline tests:
    device files, a saved snapshot, whether snapshot loading works, and which APK is
    installed. Containers are 'recreated' with an empty device."""

    PKG, APK_SHA = "com.example.canary", "d" * 64

    def __init__(self):
        self.files, self.snapshots, self.calls, self.guard_inputs = set(), {}, [], []
        self.snapshot_load_ok = True
        self.installed_sha = self.APK_SHA
        self.new_device_sha = self.APK_SHA

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        ok = lambda out="": SimpleNamespace(rc=0, out=out, err="")
        bad = lambda out="": SimpleNamespace(rc=1, out=out, err="")
        if argv[:3] == ["docker", "rm", "-f"]:
            return ok()
        if argv[:2] == ["docker", "run"] and "--name" in argv and "android" in argv:
            self.files, self.installed_sha = set(), None       # a brand-new emulator
            return ok()
        if "nft" in argv:
            self.guard_inputs.append((kwargs.get("input") or b"").decode())
            return ok()
        if "adb" not in argv:
            return ok()
        adb = argv[argv.index("adb") + 1:]
        if adb[:2] == ["-s", "10.90.0.4:5555"]:
            adb = adb[2:]
        if adb[:3] == ["emu", "avd", "snapshot"]:
            if adb[3] == "save":
                self.snapshots[adb[4]] = (set(self.files), self.installed_sha)
                return ok("OK")
            if adb[3] == "load" and self.snapshot_load_ok and adb[4] in self.snapshots:
                self.files, self.installed_sha = (set(self.snapshots[adb[4]][0]),
                                                  self.snapshots[adb[4]][1])
                return ok("OK")
            return bad("KO: snapshot not found")
        if adb[:2] == ["shell", "getprop"]:
            return ok("1")
        if adb[:1] == ["install"]:
            self.installed_sha = self.new_device_sha
            return ok("Success")
        if adb[:3] == ["shell", "pm", "path"]:
            return ok("package:/data/app/base.apk") if self.installed_sha else bad()
        if adb[:2] == ["shell", "sha256sum"]:
            return ok(f"{self.installed_sha}  {adb[2]}")
        if adb[:2] == ["shell", "touch"]:
            self.files.add(adb[2])
            return ok()
        if adb[:3] == ["shell", "ls", "/sdcard/leftover"]:
            return ok("/sdcard/leftover") if "/sdcard/leftover" in self.files else bad()
        return ok()


def _started_runtime(device):
    """An AndroidRuntime that has been through start(), a replaced guard and save_baseline()."""
    sandbox = DockerSandbox(run=device)
    runtime = sandbox.mobile
    runtime.attacker, runtime.container = "attacker", "android"
    inventory = {**inventory_manifest(MANIFEST), "sha256": FakeAndroid.APK_SHA}
    with patch.object(runtime, "_read_file", return_value="public-adb-key"),             patch("harness.mobile.sandbox.inspect_apk", return_value=inventory):
        runtime.start("canary.apk", "10.90.0.4", "10.90.0.2")
        runtime.install_guard("10.90.0.2", [("10.90.0.5", [8080])], replace=True)
        runtime.save_baseline()
    return runtime


def _restore(runtime):
    with patch.object(runtime, "_read_file", return_value="public-adb-key"),             patch("harness.mobile.sandbox.inspect_apk",
                  return_value={**inventory_manifest(MANIFEST), "sha256": FakeAndroid.APK_SHA}):
        return runtime.restore_baseline()


def test_restoring_the_baseline_removes_state_left_on_the_device():
    device = FakeAndroid()
    runtime = _started_runtime(device)
    runtime.adb(["shell", "touch", "/sdcard/leftover"])
    assert "/sdcard/leftover" in device.files
    report = _restore(runtime)
    assert "/sdcard/leftover" not in device.files
    assert report["method"] == "snapshot" and report["baseline_id"]
    assert isinstance(report["restore_ms"], int) and report["restore_ms"] >= 0
    assert not any(c[:3] == ["docker", "rm", "-f"] and "android" in c for c in device.calls[-12:])


def test_a_failed_snapshot_load_recreates_the_emulator_under_the_same_guard():
    device = FakeAndroid()
    runtime = _started_runtime(device)
    runtime.adb(["shell", "touch", "/sdcard/leftover"])
    device.snapshot_load_ok = False
    device.calls.clear()
    report = _restore(runtime)
    assert report["method"] == "recreate"
    assert "/sdcard/leftover" not in device.files
    rm = next(i for i, c in enumerate(device.calls) if c[:3] == ["docker", "rm", "-f"])
    run = next(i for i, c in enumerate(device.calls) if c[:2] == ["docker", "run"] and "android" in c)
    guards = [i for i, c in enumerate(device.calls) if "nft" in c]
    assert rm < run < guards[-1]                      # guard reinstalled after the new emulator
    assert "ip daddr 10.90.0.5 tcp dport { 8080 } accept" in device.guard_inputs[-1]


def test_baseline_restore_fails_closed_when_neither_path_yields_the_installed_apk():
    device = FakeAndroid()
    runtime = _started_runtime(device)
    device.snapshot_load_ok = False
    device.new_device_sha = "e" * 64                  # a reinstall that is not the tested build
    try:
        _restore(runtime)
    except SandboxError as exc:
        assert "baseline" in str(exc)
    else:
        raise AssertionError("an unverifiable device was handed to the Verifier")


def test_a_snapshot_whose_package_hash_differs_is_not_trusted():
    device = FakeAndroid()
    runtime = _started_runtime(device)
    device.snapshots[next(iter(device.snapshots))] = (set(), "f" * 64)   # tampered baseline
    report = _restore(runtime)
    assert report["method"] == "recreate"             # fell through to a fresh emulator


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
    invocations = []
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
    result = probe.run({"args": {"option_id": "link-0001"}})
    assert result["deterministic_signals"]["hit"] is True
    assert invocations[0] == ["shell", "pm", "clear", "com.example.canary"]
    launch = invocations[1]
    assert launch[:7] == ["shell", "am", "start", "-W", "-a", "android.intent.action.VIEW", "-c"]
    callback = parse_qs(urlparse(launch[launch.index("-d") + 1]).query)["url"][0]
    assert callback.startswith("http://10.90.0.3:8080/")
    assert "arbitrary" not in str(launch)


class FakeClock:
    """Virtual time so the callback-wait tests never sleep for real."""

    def __init__(self):
        self.t = 0.0

    def monotonic(self):
        return self.t

    def sleep(self, seconds):
        self.t += seconds


def _probe_with_collaborator(responses, clock, manifest=MANIFEST):
    """A probe whose collaborator log is `responses(nonce, poll_number)` and whose
    emulator accepts every ADB call; returns the probe and the poll counter."""
    invocations, polls = [], []

    def adb(args):
        invocations.append(args)
        return SimpleNamespace(rc=0, out="Success", err="")

    def collaborator():
        launch = [args for args in invocations if "-d" in args][-1]
        url = launch[launch.index("-d") + 1]
        nonce = urlparse(parse_qs(urlparse(url).query)["url"][0]).path.lstrip("/")
        polls.append(clock.t)
        return responses(nonce, len(polls))

    probe = DeepLinkProbe("com.example.canary", inventory_manifest(manifest)["deep_links"],
                          adb=adb, collaborator=collaborator, collab_addr="10.90.0.3:8080",
                          expected_source="10.90.0.4", monotonic=clock.monotonic,
                          sleep=clock.sleep)
    return probe, polls


def test_a_callback_that_arrives_after_launch_still_confirms_and_stops_the_wait():
    clock = FakeClock()
    probe, polls = _probe_with_collaborator(
        lambda nonce, n: f"/{nonce} 10.90.0.4" if n >= 4 else "", clock)
    result = probe.run({"args": {"option_id": "link-0001"}})
    assert result["deterministic_signals"]["hit"] is True
    assert len(polls) == 4, polls          # stopped at the first matching line, not the deadline
    assert clock.t == 3 * CALLBACK_POLL_S


def test_no_callback_gives_up_at_the_deadline_without_a_hit():
    clock = FakeClock()
    probe, polls = _probe_with_collaborator(lambda nonce, n: "", clock)
    result = probe.run({"args": {"option_id": "link-0001"}})
    assert result["deterministic_signals"]["hit"] is False
    assert result["status"] == "error"
    assert CALLBACK_WAIT_S <= clock.t <= CALLBACK_WAIT_S + CALLBACK_POLL_S, clock.t


def test_deep_link_probe_rejects_unknown_manifest_link():
    probe = DeepLinkProbe("com.example.canary", [], adb=lambda args: None,
                          collaborator=lambda: "", collab_addr="10.90.0.3:8080",
                          expected_source="10.90.0.4")
    assert probe.run({"args": {"option_id": "caller-controlled"}})["deterministic_signals"]["hit"] is False


def test_deep_link_probe_stops_if_app_data_reset_does_not_succeed():
    def adb(args):
        return SimpleNamespace(rc=0, out="Failed", err="")

    probe = DeepLinkProbe("com.example.canary", inventory_manifest(MANIFEST)["deep_links"],
                          adb=adb, collaborator=lambda: "", collab_addr="10.90.0.3:8080",
                          expected_source="10.90.0.4")
    try:
        probe.run({"args": {"option_id": "link-0001"}})
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

    clock = FakeClock()
    probe = DeepLinkProbe("com.example.canary", inventory_manifest(MANIFEST)["deep_links"],
                          adb=adb, collaborator=collaborator, collab_addr="10.90.0.3:8080",
                          expected_source="10.90.0.4", monotonic=clock.monotonic,
                          sleep=clock.sleep)
    assert probe.run({"args": {"option_id": "link-0001"}})["deterministic_signals"]["hit"] is False


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
    sandbox.mobile.attacker = "attacker"
    sandbox.mobile.container = "android"
    with patch.object(sandbox.mobile, "_read_file", return_value="public-adb-key") as read_key, \
            patch("harness.mobile.sandbox.inspect_apk",
                  side_effect=lambda *args, **kwargs: calls.append(("APK_INSPECT", {})) or
                  {**inventory_manifest(MANIFEST), "sha256": "c" * 64}):
        sandbox.mobile.start("canary.apk", "10.90.0.4", "10.90.0.2")

    assert read_key.call_args.args[1].endswith(".pub")
    emulator_run = next(argv for argv, _ in calls
                        if isinstance(argv, list) and "ADBKEY_PUB=public-adb-key" in argv)
    assert "ADBKEY=public-adb-key" not in emulator_run
    guard_index = next(i for i, (argv, _) in enumerate(calls)
                       if isinstance(argv, list) and "nft" in argv)
    inspect_index = next(i for i, (argv, _) in enumerate(calls) if argv == "APK_INSPECT")
    assert guard_index < inspect_index


def test_baseline_restore_fails_when_pm_clear_reports_failure():
    sandbox = DockerSandbox(run=lambda argv, **kwargs: RunResult(0, "Failed", ""))
    sandbox.mobile.ip = "10.90.0.4"
    sandbox.mobile._adb_key_path = "/tmp/adb-key"
    sandbox.mobile.inventory = {"package": "com.example.canary"}
    try:
        sandbox.mobile.reset_app()
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
