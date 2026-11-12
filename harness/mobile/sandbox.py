"""Android emulator lifecycle and guest egress controls."""
import json
import os
import re
import sys
import time

from harness.mobile.apk import APK_IN_ATTACKER, MobileError, inspect_apk
from harness.sandbox.base import SandboxError
from harness.substrate import scope

ANDROID_EMULATOR_IMAGE = (
    "us-docker.pkg.dev/android-emulator-268719/images/30-google-x64-no-metrics"
    "@sha256:e78ac1816acef59e40285e90003acd490ef54bb3242ed088afa31bc982577050"
)


def android_guard_ruleset(table, attacker_ip, allowed_ports, *, dns_server=None, replace=False):
    """Fence emulator egress to scoped APIs/collaborator and ADB ingress to the attacker."""
    lines = ([f"delete table inet {table}"] if replace else []) + [f"table inet {table} {{",
             "\tchain out {",
             "\t\ttype filter hook output priority 0; policy drop;",
             '\t\toifname "lo" accept',
             "\t\tct state established,related accept"]
    for ip, ports in allowed_ports:
        ports = sorted({int(port) for port in ports})
        if ports:
            lines.append(f"\t\tip daddr {ip} tcp dport {{ {', '.join(map(str, ports))} }} accept")
    if dns_server:
        lines.append(f"\t\tip daddr {dns_server} udp dport 53 accept")
    lines += ["\t}", "\tchain input {", "\t\ttype filter hook input priority 0; policy drop;",
              '\t\tiifname "lo" accept', "\t\tct state established,related accept",
              f"\t\tip saddr {attacker_ip} tcp dport 5555 accept", "\t}", "}", ""]
    return "\n".join(lines)


# Name of the emulator snapshot taken once the APK is installed and the guard is final.
BASELINE_SNAPSHOT = "hc-baseline"


class AndroidRuntime:
    """Own the disposable emulator while the shared sandbox owns range coordination."""

    def __init__(self, *, run, docker, exec_attacker, read_file, network, attacker, guard_image):
        self._run = run
        self._docker = docker
        self._exec_attacker = exec_attacker
        self._read_file = read_file
        self.network = network
        self.container = f"{network}-android"
        self.attacker = attacker
        self.guard_image = guard_image
        self.ip = None
        self.inventory = None
        self.baseline = None
        self.last_baseline = None
        self._adb_key_path = None
        self._launch = None
        self._guard = None

    @property
    def active(self):
        return self.ip is not None

    def validate(self, apk_path):
        if sys.platform != "linux" or not os.path.exists("/dev/kvm"):
            raise MobileError("Android mobile testing requires a Linux Docker host with /dev/kvm")
        if not os.path.isfile(apk_path):
            raise MobileError("engagement.android_app.apk must name an existing APK file")
        image = self._run(["docker", "image", "inspect", ANDROID_EMULATOR_IMAGE])
        if image.rc != 0:
            raise MobileError(f"required Android emulator image {ANDROID_EMULATOR_IMAGE} is missing; "
                              "pull the pinned image before starting the engagement")

    def install_resolver(self, records, source_ip):
        """Run the in-range, non-recursive resolver inside the guarded attacker namespace."""
        source = os.path.join(os.path.dirname(__file__), "resolver.py")
        destination = "/tmp/hc-mobile-resolver.py"
        copied = self._run(["docker", "cp", source, f"{self.attacker}:{destination}"])
        if copied.rc != 0:
            raise SandboxError("could not install the in-range Android resolver")
        started = self._run(["docker", "exec", "-d", self.attacker, "python3", destination,
                             json.dumps(records, sort_keys=True), source_ip])
        if started.rc != 0:
            raise SandboxError("could not start the in-range Android resolver")

    def start(self, apk_path, ip, attacker_ip, *, runtime=None, dns_server=None,
              static_depth="manifest"):
        self._launch = (apk_path, ip, attacker_ip, runtime, dns_server, static_depth)
        self._adb_key_path = f"/tmp/hc-adbkey-{self.container}"
        keygen = self._exec_attacker("adb", "keygen", self._adb_key_path)
        if keygen.rc != 0:
            raise SandboxError("could not create a run-local ADB key")
        adb_key = self._read_file(self.attacker, self._adb_key_path + ".pub")
        if not adb_key:
            raise SandboxError("run-local ADB public key was not created")

        dns_option = ["--dns", dns_server] if dns_server else []
        self._docker("run", "-d", "--name", self.container, "--network", self.network,
                     "--ip", ip, *dns_option,
                     "--device", "/dev/kvm", "-e", f"ADBKEY_PUB={adb_key}",
                     "--tmpfs", "/data:rw,nosuid,size=1g", *(["--runtime", runtime] if runtime else []),
                     ANDROID_EMULATOR_IMAGE)
        self.ip = ip
        connected = self._run(["docker", "exec", self.attacker, "env",
                               f"ADB_VENDOR_KEYS={self._adb_key_path}", "adb",
                               "connect", f"{ip}:5555"], timeout=30)
        if connected.rc != 0:
            raise SandboxError("could not connect to the private Android ADB endpoint")
        ready = self.adb(["wait-for-device"], timeout=120)
        if ready.rc != 0:
            raise SandboxError("Android emulator did not become ready through private ADB")
        self._wait_boot()

        self.install_guard(attacker_ip, [], runtime=runtime, dns_server=dns_server)
        self.inventory = inspect_apk(apk_path, self.attacker, run=self._run, cleanup=False,
                                     static_depth=static_depth)
        installed = self.adb(["install", APK_IN_ATTACKER], timeout=120)
        self._run(["docker", "exec", self.attacker, "rm", "-f", APK_IN_ATTACKER])
        if installed.rc != 0:
            raise SandboxError("Android APK installation failed")
        present = self.adb(["shell", "pm", "path", self.inventory["package"]], timeout=15)
        if present.rc != 0 or "package:" not in (present.out or ""):
            raise SandboxError("installed Android package could not be verified")

    def _wait_boot(self):
        deadline = time.monotonic() + 120
        while True:
            boot = self.adb(["shell", "getprop", "sys.boot_completed"], timeout=10)
            if boot.rc == 0 and boot.out.strip() == "1":
                return
            if time.monotonic() >= deadline:
                raise SandboxError("Android emulator boot timed out")
            time.sleep(1)

    def adb(self, args, *, timeout=30):
        if not self.active or not self._adb_key_path:
            raise SandboxError("Android emulator control is unavailable")
        return self._run(["docker", "exec", self.attacker, "env",
                          f"ADB_VENDOR_KEYS={self._adb_key_path}", "adb", "-s",
                          f"{self.ip}:5555", *args], timeout=timeout)

    def install_guard(self, attacker_ip, allowed_ports, *, runtime=None, dns_server=None,
                      replace=False):
        self._guard = (attacker_ip, [(ip, list(ports)) for ip, ports in allowed_ports],
                       runtime, dns_server)
        command = ["run", "--rm", "--network", f"container:{self.container}"]
        if runtime:
            command += ["--runtime", runtime]
        command += ["--cap-drop=ALL", "--cap-add=NET_ADMIN", "-i", self.guard_image,
                    "nft", "-f", "-"]
        rules = android_guard_ruleset("hc_android", attacker_ip, allowed_ports,
                                      dns_server=dns_server,
                                      replace=replace).encode("utf-8")
        self._docker(*command, input=rules)

    def guard_proof(self, engagement, *, internet_canary, public_name, out_of_scope_ip):
        """Prove guest-originated egress, not only the emulator container's namespace."""
        def tcp(ip, port):
            result = self.adb(["shell", "toybox", "nc", "-z", "-w", "1", str(ip), str(port)],
                              timeout=5)
            return result.rc == 0

        def assertion(name, description, ok):
            return {"name": name, "describes": description, "ok": ok}

        internet = tcp(*internet_canary)
        dns = self.adb(["shell", "toybox", "nslookup", public_name], timeout=8)
        dns_resolved = bool(re.search(r"\bAddress(?:\s+\d+)?:\s*[0-9a-fA-F:]+",
                                      dns.out or ""))
        out_scope = tcp(out_of_scope_ip, 443)
        assertions = [
            assertion("android_guest_internet_dropped", "the Android guest cannot reach the internet", not internet),
            assertion("android_guest_public_dns_refused", "the Android guest cannot resolve public DNS", not dns_resolved),
            assertion("android_guest_out_of_scope_dropped", "the Android guest cannot reach an out-of-scope host", not out_scope),
        ]
        if engagement.pinned:
            host, address = next(iter(engagement.pinned.items()))
            resolved = self.adb(["shell", "toybox", "nslookup", host], timeout=8)
            assertions.append(assertion(
                "android_guest_scoped_dns_pinned",
                "the Android guest resolves a scoped host only to its pinned address",
                resolved.rc == 0 and str(address) in (resolved.out or "")))
        allowed = [(str(ip), port) for ip in engagement.pinned.values()
                   for port in scope.ports_for(engagement, ip)]
        if allowed:
            ip, port = allowed[0]
            assertions.append(assertion("android_guest_scoped_api_allowed",
                                        "the Android guest can reach a scoped API", tcp(ip, port)))
        return {"pass": all(item["ok"] for item in assertions), "assertions": assertions}

    def save_baseline(self):
        """Snapshot the emulator once the APK is installed and the guard is final.

        If the emulator cannot snapshot, the baseline is recreate-only: slower for every
        verification, but never a weaker one."""
        saved = self.adb(["emu", "avd", "snapshot", "save", BASELINE_SNAPSHOT], timeout=120)
        self.baseline = {"baseline_id": f"{self.container}:{BASELINE_SNAPSHOT}",
                         "snapshot": saved.rc == 0 and "OK" in (saved.out or "")}
        return self.baseline

    def restore_baseline(self):
        """Return the emulator to the saved baseline and prove it is the tested build.

        Loads the snapshot, falls back to recreating the emulator under the same guard,
        and raises if neither yields the exact installed APK, so the Verifier never
        reproduces on a device the harness cannot vouch for."""
        if not self.baseline:
            raise SandboxError("no Android device baseline was saved; cannot verify")
        started = time.monotonic()
        if self.baseline["snapshot"]:
            loaded = self.adb(["emu", "avd", "snapshot", "load", BASELINE_SNAPSHOT], timeout=120)
            if loaded.rc == 0 and "OK" in (loaded.out or ""):
                self._wait_boot()
                if self._installed_hash_matches():
                    return self._baseline_report("snapshot", started)
        self._recreate()
        if not self._installed_hash_matches():
            raise SandboxError("Android device baseline could not be restored: the installed "
                               "package does not match the APK under test")
        self.save_baseline()
        return self._baseline_report("recreate", started)

    def _baseline_report(self, method, started):
        self.last_baseline = {"baseline_id": self.baseline["baseline_id"], "method": method,
                              "emulator_image": ANDROID_EMULATOR_IMAGE,
                              "restore_ms": int((time.monotonic() - started) * 1000)}
        return self.last_baseline

    def _installed_hash_matches(self):
        located = self.adb(["shell", "pm", "path", self.inventory["package"]], timeout=15)
        path = (located.out or "").strip().removeprefix("package:")
        if located.rc != 0 or not path.startswith("/"):
            return False
        digest = self.adb(["shell", "sha256sum", path], timeout=60)
        fields = (digest.out or "").split()
        return digest.rc == 0 and bool(fields) and fields[0] == self.inventory["sha256"]

    def _recreate(self):
        apk_path, ip, attacker_ip, runtime, dns_server, static_depth = self._launch
        guard = self._guard
        self._run(["docker", "rm", "-f", self.container])
        self.ip = None
        self.start(apk_path, ip, attacker_ip, runtime=runtime, dns_server=dns_server,
                   static_depth=static_depth)
        if guard:
            self.install_guard(guard[0], guard[1], runtime=guard[2],
                               dns_server=guard[3], replace=True)

    def reset_app(self):
        if not self.inventory:
            return False
        result = self.adb(["shell", "pm", "clear", self.inventory["package"]], timeout=30)
        if result.rc != 0 or "success" not in (result.out or "").lower():
            raise SandboxError("could not restore the Android app to its clean baseline")
        return True

    def reset_after_kill(self):
        if not self.active:
            return True
        paused = self._run(["docker", "inspect", "-f", "{{.State.Status}}",
                            self.container]).out.strip() == "paused"
        self._run(["docker", "unpause", self.container])
        self.reset_app()
        return paused

    def clear(self):
        self.ip = None
        self.inventory = None
        self.baseline = None
        self.last_baseline = None
        self._adb_key_path = None
        self._launch = None
        self._guard = None
