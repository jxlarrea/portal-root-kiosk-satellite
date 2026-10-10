#!/usr/bin/env python3
"""Inspect, provision, recover, and verify supported Meta Portal devices."""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import pathlib
import re
import select
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile

from meta_debloat_components import DEBLOAT_COMPONENTS, DEBLOAT_COMPONENT_NAMES
from portal_targets import PortalTarget, find_target


ROOT = pathlib.Path(__file__).resolve().parents[1]
PROJECT_URL = "https://github.com/jxlarrea/portal-root-kiosk-satellite"
PROVISIONER_BANNER = rf"""
+----------------------------------------------------------------+
|                                                                |
|          Meta Portal Provisioner for Kiosk Satellite           |
|                                                                |
|                    Created by Xavier Larrea                    |
|    {PROJECT_URL}     |
|                                                                |
+----------------------------------------------------------------+
""".strip()
HELPER_LOCAL = ROOT / "helper/build/libportal_audio_persist.so"
PRELOAD_REMOTE = "/data/local/tmp/preload-portal.so"
HELPER_REMOTE = "/data/local/tmp/libportal_audio_persist.so"
ACCOUNT_CTL_LOCAL = ROOT / "exploit/build/portal-account-ctl.jar"
ACCOUNT_CTL_REMOTE = "/data/local/tmp/portal-account-ctl.jar"
COMPONENT_CTL_LOCAL = ROOT / "exploit/build/portal-component-ctl.jar"
COMPONENT_CTL_REMOTE = "/data/local/tmp/portal-component-ctl.jar"
PRESENCE_HELPER_PACKAGE = "dev.portal.presencehelper"
PRESENCE_HELPER_LOCAL = ROOT / "presence-helper/build/portal-presence-helper.apk"
EXPLOIT_SENTINEL_PACKAGE = "dev.portal.exploitsentinel"
EXPLOIT_SENTINEL_LOCAL = (
    ROOT / "exploit-sentinel/build/portal-exploit-sentinel.apk"
)
PRESENCE_KEY_REMOTE = "/data/local/tmp/portal-presence-adbkey.pub"
PRESENCE_SAVED_KEY_REMOTE = "/data/local/tmp/portal-presence-adbkey-v1.pub"
SHIZUKU_PACKAGE = "moe.shizuku.privileged.api"
SHIZUKU_HELPER_PACKAGE = "dev.portal.shizukuhelper"
SHIZUKU_HELPER_LOCAL = ROOT / "shizuku-helper/build/portal-shizuku-helper.apk"
SHIZUKU_KEY_REMOTE = "/data/local/tmp/portal-shizuku-adbkey.pub"
SHIZUKU_SAVED_KEY_REMOTE = "/data/local/tmp/portal-shizuku-adbkey-v1.pub"
APP_VERIFIER_BACKUP_REMOTE = "/data/local/tmp/portal-package-verifier-before-v1"
APP_VERIFIER_PACKAGE = "com.facebook.appverifier"
SHIZUKU_VERSION = "13.6.0.r1086.2650830c"
SHIZUKU_APK_NAME = "shizuku-v13.6.0.r1086.2650830c-release.apk"
SHIZUKU_APK_URL = (
    "https://github.com/RikkaApps/Shizuku/releases/download/v13.6.0/"
    + SHIZUKU_APK_NAME
)
SHIZUKU_APK_SHA256 = (
    "6e273ab0e991c4e79bc8b1bbb9b9dd739ccac1a8712a541a214078886b7b790f"
)
STATE_REMOTE = "/data/local/tmp/portal-provision-state-v1.json"
PRIVACY_BACKUP_REMOTE = "/data/local/tmp/portal-private-dns-before-v1.json"
KIOSK_COMPONENT = "me.jxl.kiosk_satellite/.KioskAdminReceiver"
KIOSK_HOME_COMPONENT = "me.jxl.kiosk_satellite/.HomeAlias"
KIOSK_PROVISION_COMPONENT = "me.jxl.kiosk_satellite/.ProvisionActivity"
KIOSK_OWNER_COMPONENTS = (
    "admin=me.jxl.kiosk_satellite/.KioskAdminReceiver",
    "admin=ComponentInfo{me.jxl.kiosk_satellite/"
    "me.jxl.kiosk_satellite.KioskAdminReceiver}",
)
DEBLOAT_BACKUP_REMOTE = "/data/local/tmp/portal-debloat-backup-v1.tsv"
DEBLOAT_COMPONENT_BACKUP_REMOTE = (
    "/data/local/tmp/portal-debloat-components-backup-v1.tsv"
)
DEBLOAT_COMPONENT_ACTIONS_REMOTE = (
    "/data/local/tmp/portal-debloat-components-actions-v1.tsv"
)
PACKAGE_STATE_SETTLE_SECONDS = 15
DEBLOAT_PACKAGES = (
    "com.facebook.aloha.analytics",
    "com.facebook.aloha.app.messenger",
    "com.facebook.aloha.app.whatsapp",
    "com.facebook.aloha.app.portalfeed",
    "com.facebook.alohaapps.superframe",
    "com.facebook.alohaapps.contacts",
)

META_ACCOUNT_BACKUP_REMOTE = "/data/local/tmp/portal-meta-accounts-before-v1.tsv"
META_ACCOUNT_TYPES = (
    "com.facebook.aloha.sso",
    "com.facebook.aloha.pl",
    "com.facebook.aloha.privowner",
)
META_AUTHENTICATOR_COMPONENTS = (
    "com.facebook.aloha.system.alohausers.services.AuthenticationService",
    "com.facebook.aloha.system.alohausers.services2.PLAuthenticatorService",
    "com.facebook.aloha.system.alohausers.services2."
    "PrivOwnerAccountsAuthenticatorService",
)
META_HARDWARE_AUTHENTICATOR = (
    "com.facebook.alohaservices.alohausers/"
    "com.facebook.aloha.system.alohausers.services2.HWAuthenticatorService"
)
SELF_MANAGED_DEBLOAT_COMPONENTS = frozenset(
    {
        "com.facebook.aloha.system.device/"
        "com.facebook.fbns.standalone.service.RegisteredMqttSystemBroadcastReceiver",
        "com.facebook.alohaservices.alohausers/com.facebook.mqttlite.MqttService",
    }
)
PRESENCE_PROFILE_SETTINGS = {
    "enable_cv_background_detector_v2": False,
    "enable_hardware_cropping": False,
    "enable_liveness_metric": False,
    "enable_color_based_reid": False,
    "enable_face_rec_based_reid_v3": False,
}
PRESENCE_PROFILE_KEYS = tuple(PRESENCE_PROFILE_SETTINGS)
PRESENCE_LOG_MARKER = "Notify people presence"
PRESENCE_ANALYSIS_FRAME_MARKER = "Frame available for analysis stream"
PRESENCE_ROI_FRAME_MARKER = "Frame available for roi stream"
PRESENCE_WIDE_FRAME_MARKER = "Disabled hardware cropping"
CAMERA_SERVICE_COMPONENT = (
    "com.facebook.portal.aiservice/"
    "com.facebook.alohaapp.app.services.CameraService"
)
OTA_UI_PACKAGE = "com.facebook.aloha.otaui"
OTA_SETUP_PACKAGE = "com.facebook.aloha.alohaotasetup"
BATTERY_STATE_PACKAGE = "com.facebook.alohasdk.platformbatterystate"
CAMERA_LIGHT_HELPER_LOCAL = (
    ROOT / "uid1000-helper/build/portal-camera-led-watch"
)
CAMERA_LIGHT_HOOK_LOCAL = ROOT / "uid1000-helper/build/portal-uid1000-hook.bin"
CAMERA_LIGHT_HELPER_REMOTE = "/data/local/tmp/portal-camera-led-watch"
CAMERA_LIGHT_HOOK_REMOTE = "/data/local/tmp/portal-uid1000-hook.bin"
CAMERA_LIGHT_INSTALLED_REMOTE = (
    "/data/local/tmp/portal-camera-light-backup/installed-v1"
)
CAMERA_LIGHT_RESTORED_REMOTE = (
    "/data/local/tmp/portal-camera-light-backup/restored-v1"
)
CAMERA_LIGHT_HELPER_INSTALLED = "/data/portal-uid1000/portal-camera-led-watch"
CAMERA_LIGHT_CONFIG_REMOTE = "/data/portal-uid1000/camera-led-enabled"
PRESENCE_UID1000_CONFIG_REMOTE = "/data/portal-uid1000/presence-fps"
UID1000_HOOK_ACTIVE_REMOTE = (
    "/data/local/tmp/portal-uid1000-hook-active-v1"
)


class ProvisionError(RuntimeError):
    pass


def print_banner() -> None:
    print(PROVISIONER_BANNER, file=sys.stderr, flush=True)


class PortalProvisioner:
    def __init__(
        self,
        serial: str,
        attempts: int,
        log_dir: pathlib.Path,
        audio: bool = False,
        restore_audio: bool = False,
        device_owner: bool = False,
        kiosk_home: bool = False,
        restore_kiosk_home: bool = False,
        disable_updates: bool = False,
        enable_updates: bool = False,
        debloat: bool = False,
        restore_bloat: bool = False,
        remove_meta_accounts: bool = False,
        optimize_presence: bool = False,
        restore_presence_profile: bool = False,
        presence_fps_cap: int | None = None,
        restore_presence_fps: bool = False,
        privacy_dns: str | None = None,
        dhcp_dns: bool = False,
        restore_privacy_dns: bool = False,
        allow_app_updates: bool = False,
        restore_app_verifier: bool = False,
        shizuku: bool = False,
        remove_shizuku: bool = False,
        disable_camera_light: bool = False,
        restore_camera_light: bool = False,
        shizuku_apk: pathlib.Path | None = None,
        status_only: bool = False,
        dry_run: bool = False,
        backup_path: pathlib.Path | None = None,
        recover: bool = False,
        skip_build: bool = False,
    ):
        self.serial = serial
        self.attempts = attempts
        self.log_dir = log_dir
        self.audio = audio
        self.audio_already_configured = False
        self.restore_audio = restore_audio
        self.device_owner = device_owner
        self.kiosk_home = kiosk_home
        self.restore_kiosk_home = restore_kiosk_home
        self.disable_updates = disable_updates
        self.enable_updates = enable_updates
        self.debloat = debloat
        self.restore_bloat = restore_bloat
        self.remove_meta_accounts = remove_meta_accounts
        self.optimize_presence = optimize_presence
        self.restore_presence_profile = restore_presence_profile
        self.presence_fps_cap = presence_fps_cap
        self.restore_presence_fps = restore_presence_fps
        self.privacy_dns = privacy_dns
        self.dhcp_dns = dhcp_dns
        self.restore_privacy_dns = restore_privacy_dns
        self.allow_app_updates = allow_app_updates
        self.restore_app_verifier = restore_app_verifier
        self.shizuku = shizuku
        self.remove_shizuku = remove_shizuku
        self.disable_camera_light = disable_camera_light
        self.restore_camera_light = restore_camera_light
        self.shizuku_apk = shizuku_apk
        self.shizuku_public_key: pathlib.Path | None = None
        self.presence_public_key: pathlib.Path | None = None
        self.package_verifier_initially_disabled: bool | None = None
        self.status_only = status_only
        self.dry_run = dry_run
        self.backup_path = backup_path
        self.recover = recover
        self.skip_build = skip_build
        self.adb = ["adb", "-s", serial]
        self.target: PortalTarget | None = None
        self.persist_wireless_adb = False

    @staticmethod
    def run(
        args: list[str], timeout: float | None = None, check: bool = False
    ) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(
                args,
                text=True,
                encoding="utf-8",
                errors="replace",
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ProvisionError(f"command timed out: {shlex.join(args)}") from exc
        if check and result.returncode != 0:
            raise ProvisionError(
                f"command failed ({result.returncode}): {shlex.join(args)}\n"
                f"{result.stdout[-2000:]}"
            )
        return result

    def adb_run(
        self, args: list[str], timeout: float | None = None, check: bool = False
    ) -> subprocess.CompletedProcess[str]:
        return self.run(self.adb + args, timeout=timeout, check=check)

    def connect(self, wait_seconds: int = 150) -> None:
        try:
            self.run(["adb", "disconnect", self.serial], timeout=5)
        except ProvisionError:
            pass
        deadline = time.monotonic() + wait_seconds
        while time.monotonic() < deadline:
            try:
                self.run(["adb", "connect", self.serial], timeout=5)
                state = self.adb_run(["get-state"], timeout=5)
                completed = self.adb_run(
                    ["shell", "getprop", "sys.boot_completed"], timeout=5
                )
                if state.returncode == 0 and completed.stdout.strip() == "1":
                    return
            except ProvisionError:
                pass
            time.sleep(3)
        raise ProvisionError(f"{self.serial} did not reconnect after {wait_seconds}s")

    def reboot(self) -> tuple[str, str]:
        before = self.adb_run(
            ["shell", "cat", "/proc/sys/kernel/random/boot_id"],
            timeout=5,
            check=True,
        ).stdout.strip()
        try:
            self.adb_run(["reboot"], timeout=8)
        except ProvisionError:
            # adbd can disappear before acknowledging a successful reboot.
            pass
        after = self.connect_after_reboot(before)
        return before, after

    def connect_after_reboot(self, before: str, wait_seconds: int = 180) -> str:
        try:
            self.run(["adb", "disconnect", self.serial], timeout=5)
        except ProvisionError:
            pass
        deadline = time.monotonic() + wait_seconds
        last_boot_id = ""
        while time.monotonic() < deadline:
            try:
                self.run(["adb", "connect", self.serial], timeout=5)
                state = self.adb_run(["get-state"], timeout=5)
                completed = self.adb_run(
                    ["shell", "getprop", "sys.boot_completed"], timeout=5
                )
                boot = self.adb_run(
                    ["shell", "cat", "/proc/sys/kernel/random/boot_id"], timeout=5
                )
                last_boot_id = boot.stdout.strip()
                if (
                    state.returncode == 0
                    and completed.stdout.strip() == "1"
                    and last_boot_id
                    and last_boot_id != before
                ):
                    return last_boot_id
            except ProvisionError:
                pass
            time.sleep(3)
        raise ProvisionError(
            f"{self.serial} did not complete a new boot after {before}; "
            f"last boot ID was {last_boot_id!r}"
        )

    def verify_target(self, require_supported: bool = True) -> PortalTarget | None:
        fingerprint = self.adb_run(
            ["shell", "getprop", "ro.build.fingerprint"], timeout=5, check=True
        ).stdout.strip()
        device = self.adb_run(
            ["shell", "getprop", "ro.product.device"], timeout=5, check=True
        ).stdout.strip()
        target = find_target(device, fingerprint)
        self.target = target
        if target is None and require_supported:
            raise ProvisionError(
                "unsupported firmware; refusing build-specific kernel writes\n"
                f"device: {device}\nfingerprint: {fingerprint}"
            )
        if target is None:
            print(
                f"TARGET_UNSUPPORTED serial={self.serial} device={device} "
                f"fingerprint={fingerprint}"
            )
        else:
            print(
                f"TARGET_OK serial={self.serial} target={target.key} "
                f"device={device} fingerprint={fingerprint}"
            )
        return target

    def stage(self) -> None:
        if self.target is None:
            raise ProvisionError("target must be selected before staging")
        files = [(self.target.preload_path(ROOT), PRELOAD_REMOTE)]
        if self.audio and not self.audio_already_configured:
            files.append((HELPER_LOCAL, HELPER_REMOTE))
        if self.remove_meta_accounts:
            files.append((ACCOUNT_CTL_LOCAL, ACCOUNT_CTL_REMOTE))
        if (
            self.debloat
            or self.restore_bloat
            or self.presence_fps_cap is not None
            or self.restore_presence_fps
            or self.restore_presence_profile
        ):
            files.append((COMPONENT_CTL_LOCAL, COMPONENT_CTL_REMOTE))
        if self.shizuku:
            if self.shizuku_public_key is None:
                raise ProvisionError("Shizuku helper key was not prepared")
            files.append((self.shizuku_public_key, SHIZUKU_KEY_REMOTE))
        if self.disable_camera_light or self.presence_fps_cap is not None:
            files.extend(
                (
                    (CAMERA_LIGHT_HELPER_LOCAL, CAMERA_LIGHT_HELPER_REMOTE),
                    (CAMERA_LIGHT_HOOK_LOCAL, CAMERA_LIGHT_HOOK_REMOTE),
                )
            )
        for local, remote in files:
            if not local.is_file() or local.stat().st_size == 0:
                raise ProvisionError(f"missing build output: {local}")
            self.adb_run(["push", str(local), remote], timeout=30, check=True)
            mode = (
                "0644"
                if remote == SHIZUKU_KEY_REMOTE
                else "0755"
            )
            self.adb_run(["shell", "chmod", mode, remote], timeout=5, check=True)
        staged = f"preload={PRELOAD_REMOTE}"
        if self.audio and not self.audio_already_configured:
            staged += f" helper={HELPER_REMOTE}"
        if self.remove_meta_accounts:
            staged += f" account_ctl={ACCOUNT_CTL_REMOTE}"
        if COMPONENT_CTL_REMOTE in {remote for _, remote in files}:
            staged += f" component_ctl={COMPONENT_CTL_REMOTE}"
        if self.shizuku:
            staged += f" shizuku_key={SHIZUKU_KEY_REMOTE}"
        if self.disable_camera_light or self.presence_fps_cap is not None:
            staged += (
                f" uid1000_helper={CAMERA_LIGHT_HELPER_REMOTE}"
                f" uid1000_hook={CAMERA_LIGHT_HOOK_REMOTE}"
            )
        print(f"STAGED {staged}")

    def requested_actions(self) -> dict[str, object]:
        actions: dict[str, object] = {}
        for name in (
            "audio",
            "restore_audio",
            "device_owner",
            "kiosk_home",
            "restore_kiosk_home",
            "disable_updates",
            "enable_updates",
            "debloat",
            "restore_bloat",
            "remove_meta_accounts",
            "optimize_presence",
            "restore_presence_profile",
            "restore_presence_fps",
            "dhcp_dns",
            "restore_privacy_dns",
            "allow_app_updates",
            "restore_app_verifier",
            "shizuku",
            "remove_shizuku",
            "disable_camera_light",
            "restore_camera_light",
        ):
            if getattr(self, name):
                actions[name] = True
        if self.privacy_dns:
            actions["privacy_dns"] = self.privacy_dns
        if self.presence_fps_cap is not None:
            actions["presence_fps_cap"] = self.presence_fps_cap
        return actions

    def tool_revision(self) -> str:
        result = self.run(
            ["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"], timeout=5
        )
        if result.returncode != 0:
            return "unknown"
        revision = result.stdout.strip()
        dirty = self.run(
            ["git", "-C", str(ROOT), "status", "--porcelain"], timeout=5
        )
        if dirty.returncode == 0 and dirty.stdout.strip():
            revision += "-dirty"
        return revision

    def selected_artifact_hashes(self) -> dict[str, str]:
        candidates = [pathlib.Path(__file__).resolve(), ROOT / "tools/portal_targets.py"]
        if self.target:
            candidates.append(self.target.preload_path(ROOT))
        if self.privileged_requested():
            candidates.append(EXPLOIT_SENTINEL_LOCAL)
        if self.audio:
            candidates.append(HELPER_LOCAL)
        if self.remove_meta_accounts:
            candidates.append(ACCOUNT_CTL_LOCAL)
        if self.shizuku:
            candidates.append(SHIZUKU_HELPER_LOCAL)
            if self.shizuku_apk:
                candidates.append(self.shizuku_apk)
        if self.disable_camera_light or self.presence_fps_cap is not None:
            candidates.extend((CAMERA_LIGHT_HELPER_LOCAL, CAMERA_LIGHT_HOOK_LOCAL))
        hashes: dict[str, str] = {}
        for path in candidates:
            if path.is_file():
                try:
                    name = str(path.relative_to(ROOT))
                except ValueError:
                    name = str(path)
                hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        return hashes

    def read_state(self) -> dict[str, object] | None:
        result = self.adb_run(["shell", "cat", STATE_REMOTE], timeout=5)
        if result.returncode != 0:
            return None
        try:
            state = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ProvisionError(f"invalid device state manifest: {exc}") from exc
        if not isinstance(state, dict) or state.get("schema") != 1:
            raise ProvisionError("unrecognized device state manifest")
        return state

    def write_state(
        self,
        state_status: str,
        first_boot: str | None = None,
        second_boot: str | None = None,
    ) -> None:
        fingerprint = self.adb_run(
            ["shell", "getprop", "ro.build.fingerprint"], timeout=5, check=True
        ).stdout.strip()
        state = {
            "schema": 1,
            "status": state_status,
            "updated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "serial": self.serial,
            "target": self.target.key if self.target else None,
            "fingerprint": fingerprint,
            "tool_revision": self.tool_revision(),
            "artifact_sha256": self.selected_artifact_hashes(),
            "actions": self.requested_actions(),
            "verification": {
                "first_boot": first_boot,
                "second_boot": second_boot,
            },
        }
        self.log_dir.mkdir(parents=True, exist_ok=True)
        local = self.log_dir / "portal-provision-state-v1.json"
        local.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
        local.chmod(0o600)
        remote_tmp = STATE_REMOTE + ".tmp"
        self.adb_run(["push", str(local), remote_tmp], timeout=15, check=True)
        self.adb_run(
            [
                "shell",
                f"chmod 0600 {shlex.quote(remote_tmp)} && "
                f"mv {shlex.quote(remote_tmp)} {shlex.quote(STATE_REMOTE)}",
            ],
            timeout=10,
            check=True,
        )
        print(f"STATE_MANIFEST status={state_status} path={STATE_REMOTE}")

    def collect_status(self) -> dict[str, object]:
        def shell(*arguments: str, timeout: int = 15) -> str:
            return self.adb_run(
                ["shell", *arguments], timeout=timeout
            ).stdout.strip()

        def exists(path: str) -> bool:
            return self.adb_run(
                ["shell", "test", "-f", path], timeout=5
            ).returncode == 0

        fingerprint = shell("getprop", "ro.build.fingerprint", timeout=5)
        device = shell("getprop", "ro.product.device", timeout=5)
        target = find_target(device, fingerprint)
        disabled_output = shell("pm", "list", "packages", "-d")
        disabled = {
            line.removeprefix("package:").strip()
            for line in disabled_output.splitlines()
            if line.startswith("package:")
        }
        installed_output = shell("pm", "list", "packages")
        installed = {
            line.removeprefix("package:").strip()
            for line in installed_output.splitlines()
            if line.startswith("package:")
        }
        policy = shell("dumpsys", "device_policy")
        owner = "Device Owner:" in policy and any(
            marker in policy for marker in KIOSK_OWNER_COMPONENTS
        )
        kiosk_dump = shell("dumpsys", "package", "me.jxl.kiosk_satellite")
        default_home = self.current_default_home()
        version_name = re.search(r"\bversionName=([^\s]+)", kiosk_dump)
        version_code = re.search(r"\bversionCode=(\d+)", kiosk_dump)
        logs = shell("logcat", "-d", "-v", "brief", timeout=20)
        connectivity = shell("dumpsys", "connectivity", timeout=20)
        audio_logs = shell("logcat", "-d", "-s", "PortalAudioPersist:*", timeout=10)
        camera = shell("dumpsys", "media.camera", timeout=20)
        webview = shell("dumpsys", "webviewupdate", timeout=15)
        accounts = self.meta_accounts()
        authenticators = self.disabled_meta_authenticators()
        ota_dump = shell("dumpsys", "facebook.aloha.otaservice", timeout=15)
        private_dns_mode = shell("settings", "get", "global", "private_dns_mode")
        private_dns_host = shell(
            "settings", "get", "global", "private_dns_specifier"
        )
        active_dns: list[str] = []
        validated_private_dns: list[str] = []
        search_domains: str | None = None
        for line in connectivity.splitlines():
            if (
                "NetworkAgentInfo{" not in line
                or "state: CONNECTED/CONNECTED" not in line
                or "DnsAddresses: [" not in line
            ):
                continue
            match = re.search(r"DnsAddresses: \[\s*([^]]*?)\s*\]", line)
            if match:
                active_dns = [
                    address.strip().lstrip("/")
                    for address in match.group(1).split(",")
                    if address.strip()
                ]
            match = re.search(
                r"ValidatedPrivateDnsAddresses: \[\s*([^]]*?)\s*\]", line
            )
            if match:
                validated_private_dns = [
                    address.strip().lstrip("/")
                    for address in match.group(1).split(",")
                    if address.strip()
                ]
            match = re.search(r"Domains: (\S+)", line)
            if match and match.group(1) != "null":
                search_domains = match.group(1)
            break
        fallback_dns_match = re.search(
            r"defaultIPv4DNS:\s*\[([^]]*)\]", connectivity
        )
        fallback_dns = (
            [
                address.strip().lstrip("/")
                for address in fallback_dns_match.group(1).split(",")
                if address.strip()
            ]
            if fallback_dns_match
            else []
        )
        manifest: object
        try:
            manifest = self.read_state()
        except ProvisionError as exc:
            manifest = {"error": str(exc)}
        profile_keys = sorted(
            key
            for key, expected in PRESENCE_PROFILE_SETTINGS.items()
            if any(
                "settings_config.xml" in line
                and key in line
                and re.search(
                    rf"\b{str(expected).lower()}\b", line, re.IGNORECASE
                )
                for line in logs.splitlines()
            )
        )
        audio_installed = exists(
            "/data/local/tmp/portal-audio-backup/installed-v1"
        )
        audio_restored = exists(
            "/data/local/tmp/portal-audio-backup/restored-v1"
        )
        ota_installed = exists("/data/local/tmp/portal-ota-backup/installed-v1")
        ota_restored = exists("/data/local/tmp/portal-ota-backup/restored-v1")
        presence_installed = exists(
            "/data/local/tmp/portal-presence-backup/installed-v1"
        )
        presence_restored = exists(
            "/data/local/tmp/portal-presence-backup/restored-v1"
        )
        presence_fps_installed = exists(
            "/data/local/tmp/portal-presence-backup/fps-cap-v1"
        )
        presence_fps_restored = exists(
            "/data/local/tmp/portal-presence-backup/fps-restored-v1"
        )
        presence_fps_value = shell(
            "cat", "/data/local/tmp/portal-presence-backup/fps-cap-v1", timeout=5
        )
        applied_fps_match = re.search(
            r"Setting AI Processing FPS\s+([0-9]+(?:\.[0-9]+)?)", logs
        )
        component_backup = self.read_component_backup(required=False)
        component_states = (
            self.current_component_states() if component_backup is not None else {}
        )
        component_disabled = sum(
            1 for _, state in component_states.values() if state == "disabled"
        )
        presence_helper_dump = shell("dumpsys", "package", PRESENCE_HELPER_PACKAGE)
        presence_uid1000_configured = exists(PRESENCE_UID1000_CONFIG_REMOTE)
        presence_uid1000_fps = shell(
            "cat", PRESENCE_UID1000_CONFIG_REMOTE, timeout=5
        )
        shizuku_dump = shell("dumpsys", "package", SHIZUKU_PACKAGE)
        shizuku_version = re.search(r"\bversionName=([^\s]+)", shizuku_dump)
        package_verifier_setting = shell(
            "settings", "get", "global", "package_verifier_enable", timeout=5
        )
        process_list = shell("ps", "-A", "-o", "USER,PID,PPID,NAME,ARGS")
        shizuku_process = next(
            (line for line in process_list.splitlines() if "shizuku_server" in line),
            "",
        )
        camera_light_process = next(
            (
                line
                for line in process_list.splitlines()
                if "portal-camera-led-watch" in line
                or "portal-led-watc" in line
            ),
            "",
        )
        camera_light_host_process = next(
            (
                line
                for line in process_list.splitlines()
                if BATTERY_STATE_PACKAGE in line
            ),
            "",
        )
        camera_light_installed = exists(CAMERA_LIGHT_INSTALLED_REMOTE)
        return {
            "schema": 1,
            "serial": self.serial,
            "target": {
                "supported": target is not None,
                "key": target.key if target else None,
                "device": device,
                "fingerprint": fingerprint,
            },
            "runtime": {
                "boot_id": shell("cat", "/proc/sys/kernel/random/boot_id", timeout=5),
                "selinux": shell("getenforce", timeout=5),
                "wireless_adb_port": shell("getprop", "persist.adb.tcp.port", timeout=5),
                "aiservice_pid": shell(
                    "pidof", "com.facebook.portal.aiservice", timeout=5
                ),
                "cameras": 2 if "Number of camera devices: 2" in camera else None,
                "webview_ready": "(com.facebook.portal.webview," in webview,
            },
            "kiosk_satellite": {
                "installed": "me.jxl.kiosk_satellite" in installed,
                "version_name": version_name.group(1) if version_name else None,
                "version_code": int(version_code.group(1)) if version_code else None,
                "admin_active": f"    {KIOSK_COMPONENT}:" in policy,
                "device_owner": owner,
                "default_home": default_home or None,
                "home_screen": default_home == KIOSK_HOME_COMPONENT,
            },
            "audio": {
                "state": (
                    "installed"
                    if audio_installed
                    else "restored"
                    if audio_restored
                    else "observed_this_boot"
                    if "persistent audio watchdog started" in audio_logs
                    else "unknown"
                ),
                "installed_marker": audio_installed,
                "watchdog_observed": "persistent audio watchdog started" in audio_logs,
                "processing_zero_observed": (
                    "audio processing verified aec=0 ns=0" in audio_logs
                ),
                "restored_marker": audio_restored,
            },
            "updates": {
                "state": (
                    "blocked"
                    if ota_installed
                    or (
                        all(
                            package in disabled
                            for package in (OTA_UI_PACKAGE, OTA_SETUP_PACKAGE)
                        )
                        and "getBool(kFirmwareOtaUpdateEnable): false" in ota_dump
                    )
                    else "restored"
                    if ota_restored
                    else "unknown"
                ),
                "installed_marker": ota_installed,
                "packages_disabled": all(
                    package in disabled
                    for package in (OTA_UI_PACKAGE, OTA_SETUP_PACKAGE)
                ),
                "firmware_gate_false": (
                    "getBool(kFirmwareOtaUpdateEnable): false" in ota_dump
                ),
                "restored_marker": ota_restored,
            },
            "debloat": {
                "disabled": sorted(set(DEBLOAT_PACKAGES) & disabled),
                "components_disabled": component_disabled,
                "components_targeted": len(DEBLOAT_COMPONENT_NAMES),
                "components_retained_self_managed": sorted(
                    SELF_MANAGED_DEBLOAT_COMPONENTS
                ),
                "component_backup_present": component_backup is not None,
                "package_profile_complete": all(
                    package not in installed or package in disabled
                    for package in DEBLOAT_PACKAGES
                ),
                "component_profile_complete": component_backup is not None
                and all(
                    original == "absent"
                    or component in SELF_MANAGED_DEBLOAT_COMPONENTS
                    or component_states[component][1] == "disabled"
                    for component, (_, original) in component_backup.items()
                ),
                "complete": all(
                    package not in installed or package in disabled
                    for package in DEBLOAT_PACKAGES
                )
                and component_backup is not None
                and all(
                    original == "absent"
                    or component in SELF_MANAGED_DEBLOAT_COMPONENTS
                    or component_states[component][1] == "disabled"
                    for component, (_, original) in component_backup.items()
                ),
            },
            "meta_accounts": {
                "remaining": len(accounts),
                "authenticators_disabled": len(
                    set(META_AUTHENTICATOR_COMPONENTS) & authenticators
                ),
            },
            "presence": {
                "state": (
                    "optimized"
                    if presence_installed or len(profile_keys) == len(PRESENCE_PROFILE_KEYS)
                    else "restored"
                    if presence_restored
                    else "unknown"
                ),
                "installed_marker": presence_installed,
                "restored_marker": presence_restored,
                "analysis_fps_cap_installed": presence_fps_installed,
                "analysis_fps_cap_restored": presence_fps_restored,
                "analysis_fps_cap": (
                    int(presence_fps_value)
                    if presence_fps_value.isdigit()
                    else None
                ),
                "analysis_fps_applied_this_boot": (
                    float(applied_fps_match.group(1))
                    if applied_fps_match
                    else None
                ),
                "analysis_fps_helper_installed": (
                    presence_uid1000_configured
                    or f"Package [{PRESENCE_HELPER_PACKAGE}]" in presence_helper_dump
                ),
                "analysis_fps_helper_key_authorized": exists(
                    PRESENCE_SAVED_KEY_REMOTE
                ),
                "analysis_fps_activation_host": (
                    "uid1000"
                    if presence_uid1000_configured
                    else "loopback_adb"
                    if f"Package [{PRESENCE_HELPER_PACKAGE}]" in presence_helper_dump
                    else None
                ),
                "analysis_fps_uid1000_configured": presence_uid1000_configured,
                "analysis_fps_uid1000_value": (
                    int(presence_uid1000_fps)
                    if presence_uid1000_fps.isdigit()
                    else None
                ),
                "analysis_fps_legacy_helper_installed": (
                    f"Package [{PRESENCE_HELPER_PACKAGE}]" in presence_helper_dump
                ),
                "analysis_fps_legacy_key_authorized": exists(
                    PRESENCE_SAVED_KEY_REMOTE
                ),
                "profile_keys_loaded": profile_keys,
                "full_scene_profile": (
                    PRESENCE_WIDE_FRAME_MARKER in logs
                    and "com.facebook.alohasdk.dewarp_crop_rect.width"
                    not in camera.split("Tag monitoring disabled", 1)[0]
                ),
                "analysis_frames_observed": PRESENCE_ANALYSIS_FRAME_MARKER in logs,
                "roi_frames_observed": PRESENCE_ROI_FRAME_MARKER in logs,
                "presence_event_observed": PRESENCE_LOG_MARKER in logs,
            },
            "privacy_dns": {
                "mode": None if private_dns_mode == "null" else private_dns_mode,
                "hostname": None if private_dns_host == "null" else private_dns_host,
                "strategy": (
                    "strict"
                    if private_dns_mode == "hostname"
                    else "network"
                    if private_dns_mode == "off"
                    else "automatic"
                ),
                "active_servers": active_dns,
                "validated_private_servers": validated_private_dns,
                "search_domains": search_domains,
                "fallback_ipv4_servers": fallback_dns,
                "backup_present": self.adb_run(
                    ["shell", "test", "-f", PRIVACY_BACKUP_REMOTE], timeout=5
                ).returncode
                == 0,
            },
            "app_updates": {
                "meta_verifier_package_enabled": (
                    APP_VERIFIER_PACKAGE in installed
                    and APP_VERIFIER_PACKAGE not in disabled
                ),
                "package_verifier_setting": (
                    None
                    if package_verifier_setting == "null"
                    else package_verifier_setting
                ),
                "third_party_updates_allowed": (
                    package_verifier_setting == "0"
                    or APP_VERIFIER_PACKAGE in disabled
                ),
                "backup_present": exists(APP_VERIFIER_BACKUP_REMOTE),
            },
            "shizuku": {
                "installed": SHIZUKU_PACKAGE in installed,
                "version_name": (
                    shizuku_version.group(1) if shizuku_version else None
                ),
                "boot_helper_installed": SHIZUKU_HELPER_PACKAGE in installed,
                "key_authorized_by_provisioner": exists(SHIZUKU_SAVED_KEY_REMOTE),
                "server_running": bool(shizuku_process),
                "server_user": (
                    shizuku_process.split()[0] if shizuku_process else None
                ),
            },
            "camera_light": {
                "state": (
                    "installed"
                    if camera_light_installed
                    else "restored"
                    if exists(CAMERA_LIGHT_RESTORED_REMOTE)
                    else "unknown"
                ),
                "installed_marker": exists(CAMERA_LIGHT_INSTALLED_REMOTE),
                "restored_marker": exists(CAMERA_LIGHT_RESTORED_REMOTE),
                "feature_config_present": exists(CAMERA_LIGHT_CONFIG_REMOTE),
                "helper_present": exists(CAMERA_LIGHT_HELPER_INSTALLED),
                "watchdog_running": bool(camera_light_process),
                "watchdog_user": (
                    camera_light_process.split()[0]
                    if camera_light_process
                    else None
                ),
                "persistent_host_running": bool(camera_light_host_process),
                "persistent_host_package": BATTERY_STATE_PACKAGE,
                "connected_this_boot": (
                    "watchdog connected uid=1000" in logs
                ),
            },
            "provision_manifest": manifest,
        }

    def print_status(self) -> dict[str, object]:
        status = self.collect_status()
        rendered = json.dumps(status, indent=2, sort_keys=True)
        print(rendered)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        (self.log_dir / "status.json").write_text(rendered + "\n")
        return status

    def privileged_requested(self) -> bool:
        return any(
            (
                self.audio,
                self.restore_audio,
                self.device_owner,
                self.disable_updates,
                self.enable_updates,
                self.debloat,
                self.restore_bloat,
                self.remove_meta_accounts,
                self.optimize_presence,
                self.restore_presence_profile,
                self.presence_fps_cap is not None,
                self.restore_presence_fps,
                self.shizuku,
                self.remove_shizuku,
                self.disable_camera_light,
                self.restore_camera_light,
            )
        )

    def dry_run_report(self, status: dict[str, object]) -> None:
        actions = self.requested_actions()
        kiosk = status.get("kiosk_satellite", {})
        audio = status.get("audio", {})
        updates = status.get("updates", {})
        debloat = status.get("debloat", {})
        accounts = status.get("meta_accounts", {})
        presence = status.get("presence", {})
        privacy = status.get("privacy_dns", {})
        app_updates = status.get("app_updates", {})
        shizuku = status.get("shizuku", {})
        camera_light = status.get("camera_light", {})
        current = {
            "audio": audio.get("state") if isinstance(audio, dict) else None,
            "device_owner": (
                kiosk.get("device_owner") if isinstance(kiosk, dict) else None
            ),
            "kiosk_home": (
                kiosk.get("home_screen") if isinstance(kiosk, dict) else None
            ),
            "updates": updates.get("state") if isinstance(updates, dict) else None,
            "debloat": debloat.get("complete") if isinstance(debloat, dict) else None,
            "meta_accounts_remaining": (
                accounts.get("remaining") if isinstance(accounts, dict) else None
            ),
            "presence": presence.get("state") if isinstance(presence, dict) else None,
            "privacy_dns": privacy if isinstance(privacy, dict) else None,
            "app_updates": app_updates if isinstance(app_updates, dict) else None,
            "shizuku": shizuku if isinstance(shizuku, dict) else None,
            "camera_light": (
                camera_light if isinstance(camera_light, dict) else None
            ),
        }
        required_outputs = []
        if self.target:
            required_outputs.append(str(self.target.preload_path(ROOT)))
        if self.privileged_requested():
            required_outputs.append(str(EXPLOIT_SENTINEL_LOCAL))
        if self.audio:
            required_outputs.append(str(HELPER_LOCAL))
        if self.remove_meta_accounts:
            required_outputs.append(str(ACCOUNT_CTL_LOCAL))
        if (
            self.debloat
            or self.restore_bloat
            or self.presence_fps_cap is not None
            or self.restore_presence_fps
            or self.restore_presence_profile
        ):
            required_outputs.append(str(COMPONENT_CTL_LOCAL))
        if self.shizuku:
            required_outputs.append(str(SHIZUKU_HELPER_LOCAL))
        if self.disable_camera_light or self.presence_fps_cap is not None:
            required_outputs.extend(
                (str(CAMERA_LIGHT_HELPER_LOCAL), str(CAMERA_LIGHT_HOOK_LOCAL))
            )
        report = {
            "actions": actions,
            "current": current,
            "requires_exploit": self.privileged_requested(),
            "minimum_reboots": 3 if self.privileged_requested() else 2,
            "host_tools": {
                name: shutil.which(name) is not None
                for name in ("adb", "git", "make", "python3")
            },
            "build_outputs": {
                path: pathlib.Path(path).is_file() for path in required_outputs
            },
            "will_modify_device": False,
        }
        print("DRY_RUN " + json.dumps(report, sort_keys=True))

    def create_backup_bundle(self, destination: pathlib.Path) -> pathlib.Path:
        if destination.suffixes[-2:] != [".tar", ".gz"]:
            destination.mkdir(parents=True, exist_ok=True)
            destination = destination / (
                "portal-backup-" + dt.datetime.now().strftime("%Y%m%d-%H%M%S") + ".tar.gz"
            )
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="portal-backup-") as temporary:
            root = pathlib.Path(temporary) / "portal-backup"
            root.mkdir()
            status = self.collect_status()
            (root / "status.json").write_text(
                json.dumps(status, indent=2, sort_keys=True) + "\n"
            )
            commands = {
                "getprop.txt": ["shell", "getprop"],
                "packages.txt": ["shell", "dumpsys", "package", "packages"],
                "device-policy.txt": ["shell", "dumpsys", "device_policy"],
                "accounts.txt": ["shell", "dumpsys", "account"],
                "ota.txt": ["shell", "dumpsys", "facebook.aloha.otaservice"],
                "webview.txt": ["shell", "dumpsys", "webviewupdate"],
            }
            for filename, arguments in commands.items():
                result = self.adb_run(arguments, timeout=30)
                (root / filename).write_text(result.stdout, errors="replace")
            device_files = root / "device-files"
            device_files.mkdir()
            for remote in (
                STATE_REMOTE,
                DEBLOAT_BACKUP_REMOTE,
                DEBLOAT_COMPONENT_BACKUP_REMOTE,
                META_ACCOUNT_BACKUP_REMOTE,
                PRIVACY_BACKUP_REMOTE,
                APP_VERIFIER_BACKUP_REMOTE,
                "/data/local/tmp/portal-ota-backup",
                "/data/local/tmp/portal-presence-backup",
                "/data/local/tmp/portal-device-owner-backup",
                "/data/local/tmp/portal-audio-backup",
                "/data/local/tmp/portal-audio-snapshot",
            ):
                self.adb_run(
                    ["pull", remote, str(device_files)], timeout=30
                )
            manifest = {
                "schema": 1,
                "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "serial": self.serial,
                "tool_revision": self.tool_revision(),
                "sha256": {},
            }
            hashes = manifest["sha256"]
            assert isinstance(hashes, dict)
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    hashes[str(path.relative_to(root))] = hashlib.sha256(
                        path.read_bytes()
                    ).hexdigest()
            (root / "manifest.json").write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n"
            )
            with tarfile.open(destination, "w:gz") as archive:
                archive.add(root, arcname="portal-backup")
        destination.chmod(0o600)
        print(f"BACKUP_OK path={destination}")
        return destination

    def backup_private_dns(self) -> None:
        existing = self.adb_run(["shell", "cat", PRIVACY_BACKUP_REMOTE], timeout=5)
        if existing.returncode != 0:
            backup = {
                "schema": 1,
                "mode": self.adb_run(
                    ["shell", "settings", "get", "global", "private_dns_mode"],
                    timeout=5,
                    check=True,
                ).stdout.strip(),
                "hostname": self.adb_run(
                    [
                        "shell",
                        "settings",
                        "get",
                        "global",
                        "private_dns_specifier",
                    ],
                    timeout=5,
                    check=True,
                ).stdout.strip(),
            }
            with tempfile.TemporaryDirectory(prefix="portal-private-dns-") as temp:
                local = pathlib.Path(temp) / "private-dns.json"
                local.write_text(json.dumps(backup, indent=2) + "\n")
                self.adb_run(
                    ["push", str(local), PRIVACY_BACKUP_REMOTE],
                    timeout=15,
                    check=True,
                )
            self.adb_run(
                ["shell", "chmod", "0600", PRIVACY_BACKUP_REMOTE],
                timeout=5,
                check=True,
            )

    def apply_privacy_dns(self) -> None:
        if not self.privacy_dns:
            return
        hostname = self.privacy_dns.strip().lower()
        if not re.fullmatch(
            r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
            hostname,
        ):
            raise ProvisionError(f"invalid Private DNS hostname: {self.privacy_dns!r}")
        self.backup_private_dns()
        self.adb_run(
            ["shell", "settings", "put", "global", "private_dns_mode", "hostname"],
            timeout=10,
            check=True,
        )
        self.adb_run(
            [
                "shell",
                "settings",
                "put",
                "global",
                "private_dns_specifier",
                hostname,
            ],
            timeout=10,
            check=True,
        )
        self.privacy_dns = hostname
        self.verify_privacy_dns()

    def apply_dhcp_dns(self) -> None:
        self.backup_private_dns()
        self.adb_run(
            ["shell", "settings", "put", "global", "private_dns_mode", "off"],
            timeout=10,
            check=True,
        )
        self.adb_run(
            ["shell", "settings", "delete", "global", "private_dns_specifier"],
            timeout=10,
            check=True,
        )
        self.verify_privacy_dns()

    def restore_private_dns(self) -> None:
        result = self.adb_run(
            ["shell", "cat", PRIVACY_BACKUP_REMOTE], timeout=5, check=True
        )
        try:
            backup = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ProvisionError(f"invalid Private DNS backup: {exc}") from exc
        if not isinstance(backup, dict) or backup.get("schema") != 1:
            raise ProvisionError("unrecognized Private DNS backup")
        for key, setting in (
            ("mode", "private_dns_mode"),
            ("hostname", "private_dns_specifier"),
        ):
            value = backup.get(key)
            if not isinstance(value, str):
                raise ProvisionError("Private DNS backup is incomplete")
            action = "delete" if value in {"", "null"} else "put"
            command = ["shell", "settings", action, "global", setting]
            if action == "put":
                command.append(value)
            self.adb_run(command, timeout=10, check=True)
        print("PRIVACY_DNS_RESTORE_OK")

    def verify_privacy_dns(self) -> None:
        mode = self.adb_run(
            ["shell", "settings", "get", "global", "private_dns_mode"],
            timeout=5,
            check=True,
        ).stdout.strip()
        hostname = self.adb_run(
            ["shell", "settings", "get", "global", "private_dns_specifier"],
            timeout=5,
            check=True,
        ).stdout.strip()
        expected_mode = "hostname"
        expected_hostname = self.privacy_dns
        if self.dhcp_dns:
            expected_mode = "off"
            expected_hostname = "null"
        elif self.restore_privacy_dns:
            result = self.adb_run(
                ["shell", "cat", PRIVACY_BACKUP_REMOTE], timeout=5, check=True
            )
            try:
                backup = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                raise ProvisionError(f"invalid Private DNS backup: {exc}") from exc
            if not isinstance(backup, dict) or backup.get("schema") != 1:
                raise ProvisionError("unrecognized Private DNS backup")
            expected_mode = backup.get("mode")
            expected_hostname = backup.get("hostname")
            if not isinstance(expected_mode, str) or not isinstance(
                expected_hostname, str
            ):
                raise ProvisionError("Private DNS backup is incomplete")
            if expected_mode in {"", "null"}:
                expected_mode = "null"
            if expected_hostname in {"", "null"}:
                expected_hostname = "null"
        if mode != expected_mode or hostname != expected_hostname:
            raise ProvisionError(
                "Private DNS did not persist: "
                f"mode={mode!r}/{expected_mode!r} "
                f"hostname={hostname!r}/{expected_hostname!r}"
            )
        action = (
            "network"
            if self.dhcp_dns
            else "restored"
            if self.restore_privacy_dns
            else "strict"
        )
        print(f"PRIVACY_DNS_OK action={action} mode={mode} hostname={hostname}")

    def app_verifier_package_disabled(self) -> bool:
        disabled = self.adb_run(
            ["shell", "pm", "list", "packages", "-d"], timeout=15, check=True
        ).stdout
        return f"package:{APP_VERIFIER_PACKAGE}" in disabled.splitlines()

    def read_app_verifier_backup(self) -> dict[str, object]:
        result = self.adb_run(
            ["shell", "cat", APP_VERIFIER_BACKUP_REMOTE], timeout=5, check=True
        )
        try:
            backup = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ProvisionError(f"invalid app-verifier backup: {exc}") from exc
        if not isinstance(backup, dict) or backup.get("schema") not in {1, 2}:
            raise ProvisionError("unrecognized app-verifier backup")
        value = backup.get("package_verifier_enable")
        if value not in {"0", "1", "null"}:
            raise ProvisionError("app-verifier backup is incomplete")
        if backup["schema"] == 1:
            # Schema 1 predated package-state management and always left Meta's
            # verifier enabled, so preserve that behavior when upgrading.
            backup["meta_verifier_package_disabled"] = False
        if not isinstance(backup.get("meta_verifier_package_disabled"), bool):
            raise ProvisionError("app-verifier package backup is incomplete")
        return backup

    def write_app_verifier_backup(self, backup: dict[str, object]) -> None:
        with tempfile.TemporaryDirectory(prefix="portal-app-verifier-") as temp:
            local = pathlib.Path(temp) / "app-verifier.json"
            local.write_text(json.dumps(backup, indent=2) + "\n")
            self.adb_run(
                ["push", str(local), APP_VERIFIER_BACKUP_REMOTE],
                timeout=15,
                check=True,
            )
        self.adb_run(
            ["shell", "chmod", "0600", APP_VERIFIER_BACKUP_REMOTE],
            timeout=5,
            check=True,
        )

    def allow_third_party_app_updates(self) -> None:
        existing = self.adb_run(
            ["shell", "test", "-f", APP_VERIFIER_BACKUP_REMOTE], timeout=5
        )
        if existing.returncode != 0:
            original = self.adb_run(
                ["shell", "settings", "get", "global", "package_verifier_enable"],
                timeout=5,
                check=True,
            ).stdout.strip()
            if original not in {"0", "1", "null"}:
                raise ProvisionError(
                    f"unexpected package_verifier_enable value: {original!r}"
                )
            backup = {
                "schema": 2,
                "package_verifier_enable": original,
                "meta_verifier_package_disabled": (
                    self.app_verifier_package_disabled()
                ),
            }
            self.write_app_verifier_backup(backup)
        else:
            backup = self.read_app_verifier_backup()
            if backup["schema"] == 1:
                backup["schema"] = 2
                self.write_app_verifier_backup(backup)
        self.adb_run(
            ["shell", "settings", "put", "global", "package_verifier_enable", "0"],
            timeout=10,
            check=True,
        )
        self.adb_run(
            [
                "shell",
                "pm",
                "disable-user",
                "--user",
                "0",
                APP_VERIFIER_PACKAGE,
            ],
            timeout=15,
            check=True,
        )
        self.adb_run(["shell", "sync"], timeout=10, check=True)
        self.verify_app_verifier_setting()

    def restore_app_verifier_setting(self) -> None:
        backup = self.read_app_verifier_backup()
        original = str(backup["package_verifier_enable"])
        command = [
            "shell",
            "settings",
            "delete" if original == "null" else "put",
            "global",
            "package_verifier_enable",
        ]
        if original != "null":
            command.append(original)
        self.adb_run(command, timeout=10, check=True)
        package_action = (
            "disable-user"
            if backup["meta_verifier_package_disabled"]
            else "enable"
        )
        package_command = [
            "shell",
            "pm",
            package_action,
            "--user",
            "0",
            APP_VERIFIER_PACKAGE,
        ]
        self.adb_run(package_command, timeout=15, check=True)
        self.adb_run(["shell", "sync"], timeout=10, check=True)
        self.verify_app_verifier_setting()

    def verify_app_verifier_setting(self) -> None:
        actual = self.adb_run(
            ["shell", "settings", "get", "global", "package_verifier_enable"],
            timeout=5,
            check=True,
        ).stdout.strip()
        expected = "0"
        expected_package_disabled = True
        action = "updates-allowed"
        if self.restore_app_verifier:
            backup = self.read_app_verifier_backup()
            expected = str(backup["package_verifier_enable"])
            expected_package_disabled = bool(
                backup["meta_verifier_package_disabled"]
            )
            action = "restored"
        package_disabled = self.app_verifier_package_disabled()
        if actual != expected or package_disabled != expected_package_disabled:
            raise ProvisionError(
                "package verifier state did not persist: "
                f"setting={actual!r}/{expected!r} "
                f"package_disabled={int(package_disabled)}/"
                f"{int(expected_package_disabled)}"
            )
        print(
            f"APP_UPDATES_OK action={action} "
            f"package_verifier_enable={actual} "
            f"meta_verifier_disabled={int(package_disabled)}"
        )

    def resolve_shizuku_apk(self) -> pathlib.Path:
        if self.shizuku_apk is not None:
            path = self.shizuku_apk.expanduser().resolve()
            if not path.is_file():
                raise ProvisionError(f"Shizuku APK does not exist: {path}")
        else:
            cache = pathlib.Path.home() / ".cache" / "portal-root"
            cache.mkdir(parents=True, exist_ok=True)
            path = cache / SHIZUKU_APK_NAME
            valid = path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == (
                SHIZUKU_APK_SHA256
            )
            if not valid:
                temporary = path.with_suffix(path.suffix + ".tmp")
                temporary.unlink(missing_ok=True)
                print(
                    f"SHIZUKU_DOWNLOAD version={SHIZUKU_VERSION} "
                    f"source={SHIZUKU_APK_URL}",
                    flush=True,
                )
                try:
                    urllib.request.urlretrieve(SHIZUKU_APK_URL, temporary)
                except OSError as exc:
                    temporary.unlink(missing_ok=True)
                    raise ProvisionError(f"Shizuku download failed: {exc}") from exc
                digest = hashlib.sha256(temporary.read_bytes()).hexdigest()
                if digest != SHIZUKU_APK_SHA256:
                    temporary.unlink(missing_ok=True)
                    raise ProvisionError(
                        "official Shizuku APK checksum mismatch: "
                        f"{digest} != {SHIZUKU_APK_SHA256}"
                    )
                temporary.replace(path)
            self.shizuku_apk = path
        try:
            with zipfile.ZipFile(path) as archive:
                if "AndroidManifest.xml" not in archive.namelist():
                    raise ProvisionError(f"invalid Shizuku APK: {path}")
                bad = archive.testzip()
                if bad:
                    raise ProvisionError(f"corrupt Shizuku APK member: {bad}")
        except zipfile.BadZipFile as exc:
            raise ProvisionError(f"invalid Shizuku APK: {path}") from exc
        return path

    def install_shizuku_payload(self) -> None:
        apk = self.resolve_shizuku_apk()
        self.install_apk_preserving_verifier(apk, "shizuku")
        self.install_apk_preserving_verifier(
            SHIZUKU_HELPER_LOCAL, "shizuku-helper"
        )
        self.settle_package_state()
        self.verify_package_verifier_state()
        package_dump = self.adb_run(
            ["shell", "dumpsys", "package", SHIZUKU_PACKAGE],
            timeout=20,
            check=True,
        ).stdout
        if f"versionName={SHIZUKU_VERSION}" not in package_dump and (
            self.shizuku_apk.name == SHIZUKU_APK_NAME
        ):
            raise ProvisionError(
                f"installed Shizuku version is not {SHIZUKU_VERSION}"
            )

        private_key = self.adb_run(
            [
                "exec-out",
                "run-as",
                SHIZUKU_HELPER_PACKAGE,
                "cat",
                "files/adbkey",
            ],
            timeout=10,
        ).stdout
        existing_public = self.adb_run(
            [
                "exec-out",
                "run-as",
                SHIZUKU_HELPER_PACKAGE,
                "cat",
                "files/adbkey.pub",
            ],
            timeout=10,
        ).stdout.strip()
        key_exists = (
            "-----BEGIN PRIVATE KEY-----" in private_key
            and "-----END PRIVATE KEY-----" in private_key
            and re.fullmatch(r"[A-Za-z0-9+/=]+ [^\r\n]+", existing_public)
            is not None
        )
        if not key_exists:
            with tempfile.TemporaryDirectory(prefix="portal-shizuku-key-") as temp:
                key = pathlib.Path(temp) / "adbkey"
                self.run(["adb", "keygen", str(key)], timeout=30, check=True)
                for source, remote, destination in (
                    (key, "/data/local/tmp/portal-shizuku-key.tmp", "files/adbkey"),
                    (
                        pathlib.Path(str(key) + ".pub"),
                        "/data/local/tmp/portal-shizuku-key.pub.tmp",
                        "files/adbkey.pub",
                    ),
                ):
                    self.adb_run(["push", str(source), remote], timeout=15, check=True)
                    self.adb_run(["shell", "chmod", "0644", remote], timeout=5, check=True)
                    self.adb_run(
                        ["shell", "run-as", SHIZUKU_HELPER_PACKAGE, "mkdir", "-p", "files"],
                        timeout=10,
                        check=True,
                    )
                    self.adb_run(
                        ["shell", "run-as", SHIZUKU_HELPER_PACKAGE, "cp", remote, destination],
                        timeout=10,
                        check=True,
                    )
                    self.adb_run(
                        ["shell", "run-as", SHIZUKU_HELPER_PACKAGE, "chmod", "0600", destination],
                        timeout=10,
                        check=True,
                    )
                    self.adb_run(["shell", "rm", "-f", remote], timeout=5)

        public = self.adb_run(
            [
                "exec-out",
                "run-as",
                SHIZUKU_HELPER_PACKAGE,
                "cat",
                "files/adbkey.pub",
            ],
            timeout=10,
            check=True,
        ).stdout.strip()
        if not re.fullmatch(r"[A-Za-z0-9+/=]+ [^\r\n]+", public):
            raise ProvisionError("Portal Shizuku helper returned an invalid ADB public key")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.shizuku_public_key = self.log_dir / "portal-shizuku-adbkey.pub"
        self.shizuku_public_key.write_text(public + "\n", encoding="ascii")
        self.shizuku_public_key.chmod(0o600)
        print(
            f"SHIZUKU_PAYLOAD_OK version={SHIZUKU_VERSION} "
            f"helper={SHIZUKU_HELPER_PACKAGE} key_reused={int(key_exists)}"
        )

    def install_apk_preserving_verifier(self, apk: pathlib.Path, tag: str) -> None:
        """Install an APK while restoring Meta's certificate verifier state."""
        remote = f"/data/local/tmp/portal-{tag}-install.apk"
        self.adb_run(["push", str(apk), remote], timeout=60, check=True)
        disabled = self.adb_run(
            ["shell", "pm", "list", "packages", "-d"], timeout=15, check=True
        ).stdout
        verifier_was_disabled = "package:com.facebook.appverifier" in disabled
        if self.package_verifier_initially_disabled is None:
            self.package_verifier_initially_disabled = verifier_was_disabled
        if verifier_was_disabled:
            command = f"pm install -r {shlex.quote(remote)}; rc=$?; " \
                f"rm -f {shlex.quote(remote)}; exit $rc"
        else:
            command = (
                "cleanup() { pm enable --user 0 com.facebook.appverifier "
                f">/dev/null; rm -f {shlex.quote(remote)}; }}; "
                "trap cleanup EXIT HUP INT TERM; "
                "pm disable-user --user 0 com.facebook.appverifier >/dev/null || exit 1; "
                f"pm install -r {shlex.quote(remote)}"
            )
        result = self.adb_run(["shell", command], timeout=120)
        if result.returncode != 0 or "Success" not in result.stdout:
            raise ProvisionError(
                f"APK installation failed for {apk}: {result.stdout.strip()}"
            )
        print(
            f"APK_INSTALL_OK package_source={apk.name} "
            f"verifier_state={'disabled' if verifier_was_disabled else 'enabled'}"
        )

    def verify_package_verifier_state(self) -> None:
        if self.package_verifier_initially_disabled is None:
            return
        disabled = self.adb_run(
            ["shell", "pm", "list", "packages", "-d"], timeout=15, check=True
        ).stdout
        actual = "package:com.facebook.appverifier" in disabled
        if actual != self.package_verifier_initially_disabled:
            raise ProvisionError(
                "Meta package verifier state was not restored: "
                f"disabled={int(actual)} expected="
                f"{int(self.package_verifier_initially_disabled)}"
            )
        print(
            "PACKAGE_VERIFIER_OK state="
            + ("disabled" if actual else "enabled")
        )

    def uninstall_shizuku_payload(self) -> None:
        self.adb_run(["shell", "pkill", "-f", "shizuku_server"], timeout=10)
        installed, _ = self.package_sets()
        for package in (SHIZUKU_HELPER_PACKAGE, SHIZUKU_PACKAGE):
            if package not in installed:
                continue
            result = self.adb_run(["uninstall", package], timeout=60)
            if result.returncode != 0 or "Success" not in result.stdout:
                raise ProvisionError(
                    f"failed to uninstall {package}: {result.stdout.strip()}"
                )
        print("SHIZUKU_REMOVE_APPS_OK")

    def verify_shizuku(self, wait_seconds: int = 120) -> None:
        self.verify_package_verifier_state()
        package_state = self.adb_run(
            ["shell", "dumpsys", "package", SHIZUKU_HELPER_PACKAGE],
            timeout=15,
            check=True,
        ).stdout
        if re.search(r"\bstopped=true\b", package_state):
            try:
                self.adb_run(
                    [
                        "shell",
                        "am",
                        "broadcast",
                        "-f",
                        "0x20",
                        "-a",
                        "dev.portal.shizukuhelper.START",
                        "-p",
                        SHIZUKU_HELPER_PACKAGE,
                    ],
                    timeout=15,
                    check=True,
                )
            except ProvisionError:
                # Portal's activity manager can finish delivery but leave the
                # host-side broadcast command waiting during early boot. The
                # process/log polling below is the authoritative check.
                print("SHIZUKU_HELPER_ACTIVATION_PENDING early_boot=1")
            print("SHIZUKU_HELPER_ACTIVATED first_install=1")
        deadline = time.monotonic() + wait_seconds
        process = ""
        logs = ""
        while time.monotonic() < deadline:
            packages = self.adb_run(
                ["shell", "pm", "list", "packages"], timeout=15, check=True
            ).stdout
            process = self.adb_run(
                ["shell", "ps", "-A"], timeout=10, check=True
            ).stdout
            logs = self.adb_run(
                ["shell", "logcat", "-d", "-s", "PortalShizuku:*"],
                timeout=15,
            ).stdout
            process_line = next(
                (line for line in process.splitlines() if "shizuku_server" in line),
                "",
            )
            if (
                f"package:{SHIZUKU_PACKAGE}" in packages
                and f"package:{SHIZUKU_HELPER_PACKAGE}" in packages
                and process_line
                and process_line.split()[0] == "shell"
            ):
                print(
                    "SHIZUKU_OK privilege=shell startup=device-local "
                    f"process={process_line.strip()!r} "
                    f"helper_log={int('Shizuku started through loopback ADB' in logs)}"
                )
                return
            time.sleep(3)
        raise ProvisionError(
            "Shizuku did not start as Android shell after boot; "
            f"process_observed={int('shizuku_server' in process)} "
            f"helper_log={logs[-500:]!r}"
        )

    def verify_shizuku_removed(self) -> None:
        packages = self.adb_run(
            ["shell", "pm", "list", "packages"], timeout=15, check=True
        ).stdout
        process = self.adb_run(["shell", "ps", "-A"], timeout=10, check=True).stdout
        remaining = [
            package
            for package in (SHIZUKU_PACKAGE, SHIZUKU_HELPER_PACKAGE)
            if f"package:{package}" in packages
        ]
        if remaining or "shizuku_server" in process:
            raise ProvisionError(
                "Shizuku removal did not persist: "
                f"packages={','.join(remaining) or 'none'} "
                f"server={int('shizuku_server' in process)}"
            )
        print("SHIZUKU_REMOVED_OK packages=absent server=absent")

    def recover_actions(self) -> bool:
        state = self.read_state()
        self.adb_run(
            [
                "shell",
                "rm",
                "-f",
                PRELOAD_REMOTE,
                HELPER_REMOTE,
                ACCOUNT_CTL_REMOTE,
                COMPONENT_CTL_REMOTE,
                DEBLOAT_COMPONENT_ACTIONS_REMOTE,
                SHIZUKU_KEY_REMOTE,
                PRESENCE_KEY_REMOTE,
                CAMERA_LIGHT_HELPER_REMOTE,
                CAMERA_LIGHT_HOOK_REMOTE,
            ],
            timeout=10,
        )
        if state is None:
            print("RECOVER_NO_STATE staged_files=cleaned")
            self.print_status()
            return False
        if state.get("status") != "pending":
            print(f"RECOVER_STATE status={state.get('status')} action=status")
            self.print_status()
            return False
        actions = state.get("actions")
        if not isinstance(actions, dict):
            raise ProvisionError("pending state has no action map")
        allowed = set(self.requested_actions()) | {
            "audio",
            "restore_audio",
            "device_owner",
            "kiosk_home",
            "restore_kiosk_home",
            "disable_updates",
            "enable_updates",
            "debloat",
            "restore_bloat",
            "remove_meta_accounts",
            "optimize_presence",
            "restore_presence_profile",
            "presence_fps_cap",
            "restore_presence_fps",
            "privacy_dns",
            "dhcp_dns",
            "restore_privacy_dns",
            "allow_app_updates",
            "restore_app_verifier",
            "shizuku",
            "remove_shizuku",
            "disable_camera_light",
            "restore_camera_light",
        }
        for name, value in actions.items():
            if name not in allowed:
                raise ProvisionError(f"unsupported recovery action: {name}")
            if name == "privacy_dns":
                if not isinstance(value, str):
                    raise ProvisionError("invalid privacy_dns recovery value")
                self.privacy_dns = value
            elif name == "presence_fps_cap":
                if not isinstance(value, int) or not 1 <= value <= 10:
                    raise ProvisionError("invalid presence_fps_cap recovery value")
                self.presence_fps_cap = value
            elif value is True:
                setattr(self, name, True)
            else:
                raise ProvisionError(f"invalid recovery value for {name}: {value!r}")
        print("RECOVER_RESUME actions=" + ",".join(sorted(actions)))
        return True

    def meta_accounts(self) -> list[tuple[str, str]]:
        output = self.adb_run(
            ["shell", "dumpsys", "account"], timeout=20, check=True
        ).stdout
        accounts = re.findall(
            r"Account \{name=([^,}]+), type=([^}]+)\}", output
        )
        return [
            (name, account_type)
            for name, account_type in accounts
            if account_type in META_ACCOUNT_TYPES
        ]

    def disabled_meta_authenticators(self) -> set[str]:
        output = self.adb_run(
            ["shell", "dumpsys", "package", "com.facebook.alohaservices.alohausers"],
            timeout=20,
            check=True,
        ).stdout
        match = re.search(
            r"disabledComponents:\s*(.*?)(?:\n\s*\w[^:\n]*:|\Z)",
            output,
            re.DOTALL,
        )
        return set() if match is None else set(match.group(1).split())

    def meta_accounts_preflight(self) -> bool:
        accounts = self.meta_accounts()
        disabled = self.disabled_meta_authenticators()
        hardware_class = META_HARDWARE_AUTHENTICATOR.split("/", 1)[1]
        already_clean = (
            not accounts
            and set(META_AUTHENTICATOR_COMPONENTS) <= disabled
            and hardware_class not in disabled
        )
        existing = self.adb_run(
            ["shell", "cat", META_ACCOUNT_BACKUP_REMOTE], timeout=5
        )
        if existing.returncode != 0:
            contents = "# portal-meta-accounts-before-v1\n" + "".join(
                f"{account_type}\t{name}\n" for name, account_type in accounts
            )
            with tempfile.TemporaryDirectory(prefix="portal-meta-accounts-") as tmp:
                local = pathlib.Path(tmp) / "accounts.tsv"
                local.write_text(contents, encoding="utf-8")
                self.adb_run(
                    ["push", str(local), META_ACCOUNT_BACKUP_REMOTE],
                    timeout=15,
                    check=True,
                )
            self.adb_run(
                ["shell", "chmod", "0600", META_ACCOUNT_BACKUP_REMOTE],
                timeout=5,
                check=True,
            )
        else:
            contents = existing.stdout
        host_backup = self.log_dir / "meta-accounts-before.tsv"
        if not host_backup.exists():
            host_backup.write_text(contents, encoding="utf-8")
            host_backup.chmod(0o600)
        print(
            f"META_ACCOUNT_PREFLIGHT accounts={len(accounts)} "
            f"authenticators_disabled={len(disabled & set(META_AUTHENTICATOR_COMPONENTS))} "
            f"already_clean={int(already_clean)} backup={META_ACCOUNT_BACKUP_REMOTE}"
        )
        return already_clean

    def device_owner_preflight(self) -> bool:
        policy = self.adb_run(
            ["shell", "dumpsys", "device_policy"], timeout=15, check=True
        ).stdout
        component = KIOSK_COMPONENT
        is_owner = "Device Owner:" in policy and any(
            owner_component in policy for owner_component in KIOSK_OWNER_COMPONENTS
        )
        is_admin = (
            "Enabled Device Admins (User 0" in policy
            and f"    {component}:" in policy
        )
        if "Device Owner:" in policy and not is_owner:
            raise ProvisionError("another Device Owner is already registered")
        if not is_admin:
            raise ProvisionError(f"Kiosk Satellite admin is not active: {component}")
        print(
            f"DEVICE_OWNER_PREFLIGHT component={component} "
            f"active_admin=1 already_owner={int(is_owner)}"
        )
        return is_owner

    def audio_preflight(self) -> bool:
        marker = "/data/local/tmp/portal-audio-backup/installed-v1"
        installed = self.adb_run(
            ["shell", "test", "-f", marker], timeout=5
        ).returncode == 0
        if not installed:
            print("AUDIO_PREFLIGHT installed=0 healthy=0 action=install")
            return False
        try:
            self.verify_watchdog(wait_seconds=5)
        except ProvisionError:
            print("AUDIO_PREFLIGHT installed=1 healthy=0 action=repair")
            return False
        print("AUDIO_PREFLIGHT installed=1 healthy=1 action=skip")
        return True

    def kaslr_base(self, tag: str) -> int:
        offsets = (
            0x3D7E,
            0x3D54,
            0x153C,
            0x11756DC,
            0x1175724,
            0x363C6,
            0xAF90E,
            0x136E,
            0x3A72,
        )
        for sample_try in range(3):
            remote = f"/data/local/tmp/portal-perf-{tag}-{sample_try}.data"
            command = (
                "simpleperf record -g -e cpu-clock -f 4000 --duration 2 "
                f"-o {shlex.quote(remote)} -- /system/bin/dd if=/dev/zero "
                "of=/dev/null bs=4096"
            )
            self.adb_run(["shell", command], timeout=20)
            report = self.adb_run(
                ["shell", "simpleperf", "report-sample", "-i", remote],
                timeout=30,
            )
            self.adb_run(["shell", "rm", "-f", remote], timeout=5)
            values = [
                int(value, 16)
                for value in re.findall(
                    r"vaddr_in_file: (ffffff[0-9a-f]+)", report.stdout
                )
            ]
            candidates: collections.Counter[int] = collections.Counter()
            for value in values:
                for offset in offsets:
                    base = value - offset
                    if (
                        base >= 0xFFFFFF8000000000
                        and (base - 0xFFFFFF8008080000) & 0x1FFFFF == 0
                    ):
                        candidates[base] += 1
            if candidates:
                return candidates.most_common(1)[0][0]
        raise ProvisionError("simpleperf did not expose a recognized kernel PC")

    def prepare_presence_helper(self) -> None:
        self.install_apk_preserving_verifier(
            PRESENCE_HELPER_LOCAL, "presence-helper"
        )
        self.settle_package_state()
        self.verify_package_verifier_state()
        private_key = self.adb_run(
            ["exec-out", "run-as", PRESENCE_HELPER_PACKAGE, "cat", "files/adbkey"],
            timeout=10,
        ).stdout
        existing_public = self.adb_run(
            [
                "exec-out",
                "run-as",
                PRESENCE_HELPER_PACKAGE,
                "cat",
                "files/adbkey.pub",
            ],
            timeout=10,
        ).stdout.strip()
        key_exists = (
            "-----BEGIN PRIVATE KEY-----" in private_key
            and "-----END PRIVATE KEY-----" in private_key
            and re.fullmatch(r"[A-Za-z0-9+/=]+ [^\r\n]+", existing_public)
            is not None
        )
        if not key_exists:
            with tempfile.TemporaryDirectory(prefix="portal-presence-key-") as temp:
                key = pathlib.Path(temp) / "adbkey"
                self.run(["adb", "keygen", str(key)], timeout=30, check=True)
                for source, remote, destination in (
                    (key, "/data/local/tmp/portal-presence-key.tmp", "files/adbkey"),
                    (
                        pathlib.Path(str(key) + ".pub"),
                        "/data/local/tmp/portal-presence-key.pub.tmp",
                        "files/adbkey.pub",
                    ),
                ):
                    self.adb_run(["push", str(source), remote], timeout=15, check=True)
                    self.adb_run(["shell", "chmod", "0644", remote], timeout=5, check=True)
                    self.adb_run(
                        ["shell", "run-as", PRESENCE_HELPER_PACKAGE, "mkdir", "-p", "files"],
                        timeout=10,
                        check=True,
                    )
                    self.adb_run(
                        ["shell", "run-as", PRESENCE_HELPER_PACKAGE, "cp", remote, destination],
                        timeout=10,
                        check=True,
                    )
                    self.adb_run(
                        ["shell", "run-as", PRESENCE_HELPER_PACKAGE, "chmod", "0600", destination],
                        timeout=10,
                        check=True,
                    )
                    self.adb_run(["shell", "rm", "-f", remote], timeout=5)
        public = self.adb_run(
            [
                "exec-out",
                "run-as",
                PRESENCE_HELPER_PACKAGE,
                "cat",
                "files/adbkey.pub",
            ],
            timeout=10,
            check=True,
        ).stdout.strip()
        if not re.fullmatch(r"[A-Za-z0-9+/=]+ [^\r\n]+", public):
            raise ProvisionError("Portal presence helper returned an invalid ADB public key")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.presence_public_key = self.log_dir / "portal-presence-adbkey.pub"
        self.presence_public_key.write_text(public + "\n", encoding="ascii")
        self.presence_public_key.chmod(0o600)
        print(
            f"PRESENCE_HELPER_PAYLOAD_OK package={PRESENCE_HELPER_PACKAGE} "
            f"key_reused={int(key_exists)}"
        )

    def activate_presence_helper(self) -> None:
        if self.presence_fps_cap is None:
            raise ProvisionError("presence helper requires an FPS cap")
        result = self.adb_run(
            [
                "shell",
                "am",
                "broadcast",
                "--include-stopped-packages",
                "-a",
                "dev.portal.presencehelper.CONFIG",
                "-n",
                f"{PRESENCE_HELPER_PACKAGE}/.BootReceiver",
                "--ei",
                "fps",
                str(self.presence_fps_cap),
            ],
            timeout=20,
            check=True,
        )
        if "result=0" not in result.stdout:
            raise ProvisionError(
                "presence helper configuration broadcast failed: "
                + result.stdout.strip()
            )
        self.adb_run(
            [
                "shell",
                "am",
                "broadcast",
                "--include-stopped-packages",
                "-a",
                "dev.portal.presencehelper.START",
                "-n",
                f"{PRESENCE_HELPER_PACKAGE}/.BootReceiver",
            ],
            timeout=20,
            check=True,
        )
        print(
            f"PRESENCE_HELPER_OK package={PRESENCE_HELPER_PACKAGE} "
            f"fps={self.presence_fps_cap}"
        )

    def uninstall_presence_helper(self) -> None:
        installed, _ = self.package_sets()
        if PRESENCE_HELPER_PACKAGE not in installed:
            print("PRESENCE_HELPER_REMOVE already_absent=1")
            return
        result = self.adb_run(
            ["uninstall", PRESENCE_HELPER_PACKAGE], timeout=30
        )
        if result.returncode != 0 or "Success" not in result.stdout:
            raise ProvisionError(
                "failed to remove presence helper: " + result.stdout.strip()
            )
        print(f"PRESENCE_HELPER_REMOVE package={PRESENCE_HELPER_PACKAGE}")

    def prepare_exploit_sentinel(self) -> None:
        if not EXPLOIT_SENTINEL_LOCAL.is_file():
            raise ProvisionError(
                f"missing exploit sentinel build output: {EXPLOIT_SENTINEL_LOCAL}"
            )
        try:
            self.install_apk_preserving_verifier(
                EXPLOIT_SENTINEL_LOCAL, "exploit-sentinel"
            )
            self.settle_package_state()
            result = self.adb_run(
                [
                    "shell",
                    "run-as",
                    EXPLOIT_SENTINEL_PACKAGE,
                    "/system/bin/true",
                ],
                timeout=15,
            )
            if result.returncode != 0:
                raise ProvisionError(
                    "exploit sentinel run-as preflight failed: "
                    + result.stdout.strip()
                )
            self.verify_package_verifier_state()
        except ProvisionError:
            self.uninstall_exploit_sentinel(best_effort=True)
            raise
        print(
            f"EXPLOIT_SENTINEL_OK package={EXPLOIT_SENTINEL_PACKAGE} "
            "run_as=verified"
        )

    def uninstall_exploit_sentinel(self, best_effort: bool = False) -> None:
        try:
            path = self.adb_run(
                ["shell", "pm", "path", EXPLOIT_SENTINEL_PACKAGE], timeout=15
            )
            if path.returncode != 0 or not path.stdout.startswith("package:"):
                print(
                    f"EXPLOIT_SENTINEL_REMOVE package={EXPLOIT_SENTINEL_PACKAGE} "
                    "already_absent=1"
                )
                return
            result = self.adb_run(
                ["uninstall", EXPLOIT_SENTINEL_PACKAGE], timeout=30
            )
            if result.returncode != 0 or "Success" not in result.stdout:
                raise ProvisionError(
                    "failed to remove exploit sentinel: "
                    + result.stdout.strip()
                )
            print(
                f"EXPLOIT_SENTINEL_REMOVE package={EXPLOIT_SENTINEL_PACKAGE} "
                "already_absent=0"
            )
        except ProvisionError as exc:
            if not best_effort:
                raise
            print(f"EXPLOIT_SENTINEL_REMOVE_DEFERRED error={exc}")

    def memstart(self, tag: str) -> int:
        result = self.adb_run(["shell", "bugreportz", "-p"], timeout=180)
        match = re.search(r"OK:(\S+\.zip)", result.stdout)
        if not match:
            raise ProvisionError(f"bugreportz failed: {result.stdout[-500:]}")
        remote = match.group(1)
        with tempfile.TemporaryDirectory(prefix=f"portal-{tag}-") as temporary:
            local = pathlib.Path(temporary) / "bugreport.zip"
            self.adb_run(["pull", remote, str(local)], timeout=60, check=True)
            self.adb_run(["shell", "rm", "-f", remote], timeout=5)
            with zipfile.ZipFile(local) as archive:
                report_name = next(
                    (
                        name
                        for name in archive.namelist()
                        if pathlib.PurePosixPath(name).name.startswith("bugreport-")
                        and name.endswith(".txt")
                    ),
                    None,
                )
                if report_name is None:
                    raise ProvisionError("bugreport text is absent from archive")
                report = archive.read(report_name).decode(errors="replace")
        match = re.search(r"memory\s+: (0x[0-9a-f]+) -", report)
        if not match:
            raise ProvisionError("kernel virtual memory range is absent from bugreport")
        virtual_start = int(match.group(1), 16)
        return (
            0x80000000 - (virtual_start - 0xFFFFFFC000000000)
        ) & 0xFFFFFFFFFFFFFFFF

    def exploit(self, base: int, memstart: int, attempt: int) -> bool:
        environment = {
            "GHOSTLOCK_KASLR_BASE": hex(base),
            "GHOSTLOCK_P0_MEMSTART": hex(memstart),
            "GHOSTLOCK_TRUST_EXTERNAL_KASLR": "1",
            "GHOSTLOCK_MM_PARTIALS": "14",
            "GHOSTLOCK_PAGE_COLLISIONS": "5",
            "GHOSTLOCK_BUDDY_HOLD_PAIRS": "64",
            "GHOSTLOCK_BUDDY_HOLD_SENDS": "1024",
            "GHOSTLOCK_RECLAIM_PAIRS": "64",
            "GHOSTLOCK_RECLAIM_SENDS": "64",
            "GHOSTLOCK_SOCKET_WATCH": "1",
            "GHOSTLOCK_WATCH_CFI": "1",
            "GHOSTLOCK_SENDMMSG_PROC_UID_LOCK": "1",
            "GHOSTLOCK_PROC_UID_APP_SENTINEL": "1",
            "GHOSTLOCK_PROC_UID_RUNAS_SENTINEL": "1",
            "GHOSTLOCK_PROC_UID_RUNAS_PACKAGE": EXPLOIT_SENTINEL_PACKAGE,
            "GHOSTLOCK_SLIDE_BREAK_OWNER_CHAIN": "1",
            "GHOSTLOCK_HOLD_AFTER_SCHED": "1",
            "GHOSTLOCK_MAIN_ROUTE": "slide-sendmmsg",
            "GHOSTLOCK_FOPS_STACK_ROUTE": "sendmmsg",
            "GHOSTLOCK_PROC_UID_WARM_MB": "256",
            "GHOSTLOCK_ADBD_ROOT_CONFIGFS": "1",
            "GHOSTLOCK_ROOT_SELF_CONFIGFS": "1",
            "GHOSTLOCK_VOLATILE_LOG": "1",
            "LD_PRELOAD": PRELOAD_REMOTE,
        }
        if self.persist_wireless_adb:
            environment["GHOSTLOCK_ENABLE_WIRELESS_ADB"] = "1"
        if self.audio and not self.audio_already_configured:
            environment.update(
                {
                    "GHOSTLOCK_AUDIO_CTL": "1",
                    "GHOSTLOCK_AUDIO_PERSIST": "1",
                    "GHOSTLOCK_AUDIO_PERSIST_SO": HELPER_REMOTE,
                }
            )
        if self.restore_audio:
            environment.update(
                {
                    "GHOSTLOCK_RESTORE_AUDIO_PERSIST": "1",
                    "GHOSTLOCK_AUDIO_RESTORE_CTL": "1",
                }
            )
        if self.device_owner:
            environment["GHOSTLOCK_KIOSK_DEVICE_OWNER"] = "1"
        if self.disable_updates:
            environment["GHOSTLOCK_OTA_BLOCK"] = "1"
        if self.enable_updates:
            environment["GHOSTLOCK_RESTORE_OTA_BLOCK"] = "1"
        if self.optimize_presence:
            environment["GHOSTLOCK_PRESENCE_PROFILE"] = "1"
        if self.restore_presence_profile:
            environment["GHOSTLOCK_RESTORE_PRESENCE_PROFILE"] = "1"
        if self.presence_fps_cap is not None:
            environment["GHOSTLOCK_PRESENCE_FPS_CAP"] = str(
                self.presence_fps_cap
            )
            environment["GHOSTLOCK_UID1000_PRESENCE_FPS"] = str(
                self.presence_fps_cap
            )
            environment["GHOSTLOCK_PRESENCE_REMOVE_KEY"] = "1"
        if self.restore_presence_fps or self.restore_presence_profile:
            environment["GHOSTLOCK_RESTORE_PRESENCE_FPS"] = "1"
            environment["GHOSTLOCK_PRESENCE_REMOVE_KEY"] = "1"
        if (
            self.debloat
            or self.restore_bloat
            or self.presence_fps_cap is not None
            or self.restore_presence_fps
            or self.restore_presence_profile
        ):
            environment.update(
                {
                    "GHOSTLOCK_COMPONENT_CTL_JAR": COMPONENT_CTL_REMOTE,
                    "GHOSTLOCK_COMPONENT_ACTIONS": (
                        DEBLOAT_COMPONENT_ACTIONS_REMOTE
                    ),
                }
            )
        if self.presence_fps_cap is not None:
            environment["GHOSTLOCK_PRESENCE_PREF_ACTION"] = (
                f"set:{self.presence_fps_cap}"
            )
        if self.restore_presence_fps or self.restore_presence_profile:
            environment["GHOSTLOCK_PRESENCE_PREF_ACTION"] = "restore"
        if self.remove_meta_accounts:
            environment.update(
                {
                    "GHOSTLOCK_REMOVE_META_ACCOUNTS": "1",
                    "GHOSTLOCK_META_ACCOUNT_CTL_JAR": ACCOUNT_CTL_REMOTE,
                }
            )
        if self.shizuku:
            environment["GHOSTLOCK_SHIZUKU_AUTHORIZE_KEY"] = "1"
        if self.remove_shizuku:
            environment["GHOSTLOCK_SHIZUKU_REMOVE_KEY"] = "1"
        if self.disable_camera_light:
            environment["GHOSTLOCK_DISABLE_CAMERA_LIGHT"] = "1"
        if self.restore_camera_light:
            environment["GHOSTLOCK_RESTORE_CAMERA_LIGHT"] = "1"
        if self.disable_camera_light or self.presence_fps_cap is not None:
            self.adb_run(
                ["shell", "rm", "-f", UID1000_HOOK_ACTIVE_REMOTE],
                timeout=5,
                check=True,
            )
            if self.uid1000_boot_hook_active():
                environment["GHOSTLOCK_UID1000_HOOK_ACTIVE"] = "1"
                self.push_text_atomic(
                    "active\n", UID1000_HOOK_ACTIVE_REMOTE
                )
                print(
                    "UID1000_HOOK_ACTIVE source=running-system-helper",
                    flush=True,
                )
        self.adb_run(
            ["shell", "am", "force-stop", "--user", "0", "com.facebook.aloha.analytics"],
            timeout=10,
        )
        self.adb_run(["shell", "logcat", "-c"], timeout=5)
        shell = "env " + " ".join(
            f"{name}={shlex.quote(value)}" for name, value in environment.items()
        ) + " /system/bin/true"
        log_path = self.log_dir / f"attempt-{attempt}.log"
        success = False
        failed = False
        failure_markers = (
            "WATCH_CFI_OK=0",
            "pre-signal FOPS check miss",
            "held reclaim payload inspection complete clean=0",
            "held child CFI complete ok=0",
        )
        expected_markers: dict[str, tuple[str, bool]] = {}
        if self.persist_wireless_adb:
            expected_markers["wireless_adb"] = (
                "wireless ADB persistence install",
                True,
            )
        if self.audio and not self.audio_already_configured:
            expected_markers.update(
                {
                    "audio_parameters": (
                        "PORTAL_AUDIO_NATIVE_OK mode=disabled",
                        False,
                    ),
                    "audio_persistence": ("audio persistence install", True),
                }
            )
        if self.restore_audio:
            expected_markers.update(
                {
                    "audio_defaults": (
                        "PORTAL_AUDIO_NATIVE_OK mode=firmware-defaults",
                        False,
                    ),
                    "audio_restore": ("audio persistence restore", True),
                }
            )
        if self.device_owner:
            expected_markers["device_owner"] = ("kiosk device owner install", True)
        if self.disable_updates:
            expected_markers["ota_block"] = ("OTA block file install", True)
        if self.enable_updates:
            expected_markers["ota_restore"] = ("OTA block restore", True)
        if self.optimize_presence:
            expected_markers["presence_profile"] = (
                "presence profile install",
                True,
            )
        if self.restore_presence_profile:
            expected_markers["presence_restore"] = (
                "presence profile restore",
                True,
            )
        if self.presence_fps_cap is not None:
            expected_markers["presence_fps"] = (
                f"PORTAL_PRESENCE_FPS action=set fps={self.presence_fps_cap}",
                True,
            )
            expected_markers["presence_uid1000_config"] = (
                "UID1000 presence activation config",
                True,
            )
            expected_markers["presence_uid1000_helper"] = (
                "UID1000 camera LED helper install",
                True,
            )
            expected_markers["presence_uid1000_hook"] = (
                "Battery ART boot hook",
                True,
            )
        if self.restore_presence_fps:
            expected_markers["presence_fps_restore"] = (
                "PORTAL_PRESENCE_FPS action=restore",
                True,
            )
        if self.restore_presence_profile:
            expected_markers["presence_fps_restore"] = (
                "PORTAL_PRESENCE_FPS action=restore",
                True,
            )
        if self.restore_presence_fps or self.restore_presence_profile:
            expected_markers["presence_helper_key_remove"] = (
                "Presence ADB key remove",
                True,
            )
            expected_markers["presence_uid1000_restore"] = (
                "UID1000 presence helper restore",
                True,
            )
        if self.debloat or self.restore_bloat:
            expected_markers["component_profile"] = (
                "component ctl child=",
                True,
            )
        if self.remove_meta_accounts:
            expected_markers["meta_accounts"] = ("Meta account removal", True)
        if self.shizuku:
            expected_markers["shizuku_key"] = (
                "Shizuku ADB key authorize",
                True,
            )
        if self.remove_shizuku:
            expected_markers["shizuku_key_remove"] = (
                "Shizuku ADB key remove",
                True,
            )
        if self.disable_camera_light:
            expected_markers["camera_light_helper"] = (
                "UID1000 camera LED helper install",
                True,
            )
            expected_markers["camera_light_hook"] = (
                "Battery ART boot hook",
                True,
            )
        if self.restore_camera_light:
            expected_markers["camera_light_restore"] = (
                "UID1000 camera LED helper restore",
                True,
            )
        observed_markers: set[str] = set()
        with log_path.open("w", encoding="utf-8") as output:
            process = subprocess.Popen(
                self.adb + ["shell", shell],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
            )
            assert process.stdout is not None
            deadline = time.monotonic() + 300
            while time.monotonic() < deadline:
                ready, _, _ = select.select([process.stdout], [], [], 1)
                if not ready:
                    if process.poll() is not None:
                        break
                    continue
                line = process.stdout.readline()
                if not line:
                    break
                sys.stdout.write(line)
                sys.stdout.flush()
                output.write(line)
                output.flush()
                for name, (marker, require_ok) in expected_markers.items():
                    if marker in line and (not require_ok or "ok=1" in line):
                        observed_markers.add(name)
                if expected_markers and observed_markers == set(expected_markers):
                    print(
                        "NATIVE_ACTIONS_OK actions="
                        + ",".join(sorted(observed_markers)),
                        flush=True,
                    )
                    success = True
                    break
                success_marker = "provision actions complete "
                if success_marker in line and "ok=1" in line:
                    success = True
                    break
                if any(marker in line for marker in failure_markers):
                    failed = True
                    break

            print(
                f"INSTALL_ATTEMPT_RESULT attempt={attempt} "
                f"success={int(success)} early_failure={int(failed)}"
            )
            try:
                self.adb_run(["reboot"], timeout=8)
            except ProvisionError:
                pass
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        return success

    def verify_watchdog(self, wait_seconds: int = 25) -> str:
        deadline = time.monotonic() + wait_seconds
        last_log = ""
        while time.monotonic() < deadline:
            result = self.adb_run(
                ["shell", "logcat", "-d", "-s", "PortalAudioPersist:*"],
                timeout=10,
            )
            last_log = result.stdout
            started = "persistent audio watchdog started" in last_log
            verified = "audio processing verified aec=0 ns=0" in last_log
            aec = re.search(r"param=3001 .*after=0 .*ok=1", last_log)
            ns = re.search(r"param=4001 .*after=0 .*ok=1", last_log)
            if started and (verified or (aec and ns)):
                pid = self.adb_run(
                    ["shell", "pidof", "com.facebook.portal.aiservice"],
                    timeout=5,
                    check=True,
                ).stdout.strip()
                boot_id = self.adb_run(
                    ["shell", "cat", "/proc/sys/kernel/random/boot_id"],
                    timeout=5,
                    check=True,
                ).stdout.strip()
                print(f"WATCHDOG_OK boot_id={boot_id} aiservice_pid={pid}")
                print(last_log.rstrip())
                return boot_id
            time.sleep(2)
        raise ProvisionError(
            "watchdog did not verify after boot; recent log follows:\n"
            + last_log[-4000:]
        )

    def verify_audio_restored(self, wait_seconds: int = 20) -> None:
        marker = "/data/local/tmp/portal-audio-backup/restored-v1"
        if self.adb_run(["shell", "test", "-f", marker], timeout=5).returncode != 0:
            raise ProvisionError("audio restore marker is absent")
        deadline = time.monotonic() + wait_seconds
        logs = ""
        pid = ""
        while time.monotonic() < deadline:
            pid = self.adb_run(
                ["shell", "pidof", "com.facebook.portal.aiservice"], timeout=5
            ).stdout.strip()
            logs = self.adb_run(
                ["shell", "logcat", "-d", "-s", "PortalAudioPersist:*"],
                timeout=10,
            ).stdout
            if pid:
                time.sleep(3)
                break
            time.sleep(2)
        logs = self.adb_run(
            ["shell", "logcat", "-d", "-s", "PortalAudioPersist:*"], timeout=10
        ).stdout
        if not pid or "persistent audio watchdog started" in logs:
            raise ProvisionError(
                "audio persistence restore did not verify: "
                f"aiservice_pid={pid!r} watchdog_started="
                f"{int('persistent audio watchdog started' in logs)}"
            )
        print(f"AUDIO_RESTORE_OK aiservice_pid={pid} watchdog=absent")

    def verify_device_owner(self) -> None:
        component = KIOSK_COMPONENT
        policy = self.adb_run(
            ["shell", "dumpsys", "device_policy"], timeout=15, check=True
        ).stdout
        owner_block = re.search(
            r"Device Owner:\s+(.*?)(?:\n\s*Profile Owner|\n\S|\Z)",
            policy,
            re.DOTALL,
        )
        if (
            owner_block is None
            or not any(
                owner_component in owner_block.group(1)
                for owner_component in KIOSK_OWNER_COMPONENTS
            )
            or "User ID: 0" not in owner_block.group(1)
        ):
            raise ProvisionError(
                "Kiosk Satellite is not the loaded Device Owner; "
                "dumpsys excerpt follows:\n" + policy[:5000]
            )
        owner_property = self.adb_run(
            ["shell", "getprop", "ro.device_owner"], timeout=5, check=True
        ).stdout.strip()
        if owner_property != "true":
            raise ProvisionError(
                f"Device Owner loaded but ro.device_owner={owner_property!r}"
            )
        print(
            f"DEVICE_OWNER_OK component={component} user=0 "
            f"ro.device_owner={owner_property}"
        )

    def current_default_home(self) -> str:
        result = self.adb_run(
            [
                "shell",
                "cmd",
                "package",
                "resolve-activity",
                "--brief",
                "-a",
                "android.intent.action.MAIN",
                "-c",
                "android.intent.category.HOME",
            ],
            timeout=10,
            check=True,
        )
        components = [
            line.strip()
            for line in result.stdout.splitlines()
            if "/" in line and not line.lstrip().startswith("priority=")
        ]
        return components[-1] if components else ""

    def kiosk_home_alias_enabled(self) -> bool:
        package = self.adb_run(
            ["shell", "dumpsys", "package", "me.jxl.kiosk_satellite"],
            timeout=15,
            check=True,
        ).stdout
        enabled = re.search(
            r"enabledComponents:\s*(.*?)(?:disabledComponents:|"
            r"isSystemUserPackagesBlacklistSupported:|\Z)",
            package,
            re.DOTALL,
        )
        return (
            enabled is not None
            and "me.jxl.kiosk_satellite.HomeAlias" in enabled.group(1)
        )

    def configure_kiosk_home(self, enabled: bool) -> None:
        if enabled:
            self.verify_device_owner()
        payload = shlex.quote(
            json.dumps({"home.enabled": enabled}, separators=(",", ":"))
        )
        result = self.adb_run(
            [
                "shell",
                "am",
                "start",
                "-W",
                "-n",
                KIOSK_PROVISION_COMPONENT,
                "--es",
                "ks.provision",
                payload,
            ],
            timeout=30,
        )
        if result.returncode != 0:
            raise ProvisionError(
                "Kiosk Satellite rejected the home-screen setting:\n"
                + result.stdout[-2000:]
            )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            held = self.current_default_home() == KIOSK_HOME_COMPONENT
            alias_enabled = self.kiosk_home_alias_enabled()
            if (enabled and held and alias_enabled) or (
                not enabled and not held and not alias_enabled
            ):
                print(
                    "KIOSK_HOME_CONFIGURED "
                    f"enabled={int(enabled)} default={self.current_default_home() or 'none'}"
                )
                return
            time.sleep(1)
        raise ProvisionError(
            "Kiosk Satellite did not apply the requested home-screen setting"
        )

    def verify_kiosk_home(self, enabled: bool) -> None:
        default_home = self.current_default_home()
        alias_enabled = self.kiosk_home_alias_enabled()
        if enabled and (default_home != KIOSK_HOME_COMPONENT or not alias_enabled):
            raise ProvisionError(
                "Kiosk Satellite is not the persistent home screen: "
                f"default={default_home!r} alias_enabled={int(alias_enabled)}"
            )
        if not enabled and (default_home == KIOSK_HOME_COMPONENT or alias_enabled):
            raise ProvisionError(
                "Kiosk Satellite remains registered as the home screen: "
                f"default={default_home!r} alias_enabled={int(alias_enabled)}"
            )
        print(
            "KIOSK_HOME_OK "
            f"enabled={int(enabled)} default={default_home or 'none'}"
        )

    def disable_ota_packages(self) -> None:
        packages = (
            OTA_UI_PACKAGE,
            OTA_SETUP_PACKAGE,
        )
        for package in packages:
            result = self.adb_run(
                ["shell", "pm", "disable-user", "--user", "0", package],
                timeout=10,
            )
            if result.returncode != 0 or "new state: disabled-user" not in result.stdout:
                already_disabled = self.adb_run(
                    ["shell", "pm", "list", "packages", "-d"],
                    timeout=10,
                    check=True,
                ).stdout
                if f"package:{package}" not in already_disabled:
                    raise ProvisionError(
                        f"failed to disable OTA package {package}: {result.stdout}"
                    )

    def enable_ota_packages(self) -> None:
        for package in (
            OTA_UI_PACKAGE,
            OTA_SETUP_PACKAGE,
        ):
            result = self.adb_run(
                ["shell", "pm", "enable", "--user", "0", package], timeout=10
            )
            if result.returncode != 0:
                raise ProvisionError(
                    f"failed to enable OTA package {package}: {result.stdout}"
                )
        self.settle_package_state()

    def verify_ota_restored(self) -> None:
        marker = "/data/local/tmp/portal-ota-backup/restored-v1"
        if self.adb_run(["shell", "test", "-f", marker], timeout=5).returncode != 0:
            raise ProvisionError("OTA restore marker is absent")
        disabled = self.adb_run(
            ["shell", "pm", "list", "packages", "-d"], timeout=10, check=True
        ).stdout
        still_disabled = [
            package
            for package in (
                OTA_UI_PACKAGE,
                OTA_SETUP_PACKAGE,
            )
            if f"package:{package}" in disabled
        ]
        if still_disabled:
            raise ProvisionError(
                "OTA packages remain disabled: " + ", ".join(still_disabled)
            )
        print("OTA_RESTORE_OK packages=enabled override=restored")

    def verify_ota_block(self, wait_seconds: int = 30) -> None:
        disabled = self.adb_run(
            ["shell", "pm", "list", "packages", "-d"],
            timeout=10,
            check=True,
        ).stdout
        required = (OTA_UI_PACKAGE, OTA_SETUP_PACKAGE)
        missing = [
            package
            for package in required
            if f"package:{package}" not in disabled
        ]
        if missing:
            raise ProvisionError(f"OTA packages became enabled: {', '.join(missing)}")

        deadline = time.monotonic() + wait_seconds
        last_dump = ""
        last_log = ""
        while time.monotonic() < deadline:
            result = self.adb_run(
                ["shell", "dumpsys", "facebook.aloha.otaservice"], timeout=10
            )
            last_dump = result.stdout
            last_log = self.adb_run(
                ["shell", "logcat", "-d", "-v", "threadtime"], timeout=15
            ).stdout
            override_loaded = re.search(
                r"getLatestBooleanWithOptions \[18296358819858434\], "
                r"latestBoolean: false, source: OVERRIDE",
                last_log,
            )
            if (
                "getBool(kFirmwareOtaUpdateEnable): false" in last_dump
                and override_loaded
            ):
                print(
                    "OTA_BLOCK_OK packages=disabled "
                    "firmware_ota_update_enable=false source=OVERRIDE"
                )
                return
            time.sleep(2)
        raise ProvisionError(
            "OTA daemon did not report its firmware-update gate from the "
            "local override; recent dump/log follow:\n"
            + last_dump[-3000:]
            + "\n"
            + last_log[-3000:]
        )

    def compile_camera_light_host_speed(self) -> None:
        self.adb_run(
            ["shell", "am", "force-stop", "--user", "0", BATTERY_STATE_PACKAGE],
            timeout=10,
        )
        result = self.adb_run(
            [
                "shell",
                "cmd",
                "package",
                "compile",
                "-f",
                "-m",
                "speed",
                BATTERY_STATE_PACKAGE,
            ],
            timeout=120,
        )
        if result.returncode != 0 or "Success" not in result.stdout:
            raise ProvisionError(
                "could not generate the guarded battery-service ART cache: "
                + result.stdout
            )
        print(
            "CAMERA_LIGHT_ART_CACHE_OK host=platformbatterystate "
            "compiler_filter=speed"
        )

    def uid1000_boot_hook_active(self) -> bool:
        result = self.adb_run(
            ["shell", "ps", "-A", "-o", "USER,PID,ARGS"],
            timeout=10,
            check=True,
        )
        return any(
            fields[0] == "system" and "portal-camera-led-watch" in line
            for line in result.stdout.splitlines()
            if (fields := line.split(maxsplit=2))
        )

    def prepare_camera_light_install(self) -> None:
        installed, _ = self.package_sets()
        if BATTERY_STATE_PACKAGE not in installed:
            raise ProvisionError(
                f"required persistent system package is absent: {BATTERY_STATE_PACKAGE}"
            )
        if self.uid1000_boot_hook_active():
            print(
                "UID1000_BOOT_HOOK_RETAINED source=running-system-helper",
                flush=True,
            )
            return
        self.compile_camera_light_host_speed()

    def restore_uid1000_package_state_if_unused(self) -> None:
        retained = [
            path
            for path in (
                CAMERA_LIGHT_CONFIG_REMOTE,
                PRESENCE_UID1000_CONFIG_REMOTE,
            )
            if self.adb_run(
                ["shell", "test", "-e", path], timeout=5
            ).returncode == 0
        ]
        if retained:
            print(
                "UID1000_BOOT_HOOK_RETAINED features="
                + ",".join(path.rsplit("/", 1)[-1] for path in retained)
            )
            return
        self.compile_camera_light_host_speed()
        print("UID1000_BOOT_HOOK_RESTORED host=platformbatterystate")

    def package_sets(self) -> tuple[set[str], set[str]]:
        installed_result = self.adb_run(
            ["shell", "pm", "list", "packages"], timeout=15, check=True
        )
        disabled_result = self.adb_run(
            ["shell", "pm", "list", "packages", "-d"], timeout=15, check=True
        )

        def parse(output: str) -> set[str]:
            return {
                line.removeprefix("package:").strip()
                for line in output.splitlines()
                if line.startswith("package:")
            }

        return parse(installed_result.stdout), parse(disabled_result.stdout)

    @staticmethod
    def parse_debloat_backup(contents: str) -> dict[str, str]:
        lines = contents.splitlines()
        if not lines or lines[0] != "# portal-debloat-backup-v1":
            raise ProvisionError("unrecognized Portal debloat backup format")
        states: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            fields = line.split("\t")
            if len(fields) != 2:
                raise ProvisionError(f"invalid Portal debloat backup line: {line!r}")
            package, state = fields
            if package in states or package not in DEBLOAT_PACKAGES:
                raise ProvisionError(
                    f"unexpected package in Portal debloat backup: {package!r}"
                )
            if state not in {"enabled", "disabled", "absent"}:
                raise ProvisionError(
                    f"invalid state in Portal debloat backup: {state!r}"
                )
            states[package] = state
        missing = set(DEBLOAT_PACKAGES) - states.keys()
        if missing:
            raise ProvisionError(
                "Portal debloat backup is incomplete: " + ", ".join(sorted(missing))
            )
        return states

    def read_debloat_backup(self, required: bool = True) -> dict[str, str] | None:
        result = self.adb_run(
            ["shell", "cat", DEBLOAT_BACKUP_REMOTE], timeout=5
        )
        if result.returncode != 0:
            if required:
                raise ProvisionError(
                    f"debloat backup is absent: {DEBLOAT_BACKUP_REMOTE}"
                )
            return None
        return self.parse_debloat_backup(result.stdout)

    def ensure_debloat_backup(self) -> dict[str, str]:
        existing = self.read_debloat_backup(required=False)
        if existing is not None:
            print(f"DEBLOAT_BACKUP_OK existing=1 path={DEBLOAT_BACKUP_REMOTE}")
            return existing

        installed, disabled = self.package_sets()
        states = {
            package: (
                "absent"
                if package not in installed
                else "disabled"
                if package in disabled
                else "enabled"
            )
            for package in DEBLOAT_PACKAGES
        }
        contents = "# portal-debloat-backup-v1\n" + "".join(
            f"{package}\t{states[package]}\n" for package in DEBLOAT_PACKAGES
        )
        remote_tmp = DEBLOAT_BACKUP_REMOTE + ".tmp"
        with tempfile.TemporaryDirectory(prefix="portal-debloat-") as temporary:
            local = pathlib.Path(temporary) / "backup.tsv"
            local.write_text(contents, encoding="utf-8")
            self.adb_run(["push", str(local), remote_tmp], timeout=15, check=True)
        command = (
            f"chmod 0600 {shlex.quote(remote_tmp)} && "
            f"mv {shlex.quote(remote_tmp)} {shlex.quote(DEBLOAT_BACKUP_REMOTE)}"
        )
        self.adb_run(["shell", command], timeout=10, check=True)
        saved = self.read_debloat_backup(required=True)
        if saved != states:
            raise ProvisionError("debloat backup verification failed after write")
        print(f"DEBLOAT_BACKUP_OK existing=0 path={DEBLOAT_BACKUP_REMOTE}")
        return states

    @staticmethod
    def parse_component_backup(contents: str) -> dict[str, tuple[str, str]]:
        lines = contents.splitlines()
        if not lines or lines[0] != "# portal-debloat-components-backup-v1":
            raise ProvisionError("unrecognized component debloat backup format")
        expected = {component: category for category, component in DEBLOAT_COMPONENTS}
        states: dict[str, tuple[str, str]] = {}
        for line in lines[1:]:
            if not line:
                continue
            fields = line.split("\t")
            if len(fields) != 3:
                raise ProvisionError(f"invalid component backup line: {line!r}")
            category, component, state = fields
            if (
                component in states
                or component not in expected
                or expected[component] != category
            ):
                raise ProvisionError(
                    f"unexpected component in debloat backup: {component!r}"
                )
            if state not in {"default", "enabled", "disabled", "absent"}:
                raise ProvisionError(
                    f"invalid component state in debloat backup: {state!r}"
                )
            states[component] = (category, state)
        missing = set(DEBLOAT_COMPONENT_NAMES) - states.keys()
        if missing:
            raise ProvisionError(
                "component debloat backup is incomplete: "
                + ", ".join(sorted(missing))
            )
        return states

    def read_component_backup(
        self, required: bool = True
    ) -> dict[str, tuple[str, str]] | None:
        result = self.adb_run(
            ["shell", "cat", DEBLOAT_COMPONENT_BACKUP_REMOTE], timeout=10
        )
        if result.returncode != 0:
            if required:
                raise ProvisionError(
                    "component debloat backup is absent: "
                    + DEBLOAT_COMPONENT_BACKUP_REMOTE
                )
            return None
        return self.parse_component_backup(result.stdout)

    @staticmethod
    def component_override_set(package_dump: str, label: str) -> set[str]:
        match = re.search(
            rf"(?m)^      {re.escape(label)}:\s*\n"
            r"((?:        \S[^\n]*\n)*)",
            package_dump,
        )
        if not match:
            return set()
        return {line.strip() for line in match.group(1).splitlines() if line.strip()}

    def current_component_states(self) -> dict[str, tuple[str, str]]:
        installed, _ = self.package_sets()
        by_package: dict[str, list[tuple[str, str]]] = collections.defaultdict(list)
        for category, component in DEBLOAT_COMPONENTS:
            package, class_name = component.split("/", 1)
            by_package[package].append((category, class_name))
        states: dict[str, tuple[str, str]] = {}
        for package, entries in by_package.items():
            if package not in installed:
                for category, class_name in entries:
                    states[f"{package}/{class_name}"] = (category, "absent")
                continue
            dump = self.adb_run(
                ["shell", "dumpsys", "package", package], timeout=20, check=True
            ).stdout
            enabled = self.component_override_set(dump, "enabledComponents")
            disabled = self.component_override_set(dump, "disabledComponents")
            for category, class_name in entries:
                state = (
                    "enabled"
                    if class_name in enabled
                    else "disabled"
                    if class_name in disabled
                    else "default"
                )
                states[f"{package}/{class_name}"] = (category, state)
        return states

    def ensure_component_backup(self) -> dict[str, tuple[str, str]]:
        existing = self.read_component_backup(required=False)
        if existing is not None:
            print(
                "DEBLOAT_COMPONENT_BACKUP_OK existing=1 path="
                + DEBLOAT_COMPONENT_BACKUP_REMOTE
            )
            return existing
        states = self.current_component_states()
        contents = "# portal-debloat-components-backup-v1\n" + "".join(
            f"{states[component][0]}\t{component}\t{states[component][1]}\n"
            for component in DEBLOAT_COMPONENT_NAMES
        )
        self.push_text_atomic(contents, DEBLOAT_COMPONENT_BACKUP_REMOTE)
        saved = self.read_component_backup(required=True)
        if saved != states:
            raise ProvisionError("component debloat backup verification failed")
        print(
            "DEBLOAT_COMPONENT_BACKUP_OK existing=0 path="
            + DEBLOAT_COMPONENT_BACKUP_REMOTE
        )
        return states

    def push_text_atomic(self, contents: str, remote: str) -> None:
        remote_tmp = remote + ".tmp"
        with tempfile.TemporaryDirectory(prefix="portal-state-") as temporary:
            local = pathlib.Path(temporary) / "state.tsv"
            local.write_text(contents, encoding="utf-8")
            self.adb_run(["push", str(local), remote_tmp], timeout=20, check=True)
        command = (
            f"chmod 0600 {shlex.quote(remote_tmp)} && "
            f"mv {shlex.quote(remote_tmp)} {shlex.quote(remote)}"
        )
        self.adb_run(["shell", command], timeout=10, check=True)

    def prepare_component_actions(self, restore: bool) -> None:
        states = self.read_component_backup(required=False)
        if states is None:
            if not restore:
                states = self.ensure_component_backup()
            else:
                print("DEBLOAT_COMPONENT_RESTORE legacy_backup=absent actions=0")
                self.push_text_atomic(
                    "# portal-debloat-component-actions-v1\n",
                    DEBLOAT_COMPONENT_ACTIONS_REMOTE,
                )
                return
        actions = []
        for component in DEBLOAT_COMPONENT_NAMES:
            _, state = states[component]
            if state == "absent":
                continue
            if not restore and component in SELF_MANAGED_DEBLOAT_COMPONENTS:
                continue
            action = (
                "disable"
                if not restore
                else "default"
                if state == "default"
                else "enable"
                if state == "enabled"
                else "disable"
            )
            actions.append(f"{action}\t{component}\n")
        if not restore:
            account_backup = self.adb_run(
                ["shell", "test", "-f", META_ACCOUNT_BACKUP_REMOTE], timeout=5
            )
            if account_backup.returncode == 0:
                actions.append(f"enable\t{META_HARDWARE_AUTHENTICATOR}\n")
        self.push_text_atomic(
            "# portal-debloat-component-actions-v1\n" + "".join(actions),
            DEBLOAT_COMPONENT_ACTIONS_REMOTE,
        )
        print(
            f"DEBLOAT_COMPONENT_ACTIONS mode={'restore' if restore else 'disable'} "
            f"count={len(actions)}"
        )

    def apply_debloat(self) -> None:
        self.ensure_debloat_backup()
        self.ensure_component_backup()
        self.prepare_component_actions(restore=False)
        installed, _ = self.package_sets()
        for package in DEBLOAT_PACKAGES:
            if package not in installed:
                print(f"DEBLOAT_SKIP package={package} reason=absent")
                continue
            result = self.adb_run(
                ["shell", "pm", "disable-user", "--user", "0", package],
                timeout=15,
            )
            if result.returncode != 0:
                raise ProvisionError(
                    f"failed to disable debloat package {package}: {result.stdout}"
                )
            print(f"DEBLOAT_DISABLE package={package}")
        self.settle_package_state()
        self.verify_debloat(require_components=False)

    def restore_debloat(self) -> None:
        states = self.read_debloat_backup(required=True)
        assert states is not None
        self.prepare_component_actions(restore=True)
        installed, _ = self.package_sets()
        for package in DEBLOAT_PACKAGES:
            state = states[package]
            if state == "absent" or package not in installed:
                print(
                    f"DEBLOAT_RESTORE_SKIP package={package} "
                    f"original_state={state}"
                )
                continue
            action = "enable" if state == "enabled" else "disable-user"
            command = ["shell", "pm", action, "--user", "0", package]
            result = self.adb_run(command, timeout=15)
            if result.returncode != 0:
                raise ProvisionError(
                    f"failed to restore package {package} to {state}: {result.stdout}"
                )
            print(f"DEBLOAT_RESTORE package={package} state={state}")
        self.settle_package_state()
        self.verify_debloat_restored(require_components=False)

    def settle_package_state(self) -> None:
        # PackageManager writes package-restrictions.xml asynchronously. An
        # immediate reboot can discard a state that pm already reports live.
        print(
            f"PACKAGE_STATE_SETTLE seconds={PACKAGE_STATE_SETTLE_SECONDS}",
            flush=True,
        )
        time.sleep(PACKAGE_STATE_SETTLE_SECONDS)
        self.adb_run(["shell", "sync"], timeout=15, check=True)

    def verify_retained_platform(self, wait_seconds: int = 45) -> None:
        deadline = time.monotonic() + wait_seconds
        ai_pid = ""
        camera = ""
        webview = ""
        home = ""
        while time.monotonic() < deadline:
            ai_pid = self.adb_run(
                ["shell", "pidof", "com.facebook.portal.aiservice"],
                timeout=5,
            ).stdout.strip()
            camera = self.adb_run(
                ["shell", "dumpsys", "media.camera"], timeout=15
            ).stdout
            webview = self.adb_run(
                ["shell", "dumpsys", "webviewupdate"], timeout=15
            ).stdout
            home = self.adb_run(
                [
                    "shell",
                    "cmd",
                    "package",
                    "resolve-activity",
                    "--brief",
                    "-a",
                    "android.intent.action.MAIN",
                    "-c",
                    "android.intent.category.HOME",
                ],
                timeout=10,
            ).stdout.strip()
            if (
                ai_pid
                and "Number of camera devices: 2" in camera
                and "Current WebView package (name, version): "
                "(com.facebook.portal.webview," in webview
                and "/" in home
            ):
                print(
                    f"DEBLOAT_PLATFORM_OK aiservice_pid={ai_pid} cameras=2 "
                    f"home={home.splitlines()[-1]}"
                )
                return
            time.sleep(2)
        raise ProvisionError(
            "retained Portal services did not become ready after package-state change: "
            f"aiservice_pid={ai_pid!r} cameras_2="
            f"{int('Number of camera devices: 2' in camera)} webview="
            f"{int('(com.facebook.portal.webview,' in webview)} home={home!r}"
        )

    def verify_debloat(self, require_components: bool = True) -> None:
        installed, disabled = self.package_sets()
        missing = [
            package
            for package in DEBLOAT_PACKAGES
            if package in installed and package not in disabled
        ]
        if missing:
            raise ProvisionError(
                "debloat packages became enabled: " + ", ".join(missing)
            )
        component_count = 0
        categories: collections.Counter[str] = collections.Counter()
        if require_components:
            saved = self.read_component_backup(required=True)
            assert saved is not None
            current = self.current_component_states()
            component_mismatches = [
                component
                for component, (_, original) in saved.items()
                if original != "absent"
                and component not in SELF_MANAGED_DEBLOAT_COMPONENTS
                and current[component][1] != "disabled"
            ]
            if component_mismatches:
                raise ProvisionError(
                    "Meta cloud components became enabled: "
                    + ", ".join(component_mismatches)
                )
            for component, (category, original) in saved.items():
                if (
                    original != "absent"
                    and component not in SELF_MANAGED_DEBLOAT_COMPONENTS
                ):
                    component_count += 1
                    categories[category] += 1
            running = self.adb_run(
                ["shell", "dumpsys", "activity", "services"],
                timeout=25,
                check=True,
            ).stdout
            forbidden = (
                "com.facebook.mqtt.service.MqttServiceV2",
                "com.facebook.multiusermqtt.MultiuserMqttService",
                "com.facebook.push.mqtt.service.MqttPushHelperService",
                "com.facebook.aloha.wifidiagnostic.WifiDiagnosticService",
                "com.facebook.alohasdk.pushnotification.PushNotificationService",
                "com.facebook.aloha.system.services.bugreporter.PillViewService",
            )
            active = [name for name in forbidden if name in running]
            if active:
                raise ProvisionError(
                    "disabled Meta cloud services are still running: "
                    + ", ".join(active)
                )
        self.verify_retained_platform()
        category_summary = ",".join(
            f"{name}:{categories[name]}" for name in sorted(categories)
        )
        print(
            f"DEBLOAT_OK packages={len(set(DEBLOAT_PACKAGES) & installed)} "
            f"components={component_count} categories={category_summary or 'pending'}"
        )

    def verify_debloat_restored(self, require_components: bool = True) -> None:
        states = self.read_debloat_backup(required=True)
        assert states is not None
        installed, disabled = self.package_sets()
        mismatches = []
        for package, state in states.items():
            if state == "absent":
                continue
            actual = "disabled" if package in disabled else "enabled"
            if package not in installed or actual != state:
                mismatches.append(f"{package}={actual}, expected {state}")
        if mismatches:
            raise ProvisionError("debloat restore mismatch: " + "; ".join(mismatches))
        if require_components:
            saved_components = self.read_component_backup(required=False)
            if saved_components is not None:
                current = self.current_component_states()
                component_mismatches = [
                    f"{component}={current[component][1]}, expected {state}"
                    for component, (_, state) in saved_components.items()
                    if state != "absent" and current[component][1] != state
                ]
                if component_mismatches:
                    raise ProvisionError(
                        "component debloat restore mismatch: "
                        + "; ".join(component_mismatches)
                    )
        self.verify_retained_platform()
        print(
            "DEBLOAT_RESTORE_OK components="
            + ("verified" if require_components else "pending")
        )

    def verify_presence_runtime(
        self,
        require_profile: bool,
        expected_analysis_fps: int | None = None,
        wait_seconds: int = 90,
    ) -> None:
        deadline = time.monotonic() + wait_seconds
        pid = ""
        camera_active = False
        camera_allowed = False
        camera_appop = ""
        presence_no_users = False
        privacy_blocked = False
        presence_event = False
        analysis_frames = False
        roi_frames = False
        pose_metrics = False
        frame_processor_loaded = False
        wide_frame = False
        loaded_keys: set[str] = set()
        analysis_fps_applied = False
        helper_activation = False
        uid1000_configured = expected_analysis_fps is None
        if expected_analysis_fps is not None:
            configured = self.adb_run(
                ["shell", "cat", PRESENCE_UID1000_CONFIG_REMOTE], timeout=5
            )
            uid1000_configured = (
                configured.returncode == 0
                and configured.stdout.strip() == str(expected_analysis_fps)
            )
        threads = ""
        while time.monotonic() < deadline:
            pid = self.adb_run(
                ["shell", "pidof", "com.facebook.portal.aiservice"], timeout=5
            ).stdout.strip()
            camera = self.adb_run(
                ["shell", "dumpsys", "media.camera"], timeout=15
            ).stdout
            camera_active = (
                "Active Camera Clients:" in camera
                and "Client Package Name: com.facebook.portal.aiservice" in camera
            )
            appops_result = self.adb_run(
                ["shell", "cmd", "appops", "get", "com.facebook.portal.aiservice", "CAMERA"],
                timeout=10,
            )
            appops = appops_result.stdout
            camera_appop = " ".join(appops.split()) or "no-operation-recorded"
            explicit_modes = re.findall(
                r"^\s*(?:Uid mode:\s*)?CAMERA:\s*(\w+)", appops, re.MULTILINE
            )
            default_allow = re.fullmatch(
                r"No operations\.\s+Default mode:\s*allow\s*", appops.strip()
            ) is not None
            camera_allowed = appops_result.returncode == 0 and (
                all(mode == "allow" for mode in explicit_modes)
                if explicit_modes else default_allow
            )
            logs = self.adb_run(
                ["shell", "logcat", "-d", "-v", "brief"], timeout=20
            ).stdout
            presence_event = PRESENCE_LOG_MARKER in logs
            presence_no_users = (
                "CAMERA_SERVICE not running, but no users found yet" in logs
            )
            privacy_blocked = any(
                marker in logs.lower()
                for marker in (
                    "cannot start privacy mode on",
                    "privacy mode is on",
                )
            )
            analysis_frames = PRESENCE_ANALYSIS_FRAME_MARKER in logs
            roi_frames = PRESENCE_ROI_FRAME_MARKER in logs
            active_request = camera.split("Tag monitoring disabled", 1)[0]
            wide_frame = (
                PRESENCE_WIDE_FRAME_MARKER in logs
                and "com.facebook.alohasdk.dewarp_crop_rect.width"
                not in active_request
            )
            loaded_keys = {
                key
                for key, expected in PRESENCE_PROFILE_SETTINGS.items()
                if any(
                    "settings_config.xml" in line
                    and key in line
                    and re.search(
                        rf"\b{str(expected).lower()}\b", line, re.IGNORECASE
                    )
                    for line in logs.splitlines()
                )
            }
            analysis_fps_applied = expected_analysis_fps is not None and any(
                "Setting AI Processing FPS" in line
                and re.search(
                    rf"\b{expected_analysis_fps}(?:\.0+)?\b", line
                )
                for line in logs.splitlines()
            )
            helper_activation = expected_analysis_fps is not None and any(
                "PortalPresence" in line
                and f"presence FPS activation complete fps={expected_analysis_fps}"
                in line
                and "uid=1000" in line
                for line in logs.splitlines()
            )
            config_ready = not require_profile or loaded_keys == set(
                PRESENCE_PROFILE_KEYS
            )
            fps_ready = expected_analysis_fps is None or (
                analysis_fps_applied
                and helper_activation
                and uid1000_configured
            )
            metrics = self.adb_run(
                [
                    "shell",
                    "dumpsys",
                    "activity",
                    "service",
                    CAMERA_SERVICE_COMPONENT,
                ],
                timeout=20,
            ).stdout
            pose_section = ""
            frame_section = ""
            if "[ PoseEstimatorManagerMetrics ]" in metrics:
                pose_section = metrics.split(
                    "[ PoseEstimatorManagerMetrics ]", 1
                )[1].split("[ AlohaFrameProcessor ]", 1)[0]
            if "[ AlohaFrameProcessor ]" in metrics:
                frame_section = metrics.split(
                    "[ AlohaFrameProcessor ]", 1
                )[1].split("[ AiCameramanController ]", 1)[0]
                frame_processor_loaded = bool(frame_section)
            latency_bucket = re.compile(r"\b\d+ ms - \d+ ms:\s+\d+\b")
            pose_metrics = bool(latency_bucket.search(pose_section))
            if (
                pid
                and camera_active
                and camera_allowed
                and analysis_frames
                and roi_frames
                and pose_metrics
                and frame_processor_loaded
                and (not require_profile or wide_frame)
                and config_ready
                and fps_ready
            ):
                threads = self.adb_run(
                    ["shell", "ps", "-T", "-p", pid.split()[0]], timeout=10
                ).stdout
                disabled_workers = [
                    name
                    for name in ("BackgroundDetec", "alohaLivenessMa")
                    if name not in threads
                ]
                print(
                    "PRESENCE_RUNTIME_OK "
                    f"pid={pid.split()[0]} camera=active appop=allow "
                    "pipeline=active analysis_frames=observed "
                    "roi_frames=observed pose_metrics=populated "
                    "frame_processor=loaded "
                    f"field_of_view={'full' if wide_frame else 'firmware_default'} "
                    f"presence_event={'observed' if presence_event else 'not_observed'} "
                    f"profile_keys={len(loaded_keys)} "
                    f"analysis_fps={expected_analysis_fps or 'unlimited'} "
                    f"activation_host={'uid1000' if expected_analysis_fps else 'none'} "
                    f"workers_absent={','.join(disabled_workers) or 'none'}"
                )
                return
            time.sleep(2)
        camera_hint = ""
        if not camera_active:
            if presence_no_users:
                camera_hint += (
                    " AIService logs report no users; its camera pipeline "
                    "may not have initialized."
                )
            if privacy_blocked:
                camera_hint += " AIService logs also report privacy mode blocking startup."
            camera_hint += (
                " An inactive camera can also result from the physical camera "
                "cover or camera/microphone privacy control."
            )
        raise ProvisionError(
            "presence pipeline did not pass its live compatibility check: "
            f"pid={pid!r} camera_active={int(camera_active)} "
            f"camera_allowed={int(camera_allowed)} "
            f"camera_appop={camera_appop!r} "
            f"analysis_frames={int(analysis_frames)} "
            f"roi_frames={int(roi_frames)} "
            f"pose_metrics={int(pose_metrics)} "
            f"frame_processor_loaded={int(frame_processor_loaded)} "
            f"wide_frame={int(wide_frame)} "
            f"presence_event={int(presence_event)} "
            f"analysis_fps_applied={int(analysis_fps_applied)} "
            f"helper_activation={int(helper_activation)} "
            f"uid1000_configured={int(uid1000_configured)} "
            f"presence_no_users={int(presence_no_users)} "
            f"privacy_blocked={int(privacy_blocked)} "
            f"profile_keys={','.join(sorted(loaded_keys)) or 'none'}."
            f"{camera_hint}"
        )

    def verify_meta_accounts_removed(self) -> None:
        accounts = self.meta_accounts()
        if accounts:
            raise ProvisionError(
                "Meta accounts remain: "
                + ", ".join(f"{account_type}/{name}" for name, account_type in accounts)
            )
        disabled = self.disabled_meta_authenticators()
        missing = set(META_AUTHENTICATOR_COMPONENTS) - disabled
        if missing:
            raise ProvisionError(
                "Meta authenticators became enabled: " + ", ".join(sorted(missing))
            )
        hardware_class = META_HARDWARE_AUTHENTICATOR.split("/", 1)[1]
        if hardware_class in disabled:
            raise ProvisionError(
                "the required hardware-identity authenticator is disabled"
            )
        package_state = self.adb_run(
            ["shell", "pm", "list", "packages", "-d"], timeout=15, check=True
        ).stdout
        if "package:com.facebook.alohaservices.alohausers" in package_state:
            raise ProvisionError("alohausers package was disabled instead of its authenticators")
        self.verify_retained_platform()
        print(
            "META_ACCOUNTS_REMOVED_OK accounts=0 authenticators=disabled "
            "alohausers=enabled"
        )

    def verify_requested_state(self) -> None:
        if self.persist_wireless_adb:
            persistent_port = self.adb_run(
                ["shell", "getprop", "persist.adb.tcp.port"],
                timeout=5,
                check=True,
            ).stdout.strip()
            if persistent_port != "5555":
                raise ProvisionError(
                    "wireless ADB did not persist on TCP port 5555: "
                    f"persist.adb.tcp.port={persistent_port!r}"
                )
            print("WIRELESS_ADB_OK persistent_port=5555")
        if self.audio:
            self.verify_watchdog()
        if self.restore_audio:
            self.verify_audio_restored()
        if self.device_owner:
            self.verify_device_owner()
        if self.kiosk_home:
            self.verify_kiosk_home(enabled=True)
        if self.restore_kiosk_home:
            self.verify_kiosk_home(enabled=False)
        if self.disable_updates:
            self.disable_ota_packages()
            self.verify_ota_block()
        if self.enable_updates:
            self.verify_ota_restored()
        if self.debloat:
            self.verify_debloat()
        if self.restore_bloat:
            self.verify_debloat_restored()
        if self.remove_meta_accounts:
            self.verify_meta_accounts_removed()
        if (
            self.optimize_presence
            or self.presence_fps_cap is not None
            or self.restore_presence_fps
        ):
            self.verify_presence_runtime(
                require_profile=True,
                expected_analysis_fps=self.presence_fps_cap,
            )
        if self.restore_presence_profile:
            self.verify_presence_runtime(require_profile=False)
        if self.restore_presence_fps or self.restore_presence_profile:
            if self.adb_run(
                ["shell", "test", "-e", PRESENCE_UID1000_CONFIG_REMOTE],
                timeout=5,
            ).returncode == 0:
                raise ProvisionError("UID-1000 presence activation config remains")
        if self.privacy_dns or self.dhcp_dns or self.restore_privacy_dns:
            self.verify_privacy_dns()
        if self.allow_app_updates or self.restore_app_verifier:
            self.verify_app_verifier_setting()
        if self.shizuku:
            self.verify_shizuku()
        if self.remove_shizuku:
            self.verify_shizuku_removed()
        if self.disable_camera_light:
            self.verify_camera_light_disabled()
        if self.restore_camera_light:
            self.verify_camera_light_restored()

    def verify_camera_light_disabled(self, wait_seconds: int = 35) -> None:
        if self.adb_run(
            ["shell", "test", "-f", CAMERA_LIGHT_INSTALLED_REMOTE], timeout=5
        ).returncode != 0:
            raise ProvisionError("camera-light install marker is absent")
        if self.adb_run(
            ["shell", "test", "-f", CAMERA_LIGHT_CONFIG_REMOTE], timeout=5
        ).returncode != 0:
            raise ProvisionError("camera-light UID-1000 configuration is absent")
        if self.adb_run(
            ["shell", "test", "-x", CAMERA_LIGHT_HELPER_INSTALLED], timeout=5
        ).returncode != 0:
            raise ProvisionError("camera-light watchdog executable is absent")
        deadline = time.monotonic() + wait_seconds
        last_process = ""
        last_logs = ""
        while time.monotonic() < deadline:
            processes = self.adb_run(
                ["shell", "ps", "-A", "-o", "USER,PID,PPID,NAME,ARGS"],
                timeout=10,
                check=True,
            ).stdout
            last_process = next(
                (
                    line
                    for line in processes.splitlines()
                    if "portal-camera-led-watch" in line
                    or "portal-led-watc" in line
                ),
                "",
            )
            last_logs = self.adb_run(
                ["shell", "logcat", "-d", "-s", "PortalCameraLed:*"],
                timeout=10,
            ).stdout
            if last_process and "watchdog connected uid=1000" in last_logs:
                selinux = self.adb_run(
                    ["shell", "getenforce"], timeout=5, check=True
                ).stdout.strip()
                if selinux != "Enforcing":
                    raise ProvisionError(f"SELinux is not enforcing: {selinux!r}")
                print(
                    "CAMERA_LIGHT_OK watchdog_uid=1000 "
                    "host=platformbatterystate trigger=persistent_app "
                    "selinux=Enforcing"
                )
                return
            time.sleep(2)
        raise ProvisionError(
            "camera-light UID-1000 watchdog did not start and connect; "
            f"process={last_process!r} logs={last_logs[-2000:]!r}"
        )

    def verify_camera_light_restored(self) -> None:
        if self.adb_run(
            ["shell", "test", "-f", CAMERA_LIGHT_RESTORED_REMOTE], timeout=5
        ).returncode != 0:
            raise ProvisionError("camera-light restore marker is absent")
        if self.adb_run(
            ["shell", "test", "-e", CAMERA_LIGHT_CONFIG_REMOTE], timeout=5
        ).returncode == 0:
            raise ProvisionError("camera-light UID-1000 configuration remains")
        retained = any(
            self.adb_run(["shell", "test", "-e", path], timeout=5).returncode
            == 0
            for path in (PRESENCE_UID1000_CONFIG_REMOTE,)
        )
        helper_present = self.adb_run(
            ["shell", "test", "-e", CAMERA_LIGHT_HELPER_INSTALLED], timeout=5
        ).returncode == 0
        if retained != helper_present:
            raise ProvisionError(
                "UID-1000 helper retention does not match remaining features: "
                f"retained_features={int(retained)} helper={int(helper_present)}"
            )
        processes = self.adb_run(
            ["shell", "ps", "-A", "-o", "USER,PID,PPID,NAME,ARGS"],
            timeout=10,
            check=True,
        ).stdout
        camera_logs = self.adb_run(
            ["shell", "logcat", "-d", "-s", "PortalCameraLed:*"], timeout=10
        ).stdout
        if "watchdog connected uid=1000" in camera_logs:
            raise ProvisionError("camera-light watchdog remains active")
        print(
            "CAMERA_LIGHT_RESTORE_OK camera_watchdog=disabled "
            f"uid1000_helper={'retained' if retained else 'absent'}"
        )

    def verify_across_two_reboots(self, first_boot: str | None = None) -> None:
        if first_boot is None:
            _, first_boot = self.reboot()
        self.verify_requested_state()
        print("VERIFY_REBOOT starting", flush=True)
        before, second_boot = self.reboot()
        if before != first_boot:
            raise ProvisionError(
                f"unexpected boot changed before verification: {first_boot} -> {before}"
            )
        self.verify_requested_state()
        self.write_state("complete", first_boot, second_boot)
        print(
            f"PROVISION_OK first_boot={first_boot} second_boot={second_boot} "
            f"logs={self.log_dir}"
        )

    def provision(self) -> None:
        self.connect(wait_seconds=30)
        resumed_pending = False
        if self.status_only:
            self.verify_target(require_supported=False)
            self.print_status()
            if self.backup_path:
                self.create_backup_bundle(self.backup_path)
            return
        if self.recover:
            self.verify_target(require_supported=False)
            if not self.recover_actions():
                return
            self.recover = False
            resumed_pending = True
        if self.dry_run:
            self.verify_target(require_supported=False)
            status = self.print_status()
            self.dry_run_report(status)
            if self.backup_path:
                self.create_backup_bundle(self.backup_path)
            return
        self.verify_target()
        if self.backup_path:
            self.create_backup_bundle(self.backup_path)
        self.audio_already_configured = (
            self.audio_preflight() if self.audio else False
        )
        if self.audio_already_configured and self.requested_actions() == {
            "audio": True
        }:
            if resumed_pending:
                self.write_state("complete")
            print(f"PROVISION_ALREADY_COMPLETE actions=audio logs={self.log_dir}")
            return
        self.write_state("pending")
        already_owner = self.device_owner_preflight() if self.device_owner else False
        already_meta_clean = (
            self.meta_accounts_preflight() if self.remove_meta_accounts else False
        )
        if self.debloat:
            self.apply_debloat()
        if self.restore_bloat:
            self.restore_debloat()
        if self.disable_camera_light or self.presence_fps_cap is not None:
            self.prepare_camera_light_install()
        if self.disable_updates:
            self.disable_ota_packages()
        if self.privacy_dns:
            self.apply_privacy_dns()
        if self.dhcp_dns:
            self.apply_dhcp_dns()
        if self.restore_privacy_dns:
            self.restore_private_dns()
        if self.allow_app_updates:
            self.allow_third_party_app_updates()
        if self.restore_app_verifier:
            self.restore_app_verifier_setting()
        if (
            (
                self.presence_fps_cap is not None
                or self.restore_presence_fps
                or self.restore_presence_profile
            )
            and not (self.debloat or self.restore_bloat)
        ):
            self.push_text_atomic(
                "# portal-debloat-component-actions-v1\n",
                DEBLOAT_COMPONENT_ACTIONS_REMOTE,
            )

        privileged_action = (
            (self.audio and not self.audio_already_configured)
            or self.restore_audio
            or self.disable_updates
            or self.enable_updates
            or self.debloat
            or self.restore_bloat
            or self.optimize_presence
            or self.restore_presence_profile
            or self.presence_fps_cap is not None
            or self.restore_presence_fps
            or (self.device_owner and not already_owner)
            or (self.remove_meta_accounts and not already_meta_clean)
            or self.shizuku
            or self.remove_shizuku
            or self.disable_camera_light
            or self.restore_camera_light
        )
        if not privileged_action:
            if self.kiosk_home:
                self.configure_kiosk_home(enabled=True)
            if self.restore_kiosk_home:
                self.configure_kiosk_home(enabled=False)
            self.verify_across_two_reboots()
            return

        persistent_port = self.adb_run(
            ["shell", "getprop", "persist.adb.tcp.port"],
            timeout=5,
            check=True,
        ).stdout.strip()
        self.persist_wireless_adb = persistent_port != "5555"
        if persistent_port != "5555":
            print(
                "STOCK_ADB_REENABLE_REQUIRED persistent_port=unset\n"
                "Keep USB connected. After every reboot until the exploit "
                "reports WIRELESS_ADB_OK, enable ADB on the Portal and run "
                "`adb -d tcpip 5555` from another terminal. The provisioner "
                "waits up to 180 seconds for each reconnect.",
                flush=True,
            )

        if not self.skip_build:
            build(
                target=self.target,
                build_audio=self.audio and not self.audio_already_configured,
                build_account=self.remove_meta_accounts,
                build_components=(
                    self.debloat
                    or self.restore_bloat
                    or self.presence_fps_cap is not None
                    or self.restore_presence_fps
                    or self.restore_presence_profile
                ),
                build_shizuku=self.shizuku,
                build_presence=False,
                build_uid1000=(
                    self.disable_camera_light
                    or self.presence_fps_cap is not None
                ),
                build_sentinel=True,
            )
        if self.shizuku:
            self.install_shizuku_payload()
        if self.restore_presence_fps or self.restore_presence_profile:
            self.uninstall_presence_helper()
        self.prepare_exploit_sentinel()
        sentinel_removed = False
        try:
            self.stage()
            clean_boot_id: str | None = None
            for attempt in range(1, self.attempts + 1):
                if clean_boot_id is None:
                    print(f"INSTALL_ATTEMPT={attempt} preparing clean boot", flush=True)
                    _, boot_id = self.reboot()
                else:
                    boot_id = clean_boot_id
                    clean_boot_id = None
                    print(
                        f"INSTALL_ATTEMPT={attempt} using post-attempt clean boot "
                        f"boot_id={boot_id}",
                        flush=True,
                    )
                try:
                    base = self.kaslr_base(str(attempt))
                    memstart = self.memstart(str(attempt))
                except ProvisionError as exc:
                    print(f"ADDRESS_DISCOVERY_RETRY attempt={attempt} error={exc}")
                    continue
                print(
                    f"RUNTIME_ADDRESSES attempt={attempt} boot_id={boot_id} "
                    f"kaslr={base:#x} memstart={memstart:#x}",
                    flush=True,
                )
                exploit_ok = self.exploit(base, memstart, attempt)
                post_attempt_boot = self.connect_after_reboot(boot_id)
                if not exploit_ok:
                    clean_boot_id = post_attempt_boot
                    continue
                self.uninstall_exploit_sentinel()
                sentinel_removed = True
                if self.enable_updates:
                    self.enable_ota_packages()
                if self.remove_shizuku:
                    self.uninstall_shizuku_payload()
                if self.presence_fps_cap is not None:
                    self.uninstall_presence_helper()
                if self.kiosk_home:
                    self.configure_kiosk_home(enabled=True)
                if self.restore_kiosk_home:
                    self.configure_kiosk_home(enabled=False)
                if (
                    self.restore_camera_light
                    or self.restore_presence_fps
                    or self.restore_presence_profile
                ):
                    self.restore_uid1000_package_state_if_unused()
                self.verify_across_two_reboots(first_boot=post_attempt_boot)
                return
        finally:
            if not sentinel_removed:
                self.uninstall_exploit_sentinel(best_effort=True)
        raise ProvisionError(f"provisioning failed after {self.attempts} attempts")


def build(
    target: PortalTarget | None,
    build_audio: bool,
    build_account: bool,
    build_components: bool,
    build_shizuku: bool,
    build_presence: bool,
    build_uid1000: bool,
    build_sentinel: bool,
) -> None:
    if target is None:
        raise ProvisionError("target must be selected before building")
    commands = [
        ["make", "-C", str(ROOT / "exploit"), "-j2", target.make_target]
    ]
    if build_audio:
        commands.append(["make", "-C", str(ROOT / "helper"), "native"])
    if build_account:
        commands.append(["make", "-C", str(ROOT / "exploit"), "account-ctl"])
    if build_components:
        commands.append(["make", "-C", str(ROOT / "exploit"), "component-ctl"])
    if build_shizuku:
        commands.append(["make", "-C", str(ROOT / "shizuku-helper"), "all"])
    if build_presence:
        commands.append(["make", "-C", str(ROOT / "presence-helper"), "all"])
    if build_uid1000:
        commands.append(["make", "-C", str(ROOT / "uid1000-helper"), "all"])
    if build_sentinel:
        commands.append(["make", "-C", str(ROOT / "exploit-sentinel"), "all"])
    for command in commands:
        result = subprocess.run(command, cwd=ROOT, check=False)
        if result.returncode != 0:
            raise ProvisionError(f"build failed: {shlex.join(command)}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Inspect, back up, provision, recover, and verify supported Meta "
            "Portal devices."
        )
    )
    parser.add_argument("--serial", default="192.168.1.72:5555")
    parser.add_argument("--attempts", type=int, default=12)
    parser.add_argument(
        "--profile",
        choices=("kiosk",),
        help="select the complete, tested Kiosk Satellite provisioning profile",
    )
    audio_group = parser.add_mutually_exclusive_group()
    audio_group.add_argument(
        "--audio",
        action="store_true",
        help=(
            "install the persistent hardware AEC/NS watchdog; this remains "
            "the default action when no provisioning action is specified"
        ),
    )
    audio_group.add_argument(
        "--restore-audio",
        action="store_true",
        help="restore AIService's original native loader and remove the audio watchdog",
    )
    parser.add_argument(
        "--device-owner",
        action="store_true",
        help=(
            "install Kiosk Satellite as Device Owner and verify it "
            "across both reboots"
        ),
    )
    kiosk_home_group = parser.add_mutually_exclusive_group()
    kiosk_home_group.add_argument(
        "--kiosk-home",
        action="store_true",
        help=(
            "make Kiosk Satellite the persistent HOME app through its Device "
            "Owner API, preventing Meta's invalid-account home from taking focus"
        ),
    )
    kiosk_home_group.add_argument(
        "--restore-kiosk-home",
        action="store_true",
        help="release Kiosk Satellite's HOME role and restore Android home resolution",
    )
    parser.add_argument(
        "--skip-build", action="store_true", help="use existing build outputs"
    )
    shizuku_group = parser.add_mutually_exclusive_group()
    shizuku_group.add_argument(
        "--shizuku",
        action="store_true",
        help=(
            "install official Shizuku and a device-local boot helper that "
            "starts it with Android shell privileges through loopback ADB"
        ),
    )
    shizuku_group.add_argument(
        "--remove-shizuku",
        action="store_true",
        help="remove Shizuku, its boot helper, and the helper's authorized ADB key",
    )
    parser.add_argument(
        "--shizuku-apk",
        type=pathlib.Path,
        metavar="PATH",
        help=(
            "use a local Shizuku APK with --shizuku instead of downloading "
            f"the pinned official {SHIZUKU_VERSION} release"
        ),
    )
    app_update_group = parser.add_mutually_exclusive_group()
    app_update_group.add_argument(
        "--allow-app-updates",
        action="store_true",
        help=(
            "persistently disable Meta's certificate allowlist so Kiosk "
            "Satellite and other non-Meta apps can update"
        ),
    )
    app_update_group.add_argument(
        "--restore-app-verifier",
        action="store_true",
        help=(
            "restore package_verifier_enable and Meta's verifier package to "
            "the states saved by the first --allow-app-updates run"
        ),
    )
    update_group = parser.add_mutually_exclusive_group()
    update_group.add_argument(
        "--disable-updates",
        action="store_true",
        help=(
            "disable Meta's OTA UI/test packages and install a persistent "
            "MobileConfig override for the native OTA daemon"
        ),
    )
    update_group.add_argument(
        "--enable-updates",
        action="store_true",
        help="restore the original MobileConfig override and re-enable OTA packages",
    )
    camera_light_group = parser.add_mutually_exclusive_group()
    camera_light_group.add_argument(
        "--disable-camera-light",
        action="store_true",
        help=(
            "install a persistent UID-1000 watchdog that clears the green "
            "software-controlled camera indicator; the orange physical-cover "
            "light is hardware-controlled"
        ),
    )
    camera_light_group.add_argument(
        "--restore-camera-light",
        action="store_true",
        help=(
            "remove the camera-light watchdog and boot hook, then restore "
            "the battery service's original ART cache"
        ),
    )
    debloat_group = parser.add_mutually_exclusive_group()
    debloat_group.add_argument(
        "--debloat",
        action="store_true",
        help=(
            "persistently disable the conservative Meta app/telemetry "
            "profile and save each package's original state"
        ),
    )
    debloat_group.add_argument(
        "--restore-bloat",
        action="store_true",
        help="restore package states saved by the first --debloat run",
    )
    parser.add_argument(
        "--remove-meta-accounts",
        action="store_true",
        help=(
            "remove the three Portal user accounts locally and persistently "
            "disable only their authenticator service components"
        ),
    )
    presence_group = parser.add_mutually_exclusive_group()
    presence_group.add_argument(
        "--optimize-presence",
        action="store_true",
        help=(
            "disable Smart Camera background segmentation, liveness scoring, "
            "and re-identification, force full-frame capture, and require "
            "AIService's analysis and pose pipeline to remain live"
        ),
    )
    parser.add_argument(
        "--presence-fps-cap",
        type=int,
        metavar="FPS",
        help=(
            "cap only AIService's presence-analysis rate (1-10 FPS); Kiosk "
            "Satellite RTSP capture keeps its configured frame rate"
        ),
    )
    privacy_group = parser.add_mutually_exclusive_group()
    privacy_group.add_argument(
        "--privacy-dns",
        metavar="HOSTNAME",
        help=(
            "persistently use the specified DNS-over-TLS filtering resolver; "
            "the resolver controls the actual domain block list"
        ),
    )
    privacy_group.add_argument(
        "--dhcp-dns",
        action="store_true",
        help=(
            "disable Android Private DNS and use the DNS servers supplied "
            "by the connected network"
        ),
    )
    privacy_group.add_argument(
        "--restore-privacy-dns",
        action="store_true",
        help=(
            "restore the Android DNS settings saved by the first "
            "--privacy-dns or --dhcp-dns run"
        ),
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--status",
        action="store_true",
        help="print a read-only JSON health report without exploiting or rebooting",
    )
    mode_group.add_argument(
        "--dry-run",
        action="store_true",
        help="inspect the device and print the requested plan without changing it",
    )
    mode_group.add_argument(
        "--recover",
        action="store_true",
        help="clean stale staging and resume actions from a pending state manifest",
    )
    parser.add_argument(
        "--backup",
        type=pathlib.Path,
        metavar="PATH",
        help="create a timestamped diagnostic and configuration backup archive",
    )
    presence_group.add_argument(
        "--restore-presence-profile",
        action="store_true",
        help=(
            "restore the AIService settings file saved by the first "
            "--optimize-presence run"
        ),
    )
    presence_group.add_argument(
        "--restore-presence-fps",
        action="store_true",
        help=(
            "remove only the optional analysis FPS cap while keeping the "
            "wide presence optimization"
        ),
    )
    parser.add_argument(
        "--log-dir",
        type=pathlib.Path,
        help="directory for exploit attempt logs (default: a timestamp under /tmp)",
    )
    args = parser.parse_args()
    if not 1 <= args.attempts <= 100:
        parser.error("--attempts must be between 1 and 100")
    if args.presence_fps_cap is not None and not 1 <= args.presence_fps_cap <= 10:
        parser.error("--presence-fps-cap must be between 1 and 10")
    if args.presence_fps_cap is not None and (
        args.restore_presence_profile or args.restore_presence_fps
    ):
        parser.error(
            "--presence-fps-cap cannot be combined with a presence rollback"
        )
    if args.presence_fps_cap is not None:
        # The activation activity also applies Meta's other camera toggles.
        # Always pair the cap with the tested full-scene presence profile.
        args.optimize_presence = True
    if args.profile == "kiosk":
        conflicting = [
            flag
            for enabled, flag in (
                (args.restore_audio, "--restore-audio"),
                (args.restore_kiosk_home, "--restore-kiosk-home"),
                (args.enable_updates, "--enable-updates"),
                (args.restore_bloat, "--restore-bloat"),
                (args.restore_presence_profile, "--restore-presence-profile"),
                (args.restore_presence_fps, "--restore-presence-fps"),
                (args.restore_app_verifier, "--restore-app-verifier"),
            )
            if enabled
        ]
        if conflicting:
            parser.error(
                "--profile kiosk cannot be combined with rollback actions: "
                + ", ".join(conflicting)
            )
        args.audio = True
        args.device_owner = True
        args.kiosk_home = True
        args.disable_updates = True
        args.debloat = True
        args.remove_meta_accounts = True
        args.optimize_presence = True
        args.allow_app_updates = True
    selected = any(
        (
            args.audio,
            args.restore_audio,
            args.device_owner,
            args.kiosk_home,
            args.restore_kiosk_home,
            args.disable_updates,
            args.enable_updates,
            args.debloat,
            args.restore_bloat,
            args.remove_meta_accounts,
            args.optimize_presence,
            args.restore_presence_profile,
            args.presence_fps_cap is not None,
            args.restore_presence_fps,
            args.privacy_dns,
            args.dhcp_dns,
            args.restore_privacy_dns,
            args.allow_app_updates,
            args.restore_app_verifier,
            args.shizuku,
            args.remove_shizuku,
            args.disable_camera_light,
            args.restore_camera_light,
        )
    )
    if args.shizuku_apk and not args.shizuku:
        parser.error("--shizuku-apk requires --shizuku")
    if args.recover and (selected or args.profile):
        parser.error("--recover resumes its saved action set and cannot take action flags")
    if args.recover and args.backup:
        parser.error("--recover cannot be combined with --backup")
    if args.status and selected:
        parser.error("--status cannot be combined with provisioning actions")
    args.backup_only = (
        args.backup is not None
        and not selected
        and not any((args.status, args.dry_run, args.recover))
    )
    if not selected and not any((args.status, args.dry_run, args.recover, args.backup)):
        args.audio = True
    return args


def main() -> int:
    args = parse_args()
    print_banner()
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    log_dir = args.log_dir or pathlib.Path(f"/tmp/portal-provision-{stamp}")
    log_dir.mkdir(parents=True, exist_ok=True)
    try:
        PortalProvisioner(
            args.serial,
            args.attempts,
            log_dir,
            audio=args.audio,
            restore_audio=args.restore_audio,
            device_owner=args.device_owner,
            kiosk_home=args.kiosk_home,
            restore_kiosk_home=args.restore_kiosk_home,
            disable_updates=args.disable_updates,
            enable_updates=args.enable_updates,
            debloat=args.debloat,
            restore_bloat=args.restore_bloat,
            remove_meta_accounts=args.remove_meta_accounts,
            optimize_presence=args.optimize_presence,
            restore_presence_profile=args.restore_presence_profile,
            presence_fps_cap=args.presence_fps_cap,
            restore_presence_fps=args.restore_presence_fps,
            privacy_dns=args.privacy_dns,
            dhcp_dns=args.dhcp_dns,
            restore_privacy_dns=args.restore_privacy_dns,
            allow_app_updates=args.allow_app_updates,
            restore_app_verifier=args.restore_app_verifier,
            shizuku=args.shizuku,
            remove_shizuku=args.remove_shizuku,
            disable_camera_light=args.disable_camera_light,
            restore_camera_light=args.restore_camera_light,
            shizuku_apk=args.shizuku_apk,
            status_only=args.status or args.backup_only,
            dry_run=args.dry_run,
            backup_path=args.backup,
            recover=args.recover,
            skip_build=args.skip_build,
        ).provision()
    except (ProvisionError, OSError, zipfile.BadZipFile) as exc:
        print(f"PROVISION_ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
