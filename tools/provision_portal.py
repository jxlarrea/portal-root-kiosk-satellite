#!/usr/bin/env python3
"""Inspect, provision, recover, and verify supported Meta Portal devices."""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import json
import os
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

if sys.version_info < (3, 9):
    raise SystemExit(
        "PROVISION_ERROR: Python 3.9 or newer is required; "
        f"running {sys.version_info.major}.{sys.version_info.minor}"
    )

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
HELPER_JAVA_LOCAL = ROOT / "helper/build/libportal_audio_persist_java.so"
PRELOAD_REMOTE = "/data/local/tmp/preload-portal.so"
HELPER_REMOTE = "/data/local/tmp/libportal_audio_persist.so"
AUDIO_CTL_LOCAL = ROOT / "exploit/build/portal-audio-ctl.jar"
AUDIO_CTL_REMOTE = "/data/local/tmp/portal-audio-ctl.jar"
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
ADB_AUTH_TIMEOUT_SETTING = "adb_allowed_connection_time"
ADB_AUTH_TIMEOUT_BACKUP_REMOTE = (
    "/data/local/tmp/portal-adb-auth-timeout-before-v1.json"
)
KIOSK_COMPONENT = "me.jxl.kiosk_satellite/.KioskAdminReceiver"
KIOSK_PACKAGE = "me.jxl.kiosk_satellite"
KIOSK_HOME_COMPONENT = "me.jxl.kiosk_satellite/.HomeAlias"
KIOSK_PROVISION_COMPONENT = "me.jxl.kiosk_satellite/.ProvisionActivity"
KIOSK_RELEASE_API = (
    "https://api.github.com/repos/jxlarrea/kiosk-satellite/releases/latest"
)
KIOSK_RELEASE_DOWNLOAD_PREFIX = (
    "https://github.com/jxlarrea/kiosk-satellite/releases/download/"
)
KIOSK_RELEASE_ABIS = ("arm64-v8a", "armeabi-v7a", "x86_64")
KIOSK_RUNTIME_PERMISSIONS = (
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.READ_LOGS",
)
KIOSK_APP_OPS = (
    "SYSTEM_ALERT_WINDOW",
    "WRITE_SETTINGS",
    "GET_USAGE_STATS",
)
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
REMOTE_WIPE_BACKUP_REMOTE = (
    "/data/local/tmp/portal-remote-wipe-components-backup-v1.tsv"
)
REMOTE_WIPE_COMPONENTS = (
    "com.facebook.alohaservices.deviceadmin/"
    "com.facebook.aloha.system.deviceadmin.remotewipe.FactoryResetReceiver",
    "com.facebook.alohaservices.deviceadmin/"
    "com.facebook.aloha.system.deviceadmin.remotewipe.RemoteWipeReceiver",
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
META_ACCOUNT_LOCAL_CLEAN_REMOTE = "/data/local/tmp/portal-meta-local-clean-v1"
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
PRESENCE_INSTALLED_REMOTE = (
    "/data/local/tmp/portal-presence-backup/installed-v1"
)
PRESENCE_LOGCAT_REGEX = (
    "settings_config.xml\\|"
    "Frame.available.for.analysis.stream\\|"
    "Frame.available.for.roi.stream\\|"
    "Disabled.hardware.cropping\\|"
    "Notify.people.presence\\|"
    "Setting.AI.Processing.FPS\\|presence.FPS.activation\\|"
    "CAMERA_SERVICE.not.running\\|privacy.mode"
)
CAMERA_SERVICE_COMPONENT = (
    "com.facebook.portal.aiservice/"
    "com.facebook.alohaapp.app.services.CameraService"
)
OTA_UI_PACKAGE = "com.facebook.aloha.otaui"
OTA_SETUP_PACKAGE = "com.facebook.aloha.alohaotasetup"
DEFAULT_UID1000_HOST_PACKAGE = "com.facebook.alohasdk.platformbatterystate"
CAMERA_LIGHT_HELPER_REMOTE = "/data/local/tmp/portal-camera-led-watch"
CAMERA_LIGHT_HOOK_REMOTE = "/data/local/tmp/portal-uid1000-hook.bin"
CAMERA_LIGHT_INSTALLED_REMOTE = (
    "/data/local/tmp/portal-camera-light-backup/installed-v1"
)
CAMERA_LIGHT_RESTORED_REMOTE = (
    "/data/local/tmp/portal-camera-light-backup/restored-v1"
)
WIRELESS_ADB_INSTALLED_REMOTE = (
    "/data/local/tmp/portal-wireless-adb-installed-v1"
)
UID1000_HOOK_ACTIVE_REMOTE = (
    "/data/local/tmp/portal-uid1000-hook-active-v1"
)
UID1000_RUNTIME_PACKAGE = "dev.portal.uid1000runtime"
UID1000_RUNTIME_APK_LOCAL = (
    ROOT / "uid1000-helper/build/portal-uid1000-runtime.apk"
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
        install_kiosk_satellite: bool = False,
        kiosk_permissions: bool = False,
        device_owner: bool = False,
        kiosk_home: bool = False,
        restore_kiosk_home: bool = False,
        disable_updates: bool = False,
        enable_updates: bool = False,
        debloat: bool = False,
        restore_bloat: bool = False,
        block_remote_wipe: bool = False,
        restore_remote_wipe: bool = False,
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
        persistent_wireless_adb: bool = False,
        disable_adb_auth_timeout: bool = False,
        restore_adb_auth_timeout: bool = False,
        wireless_adb_only: bool = False,
        meta_accounts_local_only: bool = False,
        meta_accounts_auth_only: bool = False,
        meta_accounts_finalize_only: bool = False,
    ):
        self.serial = serial
        self.attempts = attempts
        self.log_dir = log_dir
        self.audio = audio
        self.audio_already_configured = False
        self.restore_audio = restore_audio
        self.install_kiosk_satellite = install_kiosk_satellite
        self.kiosk_apk: pathlib.Path | None = None
        self.kiosk_permissions = kiosk_permissions
        self.device_owner = device_owner
        self.device_owner_already_configured = False
        self.kiosk_home = kiosk_home
        self.restore_kiosk_home = restore_kiosk_home
        self.disable_updates = disable_updates
        self.ota_already_configured = False
        self.enable_updates = enable_updates
        self.debloat = debloat
        self.debloat_already_configured = False
        self.restore_bloat = restore_bloat
        self.block_remote_wipe = block_remote_wipe
        self.remote_wipe_already_configured = False
        self.restore_remote_wipe = restore_remote_wipe
        self.remove_meta_accounts = remove_meta_accounts
        self.meta_accounts_absent = False
        self.meta_accounts_already_clean = False
        self.optimize_presence = optimize_presence
        self.presence_already_configured = False
        self.restore_presence_profile = restore_presence_profile
        self.presence_fps_cap = presence_fps_cap
        self.presence_fps_already_configured = False
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
        self.uid1000_runtime_apk_remote: str | None = None
        self.uid1000_runtime_library_remote: str | None = None
        self.uid1000_runtime_package_installed = False
        self.package_verifier_before_install_disabled: bool | None = None
        self.status_only = status_only
        self.dry_run = dry_run
        self.backup_path = backup_path
        self.recover = recover
        self.skip_build = skip_build
        self.persistent_wireless_adb = persistent_wireless_adb
        self.disable_adb_auth_timeout = (
            disable_adb_auth_timeout or persistent_wireless_adb
        )
        self.restore_adb_auth_timeout = restore_adb_auth_timeout
        self.wireless_adb_only = wireless_adb_only
        self.meta_accounts_local_only = meta_accounts_local_only
        self.meta_accounts_auth_only = meta_accounts_auth_only
        self.meta_accounts_finalize_only = meta_accounts_finalize_only
        self.adb = ["adb", "-s", serial]
        self.target: PortalTarget | None = None
        self.persist_wireless_adb = False

    def uid1000_path(self, name: str) -> str:
        directory = (
            self.target.uid1000_data_directory
            if self.target
            else "/data/portal-uid1000"
        )
        return f"{directory}/{name}"

    def uid1000_helper_local(self) -> pathlib.Path:
        artifact = (
            self.target.uid1000_helper_artifact
            if self.target
            else "portal-camera-led-watch"
        )
        return ROOT / "uid1000-helper/build" / artifact

    def uid1000_hook_local(self) -> pathlib.Path:
        artifact = (
            self.target.uid1000_hook_artifact
            if self.target
            else "portal-uid1000-hook.bin"
        )
        return ROOT / "uid1000-helper/build" / artifact

    def needs_uid1000_payload(self) -> bool:
        return bool(
            self.disable_camera_light
            or self.presence_fps_action_requested()
            or (
                self.persist_wireless_adb
                and self.target
                and self.target.wireless_adb_uid1000_boot
            )
            or (
                self.target
                and self.target.uid1000_embedded_helper
                and (
                    self.restore_camera_light
                    or self.restore_presence_fps
                    or self.restore_presence_profile
                )
            )
        )

    def uses_native_presence_prefs(self) -> bool:
        return bool(
            self.target
            and self.target.uid1000_embedded_helper
            and (
                self.presence_fps_action_requested()
                or self.restore_presence_fps
                or self.restore_presence_profile
            )
        )

    def presence_fps_action_requested(self) -> bool:
        return bool(
            self.presence_fps_cap is not None
            and not self.presence_fps_already_configured
        )

    def needs_component_ctl(self) -> bool:
        return bool(
            (self.debloat and not self.debloat_already_configured)
            or self.restore_bloat
            or (self.block_remote_wipe and not self.remote_wipe_already_configured)
            or self.restore_remote_wipe
            or (
                (
                    self.presence_fps_action_requested()
                    or self.restore_presence_fps
                    or self.restore_presence_profile
                )
                and not self.uses_native_presence_prefs()
            )
        )

    def only_component_actions_requested(self) -> bool:
        """Return whether one exploit pass can handle every selected action."""
        actions = set(self.requested_actions())
        return bool(actions) and actions <= {
            "debloat",
            "restore_bloat",
            "block_remote_wipe",
            "restore_remote_wipe",
        }

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

    def connect_after_reboot(self, before: str, wait_seconds: int = 600) -> str:
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
                observed_boot_id = boot.stdout.strip()
                if boot.returncode == 0 and re.fullmatch(
                    r"[0-9a-fA-F-]{36}", observed_boot_id
                ):
                    last_boot_id = observed_boot_id
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
        adb_hint = ""
        if not last_boot_id:
            adb_hint = (
                "; ADB did not return. If WIRELESS_ADB_OK has not appeared yet, "
                "enable ADB in the Portal Debug menu and run "
                "`adb -d tcpip 5555`, then rerun the same provisioner command"
            )
        raise ProvisionError(
            f"{self.serial} did not complete a new boot after {before}; "
            f"last valid boot ID was {last_boot_id!r}{adb_hint}"
        )

    def verify_target(self, require_supported: bool = True) -> PortalTarget | None:
        fingerprint = self.adb_run(
            ["shell", "getprop", "ro.build.fingerprint"], timeout=5, check=True
        ).stdout.strip()
        device = self.adb_run(
            ["shell", "getprop", "ro.product.device"], timeout=5, check=True
        ).stdout.strip()
        product_model = self.adb_run(
            ["shell", "getprop", "ro.product.model"], timeout=5, check=True
        ).stdout.strip()
        target = find_target(device, fingerprint, product_model)
        self.target = target
        if target is None and require_supported:
            raise ProvisionError(
                "unsupported firmware; refusing build-specific kernel writes\n"
                f"model: {product_model}\ndevice: {device}\n"
                f"fingerprint: {fingerprint}"
            )
        if target is None:
            print(
                f"TARGET_UNSUPPORTED serial={self.serial} "
                f"model={product_model} device={device} "
                f"fingerprint={fingerprint}"
            )
        else:
            print(
                f"TARGET_OK serial={self.serial} target={target.key} "
                f"model={product_model} device={device} fingerprint={fingerprint}"
            )
        return target

    def stage(self) -> None:
        if self.target is None:
            raise ProvisionError("target must be selected before staging")
        files = [(self.target.preload_path(ROOT), PRELOAD_REMOTE)]
        if self.audio and not self.audio_already_configured:
            helper = (
                HELPER_JAVA_LOCAL
                if self.target.audio_java_fallback
                else HELPER_LOCAL
            )
            files.append((helper, HELPER_REMOTE))
        if self.target.audio_java_fallback and (
            (self.audio and not self.audio_already_configured)
            or self.restore_audio
        ):
            files.append((AUDIO_CTL_LOCAL, AUDIO_CTL_REMOTE))
        if self.remove_meta_accounts:
            files.append((ACCOUNT_CTL_LOCAL, ACCOUNT_CTL_REMOTE))
        if self.needs_component_ctl():
            files.append((COMPONENT_CTL_LOCAL, COMPONENT_CTL_REMOTE))
        if self.shizuku:
            if self.shizuku_public_key is None:
                raise ProvisionError("Shizuku helper key was not prepared")
            files.append((self.shizuku_public_key, SHIZUKU_KEY_REMOTE))
        if self.needs_uid1000_payload():
            files.extend(
                (
                    (self.uid1000_helper_local(), CAMERA_LIGHT_HELPER_REMOTE),
                    (self.uid1000_hook_local(), CAMERA_LIGHT_HOOK_REMOTE),
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
        if AUDIO_CTL_REMOTE in {remote for _, remote in files}:
            staged += f" audio_ctl={AUDIO_CTL_REMOTE}"
        if self.remove_meta_accounts:
            staged += f" account_ctl={ACCOUNT_CTL_REMOTE}"
        if COMPONENT_CTL_REMOTE in {remote for _, remote in files}:
            staged += f" component_ctl={COMPONENT_CTL_REMOTE}"
        if self.shizuku:
            staged += f" shizuku_key={SHIZUKU_KEY_REMOTE}"
        if self.needs_uid1000_payload():
            staged += (
                f" uid1000_helper={CAMERA_LIGHT_HELPER_REMOTE}"
                f" uid1000_hook={CAMERA_LIGHT_HOOK_REMOTE}"
            )
        print(f"STAGED {staged}")

    def requested_actions(self) -> dict[str, object]:
        actions: dict[str, object] = {}
        for name in (
            "persistent_wireless_adb",
            "disable_adb_auth_timeout",
            "restore_adb_auth_timeout",
            "audio",
            "restore_audio",
            "install_kiosk_satellite",
            "kiosk_permissions",
            "device_owner",
            "kiosk_home",
            "restore_kiosk_home",
            "disable_updates",
            "enable_updates",
            "debloat",
            "restore_bloat",
            "block_remote_wipe",
            "restore_remote_wipe",
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
        if self.privileged_requested() and self.uses_exploit_sentinel():
            candidates.append(EXPLOIT_SENTINEL_LOCAL)
        if self.audio:
            candidates.append(
                HELPER_JAVA_LOCAL
                if self.target and self.target.audio_java_fallback
                else HELPER_LOCAL
            )
            if self.target and self.target.audio_java_fallback:
                candidates.append(AUDIO_CTL_LOCAL)
        if self.kiosk_apk:
            candidates.append(self.kiosk_apk)
        if self.remove_meta_accounts:
            candidates.append(ACCOUNT_CTL_LOCAL)
        if self.needs_component_ctl() or self.block_remote_wipe:
            candidates.append(COMPONENT_CTL_LOCAL)
        if self.shizuku:
            candidates.append(SHIZUKU_HELPER_LOCAL)
            if self.shizuku_apk:
                candidates.append(self.shizuku_apk)
        if self.needs_uid1000_payload():
            candidates.extend(
                (self.uid1000_helper_local(), self.uid1000_hook_local())
            )
            if self.target and self.target.uid1000_embedded_helper:
                candidates.append(UID1000_RUNTIME_APK_LOCAL)
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

    @staticmethod
    def presence_full_scene_active(
        logs: str, camera: str, target: PortalTarget | None
    ) -> bool:
        active_request = camera.split("Tag monitoring disabled", 1)[0]
        full_sensor_frame = (
            "com.facebook.alohasdk.dewarp_crop_rect.width"
            not in active_request
        )
        if target and target.presence_full_sensor_width:
            crop_values: dict[str, float] = {}
            for coordinate in ("x_start", "y_start", "width"):
                match = re.search(
                    rf"dewarp_crop_rect\.{coordinate}[^\n]*\n\s*"
                    r"\[([0-9.]+)",
                    active_request,
                )
                if match:
                    crop_values[coordinate] = float(match.group(1))
            full_sensor_frame = (
                crop_values.get("x_start") == 0.0
                and crop_values.get("y_start") == 0.0
                and crop_values.get("width", 0.0)
                >= target.presence_full_sensor_width
            )
        return PRESENCE_WIDE_FRAME_MARKER in logs and full_sensor_frame

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
        product_model = shell("getprop", "ro.product.model", timeout=5)
        target = find_target(device, fingerprint, product_model)
        uid1000_host_package = (
            target.uid1000_host_package
            if target
            else DEFAULT_UID1000_HOST_PACKAGE
        )
        ota_packages = (
            target.ota_packages
            if target
            else (OTA_UI_PACKAGE, OTA_SETUP_PACKAGE)
        )
        disabled_output = shell("pm", "list", "packages", "-d", "-u")
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
        kiosk_installed = KIOSK_PACKAGE in installed
        kiosk_permissions = self.kiosk_permission_status(
            package_dump=kiosk_dump,
            installed=kiosk_installed,
        )
        default_home = self.current_default_home()
        version_name = re.search(r"\bversionName=([^\s]+)", kiosk_dump)
        version_code = re.search(r"\bversionCode=(\d+)", kiosk_dump)
        logs = shell(
            "logcat",
            "-d",
            "-b",
            "main",
            "-v",
            "brief",
            "-e",
            PRESENCE_LOGCAT_REGEX,
            timeout=20,
        )
        connectivity = shell("dumpsys", "connectivity", timeout=20)
        audio_logs = shell(
            "logcat",
            "-d",
            "-b",
            "main",
            "-s",
            "PortalAudioPersist:*",
            timeout=10,
        )
        camera_light_logs = shell(
            "logcat",
            "-d",
            "-t",
            "10000",
            "-s",
            "PortalCameraLed:*",
            timeout=10,
        )
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
        required_profile_keys = set(
            target.presence_runtime_keys
            if target and target.presence_runtime_keys
            else PRESENCE_PROFILE_KEYS
        )
        audio_installed = exists(
            "/data/local/tmp/portal-audio-backup/installed-v1"
        )
        audio_restored = exists(
            "/data/local/tmp/portal-audio-backup/restored-v1"
        )
        ota_installed = exists("/data/local/tmp/portal-ota-backup/installed-v1")
        ota_restored = exists("/data/local/tmp/portal-ota-backup/restored-v1")
        presence_installed = exists(PRESENCE_INSTALLED_REMOTE)
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
            1
            for component, (_, state) in component_states.items()
            if state == "disabled"
            and component not in SELF_MANAGED_DEBLOAT_COMPONENTS
        )
        remote_wipe_backup = self.read_remote_wipe_backup(required=False)
        remote_wipe_states = self.current_named_component_states(
            REMOTE_WIPE_COMPONENTS, detect_missing=True
        )
        remote_wipe_present = sum(
            state != "absent" for state in remote_wipe_states.values()
        )
        remote_wipe_disabled = sum(
            state == "disabled" for state in remote_wipe_states.values()
        )
        presence_helper_dump = shell("dumpsys", "package", PRESENCE_HELPER_PACKAGE)
        presence_uid1000_configured = exists(self.uid1000_path("presence-fps"))
        presence_uid1000_fps = shell(
            "cat", self.uid1000_path("presence-fps"), timeout=5
        )
        if target and target.uid1000_embedded_helper:
            presence_uid1000_configured = presence_fps_installed
            presence_uid1000_fps = presence_fps_value
        shizuku_dump = shell("dumpsys", "package", SHIZUKU_PACKAGE)
        shizuku_version = re.search(r"\bversionName=([^\s]+)", shizuku_dump)
        package_verifier_setting = shell(
            "settings", "get", "global", "package_verifier_enable", timeout=5
        )
        adb_auth_timeout = shell(
            "settings", "get", "global", ADB_AUTH_TIMEOUT_SETTING, timeout=5
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
                if uid1000_host_package in line
            ),
            "",
        )
        camera_light_installed = exists(CAMERA_LIGHT_INSTALLED_REMOTE)
        private_uid1000_runtime = bool(
            target and target.uid1000_embedded_helper
        )
        camera_light_configured = (
            camera_light_installed
            if private_uid1000_runtime
            else exists(self.uid1000_path("camera-led-enabled"))
        )
        camera_light_watchdog_running = bool(
            camera_light_process and camera_light_configured
        )
        return {
            "schema": 1,
            "serial": self.serial,
            "target": {
                "supported": target is not None,
                "key": target.key if target else None,
                "model": product_model,
                "device": device,
                "fingerprint": fingerprint,
            },
            "runtime": {
                "boot_id": shell("cat", "/proc/sys/kernel/random/boot_id", timeout=5),
                "selinux": shell("getenforce", timeout=5),
                "wireless_adb_property": (
                    target.wireless_adb_file_property
                    if target and target.wireless_adb_file_property
                    else "persist.adb.tcp.port"
                ),
                "wireless_adb_port": shell(
                    "getprop",
                    (
                        target.wireless_adb_file_property
                        if target and target.wireless_adb_file_property
                        else "persist.adb.tcp.port"
                    ),
                    timeout=5,
                ),
                "wireless_adb_persistence_verified": exists(
                    WIRELESS_ADB_INSTALLED_REMOTE
                ),
                "adb_auth_allowed_connection_time_ms": (
                    int(adb_auth_timeout)
                    if adb_auth_timeout.isdigit()
                    else None
                ),
                "adb_auth_timeout_disabled": adb_auth_timeout == "0",
                "adb_auth_timeout_backup_present": exists(
                    ADB_AUTH_TIMEOUT_BACKUP_REMOTE
                ),
                "aiservice_pid": shell(
                    "pidof", "com.facebook.portal.aiservice", timeout=5
                ),
                "cameras": 2 if "Number of camera devices: 2" in camera else None,
                "webview_ready": "(com.facebook.portal.webview," in webview,
            },
            "kiosk_satellite": {
                "installed": kiosk_installed,
                "version_name": version_name.group(1) if version_name else None,
                "version_code": int(version_code.group(1)) if version_code else None,
                "admin_active": f"    {KIOSK_COMPONENT}:" in policy,
                "device_owner": owner,
                "default_home": default_home or None,
                "home_screen": default_home == KIOSK_HOME_COMPONENT,
                "permissions": kiosk_permissions,
            },
            "audio": {
                "state": (
                    "installed"
                    if audio_installed
                    or (
                        target is not None
                        and target.audio_installer_credentials
                        and "audio processing verified aec=0 ns=0" in audio_logs
                    )
                    else "restored"
                    if audio_restored
                    else "observed_this_boot"
                    if "persistent audio watchdog started" in audio_logs
                    else "unknown"
                ),
                "installed_marker": audio_installed,
                "watchdog_observed": (
                    "persistent audio watchdog started" in audio_logs
                    or "audio processing verified aec=0 ns=0" in audio_logs
                ),
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
                            for package in ota_packages
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
                    for package in ota_packages
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
            "remote_wipe": {
                "state": (
                    "blocked"
                    if remote_wipe_present == remote_wipe_disabled
                    else "restored"
                    if remote_wipe_backup is not None
                    and all(
                        original == "absent"
                        or remote_wipe_states[component] == original
                        for component, original in remote_wipe_backup.items()
                    )
                    else "enabled"
                ),
                "backup_present": remote_wipe_backup is not None,
                "receivers_targeted": len(REMOTE_WIPE_COMPONENTS),
                "receivers_present": remote_wipe_present,
                "receivers_disabled": remote_wipe_disabled,
                "components": remote_wipe_states,
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
                    if presence_installed
                    or required_profile_keys.issubset(profile_keys)
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
                "full_scene_profile": self.presence_full_scene_active(
                    logs, camera, target
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
                "feature_config_present": camera_light_configured,
                "helper_present": (
                    bool(camera_light_process)
                    if private_uid1000_runtime
                    else exists(self.uid1000_path("portal-camera-led-watch"))
                ),
                "helper_running": bool(camera_light_process),
                "helper_user": (
                    camera_light_process.split()[0]
                    if camera_light_process
                    else None
                ),
                "watchdog_running": camera_light_watchdog_running,
                "watchdog_user": (
                    camera_light_process.split()[0]
                    if camera_light_watchdog_running
                    else None
                ),
                "persistent_host_running": bool(camera_light_host_process),
                "persistent_host_package": uid1000_host_package,
                "connected_this_boot": (
                    "watchdog connected uid=1000" in camera_light_logs
                ),
                "camera_capture_compatible": not camera_light_configured,
                "warning": (
                    "The legacy LED watchdog causes Meta's camera provider "
                    "to reject capture requests. Run --restore-camera-light."
                    if camera_light_configured
                    else None
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
                self.persistent_wireless_adb,
                self.wireless_adb_only,
                self.audio,
                self.restore_audio,
                self.device_owner,
                self.disable_updates,
                self.enable_updates,
                self.debloat,
                self.restore_bloat,
                self.block_remote_wipe,
                self.restore_remote_wipe,
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

    def uses_exploit_sentinel(self) -> bool:
        return self.target is None or self.target.proc_uid_sentinel != "thread"

    def dry_run_report(self, status: dict[str, object]) -> None:
        actions = self.requested_actions()
        kiosk = status.get("kiosk_satellite", {})
        audio = status.get("audio", {})
        updates = status.get("updates", {})
        debloat = status.get("debloat", {})
        remote_wipe = status.get("remote_wipe", {})
        accounts = status.get("meta_accounts", {})
        presence = status.get("presence", {})
        privacy = status.get("privacy_dns", {})
        app_updates = status.get("app_updates", {})
        shizuku = status.get("shizuku", {})
        camera_light = status.get("camera_light", {})
        runtime = status.get("runtime", {})
        current = {
            "audio": audio.get("state") if isinstance(audio, dict) else None,
            "install_kiosk_satellite": (
                kiosk.get("installed") if isinstance(kiosk, dict) else None
            ),
            "device_owner": (
                kiosk.get("device_owner") if isinstance(kiosk, dict) else None
            ),
            "kiosk_home": (
                kiosk.get("home_screen") if isinstance(kiosk, dict) else None
            ),
            "kiosk_permissions": (
                kiosk.get("permissions") if isinstance(kiosk, dict) else None
            ),
            "updates": updates.get("state") if isinstance(updates, dict) else None,
            "debloat": debloat.get("complete") if isinstance(debloat, dict) else None,
            "remote_wipe": (
                remote_wipe.get("state")
                if isinstance(remote_wipe, dict)
                else None
            ),
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
            "adb_auth_timeout_disabled": (
                runtime.get("adb_auth_timeout_disabled")
                if isinstance(runtime, dict)
                else None
            ),
        }
        required_outputs = []
        if self.target and self.privileged_requested():
            required_outputs.append(str(self.target.preload_path(ROOT)))
        if self.privileged_requested() and self.uses_exploit_sentinel():
            required_outputs.append(str(EXPLOIT_SENTINEL_LOCAL))
        if self.audio:
            required_outputs.append(str(HELPER_LOCAL))
        if self.remove_meta_accounts:
            required_outputs.append(str(ACCOUNT_CTL_LOCAL))
        if self.needs_component_ctl():
            required_outputs.append(str(COMPONENT_CTL_LOCAL))
        if self.shizuku:
            required_outputs.append(str(SHIZUKU_HELPER_LOCAL))
        if self.needs_uid1000_payload():
            required_outputs.extend(
                (str(self.uid1000_helper_local()), str(self.uid1000_hook_local()))
            )
            if self.target and self.target.uid1000_embedded_helper:
                required_outputs.append(str(UID1000_RUNTIME_APK_LOCAL))
        report = {
            "actions": actions,
            "current": current,
            "requires_exploit": self.privileged_requested(),
            "minimum_reboots": (
                3
                if self.privileged_requested()
                else 0
                if set(actions) <= {
                    "install_kiosk_satellite",
                    "kiosk_permissions",
                    "disable_adb_auth_timeout",
                    "restore_adb_auth_timeout",
                }
                else 2
            ),
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
                REMOTE_WIPE_BACKUP_REMOTE,
                META_ACCOUNT_BACKUP_REMOTE,
                PRIVACY_BACKUP_REMOTE,
                ADB_AUTH_TIMEOUT_BACKUP_REMOTE,
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

    def backup_adb_auth_timeout(self) -> None:
        existing = self.adb_run(
            ["shell", "cat", ADB_AUTH_TIMEOUT_BACKUP_REMOTE], timeout=5
        )
        if existing.returncode == 0:
            self.read_adb_auth_timeout_backup()
            return
        original = self.adb_run(
            ["shell", "settings", "get", "global", ADB_AUTH_TIMEOUT_SETTING],
            timeout=5,
            check=True,
        ).stdout.strip()
        if original != "null" and not re.fullmatch(r"\d{1,19}", original):
            raise ProvisionError(
                f"invalid existing ADB authorization timeout: {original!r}"
            )
        self.push_text_atomic(
            json.dumps({"schema": 1, "value": original}, indent=2) + "\n",
            ADB_AUTH_TIMEOUT_BACKUP_REMOTE,
        )

    def read_adb_auth_timeout_backup(self) -> str:
        result = self.adb_run(
            ["shell", "cat", ADB_AUTH_TIMEOUT_BACKUP_REMOTE],
            timeout=5,
        )
        if result.returncode != 0:
            raise ProvisionError(
                "ADB authorization timeout backup is absent; nothing can be restored"
            )
        try:
            backup = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise ProvisionError(
                f"invalid ADB authorization timeout backup: {exc}"
            ) from exc
        value = backup.get("value") if isinstance(backup, dict) else None
        if (
            not isinstance(backup, dict)
            or backup.get("schema") != 1
            or not isinstance(value, str)
            or (value != "null" and not re.fullmatch(r"\d{1,19}", value))
        ):
            raise ProvisionError("unrecognized ADB authorization timeout backup")
        return value

    def disable_adb_authorization_timeout(self) -> None:
        self.backup_adb_auth_timeout()
        self.adb_run(
            [
                "shell",
                "settings",
                "put",
                "global",
                ADB_AUTH_TIMEOUT_SETTING,
                "0",
            ],
            timeout=10,
            check=True,
        )
        self.verify_adb_auth_timeout()

    def restore_adb_authorization_timeout(self) -> None:
        original = self.read_adb_auth_timeout_backup()
        command = [
            "shell",
            "settings",
            "delete" if original == "null" else "put",
            "global",
            ADB_AUTH_TIMEOUT_SETTING,
        ]
        if original != "null":
            command.append(original)
        self.adb_run(command, timeout=10, check=True)
        self.verify_adb_auth_timeout()

    def verify_adb_auth_timeout(self) -> None:
        actual = self.adb_run(
            ["shell", "settings", "get", "global", ADB_AUTH_TIMEOUT_SETTING],
            timeout=5,
            check=True,
        ).stdout.strip()
        expected = (
            self.read_adb_auth_timeout_backup()
            if self.restore_adb_auth_timeout
            else "0"
        )
        if actual != expected:
            raise ProvisionError(
                "ADB authorization timeout did not persist: "
                f"setting={actual!r}/{expected!r}"
            )
        action = "restored" if self.restore_adb_auth_timeout else "disabled"
        print(
            f"ADB_AUTH_TIMEOUT_OK action={action} "
            f"{ADB_AUTH_TIMEOUT_SETTING}={actual}"
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
            ["shell", "pm", "list", "packages", "-d", "-u"],
            timeout=15,
            check=True,
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

    def kiosk_permission_status(
        self,
        package_dump: str | None = None,
        installed: bool | None = None,
    ) -> dict[str, object]:
        if installed is None:
            installed = (
                self.adb_run(
                    ["shell", "pm", "path", KIOSK_PACKAGE], timeout=10
                ).returncode
                == 0
            )
        if package_dump is None:
            package_dump = self.adb_run(
                ["shell", "dumpsys", "package", KIOSK_PACKAGE], timeout=15
            ).stdout

        runtime = {
            permission: bool(
                installed
                and re.search(
                    rf"^\s*{re.escape(permission)}:\s+granted=true\b",
                    package_dump,
                    re.MULTILINE,
                )
            )
            for permission in KIOSK_RUNTIME_PERMISSIONS
        }
        app_ops: dict[str, bool] = {}
        for operation in KIOSK_APP_OPS:
            output = self.adb_run(
                ["shell", "appops", "get", KIOSK_PACKAGE, operation],
                timeout=10,
            ).stdout
            app_ops[operation] = bool(
                installed
                and re.search(
                    rf"(?:^|\s){re.escape(operation)}:\s*allow\b",
                    output,
                    re.MULTILINE,
                )
            )
        whitelist = self.adb_run(
            ["shell", "dumpsys", "deviceidle", "whitelist"], timeout=15
        ).stdout
        battery_exempt = bool(
            installed
            and any(
                re.search(
                    rf"(?:^|,){re.escape(KIOSK_PACKAGE)}(?:,|$)",
                    line.strip(),
                )
                for line in whitelist.splitlines()
            )
        )
        return {
            "complete": bool(
                installed
                and all(runtime.values())
                and all(app_ops.values())
                and battery_exempt
            ),
            "runtime": runtime,
            "app_ops": app_ops,
            "battery_optimization_exempt": battery_exempt,
        }

    def apply_kiosk_permissions(self) -> None:
        if self.adb_run(
            ["shell", "pm", "path", KIOSK_PACKAGE], timeout=10
        ).returncode != 0:
            raise ProvisionError(
                "Kiosk Satellite must be installed before applying its permissions"
            )

        for permission in KIOSK_RUNTIME_PERMISSIONS:
            result = self.adb_run(
                ["shell", "pm", "grant", KIOSK_PACKAGE, permission],
                timeout=15,
            )
            if result.returncode != 0:
                raise ProvisionError(
                    f"failed to grant {permission} to Kiosk Satellite: "
                    f"{result.stdout.strip()}"
                )
        for operation in KIOSK_APP_OPS:
            result = self.adb_run(
                [
                    "shell",
                    "appops",
                    "set",
                    KIOSK_PACKAGE,
                    operation,
                    "allow",
                ],
                timeout=15,
            )
            if result.returncode != 0:
                raise ProvisionError(
                    f"failed to allow {operation} for Kiosk Satellite: "
                    f"{result.stdout.strip()}"
                )
        whitelist = self.adb_run(
            [
                "shell",
                "dumpsys",
                "deviceidle",
                "whitelist",
                f"+{KIOSK_PACKAGE}",
            ],
            timeout=15,
        )
        if whitelist.returncode != 0:
            raise ProvisionError(
                "failed to exempt Kiosk Satellite from battery optimization: "
                + whitelist.stdout.strip()
            )

        self.adb_run(
            ["shell", "am", "force-stop", KIOSK_PACKAGE], timeout=15, check=True
        )
        launch = self.adb_run(
            [
                "shell",
                "monkey",
                "-p",
                KIOSK_PACKAGE,
                "-c",
                "android.intent.category.LAUNCHER",
                "1",
            ],
            timeout=30,
        )
        if launch.returncode != 0 or "Events injected: 1" not in launch.stdout:
            raise ProvisionError(
                "Kiosk Satellite did not relaunch after READ_LOGS was granted: "
                + launch.stdout[-2000:].strip()
            )
        self.verify_kiosk_permissions()
        settle_seconds = (
            self.target.kiosk_permission_settle_seconds
            if self.target is not None
            else 0
        )
        if settle_seconds:
            print(
                "KIOSK_PERMISSION_STATE_SETTLE "
                f"seconds={settle_seconds}",
                flush=True,
            )
            time.sleep(settle_seconds)
            self.verify_kiosk_permissions()

    def verify_kiosk_permissions(self) -> None:
        status = self.kiosk_permission_status()
        if not status["complete"]:
            runtime = status["runtime"]
            app_ops = status["app_ops"]
            assert isinstance(runtime, dict)
            assert isinstance(app_ops, dict)
            missing_runtime = [
                permission
                for permission, granted in runtime.items()
                if not granted
            ]
            missing_app_ops = [
                operation
                for operation, allowed in app_ops.items()
                if not allowed
            ]
            raise ProvisionError(
                "Kiosk Satellite permission verification failed: "
                f"runtime={missing_runtime} app_ops={missing_app_ops} "
                "battery_optimization_exempt="
                f"{int(bool(status['battery_optimization_exempt']))}"
            )
        print(
            "KIOSK_PERMISSIONS_OK runtime="
            f"{len(KIOSK_RUNTIME_PERMISSIONS)} app_ops={len(KIOSK_APP_OPS)} "
            "battery_optimization_exempt=1 accessibility=unchanged"
        )

    def kiosk_satellite_version(self) -> str | None:
        if self.adb_run(
            ["shell", "pm", "path", KIOSK_PACKAGE], timeout=10
        ).returncode != 0:
            return None
        package_dump = self.adb_run(
            ["shell", "dumpsys", "package", KIOSK_PACKAGE],
            timeout=15,
            check=True,
        ).stdout
        match = re.search(r"^\s*versionName=(\S+)", package_dump, re.MULTILINE)
        return match.group(1) if match else "unknown"

    @staticmethod
    def select_kiosk_release_asset(
        release: object, device_abis: tuple[str, ...]
    ) -> tuple[str, str, int, str, str]:
        if not isinstance(release, dict):
            raise ProvisionError("invalid Kiosk Satellite release metadata")
        tag = release.get("tag_name")
        assets = release.get("assets")
        if (
            not isinstance(tag, str)
            or not re.fullmatch(r"v?[0-9][0-9A-Za-z._-]*", tag)
            or not isinstance(assets, list)
        ):
            raise ProvisionError("invalid Kiosk Satellite release metadata")
        versions = (tag, tag[1:]) if tag.startswith("v") else (tag,)
        preferred_abis = [abi for abi in device_abis if abi in KIOSK_RELEASE_ABIS]
        expected_names = [
            (f"kiosk-satellite-{version}.{abi}.apk", abi)
            for abi in preferred_abis
            for version in versions
        ]
        expected_names.extend(
            (f"kiosk-satellite-{version}.apk", "universal")
            for version in versions
        )
        by_name = {
            asset.get("name"): asset
            for asset in assets
            if isinstance(asset, dict) and isinstance(asset.get("name"), str)
        }
        selected_name = ""
        selected_abi = ""
        selected: dict[str, object] | None = None
        for name, abi in expected_names:
            candidate = by_name.get(name)
            if isinstance(candidate, dict):
                selected_name, selected_abi, selected = name, abi, candidate
                break
        if selected is None:
            raise ProvisionError(
                "the latest Kiosk Satellite release has no APK for device ABIs: "
                + (",".join(device_abis) or "unknown")
            )
        url = selected.get("browser_download_url")
        digest_value = selected.get("digest")
        size = selected.get("size")
        expected_url = f"{KIOSK_RELEASE_DOWNLOAD_PREFIX}{tag}/{selected_name}"
        if url != expected_url:
            raise ProvisionError("unexpected Kiosk Satellite release download URL")
        if (
            not isinstance(digest_value, str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest_value)
        ):
            raise ProvisionError(
                "the Kiosk Satellite release asset has no valid SHA-256 digest"
            )
        if not isinstance(size, int) or size <= 0:
            raise ProvisionError("invalid Kiosk Satellite release asset size")
        return (
            tag,
            selected_name,
            size,
            digest_value.removeprefix("sha256:"),
            selected_abi,
        )

    def resolve_kiosk_satellite_apk(self) -> tuple[pathlib.Path, str, str]:
        abi_list = self.adb_run(
            ["shell", "getprop", "ro.product.cpu.abilist"],
            timeout=5,
            check=True,
        ).stdout.strip()
        device_abis = tuple(abi for abi in abi_list.split(",") if abi)
        request = urllib.request.Request(
            KIOSK_RELEASE_API,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "portal-root-kiosk-satellite",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw_metadata = response.read(2 * 1024 * 1024 + 1)
        except OSError as exc:
            raise ProvisionError(
                f"Kiosk Satellite release lookup failed: {exc}"
            ) from exc
        if len(raw_metadata) > 2 * 1024 * 1024:
            raise ProvisionError(
                "Kiosk Satellite release metadata is unexpectedly large"
            )
        try:
            release = json.loads(raw_metadata)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProvisionError(
                f"invalid Kiosk Satellite release metadata: {exc}"
            ) from exc
        tag, name, expected_size, expected_digest, selected_abi = (
            self.select_kiosk_release_asset(release, device_abis)
        )
        path = (
            pathlib.Path.home()
            / ".cache"
            / "portal-root"
            / "kiosk-satellite"
            / name
        )
        path.parent.mkdir(parents=True, exist_ok=True)

        def valid(candidate: pathlib.Path) -> bool:
            if not candidate.is_file() or candidate.stat().st_size != expected_size:
                return False
            digest = hashlib.sha256()
            with candidate.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            return digest.hexdigest() == expected_digest

        if not valid(path):
            temporary = path.with_suffix(path.suffix + ".tmp")
            temporary.unlink(missing_ok=True)
            url = f"{KIOSK_RELEASE_DOWNLOAD_PREFIX}{tag}/{name}"
            print(
                f"KIOSK_DOWNLOAD version={tag} abi={selected_abi} source={url}",
                flush=True,
            )
            download_request = urllib.request.Request(
                url,
                headers={"User-Agent": "portal-root-kiosk-satellite"},
            )
            try:
                digest = hashlib.sha256()
                downloaded = 0
                with urllib.request.urlopen(
                    download_request, timeout=60
                ) as response:
                    with temporary.open("wb") as output:
                        while True:
                            chunk = response.read(1024 * 1024)
                            if not chunk:
                                break
                            output.write(chunk)
                            digest.update(chunk)
                            downloaded += len(chunk)
            except OSError as exc:
                temporary.unlink(missing_ok=True)
                raise ProvisionError(
                    f"Kiosk Satellite APK download failed: {exc}"
                ) from exc
            if downloaded != expected_size or digest.hexdigest() != expected_digest:
                temporary.unlink(missing_ok=True)
                raise ProvisionError(
                    "Kiosk Satellite APK size or SHA-256 digest did not match "
                    "GitHub release metadata"
                )
            temporary.replace(path)
        try:
            with zipfile.ZipFile(path) as archive:
                if "AndroidManifest.xml" not in archive.namelist():
                    raise ProvisionError(
                        "Kiosk Satellite download is not a valid Android APK"
                    )
        except zipfile.BadZipFile as exc:
            path.unlink(missing_ok=True)
            raise ProvisionError(
                "Kiosk Satellite download is not a valid APK"
            ) from exc
        self.kiosk_apk = path
        return path, tag, selected_abi

    def ensure_kiosk_satellite(self) -> None:
        installed_version = self.kiosk_satellite_version()
        if installed_version is not None:
            print(
                f"KIOSK_INSTALL_SKIP package={KIOSK_PACKAGE} "
                f"version={installed_version} reason=already-installed"
            )
            return
        apk, release, abi = self.resolve_kiosk_satellite_apk()
        self.install_apk_preserving_verifier(apk, "kiosk-satellite")
        self.settle_package_state()
        self.verify_package_verifier_state()
        installed_version = self.kiosk_satellite_version()
        expected_version = release.removeprefix("v")
        if installed_version not in (release, expected_version):
            raise ProvisionError(
                "Kiosk Satellite version verification failed after installation: "
                f"installed={installed_version!r} release={release!r}"
            )
        launch = self.adb_run(
            [
                "shell", "monkey", "-p", KIOSK_PACKAGE, "-c",
                "android.intent.category.LAUNCHER", "1",
            ],
            timeout=30,
        )
        if launch.returncode != 0 or "Events injected: 1" not in launch.stdout:
            raise ProvisionError(
                "Kiosk Satellite installed but could not be launched: "
                + launch.stdout[-2000:].strip()
            )
        print(
            f"KIOSK_INSTALL_OK package={KIOSK_PACKAGE} "
            f"version={installed_version} abi={abi} source=github"
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
                    raise ProvisionError(
                        "Shizuku APK download failed on the host computer: "
                        f"{exc}. Connect the host to the internet or download "
                        "the pinned APK separately and pass --shizuku-apk PATH"
                    ) from exc
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
        self.adb_run(["push", str(apk), remote], timeout=600, check=True)
        disabled = self.adb_run(
            ["shell", "pm", "list", "packages", "-d", "-u"],
            timeout=15,
            check=True,
        ).stdout
        verifier_was_disabled = "package:com.facebook.appverifier" in disabled
        # Record the state for this installation transaction. A profile can
        # intentionally change the durable verifier state between APKs (for
        # example, install Kiosk Satellite and then apply --allow-app-updates)
        # so an earlier transaction's baseline must not be reused here.
        self.package_verifier_before_install_disabled = verifier_was_disabled
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
        result = self.adb_run(["shell", command], timeout=300)
        if result.returncode != 0 or "Success" not in result.stdout:
            raise ProvisionError(
                f"APK installation failed for {apk}: {result.stdout.strip()}"
            )
        print(
            f"APK_INSTALL_OK package_source={apk.name} "
            f"verifier_state={'disabled' if verifier_was_disabled else 'enabled'}"
        )

    def verify_package_verifier_state(self) -> None:
        if self.package_verifier_before_install_disabled is None:
            return
        disabled = self.adb_run(
            ["shell", "pm", "list", "packages", "-d", "-u"],
            timeout=15,
            check=True,
        ).stdout
        actual = "package:com.facebook.appverifier" in disabled
        if actual != self.package_verifier_before_install_disabled:
            raise ProvisionError(
                "Meta package verifier state was not restored: "
                f"disabled={int(actual)} expected="
                f"{int(self.package_verifier_before_install_disabled)}"
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
        if self.target and self.target.buffer_root_staged_sources:
            self.adb_run(
                ["shell", "rm", "-f", SHIZUKU_SAVED_KEY_REMOTE],
                timeout=5,
                check=True,
            )
        print("SHIZUKU_REMOVE_APPS_OK")

    def finalize_buffered_shizuku_key(self) -> None:
        if not self.target or not self.target.buffer_root_staged_sources:
            return
        if self.shizuku_public_key is None:
            raise ProvisionError("Shizuku helper key was not prepared")
        self.adb_run(
            ["push", str(self.shizuku_public_key), SHIZUKU_SAVED_KEY_REMOTE],
            timeout=30,
            check=True,
        )
        self.adb_run(
            ["shell", "chmod", "0600", SHIZUKU_SAVED_KEY_REMOTE],
            timeout=5,
            check=True,
        )
        print("SHIZUKU_KEY_MARKER_OK source=post-reboot")

    def finalize_buffered_uid1000_markers(self) -> None:
        if not self.target or not self.target.buffer_root_staged_sources:
            return
        if self.disable_camera_light:
            self.adb_run(
                [
                    "shell", "mkdir", "-p",
                    "/data/local/tmp/portal-camera-light-backup",
                ],
                timeout=5,
                check=True,
            )
            self.push_text_atomic(
                "Portal camera light watchdog installed\n",
                CAMERA_LIGHT_INSTALLED_REMOTE,
            )
            self.adb_run(
                ["shell", "rm", "-f", CAMERA_LIGHT_RESTORED_REMOTE],
                timeout=5,
                check=True,
            )
            print("CAMERA_LIGHT_MARKER_OK source=post-reboot")
        if self.restore_camera_light:
            self.adb_run(
                [
                    "shell",
                    "mkdir",
                    "-p",
                    "/data/local/tmp/portal-camera-light-backup",
                ],
                timeout=5,
                check=True,
            )
            self.adb_run(
                ["shell", "rm", "-f", CAMERA_LIGHT_INSTALLED_REMOTE],
                timeout=5,
                check=True,
            )
            self.push_text_atomic(
                "Portal camera light watchdog restored\n",
                CAMERA_LIGHT_RESTORED_REMOTE,
            )
            print("CAMERA_LIGHT_RESTORE_MARKER_OK source=post-reboot")
        if self.presence_fps_action_requested():
            self.adb_run(
                [
                    "shell", "mkdir", "-p",
                    "/data/local/tmp/portal-presence-backup",
                ],
                timeout=5,
                check=True,
            )
            self.push_text_atomic(
                f"{self.presence_fps_cap}\n",
                "/data/local/tmp/portal-presence-backup/fps-cap-v1",
            )
            self.adb_run(
                [
                    "shell", "rm", "-f",
                    "/data/local/tmp/portal-presence-backup/fps-restored-v1",
                ],
                timeout=5,
                check=True,
            )
            print("PRESENCE_FPS_MARKER_OK source=post-reboot")
        if self.restore_presence_fps or self.restore_presence_profile:
            self.adb_run(
                [
                    "shell", "mkdir", "-p",
                    "/data/local/tmp/portal-presence-backup",
                ],
                timeout=5,
                check=True,
            )
            self.adb_run(
                [
                    "shell", "rm", "-f",
                    "/data/local/tmp/portal-presence-backup/fps-cap-v1",
                ],
                timeout=5,
                check=True,
            )
            self.push_text_atomic(
                "Portal presence FPS cap restored\n",
                "/data/local/tmp/portal-presence-backup/fps-restored-v1",
            )
            print("PRESENCE_FPS_RESTORE_MARKER_OK source=post-reboot")

    def install_uid1000_runtime_payload(self) -> None:
        self.install_apk_preserving_verifier(
            UID1000_RUNTIME_APK_LOCAL, "uid1000-runtime"
        )
        package_path = self.adb_run(
            ["shell", "pm", "path", UID1000_RUNTIME_PACKAGE],
            timeout=10,
            check=True,
        ).stdout.strip()
        match = re.search(r"^package:(.+/base\.apk)$", package_path, re.MULTILINE)
        if not match:
            raise ProvisionError(
                "could not resolve the installed UID-1000 runtime paths"
            )
        package_directory = match.group(1).rsplit("/", 1)[0]
        library_path = (
            package_directory
            + "/lib/arm64/libportal_uid1000_watch.so"
        )
        if self.adb_run(
            ["shell", "test", "-f", library_path], timeout=5
        ).returncode != 0:
            raise ProvisionError(
                "installed UID-1000 runtime native library is absent: "
                + library_path
            )
        self.uid1000_runtime_apk_remote = match.group(1)
        self.uid1000_runtime_library_remote = library_path
        self.uid1000_runtime_package_installed = True
        print("UID1000_RUNTIME_APK_OK package=installed native=extracted")

    def uninstall_uid1000_runtime_payload(self, best_effort: bool = False) -> None:
        if not self.uid1000_runtime_package_installed:
            return
        result = self.adb_run(
            ["uninstall", UID1000_RUNTIME_PACKAGE], timeout=30
        )
        if not best_effort and result.returncode != 0:
            raise ProvisionError(
                "could not remove the temporary UID-1000 runtime package: "
                + result.stdout
            )
        self.uid1000_runtime_package_installed = False
        print("UID1000_RUNTIME_APK_REMOVE package=removed")

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
            "persistent_wireless_adb",
            "disable_adb_auth_timeout",
            "restore_adb_auth_timeout",
            "audio",
            "restore_audio",
            "install_kiosk_satellite",
            "kiosk_permissions",
            "device_owner",
            "kiosk_home",
            "restore_kiosk_home",
            "disable_updates",
            "enable_updates",
            "debloat",
            "restore_bloat",
            "block_remote_wipe",
            "restore_remote_wipe",
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
        self.meta_accounts_absent = not accounts
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
            result = self.adb_run(
                ["shell", "dpm", "set-active-admin", "--user", "0", component],
                timeout=15,
            )
            policy = self.adb_run(
                ["shell", "dumpsys", "device_policy"], timeout=15, check=True
            ).stdout
            is_admin = (
                result.returncode == 0
                and "Enabled Device Admins (User 0" in policy
                and f"    {component}:" in policy
            )
            if not is_admin:
                raise ProvisionError(
                    f"Kiosk Satellite admin could not be activated: {component}: "
                    f"{result.stdout.strip()}"
                )
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
        if not installed and self.target and self.target.audio_installer_credentials:
            try:
                self.verify_watchdog(wait_seconds=5)
            except ProvisionError:
                print("AUDIO_PREFLIGHT installed=0 healthy=0 action=install")
                return False
            print(
                "AUDIO_PREFLIGHT installed=private healthy=1 action=skip"
            )
            return True
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

    def ota_preflight(self) -> bool:
        disabled = self.adb_run(
            ["shell", "pm", "list", "packages", "-d", "-u"],
            timeout=10,
            check=True,
        ).stdout
        packages = (
            self.target.ota_packages
            if self.target
            else (OTA_UI_PACKAGE, OTA_SETUP_PACKAGE)
        )
        packages_disabled = all(
            f"package:{package}" in disabled for package in packages
        )
        ota_dump = self.adb_run(
            ["shell", "dumpsys", "facebook.aloha.otaservice"], timeout=10
        ).stdout
        gate_false = "getBool(kFirmwareOtaUpdateEnable): false" in ota_dump
        healthy = packages_disabled and gate_false
        print(
            "OTA_PREFLIGHT "
            f"packages_disabled={int(packages_disabled)} "
            f"firmware_gate_false={int(gate_false)} "
            f"action={'skip' if healthy else 'install'}"
        )
        return healthy

    def debloat_preflight(self) -> bool:
        installed, disabled = self.package_sets()
        packages_complete = all(
            package not in installed or package in disabled
            for package in DEBLOAT_PACKAGES
        )
        saved = self.read_component_backup(required=False)
        components_complete = False
        if saved is not None:
            current = self.current_component_states()
            components_complete = all(
                original == "absent"
                or component in SELF_MANAGED_DEBLOAT_COMPONENTS
                or current[component][1] == "disabled"
                for component, (_, original) in saved.items()
            )
        complete = packages_complete and components_complete
        print(
            "DEBLOAT_PREFLIGHT "
            f"packages_complete={int(packages_complete)} "
            f"components_complete={int(components_complete)} "
            f"action={'skip' if complete else 'install'}"
        )
        return complete

    def remote_wipe_preflight(self) -> bool:
        saved = self.read_remote_wipe_backup(required=False)
        current = self.current_named_component_states(
            REMOTE_WIPE_COMPONENTS, detect_missing=True
        )
        complete = saved is not None and all(
            state in {"disabled", "absent"} for state in current.values()
        )
        print(
            "REMOTE_WIPE_PREFLIGHT "
            f"backup_present={int(saved is not None)} "
            f"receivers_disabled={sum(state == 'disabled' for state in current.values())} "
            f"receivers_absent={sum(state == 'absent' for state in current.values())} "
            f"action={'skip' if complete else 'install'}"
        )
        return complete

    def presence_preflight(self) -> bool:
        marker_present = self.adb_run(
            ["shell", "test", "-f", PRESENCE_INSTALLED_REMOTE], timeout=5
        ).returncode == 0
        try:
            self.verify_presence_runtime(
                require_profile=not marker_present, wait_seconds=90
            )
        except ProvisionError as exc:
            print(f"PRESENCE_PREFLIGHT action=install reason={exc}")
            return False
        print(
            "PRESENCE_PREFLIGHT action=skip profile=active "
            f"verified_marker={int(marker_present)}"
        )
        return True

    def presence_fps_preflight(self) -> bool:
        if self.presence_fps_cap is None:
            return False
        marker = self.adb_run(
            [
                "shell", "cat",
                "/data/local/tmp/portal-presence-backup/fps-cap-v1",
            ],
            timeout=5,
        )
        if (
            marker.returncode != 0
            or marker.stdout.strip() != str(self.presence_fps_cap)
        ):
            print(
                "PRESENCE_FPS_PREFLIGHT action=install "
                f"expected={self.presence_fps_cap} marker=absent-or-mismatched"
            )
            return False
        try:
            self.verify_presence_runtime(
                require_profile=True,
                expected_analysis_fps=self.presence_fps_cap,
                wait_seconds=90,
            )
        except ProvisionError as exc:
            print(f"PRESENCE_FPS_PREFLIGHT action=install reason={exc}")
            return False
        print(
            "PRESENCE_FPS_PREFLIGHT action=skip "
            f"fps={self.presence_fps_cap} activation=uid1000"
        )
        return True

    def kaslr_base(self, tag: str) -> int:
        if self.target is None:
            raise ProvisionError("target must be selected before KASLR discovery")
        if self.target.kaslr_strategy == "bugreport":
            # dumpstate reads the kernel log as root, so the boot-time
            # "Virtual kernel memory layout" dump exposes this boot's .text
            # address — the KASLR base — without simpleperf or a leak.
            report = self.bugreport_text(tag)
            match = re.search(r"\.text\s+: (0x[0-9a-f]+) -", report)
            if not match:
                raise ProvisionError(
                    "kernel .text range is absent from bugreport"
                )
            return int(match.group(1), 16)
        offsets = self.target.kaslr_pc_offsets
        simpleperf = "simpleperf"
        if self.target.bundled_simpleperf:
            roots = []
            for name in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "NDK"):
                value = os.environ.get(name)
                if value:
                    roots.append(pathlib.Path(value))
            roots.extend(
                (
                    pathlib.Path.home() / "android-sdk/ndk",
                    pathlib.Path.home() / "Android/Sdk/ndk",
                )
            )
            candidates: list[pathlib.Path] = []
            for root in roots:
                if (root / "simpleperf/bin/android/arm64/simpleperf").is_file():
                    candidates.append(root / "simpleperf/bin/android/arm64/simpleperf")
                if root.is_dir():
                    candidates.extend(
                        sorted(
                            root.glob("*/simpleperf/bin/android/arm64/simpleperf"),
                            reverse=True,
                        )
                    )
            local_simpleperf = next(
                (candidate for candidate in candidates if candidate.is_file()),
                None,
            )
            if local_simpleperf is None:
                raise ProvisionError(
                    "this target needs the Android NDK arm64 simpleperf binary; "
                    "set ANDROID_NDK_HOME to the installed NDK directory"
                )
            simpleperf = "/data/local/tmp/portal-simpleperf"
            self.adb_run(
                ["push", str(local_simpleperf), simpleperf],
                timeout=120,
                check=True,
            )
            self.adb_run(
                ["shell", "chmod", "0755", simpleperf], timeout=20, check=True
            )
        for sample_try in range(3):
            remote = f"/data/local/tmp/portal-perf-{tag}-{sample_try}.data"
            command = (
                f"{shlex.quote(simpleperf)} record -g -e cpu-clock -f 4000 "
                "--duration 2 "
                f"-o {shlex.quote(remote)} -- /system/bin/dd if=/dev/zero "
                "of=/dev/null bs=4096"
            )
            self.adb_run(["shell", command], timeout=20)
            # report-sample can emit several megabytes for a two-second sample.
            # Filter on-device so remote ADB targets only transfer the kernel
            # addresses used by the KASLR calculation.
            report_command = (
                f"{shlex.quote(simpleperf)} report-sample -i "
                f"{shlex.quote(remote)} | "
                "grep -m 512 'vaddr_in_file: ffffff'"
            )
            report = self.adb_run(["shell", report_command], timeout=60)
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
        if self.target is None:
            raise ProvisionError("target must be selected before memory discovery")
        if self.target.memstart_strategy == "allocator":
            command = (
                "env GHOSTLOCK_VOLATILE_LOG=1 "
                "GHOSTLOCK_DIAG_PAGE_PREP_ONLY=1 "
                "GHOSTLOCK_PAGE_COLLISIONS=5 "
                "GHOSTLOCK_LOG_P0_CANDIDATES=1 "
                f"LD_PRELOAD={shlex.quote(PRELOAD_REMOTE)} /system/bin/true"
            )
            for _ in range(3):
                result = self.adb_run(["shell", command], timeout=90)
                match = re.search(
                    r"runtime alias .*?memstart=([0-9a-fA-F]{16})",
                    result.stdout,
                )
                if result.returncode == 0 and match:
                    return int(match.group(1), 16)
            raise ProvisionError(
                "allocator diagnostic did not expose a verified memstart_addr"
            )
        report = self.bugreport_text(tag)
        match = re.search(r"memory\s+: (0x[0-9a-f]+) -", report)
        if not match:
            raise ProvisionError("kernel virtual memory range is absent from bugreport")
        virtual_start = int(match.group(1), 16)
        return (
            0x80000000 - (virtual_start - 0xFFFFFFC000000000)
        ) & 0xFFFFFFFFFFFFFFFF

    def bugreport_text(self, tag: str) -> str:
        result = self.adb_run(["shell", "bugreportz", "-p"], timeout=180)
        match = re.search(r"OK:(\S+\.zip)", result.stdout)
        recovered_archive = False
        if match:
            remote = match.group(1)
        else:
            begun = re.search(r"BEGIN:(\S+\.zip)", result.stdout)
            if not begun:
                raise ProvisionError(f"bugreportz failed: {result.stdout[-500:]}")
            remote = begun.group(1)
            # Omni can finish and rename the ZIP, then reset adbd before the
            # client receives the final OK line. Reconnect and validate that
            # finalized archive instead of discarding a usable capture.
            self.connect(wait_seconds=600)
            if self.adb_run(
                ["shell", "test", "-s", remote], timeout=5
            ).returncode != 0:
                raise ProvisionError(
                    "bugreportz disconnected and its archive is absent: "
                    + remote
                )
            recovered_archive = True
            print(
                "BUGREPORT_ARCHIVE_RECOVERED "
                f"path={remote} returncode={result.returncode}",
                flush=True,
            )
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
        if recovered_archive:
            print("BUGREPORT_ARCHIVE_OK source=finalized-begin", flush=True)
        return report

    def exploit(self, base: int, memstart: int, attempt: int) -> bool:
        if self.target is None:
            raise ProvisionError("target must be selected before exploitation")
        stack_route = self.target.stack_route
        environment = {
            "GHOSTLOCK_KASLR_BASE": hex(base),
            "GHOSTLOCK_P0_MEMSTART": hex(memstart),
            "GHOSTLOCK_TRUST_EXTERNAL_KASLR": "1",
            "GHOSTLOCK_MM_PARTIALS": "14",
            "GHOSTLOCK_PAGE_COLLISIONS": "5",
            "GHOSTLOCK_BUDDY_HOLD_PAIRS": "64",
            "GHOSTLOCK_BUDDY_HOLD_SENDS": "1024",
            "GHOSTLOCK_RECLAIM_PAIRS": str(self.target.reclaim_pairs),
            "GHOSTLOCK_RECLAIM_SENDS": str(self.target.reclaim_sends),
            "GHOSTLOCK_SOCKET_WATCH": "1",
            "GHOSTLOCK_WATCH_CFI": "1",
            "GHOSTLOCK_SENDMMSG_PROC_UID_LOCK": "1",
            "GHOSTLOCK_SLIDE_BREAK_OWNER_CHAIN": "1",
            "GHOSTLOCK_HOLD_AFTER_SCHED": "1",
            "GHOSTLOCK_MAIN_ROUTE": f"slide-{stack_route}",
            "GHOSTLOCK_FOPS_STACK_ROUTE": stack_route,
            "GHOSTLOCK_SIGSTAMP_USEC": str(self.target.route_delay_usec),
            "GHOSTLOCK_PROC_UID_WARM_MB": "256",
            "GHOSTLOCK_ADBD_ROOT_CONFIGFS": "1",
            "GHOSTLOCK_ROOT_SELF_CONFIGFS": "1",
            "GHOSTLOCK_VOLATILE_LOG": "1",
            "LD_PRELOAD": PRELOAD_REMOTE,
        }
        if self.target.kgsl_reclaim:
            environment.update(
                {
                    "GHOSTLOCK_KGSL_ORDER2": "1",
                    "GHOSTLOCK_KGSL_WATCH": "1",
                    "GHOSTLOCK_KGSL_HOLD": "1024",
                    "GHOSTLOCK_KGSL_RECLAIM": str(
                        self.target.kgsl_reclaim_allocations
                    ),
                    "GHOSTLOCK_KGSL_RECLAIM_EARLY": "512",
                    "GHOSTLOCK_FOPS_TILE_TABLES": "1",
                }
            )
        if self.target.mm_recycle_slabs:
            environment["GHOSTLOCK_MM_RECYCLE_SLABS"] = str(
                self.target.mm_recycle_slabs
            )
        if self.target.proc_uid_sentinel in ("run_as", "app", "user"):
            environment["GHOSTLOCK_PROC_UID_APP_SENTINEL"] = "1"
            if self.target.proc_uid_sentinel == "run_as":
                environment.update(
                    {
                    "GHOSTLOCK_PROC_UID_RUNAS_SENTINEL": "1",
                    "GHOSTLOCK_PROC_UID_RUNAS_PACKAGE": (
                        EXPLOIT_SENTINEL_PACKAGE
                    ),
                    }
                )
            elif self.target.proc_uid_sentinel == "user":
                environment["GHOSTLOCK_PROC_UID_USER_SENTINEL"] = "1"
                if self.target.proc_uid_user_ids:
                    environment["GHOSTLOCK_SENTINEL_USER_IDS"] = ",".join(
                        str(uid) for uid in self.target.proc_uid_user_ids
                    )
            else:
                environment["GHOSTLOCK_PROC_UID_APP_COMPONENT"] = (
                    f"{EXPLOIT_SENTINEL_PACKAGE}/.SentinelActivity"
                )
        else:
            environment["GHOSTLOCK_PROC_UID_SENTINEL_NICE"] = "0"
        if self.persist_wireless_adb:
            environment["GHOSTLOCK_ENABLE_WIRELESS_ADB"] = "1"
            if self.target.wireless_adb_file_property:
                environment["GHOSTLOCK_WIRELESS_ADB_FILE_PROPERTY"] = (
                    self.target.wireless_adb_file_property
                )
            if self.target.wireless_adb_uid1000_boot:
                environment["GHOSTLOCK_UID1000_WIRELESS_ADB"] = "1"
        if self.audio and not self.audio_already_configured:
            environment.update(
                {
                    "GHOSTLOCK_AUDIO_PERSIST": "1",
                    "GHOSTLOCK_AUDIO_PERSIST_SO": HELPER_REMOTE,
                }
            )
            if self.target.audio_deferred_ctl:
                environment["GHOSTLOCK_AUDIO_CTL_DEFERRED_ONLY"] = "1"
            else:
                environment["GHOSTLOCK_AUDIO_CTL"] = "1"
            if self.target.audio_java_fallback:
                environment.update(
                    {
                        "GHOSTLOCK_AUDIO_CTL_JAVA_DEFERRED": "1",
                        "GHOSTLOCK_AUDIO_PERSIST_JAR": AUDIO_CTL_REMOTE,
                    }
                )
        if self.restore_audio:
            environment.update(
                {
                    "GHOSTLOCK_RESTORE_AUDIO_PERSIST": "1",
                    "GHOSTLOCK_AUDIO_RESTORE_CTL": "1",
                }
            )
            if self.target.audio_java_fallback:
                environment.update(
                    {
                        "GHOSTLOCK_AUDIO_CTL_JAVA_FALLBACK": "1",
                        "GHOSTLOCK_AUDIO_CTL_JAR": AUDIO_CTL_REMOTE,
                    }
                )
        private_audio_action = (
            self.target.audio_installer_credentials
            and self.requested_actions()
            in ({"audio": True}, {"restore_audio": True})
        )
        private_owner_action = (
            self.target.device_owner_system_credentials
            and self.requested_actions() == {"device_owner": True}
        )
        private_ota_action = (
            self.target.ota_installer_credentials
            and self.requested_actions()
            in ({"disable_updates": True}, {"enable_updates": True})
        )
        private_meta_action = (
            self.target.meta_accounts_system_credentials
            and self.requested_actions() == {"remove_meta_accounts": True}
            and not self.meta_accounts_absent
            and not self.meta_accounts_auth_only
        )
        private_presence_action = (
            self.target.presence_installer_credentials
            and self.requested_actions()
            in (
                {"optimize_presence": True},
                {"restore_presence_profile": True},
            )
        )
        private_uid1000_action = (
            self.target.uid1000_installer_credentials
            and self.requested_actions()
            in (
                {"disable_camera_light": True},
                {"restore_camera_light": True},
                {"presence_fps_cap": self.presence_fps_cap},
                {
                    "optimize_presence": True,
                    "presence_fps_cap": self.presence_fps_cap,
                },
                {"restore_presence_fps": True},
            )
        )
        preserve_shell_domain = (
            self.target.shell_root_package_actions
            and (
                self.meta_accounts_auth_only
                or self.meta_accounts_finalize_only
                or
                (
                    self.remove_meta_accounts
                    and not self.meta_accounts_already_clean
                    and self.meta_accounts_absent
                    and self.requested_actions()
                    == {"remove_meta_accounts": True}
                )
                or (
                    set(self.requested_actions())
                    <= {
                        "debloat",
                        "restore_bloat",
                        "block_remote_wipe",
                        "restore_remote_wipe",
                    }
                    and any(
                        (
                            self.debloat,
                            self.restore_bloat,
                            self.block_remote_wipe,
                            self.restore_remote_wipe,
                        )
                    )
                )
            )
        )
        credential_action = (
            private_audio_action
            or private_owner_action
            or private_ota_action
            or private_meta_action
            or private_presence_action
            or private_uid1000_action
        )
        if credential_action:
            if private_meta_action and (
                self.meta_accounts_local_only or self.meta_accounts_finalize_only
            ):
                source_process = "com.facebook.alohaservices.alohausers"
            else:
                source_process = (
                    "installd"
                    if (
                        private_audio_action
                        or private_ota_action
                        or private_presence_action
                        or private_uid1000_action
                    )
                    else "system_server"
                )
            process = self.adb_run(
                ["shell", "pidof", source_process],
                timeout=5,
                check=True,
            ).stdout.strip().split()
            uid = self.adb_run(
                [
                    "shell", "stat", "-c", "%u",
                    f"/proc/{process[0]}" if process else "/proc/invalid",
                ],
                timeout=5,
                check=True,
            ).stdout.strip()
            if not process or not uid.isdigit():
                raise ProvisionError(
                    f"could not resolve {source_process} action identity"
                )
            environment.update(
                {
                    "GHOSTLOCK_ACTION_CREDENTIAL_PID": process[0],
                    "GHOSTLOCK_ACTION_EXPECT_UID": uid,
                }
            )
            if private_audio_action:
                environment.update(
                    {
                        "GHOSTLOCK_AUDIO_PRIVATE_ONLY": "1",
                        "GHOSTLOCK_AUDIO_IN_MEMORY_SOURCES": "1",
                        "GHOSTLOCK_AUDIO_PRESERVE_METADATA": "1",
                    }
                )
            if private_owner_action:
                environment["GHOSTLOCK_DEVICE_OWNER_PRIVATE_ONLY"] = "1"
            if private_ota_action:
                environment["GHOSTLOCK_OTA_PRIVATE_ONLY"] = "1"
            if private_presence_action:
                environment["GHOSTLOCK_PRESENCE_PRIVATE_ONLY"] = "1"
        if preserve_shell_domain:
            environment["GHOSTLOCK_ACTION_PRESERVE_SELINUX"] = "1"
        if (
            self.remove_meta_accounts
            and not self.meta_accounts_already_clean
            and self.meta_accounts_absent
        ):
            environment["GHOSTLOCK_META_ACCOUNTS_EMPTY"] = "1"
        if self.device_owner and not self.device_owner_already_configured:
            environment["GHOSTLOCK_KIOSK_DEVICE_OWNER"] = "1"
        if self.disable_updates and not self.ota_already_configured:
            environment["GHOSTLOCK_OTA_BLOCK"] = "1"
        if self.enable_updates:
            environment["GHOSTLOCK_RESTORE_OTA_BLOCK"] = "1"
        if self.optimize_presence and not self.presence_already_configured:
            environment["GHOSTLOCK_PRESENCE_PROFILE"] = "1"
        if self.restore_presence_profile:
            environment["GHOSTLOCK_RESTORE_PRESENCE_PROFILE"] = "1"
        if self.presence_fps_action_requested():
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
        native_presence_prefs = self.uses_native_presence_prefs()
        if native_presence_prefs:
            environment["GHOSTLOCK_PRESENCE_NATIVE_PREFS"] = "1"
        if (
            (self.debloat and not self.debloat_already_configured)
            or self.restore_bloat
            or (self.needs_component_ctl() and not native_presence_prefs)
        ):
            environment.update(
                {
                    "GHOSTLOCK_COMPONENT_CTL_JAR": COMPONENT_CTL_REMOTE,
                    "GHOSTLOCK_COMPONENT_ACTIONS": (
                        DEBLOAT_COMPONENT_ACTIONS_REMOTE
                    ),
                }
            )
        if self.presence_fps_action_requested() and not native_presence_prefs:
            environment["GHOSTLOCK_PRESENCE_PREF_ACTION"] = (
                f"set:{self.presence_fps_cap}"
            )
        if (
            (self.restore_presence_fps or self.restore_presence_profile)
            and not native_presence_prefs
        ):
            environment["GHOSTLOCK_PRESENCE_PREF_ACTION"] = "restore"
        if self.remove_meta_accounts and not self.meta_accounts_already_clean:
            environment.update(
                {
                    "GHOSTLOCK_REMOVE_META_ACCOUNTS": "1",
                    "GHOSTLOCK_META_ACCOUNT_CTL_JAR": ACCOUNT_CTL_REMOTE,
                }
            )
            if self.target.meta_accounts_skip_force_stop:
                environment["GHOSTLOCK_META_ACCOUNTS_SKIP_FORCE_STOP"] = "1"
            if self.meta_accounts_local_only:
                environment["GHOSTLOCK_META_ACCOUNTS_LOCAL_ONLY"] = "1"
            if self.meta_accounts_auth_only:
                environment["GHOSTLOCK_META_ACCOUNTS_AUTH_ONLY"] = "1"
            if self.meta_accounts_finalize_only:
                environment["GHOSTLOCK_META_ACCOUNTS_FINALIZE_ONLY"] = "1"
                package_uid_result = self.adb_run(
                    [
                        "shell", "cmd", "package", "list", "packages", "-U",
                        "com.facebook.alohaservices.alohausers",
                    ],
                    timeout=10,
                    check=True,
                ).stdout
                package_uid_match = re.search(r"\buid:(\d+)\b", package_uid_result)
                if (
                    package_uid_match is None
                    or not 10000 <= int(package_uid_match.group(1)) < 100000
                ):
                    raise ProvisionError(
                        "could not resolve the Meta account authenticator UID"
                    )
                environment["GHOSTLOCK_META_ACCOUNT_PACKAGE_UID"] = (
                    package_uid_match.group(1)
                )
        if self.shizuku:
            environment["GHOSTLOCK_SHIZUKU_AUTHORIZE_KEY"] = "1"
        if self.remove_shizuku:
            environment["GHOSTLOCK_SHIZUKU_REMOVE_KEY"] = "1"
        if self.disable_camera_light:
            environment["GHOSTLOCK_DISABLE_CAMERA_LIGHT"] = "1"
        if self.restore_camera_light:
            environment["GHOSTLOCK_RESTORE_CAMERA_LIGHT"] = "1"
        if self.target.uid1000_embedded_helper and self.needs_uid1000_payload():
            if (
                not self.uid1000_runtime_apk_remote
                or not self.uid1000_runtime_library_remote
            ):
                raise ProvisionError("UID-1000 runtime APK paths were not prepared")
            environment.update(
                {
                    "GHOSTLOCK_UID1000_RUNTIME_APK": (
                        self.uid1000_runtime_apk_remote
                    ),
                    "GHOSTLOCK_UID1000_RUNTIME_LIBRARY": (
                        self.uid1000_runtime_library_remote
                    ),
                }
            )
            camera_installed = self.adb_run(
                ["shell", "test", "-f", CAMERA_LIGHT_INSTALLED_REMOTE],
                timeout=5,
            ).returncode == 0
            retained_fps = self.adb_run(
                [
                    "shell",
                    "cat",
                    "/data/local/tmp/portal-presence-backup/fps-cap-v1",
                ],
                timeout=5,
            ).stdout.strip()
            if camera_installed and not self.restore_camera_light:
                environment["GHOSTLOCK_DISABLE_CAMERA_LIGHT"] = "1"
            if (
                retained_fps.isdigit()
                and 1 <= int(retained_fps) <= 10
                and not self.restore_presence_fps
                and not self.restore_presence_profile
            ):
                environment["GHOSTLOCK_UID1000_PRESENCE_FPS"] = retained_fps
        if self.needs_uid1000_payload():
            self.adb_run(
                ["shell", "rm", "-f", UID1000_HOOK_ACTIVE_REMOTE],
                timeout=5,
                check=True,
            )
            if (
                not self.target.uid1000_embedded_helper
                and self.uid1000_boot_hook_active()
            ):
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
        environment.update(self.target.exploit_env)
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
            audio_marker = (
                "PORTAL_AUDIO_JAVA_DEFERRED_OK mode=disabled"
                if self.target.audio_java_fallback
                else "PORTAL_AUDIO_NATIVE_OK mode=disabled"
            )
            expected_markers.update(
                {
                    "audio_parameters": (audio_marker, False),
                    "audio_persistence": ("audio persistence install", True),
                }
            )
        if self.restore_audio:
            audio_marker = (
                "PORTAL_AUDIO_JAVA_OK mode=firmware-defaults"
                if self.target.audio_java_fallback
                else "PORTAL_AUDIO_NATIVE_OK mode=firmware-defaults"
            )
            expected_markers.update(
                {
                    "audio_defaults": (audio_marker, False),
                    "audio_restore": ("audio persistence restore", True),
                }
            )
        if self.device_owner and not self.device_owner_already_configured:
            expected_markers["device_owner"] = ("kiosk device owner install", True)
        if self.disable_updates and not self.ota_already_configured:
            expected_markers["ota_block"] = ("OTA block file install", True)
        if self.enable_updates:
            expected_markers["ota_restore"] = ("OTA block restore", True)
        if self.optimize_presence and not self.presence_already_configured:
            expected_markers["presence_profile"] = (
                "presence profile install",
                True,
            )
        if self.restore_presence_profile:
            expected_markers["presence_restore"] = (
                "presence profile restore",
                True,
            )
        if self.presence_fps_action_requested():
            presence_marker = (
                "PORTAL_PRESENCE_FPS_NATIVE action=set "
                f"fps={self.presence_fps_cap}"
                if self.uses_native_presence_prefs()
                else f"PORTAL_PRESENCE_FPS action=set fps={self.presence_fps_cap}"
            )
            expected_markers["presence_fps"] = (
                presence_marker,
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
                (
                    "PORTAL_PRESENCE_FPS_NATIVE action=restore"
                    if self.uses_native_presence_prefs()
                    else "PORTAL_PRESENCE_FPS action=restore"
                ),
                True,
            )
        if self.restore_presence_profile:
            expected_markers["presence_fps_restore"] = (
                (
                    "PORTAL_PRESENCE_FPS_NATIVE action=restore"
                    if self.uses_native_presence_prefs()
                    else "PORTAL_PRESENCE_FPS action=restore"
                ),
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
        if (self.debloat and not self.debloat_already_configured) or self.restore_bloat:
            expected_markers["component_profile"] = (
                "component ctl child=",
                True,
            )
        if self.remove_meta_accounts and not self.meta_accounts_already_clean:
            expected_markers["meta_accounts"] = (
                "PORTAL_META_ACCOUNTS_COMPLETE",
                True,
            )
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
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
            )
            assert process.stdout is not None
            deadline = time.monotonic() + self.target.exploit_timeout_seconds
            post_root_deadline_extended = False
            pending_output = ""
            while time.monotonic() < deadline:
                ready, _, _ = select.select([process.stdout], [], [], 1)
                if not ready:
                    if process.poll() is not None:
                        break
                    continue
                chunk = os.read(process.stdout.fileno(), 4096)
                if not chunk:
                    break
                text = chunk.decode("utf-8", errors="replace")
                sys.stdout.write(text)
                sys.stdout.flush()
                output.write(text)
                output.flush()
                pending_output += text
                lines = pending_output.splitlines(keepends=True)
                if lines and not lines[-1].endswith(("\n", "\r")):
                    pending_output = lines.pop()
                else:
                    pending_output = ""
                for line in lines:
                    if (
                        not post_root_deadline_extended
                        and self.target.post_root_timeout_seconds > 0
                        and "configfs action-child credentials installed" in line
                    ):
                        deadline = max(
                            deadline,
                            time.monotonic()
                            + self.target.post_root_timeout_seconds,
                        )
                        post_root_deadline_extended = True
                        print(
                            "POST_ROOT_ACTION_GRACE "
                            f"seconds={self.target.post_root_timeout_seconds}",
                            flush=True,
                        )
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
                    if credential_action and "WATCH_CFI_OK=1" in line:
                        print(
                            "NATIVE_ACTIONS_OK actions=credential-scoped",
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
                if success or failed:
                    break

            if (
                not success
                and not failed
                and self.target.recover_watch_result_after_disconnect
            ):
                # Cipher restarts its live adbd when the persistent TCP
                # property first becomes active. The kernel-side watcher has
                # already completed cleanup, but that restart can sever the
                # adb shell before its final marker reaches this pipe. Accept
                # only the exact, freshly generated success record written by
                # the same watcher after all actions and cleanup succeeded.
                recovery_deadline = time.monotonic() + 15
                while time.monotonic() < recovery_deadline:
                    try:
                        self.run(["adb", "connect", self.serial], timeout=5)
                        watch_result = self.adb_run(
                            [
                                "shell",
                                "cat",
                                "/data/local/tmp/ghostlock-watch-result.txt",
                            ],
                            timeout=5,
                        ).stdout.strip()
                    except ProvisionError:
                        time.sleep(1)
                        continue
                    if re.fullmatch(
                        r"WATCH_CFI_OK=1 STEP=0 ERRNO=0 ROOT=1 "
                        r"RSTEP=\d+ RERR=\d+",
                        watch_result,
                    ):
                        print(
                            "NATIVE_ACTIONS_OK actions=watch-result-recovery",
                            flush=True,
                        )
                        success = True
                        break
                    time.sleep(1)

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
        marker_required = not (
            self.target and self.target.audio_installer_credentials
        )
        if marker_required and self.adb_run(
            ["shell", "test", "-f", marker], timeout=5
        ).returncode != 0:
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

    def ensure_kiosk_home(self) -> None:
        default_home = self.current_default_home()
        alias_enabled = self.kiosk_home_alias_enabled()
        if default_home != KIOSK_HOME_COMPONENT or not alias_enabled:
            print(
                "KIOSK_HOME_REPAIR "
                f"previous_default={default_home or 'none'} "
                f"alias_enabled={int(alias_enabled)}",
                flush=True,
            )
            self.configure_kiosk_home(enabled=True)
        self.verify_kiosk_home(enabled=True)

    def disable_ota_packages(self) -> None:
        packages = (
            self.target.ota_packages
            if self.target
            else (OTA_UI_PACKAGE, OTA_SETUP_PACKAGE)
        )
        for package in packages:
            result = self.adb_run(
                ["shell", "pm", "disable-user", "--user", "0", package],
                timeout=10,
            )
            if result.returncode != 0 or "new state: disabled-user" not in result.stdout:
                already_disabled = self.adb_run(
                    ["shell", "pm", "list", "packages", "-d", "-u"],
                    timeout=10,
                    check=True,
                ).stdout
                if f"package:{package}" not in already_disabled:
                    raise ProvisionError(
                        f"failed to disable OTA package {package}: {result.stdout}"
                    )

    def enable_ota_packages(self) -> None:
        packages = (
            self.target.ota_packages
            if self.target
            else (OTA_UI_PACKAGE, OTA_SETUP_PACKAGE)
        )
        for package in packages:
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
            ["shell", "pm", "list", "packages", "-d", "-u"],
            timeout=10,
            check=True,
        ).stdout
        packages = (
            self.target.ota_packages
            if self.target
            else (OTA_UI_PACKAGE, OTA_SETUP_PACKAGE)
        )
        still_disabled = [
            package
            for package in packages
            if f"package:{package}" in disabled
        ]
        if still_disabled:
            raise ProvisionError(
                "OTA packages remain disabled: " + ", ".join(still_disabled)
            )
        print("OTA_RESTORE_OK packages=enabled override=restored")

    def verify_ota_block(self, wait_seconds: int = 30) -> None:
        disabled = self.adb_run(
            ["shell", "pm", "list", "packages", "-d", "-u"],
            timeout=10,
            check=True,
        ).stdout
        required = (
            self.target.ota_packages
            if self.target
            else (OTA_UI_PACKAGE, OTA_SETUP_PACKAGE)
        )
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
                [
                    "shell",
                    "logcat",
                    "-d",
                    "-v",
                    "threadtime",
                    "-e",
                    "getLatestBooleanWithOptions.*18296358819858434",
                ],
                timeout=15,
            ).stdout
            override_loaded = re.search(
                r"getLatestBooleanWithOptions \[18296358819858434\], "
                r"latestBoolean: false, source: OVERRIDE",
                last_log,
            )
            if "getBool(kFirmwareOtaUpdateEnable): false" in last_dump:
                print(
                    "OTA_BLOCK_OK packages=disabled "
                    "firmware_ota_update_enable=false source="
                    + ("OVERRIDE" if override_loaded else "effective-config")
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
        if self.target is None:
            raise ProvisionError("target must be selected before preparing UID 1000")
        host_package = self.target.uid1000_host_package
        self.adb_run(
            ["shell", "am", "force-stop", "--user", "0", host_package],
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
                host_package,
            ],
            timeout=120,
        )
        if result.returncode != 0 or "Success" not in result.stdout:
            raise ProvisionError(
                "could not generate the guarded UID-1000 host ART cache: "
                + result.stdout
            )
        print(
            f"CAMERA_LIGHT_ART_CACHE_OK host={self.target.uid1000_host_label} "
            "compiler_filter=speed"
        )

    def uid1000_boot_hook_active(self) -> bool:
        result = self.adb_run(
            ["shell", "ps", "-A", "-o", "USER,PID,ARGS"],
            timeout=10,
            check=True,
        )
        for line in result.stdout.splitlines():
            fields = line.split(maxsplit=2)
            if (
                fields
                and fields[0] == "system"
                and "portal-camera-led-watch" in line
            ):
                return True
        return False

    def prepare_camera_light_install(self) -> None:
        if self.target is None:
            raise ProvisionError("target must be selected before preparing UID 1000")
        installed, _ = self.package_sets()
        host_package = self.target.uid1000_host_package
        if host_package not in installed:
            raise ProvisionError(
                f"required persistent system package is absent: {host_package}"
            )
        if (
            self.uid1000_boot_hook_active()
            and not self.target.uid1000_embedded_helper
        ):
            print(
                "UID1000_BOOT_HOOK_RETAINED source=running-system-helper",
                flush=True,
            )
            return
        self.compile_camera_light_host_speed()

    def restore_uid1000_package_state_if_unused(self) -> None:
        if self.target and self.target.uid1000_embedded_helper:
            retained = []
            for path, label in (
                (CAMERA_LIGHT_INSTALLED_REMOTE, "camera-light"),
                (
                    "/data/local/tmp/portal-presence-backup/fps-cap-v1",
                    "presence-fps",
                ),
            ):
                if self.adb_run(
                    ["shell", "test", "-f", path], timeout=5
                ).returncode == 0:
                    retained.append(label)
            if retained:
                if self.uid1000_runtime_package_installed:
                    self.uid1000_runtime_package_installed = False
                    print("UID1000_RUNTIME_APK_RETAIN package=installed")
                print("UID1000_BOOT_HOOK_RETAINED features=" + ",".join(retained))
                return
            self.compile_camera_light_host_speed()
            if self.uid1000_runtime_package_installed:
                self.uninstall_uid1000_runtime_payload()
            print(
                f"UID1000_BOOT_HOOK_RESTORED host={self.target.uid1000_host_label}"
            )
            return
        retained = [
            path
            for path in (
                self.uid1000_path("camera-led-enabled"),
                self.uid1000_path("presence-fps"),
                self.uid1000_path("wireless-adb-enabled"),
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
        host_label = (
            self.target.uid1000_host_label
            if self.target
            else DEFAULT_UID1000_HOST_PACKAGE.rsplit(".", 1)[-1]
        )
        print(f"UID1000_BOOT_HOOK_RESTORED host={host_label}")

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

    def current_named_component_states(
        self, components: tuple[str, ...], detect_missing: bool = False
    ) -> dict[str, str]:
        installed, _ = self.package_sets()
        by_package: dict[str, list[str]] = collections.defaultdict(list)
        for component in components:
            package, class_name = component.split("/", 1)
            by_package[package].append(class_name)
        states: dict[str, str] = {}
        for package, entries in by_package.items():
            if package not in installed:
                for class_name in entries:
                    states[f"{package}/{class_name}"] = "absent"
                continue
            dump = self.adb_run(
                ["shell", "dumpsys", "package", package], timeout=20, check=True
            ).stdout
            enabled = self.component_override_set(dump, "enabledComponents")
            disabled = self.component_override_set(dump, "disabledComponents")
            for class_name in entries:
                state = (
                    "enabled"
                    if class_name in enabled
                    else "disabled"
                    if class_name in disabled
                    else "absent"
                    if detect_missing and class_name not in dump
                    else "default"
                )
                states[f"{package}/{class_name}"] = state
        return states

    def current_component_states(self) -> dict[str, tuple[str, str]]:
        categories = {
            component: category for category, component in DEBLOAT_COMPONENTS
        }
        states = self.current_named_component_states(DEBLOAT_COMPONENT_NAMES)
        return {
            component: (categories[component], state)
            for component, state in states.items()
        }

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

    @staticmethod
    def parse_remote_wipe_backup(contents: str) -> dict[str, str]:
        lines = contents.splitlines()
        if not lines or lines[0] != "# portal-remote-wipe-components-backup-v1":
            raise ProvisionError("unrecognized remote-wipe backup format")
        states: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            fields = line.split("\t")
            if len(fields) != 2:
                raise ProvisionError(f"invalid remote-wipe backup line: {line!r}")
            component, state = fields
            if component in states or component not in REMOTE_WIPE_COMPONENTS:
                raise ProvisionError(
                    f"unexpected component in remote-wipe backup: {component!r}"
                )
            if state not in {"default", "enabled", "disabled", "absent"}:
                raise ProvisionError(
                    f"invalid state in remote-wipe backup: {state!r}"
                )
            states[component] = state
        missing = set(REMOTE_WIPE_COMPONENTS) - states.keys()
        if missing:
            raise ProvisionError(
                "remote-wipe backup is incomplete: " + ", ".join(sorted(missing))
            )
        return states

    def read_remote_wipe_backup(
        self, required: bool = True
    ) -> dict[str, str] | None:
        result = self.adb_run(
            ["shell", "cat", REMOTE_WIPE_BACKUP_REMOTE], timeout=5
        )
        if result.returncode != 0:
            if required:
                raise ProvisionError(
                    f"remote-wipe backup is absent: {REMOTE_WIPE_BACKUP_REMOTE}"
                )
            return None
        return self.parse_remote_wipe_backup(result.stdout)

    def ensure_remote_wipe_backup(self) -> dict[str, str]:
        existing = self.read_remote_wipe_backup(required=False)
        if existing is not None:
            print(
                "REMOTE_WIPE_BACKUP_OK existing=1 path="
                + REMOTE_WIPE_BACKUP_REMOTE
            )
            return existing
        states = self.current_named_component_states(
            REMOTE_WIPE_COMPONENTS, detect_missing=True
        )
        contents = "# portal-remote-wipe-components-backup-v1\n" + "".join(
            f"{component}\t{states[component]}\n"
            for component in REMOTE_WIPE_COMPONENTS
        )
        self.push_text_atomic(contents, REMOTE_WIPE_BACKUP_REMOTE)
        saved = self.read_remote_wipe_backup(required=True)
        if saved != states:
            raise ProvisionError("remote-wipe backup verification failed")
        print(
            "REMOTE_WIPE_BACKUP_OK existing=0 path="
            + REMOTE_WIPE_BACKUP_REMOTE
        )
        return states

    def push_text_atomic(self, contents: str, remote: str) -> None:
        remote_tmp = remote + ".tmp"
        with tempfile.TemporaryDirectory(prefix="portal-state-") as temporary:
            local = pathlib.Path(temporary) / "state.tsv"
            local.write_text(contents, encoding="utf-8")
            self.adb_run(["push", str(local), remote_tmp], timeout=20, check=True)
        mode = "0644" if remote == DEBLOAT_COMPONENT_ACTIONS_REMOTE else "0600"
        command = (
            f"chmod {mode} {shlex.quote(remote_tmp)} && "
            f"mv {shlex.quote(remote_tmp)} {shlex.quote(remote)}"
        )
        self.adb_run(["shell", command], timeout=10, check=True)

    @staticmethod
    def restore_component_action(state: str) -> str:
        return (
            "default"
            if state == "default"
            else "enable"
            if state == "enabled"
            else "disable"
        )

    def prepare_component_actions(self) -> None:
        actions: list[str] = []
        modes: list[str] = []
        if self.debloat or self.restore_bloat:
            states = self.read_component_backup(required=False)
            if states is None:
                if self.debloat:
                    states = self.ensure_component_backup()
                else:
                    print("DEBLOAT_COMPONENT_RESTORE legacy_backup=absent actions=0")
            if states is not None:
                for component in DEBLOAT_COMPONENT_NAMES:
                    _, state = states[component]
                    if state == "absent":
                        continue
                    if self.debloat and component in SELF_MANAGED_DEBLOAT_COMPONENTS:
                        continue
                    action = (
                        "disable"
                        if self.debloat
                        else self.restore_component_action(state)
                    )
                    actions.append(f"{action}\t{component}\n")
                modes.append("debloat-disable" if self.debloat else "debloat-restore")
                if self.debloat:
                    account_backup = self.adb_run(
                        ["shell", "test", "-f", META_ACCOUNT_BACKUP_REMOTE],
                        timeout=5,
                    )
                    if account_backup.returncode == 0:
                        actions.append(f"enable\t{META_HARDWARE_AUTHENTICATOR}\n")
        if self.block_remote_wipe or self.restore_remote_wipe:
            remote_states = (
                self.ensure_remote_wipe_backup()
                if self.block_remote_wipe
                else self.read_remote_wipe_backup(required=True)
            )
            assert remote_states is not None
            for component in REMOTE_WIPE_COMPONENTS:
                state = remote_states[component]
                if state == "absent":
                    continue
                action = (
                    "disable"
                    if self.block_remote_wipe
                    else self.restore_component_action(state)
                )
                actions.append(f"{action}\t{component}\n")
            modes.append(
                "remote-wipe-disable"
                if self.block_remote_wipe
                else "remote-wipe-restore"
            )
        self.push_text_atomic(
            "# portal-debloat-component-actions-v1\n" + "".join(actions),
            DEBLOAT_COMPONENT_ACTIONS_REMOTE,
        )
        self.adb_run(
            ["shell", "chmod", "0644", DEBLOAT_COMPONENT_ACTIONS_REMOTE],
            timeout=5,
            check=True,
        )
        print(
            f"COMPONENT_ACTIONS modes={','.join(modes) or 'none'} "
            f"count={len(actions)}"
        )

    def apply_debloat(self) -> None:
        self.ensure_debloat_backup()
        self.ensure_component_backup()
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

    def verify_remote_wipe_blocked(self) -> None:
        saved = self.read_remote_wipe_backup(required=True)
        assert saved is not None
        current = self.current_named_component_states(
            REMOTE_WIPE_COMPONENTS, detect_missing=True
        )
        mismatches = [
            f"{component}={current[component]}"
            for component in saved
            if current[component] not in {"disabled", "absent"}
        ]
        if mismatches:
            raise ProvisionError(
                "Meta remote-wipe receivers became enabled: "
                + "; ".join(mismatches)
            )
        print(
            "REMOTE_WIPE_BLOCK_OK receivers_disabled="
            + str(sum(state == "disabled" for state in current.values()))
            + " receivers_absent="
            + str(sum(state == "absent" for state in current.values()))
        )

    def verify_remote_wipe_restored(self) -> None:
        saved = self.read_remote_wipe_backup(required=True)
        assert saved is not None
        current = self.current_named_component_states(
            REMOTE_WIPE_COMPONENTS, detect_missing=True
        )
        mismatches = [
            f"{component}={current[component]}, expected {state}"
            for component, state in saved.items()
            if state != "absent" and current[component] != state
        ]
        if mismatches:
            raise ProvisionError(
                "remote-wipe receiver restore mismatch: "
                + "; ".join(mismatches)
            )
        print("REMOTE_WIPE_RESTORE_OK receivers=verified")

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
        required_profile_keys = set(
            self.target.presence_runtime_keys
            if self.target and self.target.presence_runtime_keys
            else PRESENCE_PROFILE_KEYS
        )
        if expected_analysis_fps is not None:
            configured_path = (
                "/data/local/tmp/portal-presence-backup/fps-cap-v1"
                if self.target and self.target.uid1000_embedded_helper
                else self.uid1000_path("presence-fps")
            )
            configured = self.adb_run(
                ["shell", "cat", configured_path], timeout=5
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
            appops = self.adb_run(
                [
                    "shell",
                    "cmd",
                    "appops",
                    "get",
                    "com.facebook.portal.aiservice",
                    "CAMERA",
                ],
                timeout=10,
            ).stdout
            camera_appop = " ".join(appops.split()) or "no-operation-recorded"
            camera_allowed = "CAMERA: allow" in appops
            logs = self.adb_run(
                [
                    "shell",
                    "logcat",
                    "-d",
                    "-v",
                    "brief",
                    "-e",
                    PRESENCE_LOGCAT_REGEX,
                ],
                timeout=20,
            ).stdout
            presence_event = presence_event or PRESENCE_LOG_MARKER in logs
            presence_no_users = presence_no_users or (
                "CAMERA_SERVICE not running, but no users found yet" in logs
            )
            privacy_blocked = privacy_blocked or any(
                marker in logs.lower()
                for marker in (
                    "cannot start privacy mode on",
                    "privacy mode is on",
                )
            )
            analysis_frames = (
                analysis_frames or PRESENCE_ANALYSIS_FRAME_MARKER in logs
            )
            roi_frames = roi_frames or PRESENCE_ROI_FRAME_MARKER in logs
            wide_frame = wide_frame or self.presence_full_scene_active(
                logs, camera, self.target
            )
            loaded_keys.update({
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
            })
            analysis_fps_applied = analysis_fps_applied or (
                expected_analysis_fps is not None
                and any(
                    "Setting AI Processing FPS" in line
                    and re.search(
                        rf"\b{expected_analysis_fps}(?:\.0+)?\b", line
                    )
                    for line in logs.splitlines()
                )
            )
            helper_activation = helper_activation or (
                expected_analysis_fps is not None
                and any(
                    "PortalPresence" in line
                    and f"presence FPS activation complete fps={expected_analysis_fps}"
                    in line
                    and "uid=1000" in line
                    for line in logs.splitlines()
                )
            )
            config_ready = not require_profile or required_profile_keys.issubset(
                loaded_keys
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
                if require_profile:
                    self.adb_run(
                        [
                            "shell",
                            "mkdir",
                            "-p",
                            "/data/local/tmp/portal-presence-backup",
                        ],
                        timeout=5,
                        check=True,
                    )
                    self.push_text_atomic(
                        "Portal presence profile verified\n",
                        PRESENCE_INSTALLED_REMOTE,
                    )
                    self.adb_run(
                        [
                            "shell",
                            "rm",
                            "-f",
                            "/data/local/tmp/portal-presence-backup/restored-v1",
                        ],
                        timeout=5,
                    )
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
        camera_hint = (
            " Check that the Portal's physical camera cover is open and its "
            "camera/microphone privacy control is off."
            if not camera_active
            else ""
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
        if self.install_kiosk_satellite:
            version = self.kiosk_satellite_version()
            if version is None:
                raise ProvisionError("Kiosk Satellite is not installed")
            print(
                f"KIOSK_INSTALL_VERIFY_OK package={KIOSK_PACKAGE} version={version}"
            )
        if self.persist_wireless_adb:
            property_name = (
                self.target.wireless_adb_file_property
                if self.target and self.target.wireless_adb_file_property
                else "persist.adb.tcp.port"
            )
            persistent_port = self.adb_run(
                ["shell", "getprop", property_name],
                timeout=5,
                check=True,
            ).stdout.strip()
            if persistent_port != "5555":
                raise ProvisionError(
                    "wireless ADB did not persist on TCP port 5555: "
                    f"{property_name}={persistent_port!r}"
                )
            print(
                "WIRELESS_ADB_OK persistent_port=5555 "
                f"property={property_name}"
            )
        if self.disable_adb_auth_timeout or self.restore_adb_auth_timeout:
            self.verify_adb_auth_timeout()
        if self.audio:
            self.verify_watchdog()
        if self.restore_audio:
            self.verify_audio_restored()
        if self.kiosk_permissions:
            self.verify_kiosk_permissions()
        if self.device_owner:
            self.verify_device_owner()
        if self.kiosk_home:
            self.ensure_kiosk_home()
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
        if self.block_remote_wipe:
            self.verify_remote_wipe_blocked()
        if self.restore_remote_wipe:
            self.verify_remote_wipe_restored()
        if self.remove_meta_accounts:
            if self.meta_accounts_auth_only:
                disabled = self.disabled_meta_authenticators()
                missing = set(META_AUTHENTICATOR_COMPONENTS) - disabled
                hardware_class = META_HARDWARE_AUTHENTICATOR.split("/", 1)[1]
                if missing or hardware_class in disabled:
                    raise ProvisionError(
                        "Meta authenticator guard did not persist"
                    )
                print("META_AUTHENTICATOR_GUARD_OK authenticators=disabled")
            elif self.meta_accounts_local_only:
                self.adb_run(
                    ["shell", "touch", META_ACCOUNT_LOCAL_CLEAN_REMOTE],
                    timeout=5,
                    check=True,
                )
                self.adb_run(
                    ["shell", "chmod", "0600", META_ACCOUNT_LOCAL_CLEAN_REMOTE],
                    timeout=5,
                    check=True,
                )
                accounts = self.meta_accounts()
                print(
                    "META_ACCOUNT_PACKAGE_CLEANUP_OK local_rows=0 "
                    f"system_records={len(accounts)}"
                )
            else:
                self.verify_meta_accounts_removed()
        # Start a newly installed Shizuku helper before the longer camera
        # checks. Android keeps freshly installed packages stopped until their
        # first explicit launch, so its BOOT_COMPLETED receiver cannot run yet.
        if self.shizuku:
            self.verify_shizuku()
        if self.remove_shizuku:
            self.verify_shizuku_removed()
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
                ["shell", "test", "-e", self.uid1000_path("presence-fps")],
                timeout=5,
            ).returncode == 0:
                raise ProvisionError("UID-1000 presence activation config remains")
        if self.privacy_dns or self.dhcp_dns or self.restore_privacy_dns:
            self.verify_privacy_dns()
        if self.allow_app_updates or self.restore_app_verifier:
            self.verify_app_verifier_setting()
        if self.disable_camera_light:
            self.verify_camera_light_disabled()
        if self.restore_camera_light:
            self.verify_camera_light_restored()

    def verify_camera_light_disabled(self, wait_seconds: int = 35) -> None:
        if self.adb_run(
            ["shell", "test", "-f", CAMERA_LIGHT_INSTALLED_REMOTE], timeout=5
        ).returncode != 0:
            raise ProvisionError("camera-light install marker is absent")
        private_runtime = bool(
            self.target and self.target.uid1000_embedded_helper
        )
        if not private_runtime:
            if self.adb_run(
                [
                    "shell", "test", "-f",
                    self.uid1000_path("camera-led-enabled"),
                ],
                timeout=5,
            ).returncode != 0:
                raise ProvisionError(
                    "camera-light UID-1000 configuration is absent"
                )
            if self.adb_run(
                [
                    "shell", "test", "-x",
                    self.uid1000_path("portal-camera-led-watch"),
                ],
                timeout=5,
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
                    f"host={self.target.uid1000_host_label if self.target else 'unknown'} "
                    "trigger=persistent_app "
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
        if (
            not (self.target and self.target.uid1000_embedded_helper)
            and self.adb_run(
                ["shell", "test", "-e", self.uid1000_path("camera-led-enabled")],
                timeout=5,
            ).returncode == 0
        ):
            raise ProvisionError("camera-light UID-1000 configuration remains")
        if self.target and self.target.uid1000_embedded_helper:
            retained = self.adb_run(
                [
                    "shell",
                    "test",
                    "-f",
                    "/data/local/tmp/portal-presence-backup/fps-cap-v1",
                ],
                timeout=5,
            ).returncode == 0
            helper_present = retained
        else:
            retained = any(
                self.adb_run(["shell", "test", "-e", path], timeout=5).returncode
                == 0
                for path in (
                    self.uid1000_path("presence-fps"),
                    self.uid1000_path("wireless-adb-enabled"),
                )
            )
            helper_present = self.adb_run(
                [
                    "shell", "test", "-e",
                    self.uid1000_path("portal-camera-led-watch"),
                ],
                timeout=5,
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
        if self.persist_wireless_adb:
            property_name = (
                self.target.wireless_adb_file_property
                if self.target and self.target.wireless_adb_file_property
                else "persist.adb.tcp.port"
            )
            self.push_text_atomic(
                f"property={property_name}\nport=5555\n"
                f"first_boot={first_boot}\nsecond_boot={second_boot}\n",
                WIRELESS_ADB_INSTALLED_REMOTE,
            )
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
        # Resolve host-side downloads before any exploit bootstrap can reboot the
        # Portal. This turns a missing host network connection into an immediate,
        # actionable error instead of a late failure after several phases.
        if self.shizuku:
            self.resolve_shizuku_apk()
        if self.disable_camera_light:
            raise ProvisionError(
                "--disable-camera-light has been retired because Meta's "
                "camera provider rejects capture requests while its green "
                "indicator is cleared. This breaks detection, snapshots, "
                "and RTSP streaming. Use --restore-camera-light on devices "
                "that previously installed it."
            )
        legacy_camera_light = self.adb_run(
            ["shell", "test", "-f", CAMERA_LIGHT_INSTALLED_REMOTE],
            timeout=5,
        ).returncode == 0
        if not legacy_camera_light and not self.target.uid1000_embedded_helper:
            legacy_camera_light = self.adb_run(
                [
                    "shell",
                    "test",
                    "-e",
                    self.uid1000_path("camera-led-enabled"),
                ],
                timeout=5,
            ).returncode == 0
        if legacy_camera_light and not self.restore_camera_light:
            self.restore_camera_light = True
            print(
                "CAMERA_LIGHT_AUTO_RESTORE reason=camera-capture-incompatible",
                flush=True,
            )
        if (
            self.restore_camera_light
            and self.requested_actions() == {"restore_camera_light": True}
        ):
            try:
                self.verify_camera_light_restored()
            except ProvisionError:
                pass
            else:
                self.write_state("complete")
                print(
                    "PROVISION_ALREADY_COMPLETE actions=restore-camera-light "
                    f"logs={self.log_dir}"
                )
                return
        if self.backup_path:
            self.create_backup_bundle(self.backup_path)
        persistent_property = (
            self.target.wireless_adb_file_property
            if self.target and self.target.wireless_adb_file_property
            else "persist.adb.tcp.port"
        )
        if self.target and self.target.wireless_adb_file_property:
            persistence_verified = self.adb_run(
                ["shell", "test", "-f", WIRELESS_ADB_INSTALLED_REMOTE],
                timeout=5,
            ).returncode == 0
            persistent_port = "5555" if persistence_verified else ""
        else:
            persistent_port = self.adb_run(
                ["shell", "getprop", persistent_property],
                timeout=5,
                check=True,
            ).stdout.strip()
        self.persist_wireless_adb = (
            self.privileged_requested() and persistent_port != "5555"
        )
        if self.persist_wireless_adb:
            self.disable_adb_auth_timeout = True
            print(
                "STOCK_ADB_REENABLE_REQUIRED "
                f"property={persistent_property} persistent_port=unset\n"
                "Keep USB connected. After every reboot until the exploit "
                "reports WIRELESS_ADB_OK, enable ADB in the Portal's Debug "
                "menu and run `adb -d tcpip 5555` from another terminal. "
                "The provisioner waits up to 10 minutes for each reconnect.",
                flush=True,
            )
        if (
            self.persist_wireless_adb
            and self.target
            and self.target.audio_installer_credentials
            and not self.wireless_adb_only
        ):
            phase_logs = self.log_dir / "wireless-adb-bootstrap"
            phase_logs.mkdir(parents=True, exist_ok=True)
            print(
                "WIRELESS_ADB_BOOTSTRAP_PHASE action=install "
                "reason=credential-specific-followup-actions",
                flush=True,
            )
            PortalProvisioner(
                self.serial,
                self.attempts,
                phase_logs,
                skip_build=self.skip_build,
                wireless_adb_only=True,
            ).provision()
            self.connect(wait_seconds=30)
            self.verify_target()
            persistent_port = self.adb_run(
                ["shell", "getprop", persistent_property],
                timeout=5,
                check=True,
            ).stdout.strip()
            if persistent_port != "5555":
                raise ProvisionError(
                    "the dedicated wireless ADB bootstrap did not verify: "
                    f"{persistent_property}={persistent_port!r}"
                )
            self.persist_wireless_adb = False
            print(
                "WIRELESS_ADB_BOOTSTRAP_OK persistent_port=5555 "
                f"property={persistent_property}",
                flush=True,
            )
        self.audio_already_configured = (
            self.audio_preflight() if self.audio else False
        )
        if (
            self.audio
            and not self.audio_already_configured
            and self.target
            and self.target.audio_installer_credentials
            and self.requested_actions() != {"audio": True}
        ):
            phase_logs = self.log_dir / "audio-bootstrap"
            phase_logs.mkdir(parents=True, exist_ok=True)
            print(
                "AUDIO_BOOTSTRAP_PHASE action=install reason=installer-credential",
                flush=True,
            )
            PortalProvisioner(
                self.serial,
                self.attempts,
                phase_logs,
                audio=True,
                skip_build=self.skip_build,
            ).provision()
            self.connect(wait_seconds=30)
            self.verify_target()
            self.audio_already_configured = self.audio_preflight()
            if not self.audio_already_configured:
                raise ProvisionError(
                    "the dedicated Aloha audio bootstrap did not verify"
                )
        if (
            self.audio_already_configured
            and not self.persist_wireless_adb
            and self.requested_actions() == {"audio": True}
        ):
            if resumed_pending:
                self.write_state("complete")
            print(f"PROVISION_ALREADY_COMPLETE actions=audio logs={self.log_dir}")
            return
        if self.install_kiosk_satellite:
            self.ensure_kiosk_satellite()
        self.write_state("pending")
        already_owner = self.device_owner_preflight() if self.device_owner else False
        if (
            self.device_owner
            and not already_owner
            and self.target
            and self.target.device_owner_system_credentials
            and self.requested_actions() != {"device_owner": True}
        ):
            phase_logs = self.log_dir / "device-owner-bootstrap"
            phase_logs.mkdir(parents=True, exist_ok=True)
            print(
                "DEVICE_OWNER_BOOTSTRAP_PHASE action=install "
                "reason=system-server-credential",
                flush=True,
            )
            PortalProvisioner(
                self.serial,
                self.attempts,
                phase_logs,
                device_owner=True,
                skip_build=self.skip_build,
            ).provision()
            self.connect(wait_seconds=30)
            self.verify_target()
            already_owner = self.device_owner_preflight()
            if not already_owner:
                raise ProvisionError(
                    "the dedicated Aloha Device Owner bootstrap did not verify"
                )
            self.write_state("pending")
        self.device_owner_already_configured = already_owner
        self.ota_already_configured = (
            self.ota_preflight() if self.disable_updates else False
        )
        if (
            self.disable_updates
            and not self.ota_already_configured
            and self.target
            and self.target.ota_installer_credentials
            and self.requested_actions() != {"disable_updates": True}
        ):
            phase_logs = self.log_dir / "ota-bootstrap"
            phase_logs.mkdir(parents=True, exist_ok=True)
            print(
                "OTA_BOOTSTRAP_PHASE action=install "
                "reason=installer-credential",
                flush=True,
            )
            PortalProvisioner(
                self.serial,
                self.attempts,
                phase_logs,
                disable_updates=True,
                skip_build=self.skip_build,
            ).provision()
            self.connect(wait_seconds=30)
            self.verify_target()
            self.ota_already_configured = self.ota_preflight()
            if not self.ota_already_configured:
                raise ProvisionError(
                    "the dedicated Aloha OTA bootstrap did not verify"
                )
            self.write_state("pending")
        if (
            self.ota_already_configured
            and not self.persist_wireless_adb
            and self.requested_actions() == {"disable_updates": True}
        ):
            if resumed_pending:
                self.write_state("complete")
            print(
                f"PROVISION_ALREADY_COMPLETE actions=disable_updates "
                f"logs={self.log_dir}"
            )
            return
        already_meta_clean = (
            self.meta_accounts_preflight() if self.remove_meta_accounts else False
        )
        self.meta_accounts_already_clean = already_meta_clean
        if (
            self.remove_meta_accounts
            and not already_meta_clean
            and not self.meta_accounts_absent
            and self.target
            and self.target.meta_accounts_package_bootstrap
            and not self.meta_accounts_local_only
            and not self.meta_accounts_auth_only
            and not self.meta_accounts_finalize_only
        ):
            disabled = self.disabled_meta_authenticators()
            hardware_class = META_HARDWARE_AUTHENTICATOR.split("/", 1)[1]
            if (
                set(META_AUTHENTICATOR_COMPONENTS) - disabled
                or hardware_class in disabled
            ):
                auth_logs = self.log_dir / "meta-accounts-auth-bootstrap"
                auth_logs.mkdir(parents=True, exist_ok=True)
                print(
                    "META_ACCOUNTS_AUTH_PHASE action=guard "
                    "reason=prevent-account-recreation",
                    flush=True,
                )
                PortalProvisioner(
                    self.serial,
                    self.attempts,
                    auth_logs,
                    remove_meta_accounts=True,
                    skip_build=self.skip_build,
                    meta_accounts_auth_only=True,
                ).provision()
                self.connect(wait_seconds=30)
                self.verify_target()
            local_clean = (
                self.adb_run(
                    ["shell", "test", "-f", META_ACCOUNT_LOCAL_CLEAN_REMOTE],
                    timeout=5,
                ).returncode
                == 0
            )
            if not local_clean:
                phase_logs = self.log_dir / "meta-accounts-package-bootstrap"
                phase_logs.mkdir(parents=True, exist_ok=True)
                print(
                    "META_ACCOUNTS_PACKAGE_PHASE action=remove "
                    "reason=package-private-identity",
                    flush=True,
                )
                PortalProvisioner(
                    self.serial,
                    self.attempts,
                    phase_logs,
                    remove_meta_accounts=True,
                    skip_build=self.skip_build,
                    meta_accounts_local_only=True,
                ).provision()
                self.connect(wait_seconds=30)
                self.verify_target()
            finalize_logs = self.log_dir / "meta-accounts-finalize-bootstrap"
            finalize_logs.mkdir(parents=True, exist_ok=True)
            print(
                "META_ACCOUNTS_FINALIZE_PHASE action=remove "
                "reason=system-account-records",
                flush=True,
            )
            PortalProvisioner(
                self.serial,
                self.attempts,
                finalize_logs,
                remove_meta_accounts=True,
                skip_build=self.skip_build,
                meta_accounts_finalize_only=True,
            ).provision()
            self.connect(wait_seconds=30)
            self.verify_target()
            already_meta_clean = self.meta_accounts_preflight()
            self.meta_accounts_already_clean = already_meta_clean
            if not already_meta_clean:
                raise ProvisionError(
                    "the dedicated Meta account cleanup phases did not verify"
                )
            self.write_state("pending")
        if (
            self.remove_meta_accounts
            and not already_meta_clean
            and self.target
            and self.target.meta_accounts_system_credentials
            and self.requested_actions() != {"remove_meta_accounts": True}
        ):
            phase_logs = self.log_dir / "meta-accounts-bootstrap"
            phase_logs.mkdir(parents=True, exist_ok=True)
            print(
                "META_ACCOUNTS_BOOTSTRAP_PHASE action=remove "
                "reason=system-server-credential",
                flush=True,
            )
            PortalProvisioner(
                self.serial,
                self.attempts,
                phase_logs,
                remove_meta_accounts=True,
                skip_build=self.skip_build,
            ).provision()
            self.connect(wait_seconds=30)
            self.verify_target()
            already_meta_clean = self.meta_accounts_preflight()
            self.meta_accounts_already_clean = already_meta_clean
            if not already_meta_clean:
                raise ProvisionError(
                    "the dedicated Aloha Meta-account cleanup did not verify"
                )
            self.write_state("pending")
        if (
            already_meta_clean
            and not self.persist_wireless_adb
            and self.requested_actions() == {"remove_meta_accounts": True}
        ):
            if resumed_pending:
                self.write_state("complete")
            print(
                f"PROVISION_ALREADY_COMPLETE actions=remove_meta_accounts "
                f"logs={self.log_dir}"
            )
            return
        self.debloat_already_configured = (
            self.debloat_preflight() if self.debloat else False
        )
        if (
            self.debloat
            and not self.debloat_already_configured
            and self.target
            and self.target.shell_root_package_actions
            and not self.only_component_actions_requested()
        ):
            phase_logs = self.log_dir / "debloat-bootstrap"
            phase_logs.mkdir(parents=True, exist_ok=True)
            print(
                "DEBLOAT_BOOTSTRAP_PHASE action=install "
                "reason=root-shell-credential",
                flush=True,
            )
            PortalProvisioner(
                self.serial,
                self.attempts,
                phase_logs,
                debloat=True,
                block_remote_wipe=self.block_remote_wipe,
                skip_build=self.skip_build,
            ).provision()
            self.connect(wait_seconds=30)
            self.verify_target()
            self.debloat_already_configured = self.debloat_preflight()
            if not self.debloat_already_configured:
                raise ProvisionError(
                    "the dedicated Aloha component debloat did not verify"
                )
            self.write_state("pending")
        if (
            self.debloat_already_configured
            and not self.persist_wireless_adb
            and self.requested_actions() == {"debloat": True}
        ):
            if resumed_pending:
                self.write_state("complete")
            print(
                f"PROVISION_ALREADY_COMPLETE actions=debloat "
                f"logs={self.log_dir}"
            )
            return
        self.remote_wipe_already_configured = (
            self.remote_wipe_preflight() if self.block_remote_wipe else False
        )
        if (
            self.block_remote_wipe
            and not self.remote_wipe_already_configured
            and self.target
            and self.target.shell_root_package_actions
            and not self.only_component_actions_requested()
        ):
            phase_logs = self.log_dir / "remote-wipe-bootstrap"
            phase_logs.mkdir(parents=True, exist_ok=True)
            print(
                "REMOTE_WIPE_BOOTSTRAP_PHASE action=block "
                "reason=root-shell-credential",
                flush=True,
            )
            PortalProvisioner(
                self.serial,
                self.attempts,
                phase_logs,
                block_remote_wipe=True,
                skip_build=self.skip_build,
            ).provision()
            self.connect(wait_seconds=30)
            self.verify_target()
            self.remote_wipe_already_configured = self.remote_wipe_preflight()
            if not self.remote_wipe_already_configured:
                raise ProvisionError(
                    "the dedicated Aloha remote-wipe block did not verify"
                )
            self.write_state("pending")
        if (
            self.remote_wipe_already_configured
            and not self.persist_wireless_adb
            and self.requested_actions() == {"block_remote_wipe": True}
        ):
            if resumed_pending:
                self.write_state("complete")
            print(
                "PROVISION_ALREADY_COMPLETE actions=block_remote_wipe "
                f"logs={self.log_dir}"
            )
            return
        self.presence_already_configured = (
            self.presence_preflight() if self.optimize_presence else False
        )
        if (
            self.optimize_presence
            and not self.presence_already_configured
            and self.target
            and self.target.presence_installer_credentials
            and self.requested_actions() != {"optimize_presence": True}
        ):
            phase_logs = self.log_dir / "presence-bootstrap"
            phase_logs.mkdir(parents=True, exist_ok=True)
            print(
                "PRESENCE_BOOTSTRAP_PHASE action=install "
                "reason=installer-credential",
                flush=True,
            )
            PortalProvisioner(
                self.serial,
                self.attempts,
                phase_logs,
                optimize_presence=True,
                skip_build=self.skip_build,
            ).provision()
            self.connect(wait_seconds=30)
            self.verify_target()
            self.presence_already_configured = self.presence_preflight()
            if not self.presence_already_configured:
                raise ProvisionError(
                    "the dedicated Aloha presence bootstrap did not verify"
                )
            self.write_state("pending")
        if (
            self.presence_already_configured
            and not self.persist_wireless_adb
            and self.requested_actions() == {"optimize_presence": True}
        ):
            self.write_state("complete")
            print(
                f"PROVISION_ALREADY_COMPLETE actions=optimize_presence "
                f"logs={self.log_dir}"
            )
            return
        self.presence_fps_already_configured = (
            self.presence_fps_preflight()
            if self.presence_fps_cap is not None
            else False
        )
        dedicated_presence_fps_actions = (
            {"presence_fps_cap": self.presence_fps_cap},
            {
                "optimize_presence": True,
                "presence_fps_cap": self.presence_fps_cap,
            },
        )
        if (
            self.presence_fps_cap is not None
            and not self.presence_fps_already_configured
            and self.target
            and self.target.uid1000_installer_credentials
            and self.requested_actions() not in dedicated_presence_fps_actions
        ):
            phase_logs = self.log_dir / "presence-fps-bootstrap"
            phase_logs.mkdir(parents=True, exist_ok=True)
            print(
                "PRESENCE_FPS_BOOTSTRAP_PHASE action=install "
                "reason=installer-credential",
                flush=True,
            )
            PortalProvisioner(
                self.serial,
                self.attempts,
                phase_logs,
                optimize_presence=True,
                presence_fps_cap=self.presence_fps_cap,
                skip_build=self.skip_build,
            ).provision()
            self.connect(wait_seconds=30)
            self.verify_target()
            self.presence_fps_already_configured = (
                self.presence_fps_preflight()
            )
            if not self.presence_fps_already_configured:
                raise ProvisionError(
                    "the dedicated Aloha presence FPS bootstrap did not verify"
                )
            self.write_state("pending")
        if self.debloat and not self.debloat_already_configured:
            self.apply_debloat()
        if self.restore_bloat:
            self.restore_debloat()
        if self.block_remote_wipe and not self.remote_wipe_already_configured:
            self.ensure_remote_wipe_backup()
        if self.restore_remote_wipe:
            self.read_remote_wipe_backup(required=True)
        if self.needs_uid1000_payload():
            self.prepare_camera_light_install()
        if self.disable_updates:
            self.disable_ota_packages()
        if self.disable_adb_auth_timeout:
            self.disable_adb_authorization_timeout()
        if self.restore_adb_auth_timeout:
            self.restore_adb_authorization_timeout()
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
        if self.kiosk_permissions:
            self.apply_kiosk_permissions()
        if self.needs_component_ctl():
            self.prepare_component_actions()

        privileged_action = (
            self.persist_wireless_adb
            or (self.audio and not self.audio_already_configured)
            or self.restore_audio
            or (self.disable_updates and not self.ota_already_configured)
            or self.enable_updates
            or (self.debloat and not self.debloat_already_configured)
            or self.restore_bloat
            or (self.block_remote_wipe and not self.remote_wipe_already_configured)
            or self.restore_remote_wipe
            or (self.optimize_presence and not self.presence_already_configured)
            or self.restore_presence_profile
            or self.presence_fps_action_requested()
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
                self.ensure_kiosk_home()
            if self.restore_kiosk_home:
                self.configure_kiosk_home(enabled=False)
            if set(self.requested_actions()) <= {
                "install_kiosk_satellite",
                "kiosk_permissions",
                "disable_adb_auth_timeout",
                "restore_adb_auth_timeout",
            }:
                self.verify_requested_state()
                self.write_state("complete")
                print(f"PROVISION_OK reboots=0 logs={self.log_dir}")
                return
            self.verify_across_two_reboots()
            return

        if not self.skip_build:
            build(
                target=self.target,
                build_audio=(
                    (self.audio and not self.audio_already_configured)
                    or self.restore_audio
                ),
                build_account=self.remove_meta_accounts,
                build_components=(
                    self.needs_component_ctl()
                ),
                build_shizuku=self.shizuku,
                build_presence=False,
                build_uid1000=self.needs_uid1000_payload(),
                build_sentinel=self.uses_exploit_sentinel(),
            )
        if self.shizuku:
            self.install_shizuku_payload()
        if (
            self.needs_uid1000_payload()
            and self.target.uid1000_embedded_helper
        ):
            self.install_uid1000_runtime_payload()
        if self.restore_presence_fps or self.restore_presence_profile:
            self.uninstall_presence_helper()
        use_exploit_sentinel = self.uses_exploit_sentinel()
        if use_exploit_sentinel:
            self.prepare_exploit_sentinel()
        sentinel_removed = not use_exploit_sentinel
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
                if self.target.address_discovery_settle_seconds:
                    print(
                        "ADDRESS_DISCOVERY_SETTLE "
                        f"seconds={self.target.address_discovery_settle_seconds}",
                        flush=True,
                    )
                    time.sleep(self.target.address_discovery_settle_seconds)
                try:
                    base = self.kaslr_base(str(attempt))
                    memstart = self.memstart(str(attempt))
                except ProvisionError as exc:
                    print(f"ADDRESS_DISCOVERY_RETRY attempt={attempt} error={exc}")
                    try:
                        self.connect(wait_seconds=600)
                        recovered_boot = self.adb_run(
                            [
                                "shell",
                                "cat",
                                "/proc/sys/kernel/random/boot_id",
                            ],
                            timeout=5,
                            check=True,
                        ).stdout.strip()
                        if recovered_boot:
                            clean_boot_id = recovered_boot
                            print(
                                "ADDRESS_DISCOVERY_RECOVERED "
                                f"boot_id={recovered_boot}",
                                flush=True,
                            )
                            if self.target.address_discovery_reboot_on_failure:
                                print(
                                    "ADDRESS_DISCOVERY_REBOOT "
                                    "reason=unusable-capture",
                                    flush=True,
                                )
                                _, clean_boot_id = self.reboot()
                    except ProvisionError as reconnect_error:
                        print(
                            "ADDRESS_DISCOVERY_RECONNECT_FAILED "
                            f"error={reconnect_error}",
                            flush=True,
                        )
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
                if use_exploit_sentinel:
                    self.uninstall_exploit_sentinel()
                    sentinel_removed = True
                if self.shizuku:
                    self.finalize_buffered_shizuku_key()
                if self.needs_uid1000_payload():
                    self.finalize_buffered_uid1000_markers()
                if (
                    self.uid1000_runtime_package_installed
                    and not (
                        self.restore_camera_light
                        or self.restore_presence_fps
                        or self.restore_presence_profile
                    )
                ):
                    self.uid1000_runtime_package_installed = False
                    print("UID1000_RUNTIME_APK_RETAIN package=installed")
                if self.enable_updates:
                    self.enable_ota_packages()
                if self.remove_shizuku:
                    self.uninstall_shizuku_payload()
                if self.presence_fps_action_requested():
                    self.uninstall_presence_helper()
                if self.kiosk_home:
                    self.ensure_kiosk_home()
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
            if use_exploit_sentinel and not sentinel_removed:
                self.uninstall_exploit_sentinel(best_effort=True)
            if self.uid1000_runtime_package_installed:
                self.uninstall_uid1000_runtime_payload(best_effort=True)
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
        helper_target = "native-java" if target.audio_java_fallback else "native"
        commands.append(["make", "-C", str(ROOT / "helper"), helper_target])
        if target.audio_java_fallback:
            commands.append(
                [
                    "make", "-C", str(ROOT / "exploit"),
                    f"PORTAL_TARGET={target.make_target}", "audio-ctl",
                ]
            )
    if build_account:
        commands.append(
            [
                "make", "-C", str(ROOT / "exploit"),
                f"PORTAL_TARGET={target.make_target}", "account-ctl",
            ]
        )
    if build_components:
        commands.append(
            [
                "make", "-C", str(ROOT / "exploit"),
                f"PORTAL_TARGET={target.make_target}", "component-ctl",
            ]
        )
    if build_shizuku:
        commands.append(["make", "-C", str(ROOT / "shizuku-helper"), "all"])
    if build_presence:
        commands.append(["make", "-C", str(ROOT / "presence-helper"), "all"])
    if build_uid1000:
        commands.append(
            [
                "make", "-C", str(ROOT / "uid1000-helper"),
                target.uid1000_helper_make_target,
            ]
        )
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
        "--persistent-wireless-adb",
        action="store_true",
        help=(
            "make wireless ADB on TCP port 5555 survive reboots without "
            "applying any other provisioning feature"
        ),
    )
    adb_auth_group = parser.add_mutually_exclusive_group()
    adb_auth_group.add_argument(
        "--disable-adb-auth-timeout",
        action="store_true",
        help=(
            "keep previously approved ADB host keys authorized indefinitely; "
            "this does not disable ADB authentication"
        ),
    )
    adb_auth_group.add_argument(
        "--restore-adb-auth-timeout",
        action="store_true",
        help=(
            "restore the ADB authorization timeout saved by the first "
            "--disable-adb-auth-timeout run"
        ),
    )
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
        "--install-kiosk-satellite",
        action="store_true",
        help=(
            "install the latest compatible Kiosk Satellite release from "
            "GitHub when the app is not already installed"
        ),
    )
    parser.add_argument(
        "--device-owner",
        action="store_true",
        help=(
            "make Kiosk Satellite Device Owner and verify it "
            "across both reboots"
        ),
    )
    parser.add_argument(
        "--kiosk-permissions",
        action="store_true",
        help=(
            "grant Kiosk Satellite the Portal runtime permissions, special "
            "app access, READ_LOGS, and battery exemption without changing "
            "accessibility services"
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
    remote_wipe_group = parser.add_mutually_exclusive_group()
    remote_wipe_group.add_argument(
        "--block-remote-wipe",
        action="store_true",
        help=(
            "disable Meta's two known factory-reset and remote-wipe receivers "
            "without disabling the rest of the device-admin package"
        ),
    )
    remote_wipe_group.add_argument(
        "--restore-remote-wipe",
        action="store_true",
        help=(
            "restore the two Meta remote-wipe receivers to the component states "
            "saved by the first --block-remote-wipe run"
        ),
    )
    camera_light_group = parser.add_mutually_exclusive_group()
    camera_light_group.add_argument(
        "--disable-camera-light",
        action="store_true",
        help=(
            "retired unsafe action; Meta's camera provider rejects capture "
            "while its green indicator is cleared"
        ),
    )
    camera_light_group.add_argument(
        "--restore-camera-light",
        action="store_true",
        help=(
            "remove the camera-light watchdog and boot hook, then restore "
            "the UID-1000 host app's original ART cache"
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
                (args.restore_remote_wipe, "--restore-remote-wipe"),
                (args.restore_bloat, "--restore-bloat"),
                (args.restore_presence_profile, "--restore-presence-profile"),
                (args.restore_presence_fps, "--restore-presence-fps"),
                (args.restore_app_verifier, "--restore-app-verifier"),
                (args.restore_adb_auth_timeout, "--restore-adb-auth-timeout"),
            )
            if enabled
        ]
        if conflicting:
            parser.error(
                "--profile kiosk cannot be combined with rollback actions: "
                + ", ".join(conflicting)
            )
        args.audio = True
        args.install_kiosk_satellite = True
        args.kiosk_permissions = True
        args.device_owner = True
        args.kiosk_home = True
        args.disable_updates = True
        args.block_remote_wipe = True
        args.debloat = True
        args.remove_meta_accounts = True
        args.optimize_presence = True
        args.allow_app_updates = True
        args.disable_adb_auth_timeout = True
    if args.persistent_wireless_adb:
        if args.restore_adb_auth_timeout:
            parser.error(
                "--persistent-wireless-adb cannot be combined with "
                "--restore-adb-auth-timeout"
            )
        args.disable_adb_auth_timeout = True
    selected = any(
        (
            args.persistent_wireless_adb,
            args.disable_adb_auth_timeout,
            args.restore_adb_auth_timeout,
            args.audio,
            args.restore_audio,
            args.install_kiosk_satellite,
            args.kiosk_permissions,
            args.device_owner,
            args.kiosk_home,
            args.restore_kiosk_home,
            args.disable_updates,
            args.enable_updates,
            args.block_remote_wipe,
            args.restore_remote_wipe,
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
    if args.disable_camera_light:
        parser.error(
            "--disable-camera-light has been retired because it breaks camera "
            "capture. Run --restore-camera-light on previously provisioned "
            "devices."
        )
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
            install_kiosk_satellite=args.install_kiosk_satellite,
            kiosk_permissions=args.kiosk_permissions,
            device_owner=args.device_owner,
            kiosk_home=args.kiosk_home,
            restore_kiosk_home=args.restore_kiosk_home,
            disable_updates=args.disable_updates,
            enable_updates=args.enable_updates,
            block_remote_wipe=args.block_remote_wipe,
            restore_remote_wipe=args.restore_remote_wipe,
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
            persistent_wireless_adb=args.persistent_wireless_adb,
            disable_adb_auth_timeout=args.disable_adb_auth_timeout,
            restore_adb_auth_timeout=args.restore_adb_auth_timeout,
        ).provision()
    except (ProvisionError, OSError, zipfile.BadZipFile) as exc:
        print(f"PROVISION_ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
