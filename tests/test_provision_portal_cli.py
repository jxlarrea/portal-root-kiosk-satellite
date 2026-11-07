from __future__ import annotations

import contextlib
import io
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from provision_portal import (  # noqa: E402
    ADB_AUTH_TIMEOUT_BACKUP_REMOTE,
    ADB_ENABLED_SETTING,
    KIOSK_RELEASE_DOWNLOAD_PREFIX,
    MHA_AUDIO_VERIFIED_LOG,
    OTA_JSON_URL,
    OTA_POLL_INTERVAL_MINUTES,
    REMOTE_WIPE_COMPONENTS,
    PortalProvisioner,
    ProvisionError,
    android_build_environment,
    build,
    parse_args,
    parse_ota_config,
)
from meta_debloat_components import (  # noqa: E402
    DEBLOAT_COMPONENT_NAMES,
    PORTAL_PLUS_ALOHA_SAFE_COMPONENT_NAMES,
)
from portal_targets import TARGETS  # noqa: E402


class AudioWatchdogVerificationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.omni = next(target for target in TARGETS if target.device == "omni")
        self.terry = next(target for target in TARGETS if target.device == "terry")

    def test_omni_rejects_legacy_voice_parameter_success_log(self) -> None:
        legacy = "audio processing verified aec=0 ns=0 backend=java"
        self.assertFalse(
            PortalProvisioner.audio_processing_disabled_observed(
                legacy, self.omni
            )
        )

    def test_omni_accepts_only_the_mha_verification_log(self) -> None:
        self.assertTrue(
            PortalProvisioner.audio_processing_disabled_observed(
                MHA_AUDIO_VERIFIED_LOG, self.omni
            )
        )

    def test_non_omni_keeps_voice_parameter_verification(self) -> None:
        legacy = "audio processing verified aec=0 ns=0 backend=java"
        self.assertTrue(
            PortalProvisioner.audio_processing_disabled_observed(
                legacy, self.terry
            )
        )


class PersistentWirelessAdbCliTest(unittest.TestCase):
    def test_standalone_flag_does_not_enable_the_default_audio_action(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--persistent-wireless-adb"],
        ):
            arguments = parse_args()

        self.assertTrue(arguments.persistent_wireless_adb)
        self.assertFalse(arguments.audio)

        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                persistent_wireless_adb=True,
            )
            self.assertEqual(
                provisioner.requested_actions(),
                {
                    "persistent_wireless_adb": True,
                    "disable_adb_auth_timeout": True,
                },
            )
            self.assertTrue(provisioner.privileged_requested())

    def test_cli_pairs_persistent_wireless_adb_with_non_expiring_auth(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--persistent-wireless-adb"],
        ):
            arguments = parse_args()

        self.assertTrue(arguments.disable_adb_auth_timeout)

    def test_persistent_wireless_adb_rejects_timeout_restore(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            [
                "provision_portal.py",
                "--persistent-wireless-adb",
                "--restore-adb-auth-timeout",
            ],
        ):
            with self.assertRaises(SystemExit):
                parse_args()

    def test_every_target_installs_adb_framework_boot_enforcement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for target in TARGETS:
                with self.subTest(target=target.key):
                    provisioner = PortalProvisioner(
                        "192.0.2.1:5555",
                        1,
                        pathlib.Path(temporary),
                        persistent_wireless_adb=True,
                    )
                    provisioner.target = target
                    self.assertTrue(
                        provisioner.adb_framework_boot_install_requested()
                    )
                    self.assertTrue(provisioner.needs_uid1000_payload())
                    provisioner.adb_framework_boot_configured = True
                    self.assertFalse(
                        provisioner.adb_framework_boot_install_requested()
                    )
                    self.assertFalse(provisioner.needs_uid1000_payload())

    def test_android9_internal_bootstrap_keeps_wireless_and_uid1000_phases_split(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            wireless = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                wireless_adb_only=True,
            )
            framework = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                adb_framework_only=True,
            )
            self.assertFalse(
                wireless.adb_framework_boot_persistence_requested()
            )
            self.assertTrue(
                framework.adb_framework_boot_persistence_requested()
            )
            self.assertTrue(framework.privileged_requested())


class SystemThemeControlCliTest(unittest.TestCase):
    def test_flag_accepts_only_light_or_dark_without_default_audio(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--system-theme-control", "dark"],
        ):
            arguments = parse_args()

        self.assertEqual(arguments.system_theme_control, "dark")
        self.assertFalse(arguments.audio)

        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--system-theme-control", "automatic"],
        ):
            with self.assertRaises(SystemExit):
                parse_args()

    def test_android_10_uses_uid1000_but_android_9_uses_shell(self) -> None:
        targets = {target.key: target for target in TARGETS}
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                system_theme_control="light",
            )
            self.assertEqual(
                provisioner.requested_actions(),
                {"system_theme_control": "light"},
            )

            provisioner.target = targets["portal-10-omni-3051355900018050"]
            self.assertTrue(provisioner.needs_uid1000_payload())
            self.assertTrue(provisioner.privileged_requested())

            provisioner.target = targets["portal-plus-aloha-1041515800015050"]
            self.assertFalse(provisioner.needs_uid1000_payload())
            self.assertFalse(provisioner.privileged_requested())

    def test_locked_build_sends_a_strict_property_request(self) -> None:
        target = next(
            target
            for target in TARGETS
            if target.key == "portal-10-omni-3051355900018050"
        )
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                system_theme_control="dark",
            )
            provisioner.target = target
            with (
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess([], 0, ""),
                ) as adb_run,
                mock.patch("provision_portal.time.sleep"),
            ):
                provisioner.apply_system_theme_request()

        self.assertEqual(
            adb_run.call_args_list,
            [
                mock.call(
                    [
                        "shell",
                        "logcat",
                        "-d",
                        "-s",
                        "PortalSystemTheme:*",
                    ],
                    timeout=10,
                ),
                mock.call(
                    [
                        "shell",
                        "setprop",
                        "debug.portal.system_theme",
                        "none",
                    ],
                    timeout=5,
                    check=True,
                ),
                mock.call(
                    [
                        "shell",
                        "setprop",
                        "debug.portal.system_theme",
                        "dark",
                    ],
                    timeout=5,
                    check=True,
                ),
            ],
        )

    def test_uid1000_payload_rejects_a_hook_for_another_runtime(self) -> None:
        target = next(
            target
            for target in TARGETS
            if target.key == "portal-go-terry-5051355900018050"
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = pathlib.Path(temporary)
            helper = directory / "helper"
            hook = directory / "hook"
            helper.write_bytes(b"helper")
            hook.write_bytes(
                b"/data/app/dev.portal.uid1000runtime-stale/lib/arm64/"
                b"libportal_uid1000_exec.so\0"
            )
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                directory,
                system_theme_control="dark",
            )
            provisioner.target = target
            with (
                mock.patch.object(
                    provisioner, "uid1000_helper_local", return_value=helper
                ),
                mock.patch.object(
                    provisioner, "uid1000_hook_local", return_value=hook
                ),
            ):
                with self.assertRaisesRegex(
                    ProvisionError, "does not contain the target helper path"
                ):
                    provisioner.validate_uid1000_payload()

                hook.write_bytes(
                    b"prefix/data/portal-uid1000/portal-camera-led-watch\0suffix"
                )
                provisioner.validate_uid1000_payload()

    def test_uid1000_build_does_not_reuse_timestamp_fresh_artifacts(self) -> None:
        target = next(
            target
            for target in TARGETS
            if target.key == "portal-go-terry-5051355900018050"
        )
        with (
            mock.patch(
                "provision_portal.android_build_environment", return_value={}
            ),
            mock.patch(
                "provision_portal.subprocess.run",
                return_value=subprocess.CompletedProcess([], 0),
            ) as run,
        ):
            build(
                target=target,
                build_audio=False,
                build_account=False,
                build_components=False,
                build_shizuku=False,
                build_presence=False,
                build_uid1000=True,
                build_sentinel=False,
            )

        commands = [call.args[0] for call in run.call_args_list]
        self.assertIn(
            ["make", "-B", "-C", str(ROOT / "uid1000-helper"), "all"],
            commands,
        )


class AndroidBuildEnvironmentTest(unittest.TestCase):
    def test_build_files_do_not_contain_an_author_home_path(self) -> None:
        build_files = [ROOT / "android-env.mk", *ROOT.glob("*/Makefile")]
        for path in build_files:
            self.assertNotIn("/home/jxlarrea", path.read_text(), str(path))

    def test_explicit_sdk_root_is_propagated_to_make(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sdk = pathlib.Path(temporary) / "sdk"
            ndk = sdk / "ndk" / "28.2.13676358"
            toolchain = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin"
            build_tools = sdk / "build-tools" / "37.0.0"
            platform = sdk / "platforms" / "android-36"
            for path in (
                toolchain / "aarch64-linux-android29-clang",
                toolchain / "armv7a-linux-androideabi28-clang",
                toolchain / "armv7a-linux-androideabi29-clang",
                build_tools / "aapt",
                build_tools / "apksigner",
                build_tools / "zipalign",
                build_tools / "d8",
                platform / "android.jar",
            ):
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()

            with (
                mock.patch.dict(
                    os.environ,
                    {"ANDROID_SDK_ROOT": str(sdk)},
                    clear=True,
                ),
                mock.patch.object(shutil, "which", return_value="/usr/bin/tool"),
            ):
                environment = android_build_environment()

        self.assertEqual(environment["SDK"], str(sdk))
        self.assertEqual(environment["ANDROID_SDK_ROOT"], str(sdk))
        self.assertEqual(environment["NDK"], str(ndk))
        self.assertEqual(environment["BUILD_TOOLS"], str(build_tools))

    def test_missing_sdk_fails_with_configuration_help(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            sdk = pathlib.Path(temporary) / "missing-sdk"
            with (
                mock.patch.dict(
                    os.environ,
                    {"ANDROID_SDK_ROOT": str(sdk)},
                    clear=True,
                ),
                mock.patch.object(shutil, "which", return_value="/usr/bin/tool"),
            ):
                with self.assertRaisesRegex(
                    ProvisionError,
                    "no Portal changes were made.*ANDROID_SDK_ROOT",
                ):
                    android_build_environment()

class AdbAuthorizationTimeoutCliTest(unittest.TestCase):
    def test_standalone_flag_needs_no_root_action(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--disable-adb-auth-timeout"],
        ):
            arguments = parse_args()

        self.assertTrue(arguments.disable_adb_auth_timeout)
        self.assertFalse(arguments.audio)
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                disable_adb_auth_timeout=True,
            )
            self.assertEqual(
                provisioner.requested_actions(),
                {"disable_adb_auth_timeout": True},
            )
            self.assertFalse(provisioner.privileged_requested())
            provisioner.target = TARGETS[0]
            self.assertFalse(
                provisioner.adb_framework_boot_persistence_requested()
            )
            self.assertFalse(provisioner.needs_uid1000_payload())

    def test_disable_and_restore_preserve_an_absent_original_setting(self) -> None:
        current = {
            ADB_ENABLED_SETTING: "0",
            "adb_allowed_connection_time": "null",
        }
        saved: list[str] = []

        def adb_run(
            arguments: list[str],
            timeout: float | None = None,
            check: bool = False,
        ) -> subprocess.CompletedProcess[str]:
            del timeout, check
            if arguments[:2] == ["shell", "cat"]:
                if not saved:
                    return subprocess.CompletedProcess(arguments, 1, "")
                return subprocess.CompletedProcess(arguments, 0, saved[0])
            if arguments[1:4] == ["settings", "get", "global"]:
                return subprocess.CompletedProcess(
                    arguments, 0, current[arguments[4]] + "\n"
                )
            if arguments[1:4] == ["settings", "put", "global"]:
                current[arguments[4]] = arguments[-1]
            elif arguments[1:4] == ["settings", "delete", "global"]:
                current[arguments[4]] = "null"
            return subprocess.CompletedProcess(arguments, 0, "")

        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                disable_adb_auth_timeout=True,
            )
            with (
                mock.patch.object(provisioner, "adb_run", side_effect=adb_run),
                mock.patch.object(
                    provisioner,
                    "push_text_atomic",
                    side_effect=lambda contents, remote: (
                        self.assertEqual(remote, ADB_AUTH_TIMEOUT_BACKUP_REMOTE),
                        saved.append(contents),
                    ),
                ),
            ):
                provisioner.disable_adb_authorization_timeout()
                self.assertEqual(current[ADB_ENABLED_SETTING], "1")
                self.assertEqual(current["adb_allowed_connection_time"], "0")
                provisioner.disable_adb_auth_timeout = False
                provisioner.restore_adb_auth_timeout = True
                provisioner.restore_adb_authorization_timeout()

        self.assertEqual(current[ADB_ENABLED_SETTING], "1")
        self.assertEqual(current["adb_allowed_connection_time"], "null")

    def test_kiosk_profile_includes_non_expiring_adb_authorization(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--profile", "kiosk"],
        ):
            arguments = parse_args()

        self.assertTrue(arguments.disable_adb_auth_timeout)

    def test_privileged_timeout_action_installs_boot_enforcement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for target in TARGETS:
                with self.subTest(target=target.key):
                    provisioner = PortalProvisioner(
                        "192.0.2.1:5555",
                        1,
                        pathlib.Path(temporary),
                        audio=True,
                        disable_adb_auth_timeout=True,
                    )
                    provisioner.target = target
                    self.assertTrue(
                        provisioner.adb_framework_boot_persistence_requested()
                    )
                    self.assertTrue(provisioner.needs_uid1000_payload())

    def test_wireless_adb_waits_for_framework_boot_recovery_on_all_targets(
        self,
    ) -> None:
        target = next(
            target
            for target in TARGETS
            if target.key == "portal-go-terry-5051355900018050"
        )
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                persistent_wireless_adb=True,
            )
            provisioner.target = target
            provisioner.persist_wireless_adb = True
            with (
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess([], 0, "5555\n"),
                ),
                mock.patch.object(provisioner, "verify_adb_auth_timeout"),
                mock.patch.object(
                    provisioner, "verify_adb_framework_enabled"
                ) as verify_framework,
            ):
                provisioner.verify_requested_state()

        verify_framework.assert_called_once_with(wait_seconds=45)

    def test_meta_account_preflight_enables_new_host_prompts_first(self) -> None:
        order: list[str] = []
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                remove_meta_accounts=True,
            )
            with (
                mock.patch.object(
                    provisioner,
                    "ensure_adb_framework_enabled",
                    side_effect=lambda: order.append("adb-framework"),
                ) as ensure,
                mock.patch.object(
                    provisioner,
                    "meta_accounts",
                    side_effect=lambda: order.append("accounts") or [],
                ),
                mock.patch.object(
                    provisioner,
                    "disabled_meta_authenticators",
                    return_value=set(),
                ),
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess(
                        [], 0, "# portal-meta-accounts-before-v1\n"
                    ),
                ),
            ):
                provisioner.meta_accounts_preflight()

        ensure.assert_called_once_with()
        self.assertEqual(order[:2], ["adb-framework", "accounts"])

    def test_framework_enable_must_persist(self) -> None:
        def adb_run(
            arguments: list[str],
            timeout: float | None = None,
            check: bool = False,
        ) -> subprocess.CompletedProcess[str]:
            del timeout, check
            output = "0\n" if arguments[1:4] == ["settings", "get", "global"] else ""
            return subprocess.CompletedProcess(arguments, 0, output)

        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555", 1, pathlib.Path(temporary)
            )
            with mock.patch.object(provisioner, "adb_run", side_effect=adb_run):
                with self.assertRaisesRegex(
                    ProvisionError, "authorization prompts cannot appear"
                ):
                    provisioner.ensure_adb_framework_enabled()


class KioskHomeResumeTest(unittest.TestCase):
    def test_existing_device_owner_is_restored_as_home_before_bootstraps(
        self,
    ) -> None:
        def adb_run(
            arguments: list[str],
            timeout: float | None = None,
            check: bool = False,
        ) -> subprocess.CompletedProcess[str]:
            del timeout, check
            if arguments[1:4] == ["pm", "path", "me.jxl.kiosk_satellite"]:
                return subprocess.CompletedProcess(
                    arguments,
                    0,
                    "package:/data/app/me.jxl.kiosk_satellite/base.apk\n",
                )
            if arguments[1:3] == ["dumpsys", "device_policy"]:
                return subprocess.CompletedProcess(
                    arguments,
                    0,
                    "Device Owner:\n"
                    "  admin=ComponentInfo{"
                    "me.jxl.kiosk_satellite/"
                    "me.jxl.kiosk_satellite.KioskAdminReceiver}\n",
                )
            raise AssertionError(arguments)

        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                device_owner=True,
                kiosk_home=True,
            )
            with (
                mock.patch.object(provisioner, "adb_run", side_effect=adb_run),
                mock.patch.object(provisioner, "ensure_kiosk_home") as ensure,
            ):
                restored = (
                    provisioner.restore_existing_kiosk_home_before_bootstraps()
                )

        self.assertTrue(restored)
        ensure.assert_called_once_with()

    def test_unowned_install_is_not_changed_before_bootstraps(self) -> None:
        def adb_run(
            arguments: list[str],
            timeout: float | None = None,
            check: bool = False,
        ) -> subprocess.CompletedProcess[str]:
            del timeout, check
            output = (
                "package:/data/app/me.jxl.kiosk_satellite/base.apk\n"
                if arguments[1:3] == ["pm", "path"]
                else "Device Owner: none\n"
            )
            return subprocess.CompletedProcess(arguments, 0, output)

        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                device_owner=True,
                kiosk_home=True,
            )
            with (
                mock.patch.object(provisioner, "adb_run", side_effect=adb_run),
                mock.patch.object(provisioner, "ensure_kiosk_home") as ensure,
            ):
                restored = (
                    provisioner.restore_existing_kiosk_home_before_bootstraps()
                )

        self.assertFalse(restored)
        ensure.assert_not_called()


class ShizukuCliTest(unittest.TestCase):
    def test_download_failure_is_reported_before_any_reboot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                shizuku=True,
            )
            with (
                mock.patch.object(provisioner, "connect"),
                mock.patch.object(provisioner, "verify_target"),
                mock.patch.object(
                    provisioner,
                    "resolve_shizuku_apk",
                    side_effect=ProvisionError(
                        "Shizuku APK download failed on the host computer"
                    ),
                ),
                mock.patch.object(provisioner, "reboot") as reboot,
            ):
                with self.assertRaisesRegex(ProvisionError, "host computer"):
                    provisioner.provision()

            reboot.assert_not_called()


class RemoteWipeCliTest(unittest.TestCase):
    def test_portal_plus_aloha_debloat_uses_only_validated_components(self) -> None:
        target = next(
            target
            for target in TARGETS
            if target.key == "portal-plus-aloha-1041515800015050"
        )
        states = {
            component: ("test", "default")
            for component in DEBLOAT_COMPONENT_NAMES
        }
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                debloat=True,
            )
            provisioner.target = target
            captured: list[str] = []
            with (
                mock.patch.object(
                    provisioner, "read_component_backup", return_value=states
                ),
                mock.patch.object(
                    provisioner,
                    "push_text_atomic",
                    side_effect=lambda contents, remote: captured.append(contents),
                ),
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess([], 1, ""),
                ),
            ):
                provisioner.prepare_component_actions()

        action_lines = captured[0].splitlines()[1:]
        self.assertEqual(len(action_lines), 39)
        self.assertEqual(
            action_lines,
            [
                f"disable\t{component}"
                for component in PORTAL_PLUS_ALOHA_SAFE_COMPONENT_NAMES
            ],
        )

    def test_portal_plus_restore_still_undoes_every_saved_component(self) -> None:
        target = next(
            target
            for target in TARGETS
            if target.key == "portal-plus-aloha-1041515800015050"
        )
        states = {
            component: ("test", "default")
            for component in DEBLOAT_COMPONENT_NAMES
        }
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                restore_bloat=True,
            )
            provisioner.target = target
            captured: list[str] = []
            with (
                mock.patch.object(
                    provisioner, "read_component_backup", return_value=states
                ),
                mock.patch.object(
                    provisioner,
                    "push_text_atomic",
                    side_effect=lambda contents, remote: captured.append(contents),
                ),
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess([], 0, ""),
                ),
            ):
                provisioner.prepare_component_actions()

        self.assertEqual(len(captured[0].splitlines()[1:]), len(DEBLOAT_COMPONENT_NAMES))

    def test_portal_plus_detects_cross_model_component_overrides(self) -> None:
        target = next(
            target
            for target in TARGETS
            if target.key == "portal-plus-aloha-1041515800015050"
        )
        outside_profile = next(
            component
            for component in DEBLOAT_COMPONENT_NAMES
            if component not in PORTAL_PLUS_ALOHA_SAFE_COMPONENT_NAMES
        )
        saved = {
            component: ("test", "default")
            for component in DEBLOAT_COMPONENT_NAMES
        }
        current = dict(saved)
        current[outside_profile] = ("test", "disabled")
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555", 1, pathlib.Path(temporary)
            )
            provisioner.target = target

            self.assertEqual(
                provisioner.unexpected_disabled_debloat_components(saved, current),
                [outside_profile],
            )

    def test_combined_ota_waits_for_remote_wipe_component_actions(self) -> None:
        target = next(
            target
            for target in TARGETS
            if target.key == "portal-go-terry-5051355900018050"
        )
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                disable_updates=True,
                debloat=True,
                block_remote_wipe=True,
            )
            provisioner.target = target
            provisioner.ota_already_configured = False
            provisioner.debloat_already_configured = True
            provisioner.remote_wipe_already_configured = False
            real_popen = subprocess.Popen
            action_processes: list[subprocess.Popen[bytes]] = []

            def action_process(
                *args: object, **kwargs: object
            ) -> subprocess.Popen[bytes]:
                process = real_popen(
                    [
                        "/bin/sh",
                        "-c",
                        "printf 'OTA block file install ok=1\\n"
                        "component ctl child=123 status=00000000 ok=1 "
                        "uid=0 euid=0\\n'; sleep 30",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=0,
                )
                action_processes.append(process)
                return process

            output = io.StringIO()
            with (
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess([], 0, ""),
                ),
                mock.patch(
                    "provision_portal.subprocess.Popen",
                    side_effect=action_process,
                ),
                mock.patch.object(sys, "stdout", output),
            ):
                self.assertTrue(provisioner.exploit(0x1000, 0x2000, 1))
            for process in action_processes:
                assert process.stdout is not None
                process.stdout.close()

        self.assertIn(
            "NATIVE_ACTIONS_OK actions=component_profile,ota_block",
            output.getvalue(),
        )

    def test_combined_component_actions_are_a_single_bootstrap_phase(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                debloat=True,
                block_remote_wipe=True,
            )

            self.assertTrue(provisioner.only_component_actions_requested())

            provisioner.audio = True
            self.assertFalse(provisioner.only_component_actions_requested())

    def test_completed_component_profiles_are_not_reapplied(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                debloat=True,
                block_remote_wipe=True,
            )
            provisioner.debloat_already_configured = True
            provisioner.remote_wipe_already_configured = True

            self.assertFalse(provisioner.needs_component_ctl())

            provisioner.remote_wipe_already_configured = False
            self.assertTrue(provisioner.needs_component_ctl())

            provisioner.remote_wipe_already_configured = True
            provisioner.debloat_already_configured = False
            self.assertTrue(provisioner.needs_component_ctl())

    def test_standalone_block_targets_only_the_two_receivers(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--block-remote-wipe"],
        ):
            arguments = parse_args()

        self.assertTrue(arguments.block_remote_wipe)
        self.assertFalse(arguments.audio)

        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                block_remote_wipe=True,
            )
            captured: list[str] = []
            states = {component: "default" for component in REMOTE_WIPE_COMPONENTS}
            with (
                mock.patch.object(
                    provisioner,
                    "ensure_remote_wipe_backup",
                    return_value=states,
                ),
                mock.patch.object(
                    provisioner,
                    "push_text_atomic",
                    side_effect=lambda contents, remote: captured.append(contents),
                ),
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess([], 0, ""),
                ),
            ):
                provisioner.prepare_component_actions()

        self.assertEqual(
            provisioner.requested_actions(), {"block_remote_wipe": True}
        )
        self.assertTrue(provisioner.privileged_requested())
        self.assertEqual(len(captured), 1)
        action_lines = captured[0].splitlines()[1:]
        self.assertEqual(
            action_lines,
            [f"disable\t{component}" for component in REMOTE_WIPE_COMPONENTS],
        )

    def test_kiosk_profile_includes_remote_wipe_block(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--profile", "kiosk"],
        ):
            arguments = parse_args()

        self.assertTrue(arguments.block_remote_wipe)

    def test_restore_preserves_each_saved_component_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                restore_remote_wipe=True,
            )
            states = {
                REMOTE_WIPE_COMPONENTS[0]: "default",
                REMOTE_WIPE_COMPONENTS[1]: "enabled",
            }
            captured: list[str] = []
            with (
                mock.patch.object(
                    provisioner,
                    "read_remote_wipe_backup",
                    return_value=states,
                ),
                mock.patch.object(
                    provisioner,
                    "push_text_atomic",
                    side_effect=lambda contents, remote: captured.append(contents),
                ),
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess([], 0, ""),
                ),
            ):
                provisioner.prepare_component_actions()

        self.assertEqual(
            captured[0].splitlines()[1:],
            [
                f"default\t{REMOTE_WIPE_COMPONENTS[0]}",
                f"enable\t{REMOTE_WIPE_COMPONENTS[1]}",
            ],
        )


class KioskPermissionsCliTest(unittest.TestCase):
    def test_standalone_permission_action_does_not_select_root_or_audio(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--kiosk-permissions"],
        ):
            arguments = parse_args()

        self.assertTrue(arguments.kiosk_permissions)
        self.assertFalse(arguments.audio)

        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                kiosk_permissions=True,
            )
            self.assertEqual(
                provisioner.requested_actions(),
                {"kiosk_permissions": True},
            )
            self.assertFalse(provisioner.privileged_requested())

    def test_kiosk_profile_includes_permissions(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--profile", "kiosk"],
        ):
            arguments = parse_args()

        self.assertTrue(arguments.kiosk_permissions)
        self.assertTrue(arguments.install_kiosk_satellite)

    def test_permission_action_never_changes_accessibility_services(self) -> None:
        calls: list[list[str]] = []

        def adb_run(
            arguments: list[str],
            timeout: float | None = None,
            check: bool = False,
        ) -> subprocess.CompletedProcess[str]:
            del timeout, check
            calls.append(arguments)
            output = "Events injected: 1\n" if "monkey" in arguments else ""
            return subprocess.CompletedProcess(arguments, 0, output)

        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                kiosk_permissions=True,
            )
            with (
                mock.patch.object(provisioner, "adb_run", side_effect=adb_run),
                mock.patch.object(provisioner, "verify_kiosk_permissions"),
            ):
                provisioner.apply_kiosk_permissions()

        rendered = [" ".join(command) for command in calls]
        self.assertEqual(
            sum(command.startswith("shell pm grant ") for command in rendered),
            7,
        )
        self.assertEqual(
            sum(command.startswith("shell appops set ") for command in rendered),
            3,
        )
        self.assertTrue(
            any("dumpsys deviceidle whitelist +me.jxl.kiosk_satellite" in command
                for command in rendered)
        )
        self.assertFalse(
            any("enabled_accessibility_services" in command for command in rendered)
        )


class KioskSatelliteInstallCliTest(unittest.TestCase):
    def test_standalone_install_does_not_select_root_or_audio(self) -> None:
        with mock.patch.object(
            sys,
            "argv",
            ["provision_portal.py", "--install-kiosk-satellite"],
        ):
            arguments = parse_args()

        self.assertTrue(arguments.install_kiosk_satellite)
        self.assertFalse(arguments.audio)

        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                install_kiosk_satellite=True,
            )
            self.assertEqual(
                provisioner.requested_actions(),
                {"install_kiosk_satellite": True},
            )
            self.assertFalse(provisioner.privileged_requested())

    def test_release_selection_prefers_first_supported_device_abi(self) -> None:
        tag = "2026.10.23"
        arm64_name = f"kiosk-satellite-{tag}.arm64-v8a.apk"
        universal_name = f"kiosk-satellite-{tag}.apk"
        release = {
            "tag_name": tag,
            "assets": [
                {
                    "name": universal_name,
                    "browser_download_url": (
                        f"{KIOSK_RELEASE_DOWNLOAD_PREFIX}{tag}/{universal_name}"
                    ),
                    "digest": "sha256:" + "a" * 64,
                    "size": 200,
                },
                {
                    "name": arm64_name,
                    "browser_download_url": (
                        f"{KIOSK_RELEASE_DOWNLOAD_PREFIX}{tag}/{arm64_name}"
                    ),
                    "digest": "sha256:" + "b" * 64,
                    "size": 100,
                },
            ],
        }

        selected = PortalProvisioner.select_kiosk_release_asset(
            release, ("arm64-v8a", "armeabi-v7a")
        )

        self.assertEqual(
            selected,
            (tag, arm64_name, 100, "b" * 64, "arm64-v8a"),
        )

    def test_release_selection_rejects_asset_without_github_digest(self) -> None:
        tag = "2026.10.23"
        name = f"kiosk-satellite-{tag}.arm64-v8a.apk"
        release = {
            "tag_name": tag,
            "assets": [
                {
                    "name": name,
                    "browser_download_url": (
                        f"{KIOSK_RELEASE_DOWNLOAD_PREFIX}{tag}/{name}"
                    ),
                    "digest": None,
                    "size": 100,
                }
            ],
        }

        with self.assertRaisesRegex(ProvisionError, "SHA-256"):
            PortalProvisioner.select_kiosk_release_asset(
                release, ("arm64-v8a",)
            )

    def test_existing_install_is_preserved_without_release_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                install_kiosk_satellite=True,
            )
            with (
                mock.patch.object(
                    provisioner,
                    "kiosk_satellite_version",
                    return_value="2026.10.22",
                ),
                mock.patch.object(
                    provisioner, "resolve_kiosk_satellite_apk"
                ) as resolve,
            ):
                provisioner.ensure_kiosk_satellite()

        resolve.assert_not_called()

    def test_missing_install_is_installed_and_launched(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            apk = pathlib.Path(temporary) / "kiosk-satellite.apk"
            provisioner = PortalProvisioner(
                "192.0.2.1:5555",
                1,
                pathlib.Path(temporary),
                install_kiosk_satellite=True,
            )
            with (
                mock.patch.object(
                    provisioner,
                    "kiosk_satellite_version",
                    side_effect=(None, "2026.10.23"),
                ),
                mock.patch.object(
                    provisioner,
                    "resolve_kiosk_satellite_apk",
                    return_value=(apk, "2026.10.23", "arm64-v8a"),
                ),
                mock.patch.object(
                    provisioner, "install_apk_preserving_verifier"
                ) as install,
                mock.patch.object(provisioner, "settle_package_state"),
                mock.patch.object(provisioner, "verify_package_verifier_state"),
                mock.patch.object(
                    provisioner,
                    "adb_run",
                    return_value=subprocess.CompletedProcess(
                        [], 0, "Events injected: 1\n"
                    ),
                ) as adb_run,
            ):
                provisioner.ensure_kiosk_satellite()

        install.assert_called_once_with(apk, "kiosk-satellite")
        self.assertIn("monkey", adb_run.call_args.args[0])

    def test_each_apk_install_records_its_own_verifier_baseline(self) -> None:
        verifier_states = iter(
            ("", "package:com.facebook.appverifier\n")
        )

        def adb_run(
            arguments: list[str],
            timeout: float | None = None,
            check: bool = False,
        ) -> subprocess.CompletedProcess[str]:
            del timeout, check
            if arguments[:5] == ["shell", "pm", "list", "packages", "-d"]:
                return subprocess.CompletedProcess(
                    arguments, 0, next(verifier_states)
                )
            if arguments[0] == "push":
                return subprocess.CompletedProcess(arguments, 0, "1 file pushed\n")
            return subprocess.CompletedProcess(arguments, 0, "Success\n")

        with tempfile.TemporaryDirectory() as temporary:
            apk = pathlib.Path(temporary) / "payload.apk"
            apk.touch()
            provisioner = PortalProvisioner(
                "192.0.2.1:5555", 1, pathlib.Path(temporary)
            )
            with mock.patch.object(provisioner, "adb_run", side_effect=adb_run):
                provisioner.install_apk_preserving_verifier(apk, "first")
                self.assertFalse(
                    provisioner.package_verifier_before_install_disabled
                )
                provisioner.install_apk_preserving_verifier(apk, "second")
                self.assertTrue(
                    provisioner.package_verifier_before_install_disabled
                )


OTA_DUMP_HEAD = (
    "----------\n"
    "Dump OtaService\n"
    "    lastKnownOtaStatus_: 0, (OtaStatusEnum: idle)\n"
)


def ota_dump(
    gate: str = "false",
    interval: str = "1000000",
    url: str = OTA_JSON_URL,
) -> str:
    return (
        OTA_DUMP_HEAD
        + "----------\n"
        "Dump OtaConfig\n"
        f"    getString(kOtaJsonUrl): {url}\n"
        "    getBool(kUpdateIntervalFromServer): false\n"
        f"    getInt64(kUpdateIntervalInitialMinutes): {interval}\n"
        f"    getBool(kFirmwareOtaUpdateEnable): {gate}\n"
        "----------\n"
    )


class OtaOverrideVerificationTest(unittest.TestCase):
    def provisioner(self, temporary: str) -> PortalProvisioner:
        provisioner = PortalProvisioner(
            "192.0.2.1:5555",
            1,
            pathlib.Path(temporary),
            disable_updates=True,
        )
        provisioner.target = next(
            target for target in TARGETS if target.device == "terry"
        )
        return provisioner

    def adb(self, dumps: list[str]) -> mock.Mock:
        disabled = "".join(
            f"package:{package}\n"
            for package in next(
                target for target in TARGETS if target.device == "terry"
            ).ota_packages
        )
        remaining = list(dumps)

        def run(args: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            if args[:2] == ["shell", "pm"]:
                return subprocess.CompletedProcess(args, 0, disabled)
            if args[:2] == ["shell", "dumpsys"]:
                text = remaining.pop(0) if len(remaining) > 1 else remaining[0]
                return subprocess.CompletedProcess(args, 0, text)
            return subprocess.CompletedProcess(args, 0, "")

        return mock.Mock(side_effect=run)

    def test_parse_rejects_dump_cut_before_config(self) -> None:
        self.assertIsNone(parse_ota_config(OTA_DUMP_HEAD))
        config = parse_ota_config(ota_dump())
        self.assertEqual(config["kFirmwareOtaUpdateEnable"], "false")
        self.assertEqual(
            config["kUpdateIntervalInitialMinutes"],
            str(OTA_POLL_INTERVAL_MINUTES),
        )

    def test_preflight_retries_while_otad_is_starting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.provisioner(temporary)
            adb = self.adb([OTA_DUMP_HEAD, OTA_DUMP_HEAD, ota_dump()])
            with mock.patch.object(provisioner, "adb_run", adb), mock.patch(
                "provision_portal.time.sleep"
            ), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertTrue(provisioner.ota_preflight())
            self.assertIn("dump=complete action=skip", output.getvalue())

    def test_preflight_reinstalls_legacy_gate_only_override(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.provisioner(temporary)
            adb = self.adb(
                [
                    ota_dump(
                        interval="6",
                        url="https://graph.facebook.com/mobile_release_updates",
                    )
                ]
            )
            with mock.patch.object(provisioner, "adb_run", adb), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertFalse(provisioner.ota_preflight())
            self.assertIn(
                "firmware_gate_false=1 poll_interval_minutes=6 "
                "update_url_blocked=0 dump=complete action=install",
                output.getvalue(),
            )

    def test_preflight_requires_blocked_update_url(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.provisioner(temporary)
            adb = self.adb(
                [ota_dump(url="https://graph.facebook.com/mobile_release_updates")]
            )
            with mock.patch.object(provisioner, "adb_run", adb), \
                    contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertFalse(provisioner.ota_preflight())
            self.assertIn(
                "poll_interval_minutes=1000000 update_url_blocked=0",
                output.getvalue(),
            )

    def test_preflight_survives_dumpsys_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            provisioner = self.provisioner(temporary)
            adb = self.adb([ota_dump()])
            original = adb.side_effect
            calls = {"dumpsys": 0}

            def flaky(args: list[str], **kwargs: object):
                if args[:2] == ["shell", "dumpsys"]:
                    calls["dumpsys"] += 1
                    if calls["dumpsys"] == 1:
                        raise ProvisionError("command timed out: adb shell dumpsys")
                return original(args, **kwargs)

            adb.side_effect = flaky
            with mock.patch.object(provisioner, "adb_run", adb), mock.patch(
                "provision_portal.time.sleep"
            ), contextlib.redirect_stdout(io.StringIO()):
                self.assertTrue(provisioner.ota_preflight())
            self.assertEqual(calls["dumpsys"], 2)


if __name__ == "__main__":
    unittest.main()
