#!/usr/bin/env python3

import pathlib
import sys
import unittest


REPOSITORY = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY / "tools"))

from portal_targets import TARGETS, find_target  # noqa: E402


class PortalTargetSelectionTest(unittest.TestCase):
    def test_every_supported_build_selects_only_its_exact_target(self) -> None:
        self.assertEqual(len(TARGETS), 7)
        for target in TARGETS:
            selected = find_target(
                target.device,
                target.fingerprint,
                target.product_models[0] if target.product_models else None,
            )
            self.assertIs(selected, target)
            self.assertIsNone(
                find_target(
                    target.device,
                    target.fingerprint + ".different",
                    target.product_models[0] if target.product_models else None,
                )
            )

    def test_portal_go_and_first_generation_portal_plus_profiles(self) -> None:
        targets = {target.key: target for target in TARGETS}
        terry = targets["portal-go-terry-5051355900018050"]
        cipher = targets["portal-plus-cipher-4051355900018050"]
        omni = targets["portal-10-omni-3051355900018050"]
        aloha = targets["portal-plus-aloha-1041515800015050"]
        self.assertEqual(terry.key, "portal-go-terry-5051355900018050")
        self.assertEqual(terry.stack_route, "sendmmsg")
        self.assertFalse(terry.bundled_simpleperf)
        self.assertFalse(terry.shell_root_package_actions)
        self.assertEqual(terry.reclaim_pairs, 64)
        self.assertEqual(terry.reclaim_sends, 64)
        self.assertEqual(terry.exploit_timeout_seconds, 300)
        self.assertEqual(terry.post_root_timeout_seconds, 0)
        self.assertFalse(terry.recover_watch_result_after_disconnect)
        self.assertEqual(
            terry.uid1000_host_package,
            "com.facebook.alohasdk.platformbatterystate",
        )

        self.assertEqual(aloha.key, "portal-plus-aloha-1041515800015050")
        self.assertEqual(aloha.stack_route, "ptrace")
        self.assertTrue(aloha.bundled_simpleperf)
        self.assertTrue(aloha.shell_root_package_actions)
        self.assertEqual(aloha.reclaim_pairs, 256)
        self.assertEqual(aloha.reclaim_sends, 256)
        self.assertEqual(aloha.exploit_timeout_seconds, 300)
        self.assertEqual(aloha.post_root_timeout_seconds, 0)
        self.assertFalse(aloha.recover_watch_result_after_disconnect)
        self.assertEqual(
            aloha.uid1000_host_package,
            "com.facebook.alohasdk.virtualcameramanager",
        )
        self.assertEqual(aloha.uid1000_host_label, "virtualcameramanager")
        self.assertTrue(aloha.buffer_root_staged_sources)
        self.assertEqual(
            aloha.uid1000_data_directory, "/data/misc/adb/portal-uid1000"
        )
        self.assertEqual(aloha.uid1000_helper_make_target, "aloha")
        self.assertEqual(
            aloha.uid1000_helper_artifact, "portal-camera-led-watch-aloha"
        )
        self.assertEqual(
            aloha.uid1000_hook_artifact, "portal-uid1000-hook-aloha.bin"
        )
        self.assertTrue(aloha.uid1000_embedded_helper)
        self.assertTrue(aloha.uid1000_installer_credentials)
        self.assertTrue(aloha.meta_accounts_skip_force_stop)
        self.assertTrue(aloha.meta_accounts_package_bootstrap)

        self.assertEqual(cipher.key, "portal-plus-cipher-4051355900018050")
        self.assertEqual(cipher.stack_route, "sendmmsg")
        self.assertFalse(cipher.shell_root_package_actions)
        self.assertEqual(cipher.reclaim_pairs, 256)
        self.assertEqual(cipher.reclaim_sends, 256)
        self.assertEqual(cipher.exploit_timeout_seconds, 120)
        self.assertEqual(cipher.post_root_timeout_seconds, 0)
        self.assertTrue(cipher.recover_watch_result_after_disconnect)
        self.assertEqual(
            cipher.uid1000_host_package,
            "com.facebook.alohasdk.platformsecurestate",
        )

        self.assertEqual(omni.key, "portal-10-omni-3051355900018050")
        self.assertEqual(omni.stack_route, "sendmmsg")
        self.assertFalse(omni.shell_root_package_actions)
        self.assertEqual(omni.reclaim_pairs, 256)
        self.assertEqual(omni.reclaim_sends, 256)
        self.assertEqual(omni.exploit_timeout_seconds, 120)
        self.assertEqual(omni.post_root_timeout_seconds, 210)
        self.assertTrue(omni.recover_watch_result_after_disconnect)
        self.assertEqual(omni.address_discovery_settle_seconds, 15)
        self.assertTrue(omni.address_discovery_reboot_on_failure)
        self.assertEqual(
            omni.wireless_adb_file_property,
            "service.adb.tcp.port",
        )
        self.assertTrue(omni.wireless_adb_uid1000_boot)
        self.assertTrue(omni.audio_java_fallback)
        self.assertTrue(omni.audio_deferred_ctl)
        self.assertEqual(
            omni.uid1000_host_package,
            "com.facebook.alohasdk.platformsecurestate",
        )

    def test_portal_tv_ripley_profile(self) -> None:
        targets = {target.key: target for target in TARGETS}
        ripley = targets["portal-tv-ripley-2041515800015050"]
        self.assertEqual(ripley.device, "ripley")
        self.assertEqual(ripley.product_models, ("PortalTV",))
        self.assertEqual(ripley.kernel, "4.4.153+")
        self.assertEqual(ripley.stack_route, "ptrace")
        self.assertEqual(ripley.kaslr_strategy, "bugreport")
        self.assertEqual(ripley.kaslr_pc_offsets, ())
        self.assertEqual(ripley.memstart_strategy, "bugreport")
        self.assertEqual(ripley.proc_uid_sentinel, "user")
        self.assertEqual(ripley.proc_uid_user_ids, (10, 11, 12))
        self.assertTrue(ripley.kgsl_reclaim)
        self.assertEqual(ripley.kgsl_reclaim_allocations, 4096)
        self.assertEqual(ripley.reclaim_pairs, 128)
        self.assertEqual(ripley.reclaim_sends, 128)
        self.assertTrue(ripley.recover_watch_result_after_disconnect)
        self.assertEqual(
            ripley.wireless_adb_file_property, "persist.adb.tcp.port"
        )
        self.assertEqual(
            ripley.exploit_env["GHOSTLOCK_PTRACE_WAITER_OFF"], "0x130"
        )
        self.assertEqual(
            ripley.exploit_env["GHOSTLOCK_CONSUME_SWEEPS"], "6"
        )

    def test_portal_mini_uses_a_distinct_model_guard_on_the_omni_build(
        self,
    ) -> None:
        targets = {target.key: target for target in TARGETS}
        omni = targets["portal-10-omni-3051355900018050"]
        mini = targets["portal-mini-omni-3051355900018050"]

        self.assertIs(
            find_target(mini.device, mini.fingerprint, "PortalMini"), mini
        )
        self.assertIs(
            find_target(omni.device, omni.fingerprint, "Portal"), omni
        )
        self.assertIsNone(
            find_target(mini.device, mini.fingerprint, "Portal+")
        )
        for field in (
            "device",
            "fingerprint",
            "kernel",
            "preload_name",
            "make_target",
            "kaslr_pc_offsets",
            "stack_route",
            "memstart_strategy",
            "reclaim_pairs",
            "reclaim_sends",
            "exploit_timeout_seconds",
            "post_root_timeout_seconds",
            "recover_watch_result_after_disconnect",
            "address_discovery_settle_seconds",
            "address_discovery_reboot_on_failure",
            "uid1000_host_package",
            "uid1000_host_label",
            "wireless_adb_file_property",
            "wireless_adb_uid1000_boot",
            "audio_java_fallback",
            "audio_deferred_ctl",
        ):
            self.assertEqual(getattr(mini, field), getattr(omni, field), field)

    def test_original_portal_uses_a_distinct_model_guard_on_the_aloha_build(
        self,
    ) -> None:
        targets = {target.key: target for target in TARGETS}
        portal_plus = targets["portal-plus-aloha-1041515800015050"]
        portal = targets["portal-10-aloha-1041515800015050"]
        self.assertTrue(portal_plus.meta_accounts_package_bootstrap)
        self.assertTrue(portal.meta_accounts_package_bootstrap)
        self.assertEqual(portal.kgsl_reclaim_allocations, 8192)
        self.assertEqual(portal_plus.kgsl_reclaim_allocations, 4096)
        self.assertEqual(portal.mm_recycle_slabs, 40)
        self.assertEqual(portal_plus.mm_recycle_slabs, 20)
        self.assertEqual(portal.kiosk_permission_settle_seconds, 30)
        self.assertEqual(portal_plus.kiosk_permission_settle_seconds, 0)

        self.assertIs(
            find_target(portal.device, portal.fingerprint, "Portal"), portal
        )
        self.assertIs(
            find_target(portal_plus.device, portal_plus.fingerprint, "Portal+"),
            portal_plus,
        )
        self.assertIsNone(
            find_target(portal.device, portal.fingerprint, "PortalMini")
        )
        for field in (
            "device",
            "fingerprint",
            "kernel",
            "preload_name",
            "make_target",
            "kaslr_pc_offsets",
            "stack_route",
            "memstart_strategy",
            "bundled_simpleperf",
            "route_delay_usec",
            "proc_uid_sentinel",
            "kgsl_reclaim",
            "reclaim_pairs",
            "reclaim_sends",
            "uid1000_host_package",
            "uid1000_host_label",
            "buffer_root_staged_sources",
            "uid1000_data_directory",
            "uid1000_helper_make_target",
            "uid1000_helper_artifact",
            "uid1000_hook_artifact",
            "uid1000_embedded_helper",
            "uid1000_installer_credentials",
            "audio_java_fallback",
            "audio_installer_credentials",
            "device_owner_system_credentials",
            "ota_installer_credentials",
            "meta_accounts_system_credentials",
            "meta_accounts_skip_force_stop",
            "meta_accounts_package_bootstrap",
            "shell_root_package_actions",
            "presence_installer_credentials",
            "presence_runtime_keys",
            "presence_full_sensor_width",
            "ota_packages",
        ):
            self.assertEqual(
                getattr(portal, field), getattr(portal_plus, field), field
            )

    def test_portal_plus_model_guard_is_enforced(self) -> None:
        for target in TARGETS:
            if target.product_models:
                self.assertIsNone(
                    find_target(target.device, target.fingerprint, "Portal Go")
                )

    def test_cipher_cleanup_guard_does_not_change_other_targets(self) -> None:
        cipher_header = (
            REPOSITORY
            / "exploit/targets/portal-cipher-4051355900018050/target.h"
        ).read_text()
        omni_header = (
            REPOSITORY
            / "exploit/targets/portal-omni-3051355900018050/target.h"
        ).read_text()
        terry_header = (
            REPOSITORY
            / "exploit/targets/portal-terry-5051355900018050/target.h"
        ).read_text()
        aloha_header = (
            REPOSITORY
            / "exploit/targets/portal-aloha-1041515800015050/target.h"
        ).read_text()
        self.assertIn("#define CONFIGFS_ZERO_GUARD_SIZE 32", cipher_header)
        self.assertIn("#define CONFIGFS_BINARY_CLEANUP 1", cipher_header)
        self.assertNotIn("#define CONFIGFS_ZERO_GUARD_SIZE", terry_header)
        self.assertNotIn("#define CONFIGFS_BINARY_CLEANUP", terry_header)
        self.assertIn("#define CONFIGFS_ZERO_GUARD_SIZE 32", aloha_header)
        self.assertNotIn("#define CONFIGFS_BINARY_CLEANUP", aloha_header)
        self.assertIn("PlatformSecureStateService.apk@classes.dex", cipher_header)
        self.assertIn("PlatformSecureStateService.apk@classes.dex", omni_header)
        self.assertIn("#define CONFIGFS_ZERO_GUARD_SIZE 32", omni_header)
        self.assertIn("#define CONFIGFS_BINARY_CLEANUP 1", omni_header)
        self.assertNotIn("PlatformSecureStateService", terry_header)
        self.assertNotIn("PlatformSecureStateService", aloha_header)
        self.assertIn("#define UID1000_ART_APPEND_SEGMENT 1", aloha_header)
        self.assertIn("VirtualCameraManagerService.apk@classes.dex", aloha_header)
        self.assertIn("#define UID1000_ART_ONCREATE_OFFSET 0x00004780", aloha_header)
        self.assertIn("#define UID1000_ART_HOOK_OFFSET 0x0000e000", aloha_header)
        self.assertIn("#define UID1000_ART_EXPECTED_MAGIC \"oat\\n138\\0\"", aloha_header)
        self.assertIn("#define CONFIGFS_BUFFER_HELPER_KEYS 1", aloha_header)
        self.assertIn("#define CONFIGFS_BUFFER_UID1000_SOURCES 1", aloha_header)
        self.assertIn("#define UID1000_EMBEDDED_HELPER 1", aloha_header)
        self.assertIn(
            '#define UID1000_DATA_DIRECTORY "/data/misc/adb/portal-uid1000"',
            aloha_header,
        )

    def test_account_ctl_descriptor_workaround_is_aloha_only(self) -> None:
        headers = {
            path.parent.name: path.read_text()
            for path in (REPOSITORY / "exploit/targets").glob("*/target.h")
        }
        capability = "#define CONFIGFS_INHERIT_ACCOUNT_CTL 1"
        self.assertIn(capability, headers["portal-aloha-1041515800015050"])
        for target in (
            "portal-cipher-4051355900018050",
            "portal-omni-3051355900018050",
            "portal-terry-5051355900018050",
        ):
            self.assertNotIn(capability, headers[target], target)

        root_source = (REPOSITORY / "exploit/src/root.c").read_text()
        self.assertIn("#ifdef CONFIGFS_INHERIT_ACCOUNT_CTL", root_source)


if __name__ == "__main__":
    unittest.main()
