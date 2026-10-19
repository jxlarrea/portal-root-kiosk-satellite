"""Exact-build Portal targets supported by the host provisioner."""

from __future__ import annotations

from dataclasses import dataclass, field
import pathlib


@dataclass(frozen=True)
class PortalTarget:
    key: str
    model: str
    device: str
    fingerprint: str
    kernel: str
    preload_name: str
    make_target: str
    kaslr_pc_offsets: tuple[int, ...]
    product_models: tuple[str, ...] = ()
    stack_route: str = "sendmmsg"
    memstart_strategy: str = "bugreport"
    kaslr_strategy: str = "simpleperf"
    proc_uid_user_ids: tuple[int, ...] = ()
    exploit_env: dict[str, str] = field(default_factory=dict)
    bundled_simpleperf: bool = False
    route_delay_usec: int = 50_000
    proc_uid_sentinel: str = "run_as"
    kgsl_reclaim: bool = False
    kgsl_reclaim_allocations: int = 4096
    mm_recycle_slabs: int = 0
    kiosk_permission_settle_seconds: int = 0
    reclaim_pairs: int = 64
    reclaim_sends: int = 64
    exploit_timeout_seconds: int = 300
    post_root_timeout_seconds: int = 0
    recover_watch_result_after_disconnect: bool = False
    address_discovery_settle_seconds: int = 0
    address_discovery_reboot_on_failure: bool = False
    wireless_adb_file_property: str | None = None
    wireless_adb_uid1000_boot: bool = False
    uid1000_host_package: str = "com.facebook.alohasdk.platformbatterystate"
    uid1000_host_label: str = "platformbatterystate"
    buffer_root_staged_sources: bool = False
    uid1000_data_directory: str = "/data/portal-uid1000"
    uid1000_helper_make_target: str = "all"
    uid1000_helper_artifact: str = "portal-camera-led-watch"
    uid1000_hook_artifact: str = "portal-uid1000-hook.bin"
    uid1000_embedded_helper: bool = False
    uid1000_installer_credentials: bool = False
    audio_java_fallback: bool = False
    audio_deferred_ctl: bool = False
    audio_installer_credentials: bool = False
    device_owner_system_credentials: bool = False
    ota_installer_credentials: bool = False
    meta_accounts_system_credentials: bool = False
    meta_accounts_skip_force_stop: bool = False
    meta_accounts_package_bootstrap: bool = False
    shell_root_package_actions: bool = False
    presence_installer_credentials: bool = False
    presence_runtime_keys: tuple[str, ...] = ()
    presence_full_sensor_width: float | None = None
    ota_packages: tuple[str, ...] = (
        "com.facebook.aloha.otaui",
        "com.facebook.aloha.alohaotasetup",
    )

    def preload_path(self, repository: pathlib.Path) -> pathlib.Path:
        return repository / "exploit" / "build" / self.preload_name


TARGETS = (
    PortalTarget(
        key="portal-go-terry-5051355900018050",
        model="Meta Portal Go",
        device="terry",
        fingerprint=(
            "Facebook/terry_prod/terry:10/QKQ1.210213.001/"
            "5051355900018050:user/prod-keys"
        ),
        kernel="4.9.227-perf+",
        preload_name="preload-portal-terry-5051355900018050.so",
        make_target="portal-terry-5051355900018050",
        kaslr_pc_offsets=(
            0x3D7E,
            0x3D54,
            0x153C,
            0x11756DC,
            0x1175724,
            0x363C6,
            0xAF90E,
            0x136E,
            0x3A72,
        ),
    ),
    PortalTarget(
        key="portal-plus-cipher-4051355900018050",
        model="Meta Portal+ (2nd generation)",
        device="cipher",
        fingerprint=(
            "Facebook/cipher_prod/cipher:10/QKQ1.210213.001/"
            "4051355900018050:user/prod-keys"
        ),
        kernel="4.9.227-perf+",
        preload_name="preload-portal-cipher-4051355900018050.so",
        make_target="portal-cipher-4051355900018050",
        kaslr_pc_offsets=(
            0x3D7E,
            0x3D54,
            0x153C,
            0x11756DC,
            0x1175724,
            0x363C6,
            0xAF90E,
            0x136E,
            0x3A72,
        ),
        product_models=("Portal+",),
        reclaim_pairs=256,
        reclaim_sends=256,
        exploit_timeout_seconds=120,
        recover_watch_result_after_disconnect=True,
        uid1000_host_package="com.facebook.alohasdk.platformsecurestate",
        uid1000_host_label="platformsecurestate",
    ),
    PortalTarget(
        key="portal-10-omni-3051355900018050",
        model="Meta Portal 10-inch (2nd generation)",
        device="omni",
        fingerprint=(
            "Facebook/omni_prod/omni:10/QKQ1.210213.001/"
            "3051355900018050:user/prod-keys"
        ),
        kernel="4.9.227-perf+",
        preload_name="preload-portal-omni-3051355900018050.so",
        make_target="portal-omni-3051355900018050",
        kaslr_pc_offsets=(
            0x3D7E,
            0x3D54,
            0x153C,
            0x11756DC,
            0x1175724,
            0x363C6,
            0xAF90E,
            0x136E,
            0x3A72,
        ),
        product_models=("Portal",),
        reclaim_pairs=256,
        reclaim_sends=256,
        exploit_timeout_seconds=120,
        post_root_timeout_seconds=210,
        recover_watch_result_after_disconnect=True,
        address_discovery_settle_seconds=15,
        address_discovery_reboot_on_failure=True,
        uid1000_host_package="com.facebook.alohasdk.platformsecurestate",
        uid1000_host_label="platformsecurestate",
        wireless_adb_file_property="service.adb.tcp.port",
        wireless_adb_uid1000_boot=True,
        audio_java_fallback=True,
        audio_deferred_ctl=True,
    ),
    PortalTarget(
        key="portal-mini-omni-3051355900018050",
        model="Meta Portal Mini",
        device="omni",
        fingerprint=(
            "Facebook/omni_prod/omni:10/QKQ1.210213.001/"
            "3051355900018050:user/prod-keys"
        ),
        kernel="4.9.227-perf+",
        preload_name="preload-portal-omni-3051355900018050.so",
        make_target="portal-omni-3051355900018050",
        kaslr_pc_offsets=(
            0x3D7E,
            0x3D54,
            0x153C,
            0x11756DC,
            0x1175724,
            0x363C6,
            0xAF90E,
            0x136E,
            0x3A72,
        ),
        product_models=("PortalMini",),
        reclaim_pairs=256,
        reclaim_sends=256,
        exploit_timeout_seconds=120,
        post_root_timeout_seconds=210,
        recover_watch_result_after_disconnect=True,
        address_discovery_settle_seconds=15,
        address_discovery_reboot_on_failure=True,
        uid1000_host_package="com.facebook.alohasdk.platformsecurestate",
        uid1000_host_label="platformsecurestate",
        wireless_adb_file_property="service.adb.tcp.port",
        wireless_adb_uid1000_boot=True,
        audio_java_fallback=True,
        audio_deferred_ctl=True,
    ),
    PortalTarget(
        key="portal-plus-aloha-1041515800015050",
        model="Meta Portal+ (1st generation)",
        device="aloha",
        fingerprint=(
            "Facebook/aloha_prod/aloha:9/PKQ1.191202.001/"
            "1041515800015050:user/prod-keys"
        ),
        kernel="4.4.153+",
        preload_name="preload-portal-aloha-1041515800015050.so",
        make_target="portal-aloha-1041515800015050",
        kaslr_pc_offsets=(0x3354,),
        product_models=("Portal+",),
        stack_route="ptrace",
        bundled_simpleperf=True,
        route_delay_usec=0,
        proc_uid_sentinel="app",
        kgsl_reclaim=True,
        mm_recycle_slabs=20,
        reclaim_pairs=256,
        reclaim_sends=256,
        uid1000_host_package="com.facebook.alohasdk.virtualcameramanager",
        uid1000_host_label="virtualcameramanager",
        buffer_root_staged_sources=True,
        uid1000_data_directory="/data/misc/adb/portal-uid1000",
        uid1000_helper_make_target="aloha",
        uid1000_helper_artifact="portal-camera-led-watch-aloha",
        uid1000_hook_artifact="portal-uid1000-hook-aloha.bin",
        uid1000_embedded_helper=True,
        uid1000_installer_credentials=True,
        audio_java_fallback=True,
        audio_installer_credentials=True,
        device_owner_system_credentials=True,
        ota_installer_credentials=True,
        meta_accounts_system_credentials=True,
        meta_accounts_skip_force_stop=True,
        meta_accounts_package_bootstrap=True,
        shell_root_package_actions=True,
        presence_installer_credentials=True,
        presence_runtime_keys=(
            "enable_cv_background_detector_v2",
            "enable_hardware_cropping",
            "enable_liveness_metric",
        ),
        presence_full_sensor_width=4032.0,
        ota_packages=("com.facebook.aloha.otaui",),
    ),
    PortalTarget(
        key="portal-10-aloha-1041515800015050",
        model="Meta Portal 10-inch (1st generation)",
        device="aloha",
        fingerprint=(
            "Facebook/aloha_prod/aloha:9/PKQ1.191202.001/"
            "1041515800015050:user/prod-keys"
        ),
        kernel="4.4.153+",
        preload_name="preload-portal-aloha-1041515800015050.so",
        make_target="portal-aloha-1041515800015050",
        kaslr_pc_offsets=(0x3354,),
        product_models=("Portal",),
        stack_route="ptrace",
        bundled_simpleperf=True,
        route_delay_usec=0,
        proc_uid_sentinel="app",
        kgsl_reclaim=True,
        kgsl_reclaim_allocations=8192,
        mm_recycle_slabs=40,
        kiosk_permission_settle_seconds=30,
        reclaim_pairs=256,
        reclaim_sends=256,
        uid1000_host_package="com.facebook.alohasdk.virtualcameramanager",
        uid1000_host_label="virtualcameramanager",
        buffer_root_staged_sources=True,
        uid1000_data_directory="/data/misc/adb/portal-uid1000",
        uid1000_helper_make_target="aloha",
        uid1000_helper_artifact="portal-camera-led-watch-aloha",
        uid1000_hook_artifact="portal-uid1000-hook-aloha.bin",
        uid1000_embedded_helper=True,
        uid1000_installer_credentials=True,
        audio_java_fallback=True,
        audio_installer_credentials=True,
        device_owner_system_credentials=True,
        ota_installer_credentials=True,
        meta_accounts_system_credentials=True,
        meta_accounts_skip_force_stop=True,
        meta_accounts_package_bootstrap=True,
        exploit_timeout_seconds=180,
        shell_root_package_actions=True,
        presence_installer_credentials=True,
        presence_runtime_keys=(
            "enable_cv_background_detector_v2",
            "enable_hardware_cropping",
            "enable_liveness_metric",
        ),
        presence_full_sensor_width=4032.0,
        ota_packages=("com.facebook.aloha.otaui",),
    ),
    PortalTarget(
        key="portal-tv-ripley-2041515800015050",
        model="Meta Portal TV",
        device="ripley",
        fingerprint=(
            "Facebook/ripley_prod/ripley:9/PKQ1.191202.001/"
            "2041515800015050:user/prod-keys"
        ),
        kernel="4.4.153+",
        preload_name="preload-portal-ripley-2041515800015050.so",
        make_target="portal-ripley-2041515800015050",
        kaslr_pc_offsets=(),
        kaslr_strategy="bugreport",
        product_models=("PortalTV",),
        stack_route="ptrace",
        route_delay_usec=0,
        proc_uid_sentinel="user",
        proc_uid_user_ids=(10, 11, 12),
        kgsl_reclaim=True,
        kgsl_reclaim_allocations=4096,
        reclaim_pairs=128,
        reclaim_sends=128,
        exploit_timeout_seconds=480,
        recover_watch_result_after_disconnect=True,
        wireless_adb_file_property="persist.adb.tcp.port",
        exploit_env={
            "GHOSTLOCK_SIGSTAMP_SPINS": "0",
            "GHOSTLOCK_PROC_UID_WARM_MB": "64",
            "GHOSTLOCK_KGSL_HOLD": "512",
            "GHOSTLOCK_BUDDY_HOLD_SENDS": "512",
            "GHOSTLOCK_SPIN_AFTER_ROUTE": "1",
            "GHOSTLOCK_PTRACE_WAITER_OFF": "0x130",
            "GHOSTLOCK_PROC_UID_DENSE_EXTENTS": "1",
            "GHOSTLOCK_PROC_UID_TAIL_MB": "768",
            "GHOSTLOCK_PTRACE_STAMP_EARLY": "1",
            "GHOSTLOCK_WAIT_TIMEOUT_RELEASE": "1",
            "GHOSTLOCK_CONSUME_SWEEPS": "6",
        },
    ),
)


def find_target(
    device: str, fingerprint: str, product_model: str | None = None
) -> PortalTarget | None:
    return next(
        (
            target
            for target in TARGETS
            if target.device == device and target.fingerprint == fingerprint
            and (
                not target.product_models
                or product_model is None
                or product_model in target.product_models
            )
        ),
        None,
    )
