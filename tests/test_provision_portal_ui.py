"""PORTAL-BEHAVE-006: host integration tests; never invoke ADB."""
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
FINGERPRINT = 'Facebook/terry_prod/terry:10/QKQ1.210213.001/5051355900018050:user/prod-keys'
FAKE = '''import json, os, signal, sys, time
from pathlib import Path
args = sys.argv[1:]
serial = args[args.index('--serial') + 1]
trace = Path(__file__).resolve().parents[1] / 'trace'
with trace.open('a') as f: f.write(json.dumps(args) + '\\n')
trace.with_suffix('.sdk').write_text(json.dumps({key: os.environ.get(key) for key in ('SDK', 'NDK', 'ANDROID_JAR', 'BUILD_TOOLS', 'D8')}))
mode = os.environ.get('UI_TEST_MODE', 'ok')
if '--status' in args:
    final = any('--status' not in json.loads(line) for line in trace.read_text().splitlines())
    if final and mode in ('post-status-fail', 'fail-post-status'): print('PROVISION_ERROR: final ADB unavailable'); sys.exit(5)
    if final and mode == 'post-identity': serial = 'another-device'
    if mode == 'status-fail':
        print('PROVISION_ERROR: ADB unavailable'); sys.exit(4)
    if mode == 'status-hang': time.sleep(30)
    if mode == 'status-lost':
        print('PROVISION_ERROR: test:5555 did not reconnect after 30s'); sys.exit(1)
    if mode == 'status-malformed': print('not json'); sys.exit(0)
    if mode == 'status-serial': serial = 'another-device'
    print(json.dumps({'serial': serial, 'target': {'device': 'terry',
        'fingerprint': 'wrong' if mode == 'identity' else %r},
        'audio': {'installed_marker': mode != 'requested-unapplied' and (mode != 'post-change' or final)},
        'kiosk_satellite': {'device_owner': True},
        'presence': {'state': 'optimized', 'analysis_frames_observed': False, 'roi_frames_observed': False},
        'runtime': {'wireless_adb_port': '5555'}}))
else:
    if mode == 'backup-only':
        print('BACKUP_OK path=test-backup.tar.gz'); sys.exit(0)
    print('compiler noise that should be hidden', flush=True)
    if mode == 'signal':
        def stop(sig, frame):
            trace.with_suffix('.signal').write_text('received'); sys.exit(130)
        signal.signal(signal.SIGINT, stop)
        print('STAGED preload=test', flush=True)
        time.sleep(30)
    print('STAGED preload=test')
    print('INSTALL_ATTEMPT=2 preparing clean boot')
    print('ADDRESS_DISCOVERY_RETRY attempt=2 error=address unavailable')
    print('INSTALL_ATTEMPT_RESULT attempt=2 success=0 early_failure=1')
    print('STOCK_ADB_REENABLE_REQUIRED persistent_port=unset')
    print('Keep USB connected. Enable ADB on the Portal.')
    print('WATCHDOG_OK boot_id=one aiservice_pid=123')
    print('VERIFY_REBOOT starting')
    if mode == 'partial':
        print('PROVISION_ERROR: presence pipeline did not pass its live compatibility check'); sys.exit(6)
    if mode in ('fail', 'fail-post-status'):
        print('unexpected native failure'); sys.exit(7)
    if mode != 'no-marker': print('PROVISION_OK first_boot=one second_boot=two logs=test')
    if mode == 'conflict': print('PROVISION_ERROR: late failure'); sys.exit(8)
''' % FINGERPRINT


FAKE_ADB = '''#!/usr/bin/env python3
import json, os, sys, time
from pathlib import Path
args = sys.argv[1:]
root = Path(__file__).resolve().parents[1]
with (root / 'adb-trace').open('a') as trace: trace.write(json.dumps(args) + '\\n')
mode = os.environ.get('UI_TEST_ADB', 'ready')
if args[:1] == ['devices']:
    print('List of devices attached')
    if mode in ('ready', 'unauthorized', 'offline', 'shell-fail', 'hang'):
        state = mode if mode in ('unauthorized', 'offline') else 'device'
        print('test:5555 ' + state + ' product:terry_prod device:terry')
    sys.exit(0)
if args[:1] == ['connect']:
    print('failed to connect: Connection refused' if mode == 'refused' else 'connected')
    sys.exit(1 if mode == 'refused' else 0)
if 'get-state' in args:
    if mode == 'hang': time.sleep(30)
    if mode == 'refused': print("error: device 'test:5555' not found"); sys.exit(1)
    if mode in ('unauthorized', 'offline'): print('error: device ' + mode); sys.exit(1)
    print('device'); sys.exit(0)
if 'shell' in args:
    if mode == 'shell-fail': print('error: shell unavailable'); sys.exit(1)
    if args[-1] == 'ro.product.device': print('omni' if mode == 'omni' else 'terry')
    elif args[-1] == 'ro.build.fingerprint': print('wrong' if mode == 'wrong-build' else %r)
    elif args[3:6] == ['service', 'call', 'sensor_privacy']:
        state = os.environ.get('UI_TEST_SENSOR', 'unknown')
        if state == 'denied': print('Result: Parcel(ffffffff)'); sys.exit(0)
        if state != 'unknown': print("Result: Parcel(00000000 %%s   '........')" %% ('00000001' if state == 'private' else '00000000'))
    elif args[3:6] == ['service', 'call', 'media.audio_flinger']:
        state = os.environ.get('UI_TEST_SENSOR', 'unknown')
        if state == 'denied': print('Result: Parcel(ffffffff)'); sys.exit(0)
        if state != 'unknown': print("Result: Parcel(%%s    '....')" %% ('00000001' if state == 'muted' else '00000000'))
    elif args[3:5] == ['pm', 'path']:
        if mode not in ('missing', 'install-fail', 'install-no-effect', 'launch-fail') or (root / 'installed').exists(): print('package:/data/app/ks/base.apk')
        else: sys.exit(1)
    elif args[3:5] == ['dumpsys', 'device_policy']:
        if mode == 'policy-empty': sys.exit(0)
        print('Current Device Policy Manager state:')
        print('  Enabled Device Admins (User 0, provisioningState: 0):')
        if mode not in ('inactive', 'missing', 'admin-no-effect') or (root / 'admin').exists():
            print('    me.jxl.kiosk_satellite/.KioskAdminReceiver:')
    elif args[3:5] == ['am', 'start']:
        if '-n' not in args:
            print('Error: Activity not started, unable to resolve Intent'); sys.exit(0)
        if mode == 'launch-fail': print('Error: Activity not started'); sys.exit(0)
        print('Starting: Intent { cmp=me.jxl.kiosk_satellite/.MainActivity }')
    elif args[3:5] == ['dpm', 'set-active-admin']:
        if mode != 'admin-no-effect': (root / 'admin').touch()
        print('Success: Active admin set')
    sys.exit(0)
if 'install' in args:
    if mode == 'install-fail': print('Failure [INSTALL_FAILED_TEST]'); sys.exit(1)
    if mode != 'install-no-effect': (root / 'installed').touch()
    print('Success'); sys.exit(0)
sys.exit(1)
''' % FINGERPRINT


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        release = self.root / 'tools'
        release.mkdir(parents=True)
        shutil.copy(ROOT / 'tools/provision_portal_ui.py', self.root / 'tools')
        shutil.copy(ROOT / 'tools/portal_targets.py', release)
        (release / 'provision_portal.py').write_text(FAKE)
        subprocess.run(['git', 'init', '-q', str(self.root)], check=True)
        sdk = self.root / 'Android/Sdk'
        compiler = sdk / 'ndk/28.2.13676358/toolchains/llvm/prebuilt/linux-x86_64/bin'
        tools = sdk / 'build-tools/36.0.0'
        mock_bin = self.root / 'bin'
        for directory, names in ((compiler, ('aarch64-linux-android29-clang', 'armv7a-linux-androideabi29-clang')),
                                 (tools, ('d8', 'aapt', 'zipalign', 'apksigner')),
                                 (mock_bin, ('make', 'java', 'javac', 'jar', 'keytool'))):
            directory.mkdir(parents=True)
            for name in names:
                executable = directory / name
                executable.write_text('#!/bin/sh\nexit 0\n')
                executable.chmod(0o755)
        (mock_bin / 'git').symlink_to(shutil.which('git'))
        fake_adb = mock_bin / 'adb'
        fake_adb.write_text(FAKE_ADB)
        fake_adb.chmod(0o755)
        android_jar = sdk / 'platforms/android-36/android.jar'
        android_jar.parent.mkdir(parents=True)
        android_jar.touch()
        self.env = {key: value for key, value in os.environ.items()
                    if key not in ('SDK', 'ANDROID_SDK_ROOT', 'ANDROID_HOME', 'NDK', 'TOOLCHAIN',
                                   'ANDROID_JAR', 'BUILD_TOOLS', 'D8')}
        self.env.update(ANDROID_SDK_ROOT=str(sdk), PATH=str(mock_bin) + os.pathsep + os.environ['PATH'])
        self.command = [sys.executable, str(self.root / 'tools/provision_portal_ui.py'),
                        '--serial', 'test:5555', '--audio', '--attempts', '3',
                        '--log-dir', str(self.root / 'logs')]

    def run_ui(self, mode='ok', extra=(), answer=''):
        return subprocess.run(self.command + list(extra), text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, input=answer,
                              env={**self.env, 'UI_TEST_MODE': mode}, timeout=10)

    def adb_calls(self):
        import json
        return [json.loads(line) for line in (self.root / 'adb-trace').read_text().splitlines()]

    def test_ks_installed_then_launched_and_admin_enabled_before_status(self):
        apk = self.root / 'ks.apk'
        apk.write_bytes(b'test apk')
        self.env['UI_TEST_ADB'] = 'missing'
        result = self.run_ui(extra=['--ks-apk', str(apk)])
        self.assertEqual(result.returncode, 0, result.stdout)
        calls = self.adb_calls()
        install = next(i for i, call in enumerate(calls) if 'install' in call)
        launch = next(i for i, call in enumerate(calls) if 'start' in call)
        admin = next(i for i, call in enumerate(calls) if 'set-active-admin' in call)
        self.assertLess(install, launch)
        self.assertLess(launch, admin)
        self.assertEqual(calls[install][:4], ['-s', 'test:5555', 'install', '--user'])
        self.assertIn('[OK] Kiosk Satellite', result.stdout)
        self.assertLess(result.stdout.index('[OK] Kiosk Satellite'), result.stdout.index('[RUNNING] Read-only preflight'))

    def test_installed_ks_without_admin_recovers_failed_first_launch(self):
        self.env['UI_TEST_ADB'] = 'inactive'
        result = self.run_ui()
        self.assertEqual(result.returncode, 0, result.stdout)
        calls = self.adb_calls()
        launch = next(i for i, call in enumerate(calls) if 'start' in call)
        admin = next(i for i, call in enumerate(calls) if 'set-active-admin' in call)
        self.assertLess(launch, admin)
        self.assertIn('-n', calls[launch])
        self.assertEqual(calls[launch][calls[launch].index('-n') + 1],
                         'me.jxl.kiosk_satellite/.MainActivity')
        self.assertFalse(any('install' in call for call in calls))

    def test_existing_ks_is_not_reinstalled_or_relaunched(self):
        result = self.run_ui()
        self.assertEqual(result.returncode, 0, result.stdout)
        calls = self.adb_calls()
        self.assertTrue(any('device_policy' in call for call in calls))
        self.assertFalse(any('install' in call or 'start' in call or 'set-active-admin' in call for call in calls))

    def test_inactive_admin_is_enabled_and_rechecked(self):
        self.env['UI_TEST_ADB'] = 'inactive'
        result = self.run_ui()
        self.assertEqual(result.returncode, 0, result.stdout)
        calls = self.adb_calls()
        self.assertEqual(sum('device_policy' in call for call in calls), 2)
        self.assertTrue(any('set-active-admin' in call for call in calls))

    def test_admin_command_success_without_policy_change_blocks_status(self):
        self.env['UI_TEST_ADB'] = 'admin-no-effect'
        result = self.run_ui()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'trace').exists())
        self.assertIn('not active', result.stdout)

    def test_omni_or_wrong_fingerprint_exits_before_package_contact(self):
        for mode in ('omni', 'wrong-build'):
            with self.subTest(mode=mode):
                self.env['UI_TEST_ADB'] = mode
                result = self.run_ui()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / 'trace').exists())
                self.assertFalse(any('pm' in call or 'install' in call or 'device_policy' in call for call in self.adb_calls()))

    def test_install_launch_or_policy_failure_blocks_status(self):
        apk = self.root / 'ks.apk'
        apk.write_bytes(b'test apk')
        for mode, expected in (('install-fail', 'INSTALL_FAILED_TEST'),
                               ('install-no-effect', 'not present'),
                               ('launch-fail', 'Cannot open'), ('policy-empty', 'Cannot read')):
            with self.subTest(mode=mode):
                (self.root / 'installed').unlink(missing_ok=True)
                self.env['UI_TEST_ADB'] = mode
                result = self.run_ui(extra=['--ks-apk', str(apk)])
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(expected, result.stdout)
                self.assertFalse((self.root / 'trace').exists())

    def test_interactive_scan_uses_guard_and_read_only_status(self):
        from unittest.mock import patch
        ui = self.load_ui()
        ui.ROOT = self.root
        apk = self.root / 'ks.apk'
        apk.write_bytes(b'test apk')
        with patch.dict(os.environ, {**self.env, 'UI_TEST_ADB': 'missing'}, clear=True), \
             patch.object(ui.termios, 'tcsetattr'), patch.object(ui.tty, 'setraw'):
            screen = ui.ConfigScreen(apk)
            screen.ip = 'test'
            screen.port = '5555'
            self.assertEqual(screen._fetch_and_apply_status(0, [], 0), 0)
            self.assertIn('terry', screen._device_info)
        calls = self.adb_calls()
        self.assertFalse(any('install' in call or 'set-active-admin' in call for call in calls))
        self.assertEqual(len((self.root / 'trace').read_text().splitlines()), 1)

    def test_status_mode_does_not_install_missing_kiosk(self):
        self.env['UI_TEST_ADB'] = 'missing'
        result = self.run_ui(extra=['--status'])
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertFalse(any('install' in call or 'set-active-admin' in call
                             for call in self.adb_calls()))

    def test_backup_only_skips_kiosk_preparation_and_provisioning_phases(self):
        import json
        self.command.remove('--audio')
        self.env['UI_TEST_ADB'] = 'missing'
        for flags in (['--backup', str(self.root / 'backup')],
                      ['--backup=' + str(self.root / 'backup'), '--skip-build']):
            with self.subTest(flags=flags):
                (self.root / 'adb-trace').unlink(missing_ok=True)
                (self.root / 'trace').unlink(missing_ok=True)
                result = self.run_ui('backup-only', extra=flags)
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertFalse(any('install' in call or 'set-active-admin' in call
                                     or 'start' in call for call in self.adb_calls()))
                calls = [json.loads(line) for line in (self.root / 'trace').read_text().splitlines()]
                self.assertEqual(len(calls), 3)
                self.assertIn('--status', calls[0])
                self.assertIn('--status', calls[2])
                for flag in flags:
                    self.assertIn(flag, calls[1])
                self.assertIn('[OK] Backup', result.stdout)
                self.assertNotIn('VERIFIED across two boots', result.stdout)
                self.assertNotIn('First boot verification', result.stdout)
                self.assertNotIn('Second boot verification', result.stdout)

    def test_backup_with_actions_and_other_mutating_modes_prepare_kiosk(self):
        self.command.remove('--audio')
        apk = self.root / 'ks.apk'
        apk.write_bytes(b'test apk')
        for flags in (['--backup', str(self.root / 'backup'), '--audio'],
                      ['--backup=' + str(self.root / 'backup'), '--restore-audio'],
                      ['--backup', str(self.root / 'backup'), '--profile', 'kiosk'],
                      ['--backup=' + str(self.root / 'backup'), '--profile=kiosk'],
                      ['--recover'], []):
            with self.subTest(flags=flags):
                self.env['UI_TEST_ADB'] = 'missing'
                for name in ('adb-trace', 'trace', 'installed', 'admin'):
                    (self.root / name).unlink(missing_ok=True)
                result = self.run_ui(extra=flags + ['--ks-apk', str(apk)], answer='yes\n')
                self.assertEqual(result.returncode, 0, result.stdout)
                calls = self.adb_calls()
                self.assertTrue(any('install' in call for call in calls))
                self.assertTrue(any('set-active-admin' in call for call in calls))

    def test_interactive_scan_exits_on_unsupported_device(self):
        from unittest.mock import patch
        ui = self.load_ui()
        ui.ROOT = self.root
        with patch.dict(os.environ, {**self.env, 'UI_TEST_ADB': 'omni'}, clear=True), \
             patch.object(ui.termios, 'tcsetattr'), patch.object(ui.tty, 'setraw'):
            screen = ui.ConfigScreen()
            screen.ip = 'test'
            with self.assertRaisesRegex(RuntimeError, 'only terry'):
                screen._fetch_and_apply_status(0, [], 0)
        self.assertFalse((self.root / 'trace').exists())
        self.assertFalse(any('install' in call or 'device_policy' in call for call in self.adb_calls()))

    def test_policy_parser_requires_enabled_receiver_for_user_zero(self):
        ui = self.load_ui()
        component = 'me.jxl.kiosk_satellite/.KioskAdminReceiver'
        header = '  Enabled Device Admins (User 0, provisioningState: 0):\n'
        self.assertTrue(ui.active_kiosk_admin(header + '    ' + component + ':\n'))
        self.assertFalse(ui.active_kiosk_admin('Device Owner: admin=' + component))
        self.assertFalse(ui.active_kiosk_admin(header.replace('User 0', 'User 10') + '    ' + component + ':\n'))
        self.assertFalse(ui.active_kiosk_admin(header + '  Other section:\n    ' + component + ':\n'))

    def test_apk_checksum_failure_prevents_installation(self):
        import io
        from unittest.mock import patch
        ui = self.load_ui()
        with patch.object(ui.urllib.request, 'urlopen', return_value=io.BytesIO(b'corrupt')):
            with self.assertRaisesRegex(RuntimeError, 'SHA-256 mismatch'):
                ui.download_kiosk_apk(self.root, ui.Display('test', True, False))
        self.assertFalse((self.root / 'kiosk-satellite.apk').exists())

    def test_dry_run_does_not_install_or_enable_admin(self):
        self.env['UI_TEST_ADB'] = 'missing'
        result = self.run_ui(extra=['--dry-run'])
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertFalse(any('install' in call or 'set-active-admin' in call for call in self.adb_calls()))

    def test_final_summary_uses_post_run_state_and_blank_line(self):
        result = self.run_ui('post-change')
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('\n\nFinal action states', result.stdout)
        summary = result.stdout.split('Final action states')[-1]
        self.assertIn('[APPLIED] Audio fix', summary)
        for label in ('Device owner', 'Kiosk home', 'Disable OTA', 'Debloat',
                      'Remove accounts', 'Optimize presence', 'App updates', 'Private DNS', 'Shizuku'):
            self.assertIn(label, summary)
        self.assertIn('runtime unconfirmed', summary)

    def test_final_scan_failure_or_identity_mismatch_never_uses_preflight(self):
        for mode in ('post-status-fail', 'post-identity'):
            with self.subTest(mode=mode):
                (self.root / 'trace').unlink(missing_ok=True)
                result = self.run_ui(mode)
                self.assertEqual(result.returncode, 0, result.stdout)
                summary = result.stdout.split('Final action states')[-1]
                self.assertIn('[UNKNOWN] Audio fix', summary)
                self.assertIn('Final scan failed', summary)
                self.assertNotIn('[APPLIED] Audio fix', summary)

    def test_failed_run_and_failed_final_scan_preserve_original_exit(self):
        result = self.run_ui('fail-post-status')
        self.assertEqual(result.returncode, 7, result.stdout)
        summary = result.stdout.split('Final action states')[-1]
        self.assertIn('Run: FAILED (exit 7)', summary)
        self.assertIn('unexpected native failure', summary)
        self.assertIn('[UNKNOWN] Audio fix', summary)
        self.assertIn('final ADB unavailable', summary)

    def test_final_summary_retains_failure_and_reports_partial_state(self):
        result = self.run_ui('partial', extra=['--device-owner', '--optimize-presence'], answer='yes\n')
        self.assertEqual(result.returncode, 6, result.stdout)
        summary = result.stdout.split('Final action states')[-1]
        self.assertIn('Run: FAILED', summary)
        self.assertIn('presence pipeline did not pass', summary)
        self.assertIn('[APPLIED] Device owner', summary)
        self.assertIn('[APPLIED] Optimize presence — runtime unconfirmed, likely because the camera shutter was closed', summary)

    def test_unobserved_requested_addition_is_failed_but_dry_run_is_not(self):
        result = self.run_ui('requested-unapplied')
        summary = result.stdout.split('Final action states')[-1]
        self.assertIn('[FAILED] Audio fix', summary)
        self.assertIn('Run: UNCONFIRMED', summary)
        self.assertNotIn('Run: VERIFIED', summary)
        result = self.run_ui('requested-unapplied', extra=['--dry-run'])
        summary = result.stdout.split('Final action states')[-1]
        self.assertIn('[NOT APPLIED] Audio fix', summary)
        self.assertNotIn('[FAILED] Audio fix', summary)

    def test_preflight_precedes_provisioning_and_output_is_hidden(self):
        result = self.run_ui()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('OBSERVED', result.stdout)
        self.assertIn('installation marker', result.stdout)
        self.assertIn('RETRYING', result.stdout)
        self.assertIn('Keep USB connected', result.stdout)
        self.assertIn('Verified across two boots', result.stdout)
        self.assertNotIn('compiler noise', result.stdout)
        self.assertNotIn('\x1b', result.stdout)
        import json
        calls = [json.loads(line) for line in (self.root / 'trace').read_text().splitlines()]
        self.assertEqual(len(calls), 3)
        self.assertIn('--status', calls[0])
        self.assertNotIn('--audio', calls[0])
        self.assertIn('--audio', calls[1])
        self.assertIn('--status', calls[2])
        self.assertNotIn('--audio', calls[2])
        sdk = json.loads((self.root / 'trace.sdk').read_text())
        self.assertEqual(sdk['SDK'], str(self.root / 'Android/Sdk'))
        self.assertEqual(sdk['BUILD_TOOLS'], str(self.root / 'Android/Sdk/build-tools/36.0.0'))
        self.assertEqual(calls[1][calls[1].index('--attempts') + 1], '3')
        directory = Path(calls[1][calls[1].index('--log-dir') + 1])
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual((directory / 'provision.log').stat().st_mode & 0o777, 0o600)
        self.assertIn('compiler noise', (directory / 'provision.log').read_text())

    def test_unknown_failure_preserves_exit_and_shows_reason(self):
        result = self.run_ui('fail')
        self.assertEqual(result.returncode, 7)
        self.assertIn('unexpected native failure', result.stdout)
        self.assertNotIn('Verified across two boots', result.stdout)

    def test_zero_exit_without_marker_is_not_verified(self):
        result = self.run_ui('no-marker')
        self.assertEqual(result.returncode, 0)
        self.assertIn('verification not confirmed', result.stdout)

    def test_late_error_overrides_success_marker(self):
        result = self.run_ui('conflict')
        self.assertEqual(result.returncode, 8)
        self.assertNotIn('Verified across two boots', result.stdout)
        self.assertIn('late failure', result.stdout)

    def test_identity_or_status_failure_never_starts_provisioning(self):
        for mode in ('identity', 'status-fail', 'status-malformed', 'status-serial'):
            with self.subTest(mode=mode):
                (self.root / 'trace').unlink(missing_ok=True)
                result = self.run_ui(mode)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len((self.root / 'trace').read_text().splitlines()), 1)

    def test_explicit_serial_required_before_any_child(self):
        result = subprocess.run(self.command[:2], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.root / 'trace').exists())

    def test_verbose_output(self):
        self.assertIn('compiler noise', self.run_ui(extra=['--ui-verbose']).stdout)

    def test_cancellation_reaches_child_and_releases_lock(self):
        child = subprocess.Popen(self.command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, env={**self.env, 'UI_TEST_MODE': 'signal'})
        self.addCleanup(lambda: child.poll() is None and child.kill())
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            line = child.stdout.readline()
            if '[RUNNING] Apply provisioning' in line:
                break
        else:
            self.fail('child did not start')
        child.send_signal(signal.SIGINT)
        output = child.communicate(timeout=5)[0]
        self.assertEqual(child.returncode, 130, output)
        self.assertEqual((self.root / 'trace.signal').read_text(), 'received')
        self.assertEqual(self.run_ui().returncode, 0)

    def test_device_lock_excludes_second_contact(self):
        import fcntl
        lock = self.root / '.git/portal-device-locks/test_5555.lock'
        lock.parent.mkdir(parents=True)
        with lock.open('w') as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            child = subprocess.Popen(self.command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=self.env)
            try:
                while True:
                    line = child.stdout.readline()
                    if 'Waiting for device lock' in line:
                        break
                    self.assertTrue(line, 'wrapper exited before taking the device lock')
                self.assertFalse((self.root / 'trace').exists())
                fcntl.flock(held, fcntl.LOCK_UN)
                output = child.communicate(timeout=5)[0]
                self.assertEqual(child.returncode, 0, output)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()

    def test_cancellation_during_status_never_provisions(self):
        child = subprocess.Popen(self.command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 text=True, env={**self.env, 'UI_TEST_MODE': 'status-hang'})
        try:
            deadline = time.monotonic() + 5
            while not (self.root / 'trace').exists() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertTrue((self.root / 'trace').exists())
            child.send_signal(signal.SIGINT)
            output = child.communicate(timeout=5)[0]
            self.assertEqual(child.returncode, 130, output)
            self.assertEqual(len((self.root / 'trace').read_text().splitlines()), 1)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()

    def test_live_terminal_redraw_and_plain_override(self):
        import pty
        master, slave = pty.openpty()
        try:
            child = subprocess.Popen(self.command, stdout=slave, stderr=slave, env=self.env)
            os.close(slave)
            slave = None
            chunks = []
            while True:
                try:
                    chunk = os.read(master, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
            self.assertEqual(child.wait(timeout=5), 0)
            self.assertIn(b'\x1b[', b''.join(chunks))
            self.assertIn(b'Verified across two boots', b''.join(chunks))
        finally:
            os.close(master)
            if slave is not None:
                os.close(slave)
        self.assertNotIn('\x1b', self.run_ui(extra=['--ui-plain']).stdout)

    def test_abbreviated_serial_override_is_rejected(self):
        result = self.run_ui(extra=['--seri=another-device'])
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.root / 'trace').exists())

    def test_status_timeout_stops_background_child(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('tested_ui', ROOT / 'tools/provision_portal_ui.py')
        ui = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ui)
        from unittest.mock import patch
        with patch.dict(os.environ, {'UI_TEST_MODE': 'status-hang'}):
            with self.assertRaisesRegex(RuntimeError, 'timed out'):
                ui.run_child([sys.executable, str(self.root / 'tools/provision_portal.py'),
                              '--serial', 'test:5555', '--status'], self.root / 'timeout.log',
                             ui.Display('test', True, False), timeout=0.1)
        self.assertEqual(len((self.root / 'trace').read_text().splitlines()), 1)

    def test_build_failure_marks_prepare_failed_and_later_phases_blocked(self):
        ui = self.load_ui()
        display = ui.Display('test', True, False)
        display.update('Prepare and stage files', 'PENDING')
        display.update('Apply provisioning', 'PENDING')
        display.update('First boot verification', 'PENDING')
        monitor = ui.Monitor(display)
        monitor.feed('PROVISION_ERROR: build failed: make -C /some/path')
        monitor.finish(1, [])
        self.assertEqual(display.rows['Prepare and stage files'][0], 'FAILED')
        self.assertEqual(display.rows['Apply provisioning'][0], 'BLOCKED')
        self.assertEqual(display.rows['First boot verification'][0], 'BLOCKED')

    def load_ui(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location('tested_ui', ROOT / 'tools/provision_portal_ui.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_narrow_terminal_keeps_full_error_in_final_output(self):
        from unittest.mock import patch
        import io
        ui = self.load_ui()
        display = ui.Display('test', False, False)
        display.live = True
        reason = '/a/very/long/build/path/clang not found; complete diagnostic reason'
        output = io.StringIO()
        with patch('sys.stdout', output), patch.object(ui.shutil, 'get_terminal_size',
                                                       return_value=os.terminal_size((35, 12))):
            display.update('Provisioning', 'FAILED', reason)
            display.finish()
        self.assertIn(reason, output.getvalue())
        self.assertLessEqual(display.lines, 11)

    def test_sdk_resolution_honors_overrides(self):
        ui = self.load_ui()
        env = ui.build_environment({'NDK': '/explicit/ndk', 'BUILD_TOOLS': '/explicit/tools'}, self.root)
        self.assertEqual(env['NDK'], '/explicit/ndk')
        self.assertEqual(env['BUILD_TOOLS'], '/explicit/tools')
        self.assertEqual(env['D8'], '/explicit/tools/d8')

    def test_missing_explicit_ndk_stops_before_device_contact(self):
        result = subprocess.run(self.command, text=True, capture_output=True,
                                env={**self.env, 'NDK': str(self.root / 'missing')}, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'trace').exists())
        self.assertIn('Host build tools', result.stdout)

    def test_read_only_or_skip_build_does_not_require_sdk(self):
        for flag in ('--status', '--skip-build'):
            result = subprocess.run(self.command + [flag], text=True, capture_output=True,
                                    env={**self.env, 'NDK': str(self.root / 'missing')}, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout)

    def test_sdk_autodetection_uses_installed_build_tools(self):
        ui = self.load_ui()
        env = ui.build_environment({}, self.root)
        self.assertEqual(env['ANDROID_SDK_ROOT'], str(self.root / 'Android/Sdk'))
        self.assertEqual(env['NDK'], str(self.root / 'Android/Sdk/ndk/28.2.13676358'))
        self.assertEqual(env['BUILD_TOOLS'], str(self.root / 'Android/Sdk/build-tools/36.0.0'))
        self.assertEqual(env['D8'], str(self.root / 'Android/Sdk/build-tools/36.0.0/d8'))

    def test_disabled_adb_stops_before_status_and_has_setup_instructions(self):
        result = subprocess.run(self.command, text=True, capture_output=True,
                                env={**self.env, 'UI_TEST_ADB': 'refused'}, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'trace').exists())
        self.assertIn('Enable ADB', result.stdout)
        self.assertIn('tcpip 5555', result.stdout)
        self.assertNotIn('did not reconnect', result.stdout)

    def test_unauthorized_offline_and_shell_failures_are_explained(self):
        for mode, expected in (('unauthorized', 'authorization'), ('offline', 'offline'),
                               ('shell-fail', 'shell')):
            with self.subTest(mode=mode):
                result = subprocess.run(self.command, text=True, capture_output=True,
                                        env={**self.env, 'UI_TEST_ADB': mode}, timeout=10)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.root / 'trace').exists())
                self.assertIn(expected, result.stdout.lower())

    def test_ready_adb_is_checked_before_status(self):
        result = self.run_ui()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertLess(result.stdout.index('[OK] ADB connection'),
                        result.stdout.index('[RUNNING] Read-only preflight'))
        import json
        calls = [json.loads(line) for line in (self.root / 'adb-trace').read_text().splitlines()]
        self.assertIn(['-s', 'test:5555', 'shell', 'getprop', 'ro.product.device'], calls)
        self.assertIn(['-s', 'test:5555', 'shell', 'getprop', 'ro.build.fingerprint'], calls)
        self.assertFalse(any('tcpip' in call or 'reboot' in call for call in calls))

    def test_missing_host_adb_is_actionable(self):
        (self.root / 'bin/adb').unlink()
        result = subprocess.run(self.command, text=True, capture_output=True,
                                env={**self.env, 'PATH': str(self.root / 'bin')}, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'trace').exists())
        self.assertIn('Install Android Platform Tools', result.stdout)

    def test_adb_probe_timeout_is_bounded_and_actionable(self):
        start = time.monotonic()
        result = subprocess.run(self.command, text=True, capture_output=True,
                                env={**self.env, 'UI_TEST_ADB': 'hang'}, timeout=10)
        self.assertLess(time.monotonic() - start, 8)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'trace').exists())
        self.assertIn('timed out', result.stdout)
        self.assertIn('Enable ADB', result.stdout)

    def test_connection_lost_during_status_has_setup_message(self):
        result = self.run_ui('status-lost')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Enable ADB', result.stdout)
        self.assertIn('ADB became unavailable', result.stdout)
        self.assertNotIn('did not reconnect after 30s', result.stdout)
        self.assertEqual(len((self.root / 'trace').read_text().splitlines()), 1)

    def test_required_sensor_block_precedes_all_device_mutations(self):
        for sensor in ('private', 'muted'):
            with self.subTest(sensor=sensor):
                self.env['UI_TEST_SENSOR'] = sensor
                result = self.run_ui()
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn('Sensor preflight', result.stdout)
                self.assertFalse((self.root / 'trace').exists())
                calls = self.adb_calls()
                self.assertFalse(any('install' in call or 'set-active-admin' in call
                                     or 'start' in call for call in calls))
                (self.root / 'adb-trace').unlink()

    def test_sensor_privacy_does_not_block_read_only_or_unrelated_actions(self):
        self.env['UI_TEST_SENSOR'] = 'private'
        self.command.remove('--audio')
        for flags in (['--status'], ['--dry-run'], ['--disable-camera-light']):
            with self.subTest(flags=flags):
                result = self.run_ui(extra=flags)
                self.assertEqual(result.returncode, 0, result.stdout)

    def test_unreadable_sensor_state_warns_without_claiming_ready(self):
        self.env['UI_TEST_SENSOR'] = 'denied'
        result = self.run_ui()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('Microphone mute state is unreadable', result.stdout)
        self.assertIn('UNCONFIRMED', result.stdout)

    def test_presence_requires_camera_but_not_unmuted_mic(self):
        self.env['UI_TEST_SENSOR'] = 'muted'
        self.command.remove('--audio')
        result = self.run_ui(extra=['--optimize-presence'], answer='yes\n')
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('Camera cover', result.stdout)
        self.assertIn('cannot read', result.stdout)

    def test_camera_confirmation_rejection_and_eof_block_mutations(self):
        for answer in ('no\n', '', '\n'):
            with self.subTest(answer=answer):
                result = self.run_ui(extra=['--optimize-presence'], answer=answer)
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn('Camera cover confirmation required', result.stdout)
                self.assertFalse((self.root / 'trace').exists())
                self.assertFalse(any('install' in call or 'set-active-admin' in call
                                     or 'start' in call for call in self.adb_calls()))
                (self.root / 'adb-trace').unlink()

    def test_camera_confirmation_does_not_override_known_privacy_block(self):
        self.env['UI_TEST_SENSOR'] = 'private'
        result = self.run_ui(extra=['--optimize-presence', '--confirm-camera-open'])
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertIn('sensor privacy is on', result.stdout)
        self.assertFalse((self.root / 'trace').exists())

    def test_explicit_camera_confirmation_is_wrapper_only(self):
        import json
        result = self.run_ui(extra=['--optimize-presence', '--confirm-camera-open'])
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('User confirmed', result.stdout)
        for line in (self.root / 'trace').read_text().splitlines():
            self.assertNotIn('--confirm-camera-open', json.loads(line))



class ConfigScreenTests(unittest.TestCase):
    """PORTAL-BEHAVE-007, PORTAL-BEHAVE-008: ConfigScreen unit tests."""

    def _load_ui(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            '_test_provision_ui', ROOT / 'tools/provision_portal_ui.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_arrow_up_read_key_returns_full_sequence(self):
        """PORTAL-BEHAVE-007: up arrow returns \\x1b[A, not bare ESC."""
        ui = self._load_ui()
        rfd, wfd = os.pipe()
        try:
            os.write(wfd, b'\x1b[A')
            key = ui.ConfigScreen._read_key(rfd)
            self.assertEqual(key, '\x1b[A')
        finally:
            os.close(rfd)
            os.close(wfd)

    def test_arrow_down_read_key_returns_full_sequence(self):
        """PORTAL-BEHAVE-007: down arrow returns \\x1b[B, not bare ESC."""
        ui = self._load_ui()
        rfd, wfd = os.pipe()
        try:
            os.write(wfd, b'\x1b[B')
            key = ui.ConfigScreen._read_key(rfd)
            self.assertEqual(key, '\x1b[B')
        finally:
            os.close(rfd)
            os.close(wfd)

    def test_config_persistence_roundtrip(self):
        """PORTAL-BEHAVE-008: IP/port written by _save_config reload on next init."""
        ui = self._load_ui()
        with tempfile.TemporaryDirectory() as tmpdir:
            orig = ui.ROOT
            ui.ROOT = Path(tmpdir)
            try:
                screen = ui.ConfigScreen()
                screen.ip = '192.168.40.100'
                screen.port = '5555'
                screen._save_config()
                screen2 = ui.ConfigScreen()
                self.assertEqual(screen2.ip, '192.168.40.100')
                self.assertEqual(screen2.port, '5555')
            finally:
                ui.ROOT = orig

    def test_config_missing_file_no_error(self):
        """PORTAL-BEHAVE-008: absent .env.local leaves fields at defaults."""
        ui = self._load_ui()
        with tempfile.TemporaryDirectory() as tmpdir:
            orig = ui.ROOT
            ui.ROOT = Path(tmpdir)
            try:
                screen = ui.ConfigScreen()
                self.assertEqual(screen.ip, '')
                self.assertEqual(screen.port, '5555')
            finally:
                ui.ROOT = orig

    def test_config_malformed_file_no_error(self):
        """PORTAL-BEHAVE-008: malformed .env.local does not crash screen init."""
        ui = self._load_ui()
        with tempfile.TemporaryDirectory() as tmpdir:
            orig = ui.ROOT
            ui.ROOT = Path(tmpdir)
            try:
                (Path(tmpdir) / '.env.local').write_text('not json at all')
                screen = ui.ConfigScreen()
                self.assertEqual(screen.ip, '')
            finally:
                ui.ROOT = orig

    def test_actions_are_not_saved_or_reloaded(self):
        """PORTAL-BEHAVE-008: persist only connection details."""
        ui = self._load_ui()
        with tempfile.TemporaryDirectory() as tmpdir:
            orig = ui.ROOT
            ui.ROOT = Path(tmpdir)
            try:
                screen = ui.ConfigScreen()
                screen.action_state['audio'] = 'add'
                screen.action_state['kiosk_home'] = 'del'
                screen._save_config()
                screen2 = ui.ConfigScreen()
                import json
                self.assertNotIn('actions', json.loads((ui.ROOT / '.env.local').read_text()))
                self.assertEqual(screen2.action_state['audio'], 'skip')
                self.assertEqual(screen2.action_state['kiosk_home'], 'skip')
            finally:
                ui.ROOT = orig

    def test_flags_add_emits_add_flag(self):
        """PORTAL-BEHAVE-009: add state emits the add flag."""
        ui = self._load_ui()
        screen = ui.ConfigScreen()
        for key in screen.action_state:
            screen.action_state[key] = 'skip'
        screen.action_state['audio'] = 'add'
        self.assertIn('--audio', screen._flags())
        self.assertNotIn('--restore-audio', screen._flags())

    def test_flags_del_emits_restore_flag(self):
        """PORTAL-BEHAVE-009: del state emits the restore flag."""
        ui = self._load_ui()
        screen = ui.ConfigScreen()
        for key in screen.action_state:
            screen.action_state[key] = 'skip'
        screen.action_state['audio'] = 'del'
        self.assertIn('--restore-audio', screen._flags())
        self.assertNotIn('--audio', screen._flags())

    def test_flags_del_on_no_restore_flag_action_is_silent(self):
        """PORTAL-BEHAVE-009: del on action with no restore flag emits nothing."""
        ui = self._load_ui()
        screen = ui.ConfigScreen()
        for key in screen.action_state:
            screen.action_state[key] = 'skip'
        screen.action_state['device_owner'] = 'del'
        flags = screen._flags()
        self.assertNotIn('--device-owner', flags)

    def test_presence_completion_probe_uses_live_pipeline_not_marker(self):
        from unittest.mock import patch
        ui = self._load_ui()
        keys = ['enable_cv_background_detector_v2', 'enable_hardware_cropping',
                'enable_liveness_metric', 'enable_color_based_reid', 'enable_face_rec_based_reid_v3']
        status = {'runtime': {'aiservice_pid': '123'},
                  'presence': {'state': 'optimized', 'full_scene_profile': True,
                               'profile_keys_loaded': keys,
                               'analysis_frames_observed': True, 'roi_frames_observed': True}}
        healthy = [(0, 'Active Camera Clients:\nClient Package Name: com.facebook.portal.aiservice', []),
                   (0, 'No operations.\nDefault mode: allow', []),
                   (0, '[ PoseEstimatorManagerMetrics ]\n0 ms - 10 ms: 2\n'
                       '[ AlohaFrameProcessor ]\nframes: 2\n[ AiCameramanController ]', [])]
        for responses, expected in ((healthy, True),
                ([(0, 'Active Camera Clients:', [])] + healthy[1:], False),
                (healthy[:1] + [(1, 'CAMERA: allow', [])] + healthy[2:], None),
                (healthy[:1] + [(0, 'CAMERA: deny', [])] + healthy[2:], False),
                (healthy[:1] + [(0, 'Uid mode: CAMERA: ignore\nCAMERA: allow', [])] + healthy[2:], False),
                (healthy[:2] + [(0, '', [])], False)):
            with self.subTest(responses=responses), tempfile.TemporaryDirectory() as tmp, \
                    patch.object(ui, 'run_child', side_effect=responses):
                ui.observe_presence_runtime('test:5555', status, Path(tmp), ui.Display('test:5555', True, False), {})
                self.assertIs(status['presence']['runtime_ready'], expected)
                self.assertIs(ui.action_states(status)['optimize_presence'], expected)

    def test_presence_fps_accepts_uid1000_without_legacy_adb_key(self):
        from unittest.mock import patch
        ui = self._load_ui()
        status = {'runtime': {'aiservice_pid': '123'}, 'presence': {
            'state': 'optimized', 'full_scene_profile': True,
            'profile_keys_loaded': ['enable_cv_background_detector_v2', 'enable_hardware_cropping',
                                   'enable_liveness_metric', 'enable_color_based_reid',
                                   'enable_face_rec_based_reid_v3'],
            'analysis_frames_observed': True, 'roi_frames_observed': True,
            'analysis_fps_cap_installed': True, 'analysis_fps_cap': 2,
            'analysis_fps_applied_this_boot': 2.0, 'analysis_fps_helper_installed': True}}
        observations = [(0, 'Active Camera Clients:\nClient Package Name: com.facebook.portal.aiservice', []),
                        (0, 'CAMERA: allow', []),
                        (0, '[ PoseEstimatorManagerMetrics ]\n0 ms - 10 ms: 2\n'
                            '[ AlohaFrameProcessor ]\nframes: 2\n[ AiCameramanController ]', [])]
        for host, configured, config_value, key, expected in (
                ('uid1000', True, 2, False, True), ('uid1000', False, 2, True, False),
                ('uid1000', True, 3, True, False), ('loopback_adb', False, None, True, True),
                ('loopback_adb', False, None, False, False), ('unexpected', True, 2, True, False)):
            with self.subTest(host=host, configured=configured, config_value=config_value, key=key), \
                    tempfile.TemporaryDirectory() as tmp, \
                    patch.object(ui, 'run_child', side_effect=observations):
                status['presence'].update(analysis_fps_activation_host=host,
                    analysis_fps_uid1000_configured=configured, analysis_fps_uid1000_value=config_value,
                    analysis_fps_helper_key_authorized=key)
                ui.observe_presence_runtime('test:5555', status, Path(tmp),
                                            ui.Display('test:5555', True, False), {})
                self.assertIs(status['presence']['runtime_ready'], expected)

    def test_presence_probe_drops_stale_ready_on_timeout(self):
        from unittest.mock import patch
        ui = self._load_ui()
        status = {'presence': {'state': 'optimized', 'runtime_ready': True}}
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(ui, 'run_child', side_effect=RuntimeError('timeout')):
            ui.observe_presence_runtime('test:5555', status, Path(tmp),
                                        ui.Display('test:5555', True, False), {})
        self.assertIsNone(status['presence']['runtime_ready'])
        self.assertIsNone(ui.action_states(status)['optimize_presence'])

    def test_presence_keep_requires_confirmed_runtime(self):
        ui = self._load_ui()
        for runtime in (False, None):
            with self.subTest(runtime=runtime):
                status = {'presence': {'state': 'optimized',
                                      'analysis_frames_observed': True,
                                      'roi_frames_observed': True,
                                      'runtime_ready': runtime}}
                states = ui.action_states(status)
                self.assertIsNot(states['optimize_presence'], True)
                screen = ui.ConfigScreen()
                screen._apply_status(states)
                screen._cursor = next(i + 1 for i, row in enumerate(ui._SCREEN_OPTS)
                                      if row[0] == 'optimize_presence')
                row = next(line for line in screen._render_actions('-' * 90) if 'Optimize presence' in line)
                self.assertNotIn('[ keep ]', row)
                screen._toggle_action()
                self.assertIn('--optimize-presence', screen._flags())
        states = ui.action_states({'presence': {'state': 'optimized', 'runtime_ready': True}})
        self.assertIs(states['optimize_presence'], True)

    def test_status_first_run_applied_defaults_to_skip(self):
        """PORTAL-BEHAVE-010: applied action defaults to skip on first run."""
        ui = self._load_ui()
        screen = ui.ConfigScreen()
        screen._apply_status({'audio': True})
        self.assertEqual(screen.action_state['audio'], 'skip')

    def test_status_first_run_not_applied_defaults_to_skip(self):
        """PORTAL-BEHAVE-010: not-applied action defaults to skip on first run."""
        ui = self._load_ui()
        screen = ui.ConfigScreen()
        screen._apply_status({'audio': False})
        self.assertEqual(screen.action_state['audio'], 'skip')

    def test_legacy_saved_actions_are_ignored_and_applied_rows_keep(self):
        import json
        from unittest.mock import patch
        ui = self._load_ui()
        with tempfile.TemporaryDirectory() as temp, patch.object(ui, 'ROOT', Path(temp)):
            (ui.ROOT / '.env.local').write_text(json.dumps({
                'ip': '192.0.2.10', 'port': '5555',
                'actions': {'device_owner': 'add', 'debloat': 'del'},
            }))
            screen = ui.ConfigScreen()
            self.assertEqual(screen.ip, '192.0.2.10')
            self.assertTrue(all(value == 'skip' for value in screen.action_state.values()))
            screen._apply_status({'device_owner': True, 'debloat': True})
            lines = screen._render_actions('---')
            self.assertIn('[ keep ]', next(line for line in lines if 'Device owner' in line))
            self.assertIn('[ keep ]', next(line for line in lines if 'Debloat' in line))
            self.assertEqual(screen._flags(), [])
            screen._save_config()
            self.assertEqual(json.loads((ui.ROOT / '.env.local').read_text()),
                             {'ip': '192.0.2.10', 'port': '5555'})

    def test_status_refresh_clears_choices_and_stale_observations(self):
        ui = self._load_ui()
        screen = ui.ConfigScreen()
        screen.action_state['audio'] = 'add'
        screen.action_state['debloat'] = 'del'
        screen.applied['shizuku'] = True
        screen._apply_status({'audio': True, 'debloat': False})
        self.assertEqual(screen.action_state['audio'], 'skip')
        self.assertEqual(screen.action_state['debloat'], 'skip')
        self.assertIsNone(screen.applied['shizuku'])
        self.assertEqual(screen._flags(), [])
        lines = screen._render_actions('---')
        self.assertIn('[ keep ]', next(line for line in lines if 'Audio fix' in line))
        self.assertIn('[      ]', next(line for line in lines if 'Debloat' in line))
        for label in ('Audio fix', 'Debloat', 'Private DNS', 'Shizuku'):
            row = next(line for line in lines if f'] {label}' in line)
            key, _, _, _, desc = next(option for option in ui._SCREEN_OPTS if option[3] == label)
            tag = '[ keep ]' if screen.applied.get(key) is True else '[      ]'
            self.assertTrue(row.startswith(f'  {tag} {label:<22} {desc}'))
        screen.action_state['shizuku'] = 'add'
        lines = screen._render_actions('---')
        self.assertEqual(next(line for line in lines if '] Shizuku' in line),
                         f'  [  add ] {"Shizuku":<22} install Shizuku helper')

    def test_applied_actions_never_offer_or_emit_add(self):
        ui = self._load_ui()
        screen = ui.ConfigScreen()
        screen._apply_status({key: True for key, *_ in ui._SCREEN_OPTS})
        for index, (key, add, remove, _, _) in enumerate(ui._SCREEN_OPTS, 1):
            if key in ui._VALUE_ACTIONS:
                continue
            with self.subTest(key=key):
                screen._cursor = index
                for expected in (('del', 'skip') if remove else ('skip', 'skip')):
                    screen._toggle_action()
                    self.assertEqual(screen.action_state[key], expected)
                    self.assertNotIn(add, screen._flags())
                    if expected == 'del':
                        self.assertIn(remove, screen._flags())
                screen.action_state[key] = 'add'
                self.assertNotIn(add, screen._flags())
                screen.action_state[key] = 'skip'
        screen._cursor = screen._IDX_KIOSK_ROW
        screen._toggle_action()
        self.assertEqual(screen._flags(), [])

    def test_unapplied_and_unknown_actions_still_offer_add(self):
        ui = self._load_ui()
        screen = ui.ConfigScreen()
        for applied in (False, None):
            screen._apply_status({'audio': applied})
            screen._cursor = 1
            screen._toggle_action()
            self.assertEqual(screen.action_state['audio'], 'add')
            self.assertIn('--audio', screen._flags())
            screen._toggle_action()
            self.assertEqual(screen.action_state['audio'], 'del')
            self.assertEqual(screen._flags(), ['--restore-audio'])

    def test_picker_covers_every_provisioner_option(self):
        import ast
        ui = self._load_ui()
        source = ROOT / 'tools/provision_portal.py'
        options = {arg.value for node in ast.walk(ast.parse(source.read_text()))
                   if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                   and node.func.attr == 'add_argument' for arg in node.args
                   if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                   and arg.value.startswith('--')}
        picker = {flag for _, add, remove, _, _ in ui._SCREEN_OPTS for flag in (add, remove) if flag}
        picker |= {'--dhcp-dns', '--backup'}
        self.assertEqual(options - picker - ui._CLI_ONLY_OPTIONS - {'--serial'}, set())
        self.assertEqual(picker & ui._CLI_ONLY_OPTIONS, set())
        self.assertFalse(hasattr(ui, '_EXTRA_OPTS'))
        labels = {row[3] for row in ui._SCREEN_OPTS}
        for removed in ('DHCP DNS', 'Profile (kiosk)', 'Status only', 'Dry run',
                        'Recover pending run', 'Exploit attempts', 'Use existing build',
                        'Shizuku APK path', 'Log directory'):
            self.assertNotIn(removed, labels)

    def test_camera_light_state_flags_and_build_requirements(self):
        ui = self._load_ui()
        screen = ui.ConfigScreen()
        key = 'disable_camera_light'
        self.assertNotIn(key, ui._KIOSK_OPT_KEYS)
        self.assertIsNone(ui.action_states({})[key])
        self.assertIsNone(ui.action_states({'camera_light': {'state': 'unknown'}})[key])
        for state, expected in (('installed', True), ('restored', False)):
            observed = ui.action_states({'camera_light': {'state': state}})
            self.assertEqual(observed[key], expected)
            screen._apply_status(observed)
            self.assertEqual(screen._flags(), [])
            screen._cursor = 1 + next(i for i, row in enumerate(ui._SCREEN_OPTS) if row[0] == key)
            screen._toggle_action()
            flag = '--restore-camera-light' if expected else '--disable-camera-light'
            self.assertEqual(screen._flags(), [flag])
            self.assertTrue(ui.requires_build(['--kiosk-home', flag]))
            self.assertEqual(ui.requested_additions([flag]), set() if expected else {key})

    def test_picker_value_arguments_and_conflicts(self):
        ui = self._load_ui()
        screen = ui.ConfigScreen()
        screen.action_state['presence_fps_cap'] = 'add'
        screen.values['presence_fps_cap'] = '2'
        screen.action_state['privacy_dns'] = 'add'
        screen.values['privacy_dns'] = 'dns.example.org'
        self.assertEqual(screen._validate_actions(), '')
        self.assertEqual(screen._flags(), ['--privacy-dns', 'dns.example.org', '--presence-fps-cap', '2'])
        screen.values['presence_fps_cap'] = '11'
        self.assertIn('1-10', screen._validate_actions())
        screen.values['presence_fps_cap'] = '2'
        screen.action_state['presence_fps_cap'] = 'skip'

    def test_private_dns_row_cycles_hostname_network_and_restore(self):
        ui = self._load_ui()
        screen = ui.ConfigScreen()
        screen.values['privacy_dns'] = 'dns.example.org'
        screen._cursor = next(i for i, row in enumerate(ui._SCREEN_OPTS, 1) if row[0] == 'privacy_dns')
        seen = []
        for _ in range(4):
            screen._toggle_action()
            seen.append(screen._flags())
        self.assertEqual(seen, [['--privacy-dns', 'dns.example.org'], ['--dhcp-dns'],
                                ['--restore-privacy-dns'], []])
        screen.action_state['privacy_dns'] = 'net'
        self.assertEqual(screen._validate_actions(), '')
        row = next(line for line in screen._render_actions('---') if 'Private DNS' in line)
        self.assertIn('network', row)
        self.assertEqual(ui.requested_additions(['--dhcp-dns']), {'dhcp_dns'})

    def test_unknown_status_can_restore_presence_fps(self):
        ui = self._load_ui()
        screen = ui.ConfigScreen()
        screen._cursor = next(i for i, row in enumerate(ui._SCREEN_OPTS, 1)
                              if row[0] == 'presence_fps_cap')
        screen._toggle_action()
        screen._toggle_action()
        self.assertEqual(screen._flags(), ['--restore-presence-fps'])


    def test_value_actions_can_reconfigure_applied_settings(self):
        ui = self._load_ui()
        screen = ui.ConfigScreen()
        screen._apply_status({'presence_fps_cap': True, 'privacy_dns': True})
        screen.values['presence_fps_cap'] = '3'
        screen.action_state['presence_fps_cap'] = 'add'
        self.assertEqual(screen._flags(), ['--presence-fps-cap', '3'])

    def test_backup_switch_and_cli_run_modes(self):
        ui = self._load_ui()
        screen = ui.ConfigScreen()
        self.assertIn('Select', screen._validate_actions())
        screen._cursor = screen._N_ACTIONS - 1
        screen._toggle_action()
        self.assertEqual(screen._flags(), ['--backup', str(ui.ROOT / 'data/backups')])
        self.assertEqual(screen._validate_actions(), '')
        row = next(line for line in screen._render_actions('---') if 'Backup' in line)
        self.assertIn('[  add ]', row)
        screen._toggle_action()
        self.assertEqual(screen._flags(), [])
        screen._editing = None
        for cli in (['--status'], ['--recover'], ['--profile', 'kiosk'], ['--backup', '/x']):
            with self.subTest(cli=cli):
                self.assertEqual(ui.ConfigScreen(cli_flags=cli)._validate_actions(), '')
        self.assertIn('Select', ui.ConfigScreen(cli_flags=['--attempts', '3'])._validate_actions())

    def test_short_terminal_keeps_last_setting_visible(self):
        import shutil
        from unittest.mock import patch
        ui = self._load_ui()
        screen = ui.ConfigScreen()
        screen._cursor = screen._N_ACTIONS - 1
        with patch.object(ui.shutil, 'get_terminal_size', return_value=shutil.os.terminal_size((80, 20))):
            lines = screen._render_actions('---')
        self.assertLessEqual(len(lines), 20)
        self.assertTrue(any(line.startswith('> ') and 'Backup' in line for line in lines))

    def test_real_terminal_keyboard_selects_and_edits_fps(self):
        """Real PTY exercises raw input, scrolling, editing and submitted argv."""
        import pty
        import select
        import json
        import time
        ui_path = ROOT / 'tools/provision_portal_ui.py'
        ui = self._load_ui()
        fps_row = 1 + next(i for i, row in enumerate(ui._SCREEN_OPTS)
                           if row[0] == 'presence_fps_cap')
        with tempfile.TemporaryDirectory() as temp:
            driver = ("import importlib.util, pathlib, json\n"
                      f"spec=importlib.util.spec_from_file_location('ui', {str(ui_path)!r})\n"
                      "ui=importlib.util.module_from_spec(spec); spec.loader.exec_module(ui)\n"
                      f"ui.ROOT=pathlib.Path({temp!r})\n"
                      "screen=ui.ConfigScreen()\n"
                      "screen._fetch_and_apply_status=lambda *args: 0\n"
                      "print('SUBMITTED=' + json.dumps(screen.run()), flush=True)\n")
            master, slave = pty.openpty()
            child = subprocess.Popen([sys.executable, '-c', driver], stdin=slave, stdout=slave, stderr=slave)
            os.close(slave)
            output = b''
            try:
                deadline = time.monotonic() + 5
                while b'IP address' not in output and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.1)[0]:
                        output += os.read(master, 65536)
                self.assertIn(b'IP address', output)
                # Target, submit discovery, navigate to FPS, select, edit, run.
                os.write(master, b'192.0.2.10\r' + b'\x1b[B' * fps_row + b' e2\r\r')
                while child.poll() is None and time.monotonic() < deadline:
                    if select.select([master], [], [], 0.1)[0]:
                        try:
                            output += os.read(master, 65536)
                        except OSError:
                            break
                child.wait(timeout=2)
                while select.select([master], [], [], 0)[0]:
                    try:
                        output += os.read(master, 65536)
                    except OSError:
                        break
                decoded = output.decode(errors='replace')
                self.assertEqual(child.returncode, 0, decoded)
                result = decoded.split('SUBMITTED=', 1)[1].splitlines()[0]
                self.assertEqual(json.loads(result), ['192.0.2.10:5555', ['--presence-fps-cap', '2']])
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()
                os.close(master)

    def test_sensor_requirements_match_selected_actions(self):
        ui = self._load_ui()
        for options, needed in (([], {'microphone'}),
                                (['--audio'], {'microphone'}),
                                (['--optimize-presence'], {'camera'}),
                                (['--presence-fps-cap', '2'], {'camera'}),
                                (['--restore-presence-fps'], {'camera'}),
                                (['--profile', 'kiosk'], {'camera', 'microphone'}),
                                (['--profile=kiosk'], {'camera', 'microphone'}),
                                (['--recover'], {'camera', 'microphone'}),
                                (['--audio', '--dry-run'], set()),
                                (['--audio', '--status'], set()),
                                (['--disable-camera-light'], set())):
            with self.subTest(options=options):
                self.assertEqual(ui.required_sensors(options), needed)

    def test_sensor_parcel_decoding_rejects_errors_and_unknown_shapes(self):
        ui = self._load_ui()
        self.assertIs(ui.sensor_parcel_bool(0, "Result: Parcel(00000000 00000001 '........')", java=True), True)
        self.assertIs(ui.sensor_parcel_bool(0, "Result: Parcel(00000000 '....')", java=False), False)
        for code, output in ((1, "Result: Parcel(00000000 00000000 '........')"),
                             (0, "Result: Parcel(ffffffff 00000000 '........')"),
                             (0, 'Permission denied'), (0, ''),
                             (0, "Result: Parcel(00000000 00000002 '........')")):
            self.assertIsNone(ui.sensor_parcel_bool(code, output, java=True))
