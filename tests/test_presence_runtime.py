"""Host regressions for presence runtime observations; no device contact."""
import contextlib
import io
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'tools'))
import provision_portal as provision


class PresenceRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.tool = provision.PortalProvisioner(
            '192.0.2.1:5555', attempts=1, log_dir=pathlib.Path(self.temp.name))
        self.appop = 'CAMERA: allow; time=+1s ago'
        self.appop_code = 0
        self.camera_active = True
        self.frames = True
        self.no_users = False
        self.tool.adb_run = Mock(side_effect=self.adb_observation)

    def adb_observation(self, args, **kwargs):
        code = 0
        if args[1:2] == ['pidof']:
            output = '123'
        elif args[1:3] == ['dumpsys', 'media.camera']:
            output = 'Number of camera devices: 2\nActive Camera Clients:\n'
            if self.camera_active:
                output += 'Client Package Name: com.facebook.portal.aiservice\n'
        elif args[1:3] == ['cmd', 'appops']:
            output = self.appop
            code = self.appop_code
        elif args[1:2] == ['logcat']:
            output = ('\n'.join((provision.PRESENCE_ANALYSIS_FRAME_MARKER,
                                 provision.PRESENCE_ROI_FRAME_MARKER))
                      if self.frames else '')
            if self.no_users:
                output += '\nCAMERA_SERVICE not running, but no users found yet'
        elif args[1:3] == ['dumpsys', 'activity']:
            output = ('[ PoseEstimatorManagerMetrics ]\n0 ms - 10 ms: 2\n'
                      '[ AlohaFrameProcessor ]\nframes: 2\n[ AiCameramanController ]')
        elif args[1:2] == ['ps']:
            output = '123 camera-worker'
        else:
            raise AssertionError(f'unexpected ADB command: {args}')
        return subprocess.CompletedProcess(args, code, output, '')

    def verify(self):
        with patch.object(provision.time, 'monotonic', side_effect=[0, 0, 200]), \
                patch.object(provision.time, 'sleep'), \
                contextlib.redirect_stdout(io.StringIO()) as output:
            self.tool.verify_presence_runtime(require_profile=False)
        return output.getvalue()

    def test_explicit_allow_accepts_healthy_pipeline(self):
        self.assertIn('PRESENCE_RUNTIME_OK', self.verify())

    def test_default_allow_accepts_healthy_pipeline(self):
        self.appop = 'No operations.\nDefault mode: allow\n'
        self.assertIn('PRESENCE_RUNTIME_OK', self.verify())

    def test_denied_unknown_or_failed_appops_never_pass(self):
        cases = (
            ('CAMERA: ignore', 0),
            ('CAMERA: deny\nDefault mode: allow', 0),
            ('CAMERA: foreground', 0),
            ('Uid mode: CAMERA: ignore\nCAMERA: allow', 0),
            ('No operations.\nDefault mode: ignore', 0),
            ('No operations.', 0),
            ('', 0),
            ('unrelated output Default mode: allow', 0),
            ('CAMERA: allow', 1),
            ('No operations.\nDefault mode: allow', 1),
        )
        for self.appop, self.appop_code in cases:
            with self.subTest(appop=self.appop, code=self.appop_code):
                with self.assertRaisesRegex(provision.ProvisionError, 'camera_allowed=0'):
                    self.verify()

    def test_default_allow_does_not_bypass_inactive_camera(self):
        self.appop = 'No operations.\nDefault mode: allow'
        self.camera_active = False
        with self.assertRaisesRegex(provision.ProvisionError,
                                    'camera_active=0 camera_allowed=1'):
            self.verify()

    def test_idle_no_users_failure_identifies_startup_condition(self):
        self.appop = 'No operations.\nDefault mode: allow'
        self.camera_active = False
        self.no_users = True
        with self.assertRaisesRegex(provision.ProvisionError,
                                    'AIService logs report no users'):
            self.verify()

    def test_default_allow_does_not_bypass_missing_frames(self):
        self.appop = 'No operations.\nDefault mode: allow'
        self.frames = False
        with self.assertRaisesRegex(provision.ProvisionError, 'analysis_frames=0'):
            self.verify()


if __name__ == '__main__':
    unittest.main()
