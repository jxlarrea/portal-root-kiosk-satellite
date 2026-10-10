"""Host-only checks for the portable terminal UI; no real ADB contact."""
import argparse
import ast
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load_ui():
    spec = importlib.util.spec_from_file_location('portable_ui', ROOT / 'tools/provision_portal_ui.py')
    ui = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ui)
    return ui


def provisioner_parser():
    # Execute only the real argparse declarations, never the provisioner body.
    tree = ast.parse((ROOT / 'tools/provision_portal.py').read_text())
    main = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'parse_args')
    declarations = []
    for node in main.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'args' for t in node.targets):
            break
        declarations.append(node)
    import pathlib
    namespace = {'argparse': argparse, 'pathlib': pathlib, 'SHIZUKU_VERSION': 'test'}
    exec(compile(ast.Module(body=declarations, type_ignores=[]), '<provisioner-parser>', 'exec'), namespace)
    return namespace['parser']


class PortableUITests(unittest.TestCase):
    def test_every_picker_flag_is_accepted_by_real_parser(self):
        ui = load_ui()
        parser = provisioner_parser()
        for key, add, remove, _, _ in ui._SCREEN_OPTS:
            for flag in (add, remove):
                if not flag:
                    continue
                with self.subTest(flag=flag):
                    screen = ui.ConfigScreen()
                    screen.action_state[key] = 'add' if flag == add else 'del'
                    screen.values.update(privacy_dns='dns.example.org', presence_fps_cap='2')
                    args = parser.parse_args(['--serial', 'test:5555', *screen._flags()])
                    self.assertEqual(args.serial, 'test:5555')
        declared = set(parser._option_string_actions) - {'-h', '--help'}
        picker = {f for _, add, remove, _, _ in ui._SCREEN_OPTS for f in (add, remove) if f}
        picker |= {'--backup', '--dhcp-dns'}
        self.assertEqual(declared, picker | ui._CLI_ONLY_OPTIONS | {'--serial'})

    def test_run_modes_match_real_provisioner_semantics(self):
        ui = load_ui()
        tree = ast.parse((ROOT / 'tools/provision_portal.py').read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'parse_args')
        import pathlib
        namespace = {'argparse': argparse, 'pathlib': pathlib, 'SHIZUKU_VERSION': 'test'}
        exec(compile(ast.Module(body=[function], type_ignores=[]), '<real-parse-args>', 'exec'), namespace)
        for options in ([], ['--status'], ['--dry-run'], ['--recover'],
                        ['--backup', '/tmp/test-backup'], ['--backup=/tmp/test-backup', '--attempts=3'],
                        ['--backup=/tmp/test-backup', '--profile=kiosk'],
                        ['--backup', '/tmp/test-backup', '--restore-audio']):
            with self.subTest(options=options), patch.object(sys, 'argv', ['provisioner', *options]):
                parsed = namespace['parse_args']()
                self.assertEqual(ui.read_only_run(options), bool(parsed.status or parsed.dry_run or parsed.backup_only))

    def test_standalone_sibling_provisioner_runs(self):
        ui = load_ui()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'tools').mkdir()
            (root / 'tools/provision_portal.py').write_text('# fake sibling')
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            with patch.object(ui, 'ROOT', root), patch.object(ui, 'scan_status', return_value={}), \
                    patch.object(ui, 'final_status', return_value={}), \
                    patch.object(ui, 'run_child', return_value=(0, '', [])) as child:
                self.assertEqual(ui.main(['--serial', 'test:5555', '--status', '--ui-plain']), 0)
                self.assertEqual(Path(child.call_args.args[0][2]), root / 'tools/provision_portal.py')

    def test_backup_is_private_release_data(self):
        ui = load_ui()
        screen = ui.ConfigScreen()
        screen.backup = True
        self.assertEqual(screen._flags(), ['--backup', str(ROOT / 'data/backups')])

    def test_submodule_uses_outer_device_lock(self):
        ui = load_ui()
        # A real local submodule supplies Git's superproject identity.
        with tempfile.TemporaryDirectory() as temp:
            source, outer = Path(temp) / 'source', Path(temp) / 'outer'
            for repo in (source, outer):
                subprocess.run(['git', 'init', '-q', str(repo)], check=True)
            (source / 'placeholder').write_text('fixture')
            subprocess.run(['git', '-C', str(source), '-c', 'user.name=Test', '-c',
                            'user.email=test@example.org', 'add', 'placeholder'], check=True)
            subprocess.run(['git', '-C', str(source), '-c', 'user.name=Test', '-c',
                            'user.email=test@example.org', 'commit', '-qm', 'fixture'], check=True)
            subprocess.run(['git', '-C', str(outer), '-c', 'protocol.file.allow=always',
                            'submodule', 'add', '-q', str(source), 'release'], check=True)
            with patch.object(ui, 'ROOT', outer / 'release'):
                with ui.device_lock('test:5555', ui.Display('test:5555', True, False)):
                    self.assertTrue((outer / '.git/portal-device-locks/test_5555.lock').is_file())


if __name__ == '__main__':
    unittest.main()
