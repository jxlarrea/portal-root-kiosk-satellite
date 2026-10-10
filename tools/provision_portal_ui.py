#!/usr/bin/env python3
"""Terminal monitor and interactive picker for the sibling Portal provisioner."""
from __future__ import annotations

import argparse
from collections import deque
from contextlib import contextmanager
import hashlib
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import selectors
import signal
import shutil
import subprocess
import sys
import tempfile
import termios
import textwrap
import time
import tty
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
KIOSK_PACKAGE = 'me.jxl.kiosk_satellite'
KIOSK_ADMIN = KIOSK_PACKAGE + '/.KioskAdminReceiver'
KIOSK_APK_URL = ('https://github.com/jxlarrea/kiosk-satellite/releases/download/'
                 '2026.10.18/kiosk-satellite-2026.10.18.apk')
KIOSK_APK_SHA256 = '0940808cff38ea6bd3af72ec761b190366e61102ee70afd5880502db38fd06ba'
ANSI = re.compile(r'\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07]*(?:\x07|\x1b\\)')


def clean(text: str) -> str:
    text = ANSI.sub('', text)
    return ''.join(c for c in text if c.isprintable() or c == '\t')[:1000]


class Cancelled(BaseException):
    def __init__(self, signum: int):
        self.signum = signum


# ---------------------------------------------------------------------------
# Interactive configuration screen
# ---------------------------------------------------------------------------

# (key, add_flag, del_flag_or_None, label, desc)
_SCREEN_OPTS: list[tuple[str, str, str | None, str, str]] = [
    ('audio',                '--audio',                '--restore-audio',            'Audio fix',         'disable echo cancel / noise suppress'),
    ('device_owner',         '--device-owner',         None,                         'Device owner',      'set MDM device owner policy'),
    ('kiosk_home',           '--kiosk-home',           '--restore-kiosk-home',       'Kiosk home',        'set kiosk app as launcher'),
    ('disable_updates',      '--disable-updates',      '--enable-updates',           'Disable OTA',       'block firmware updates'),
    ('debloat',              '--debloat',              '--restore-bloat',            'Debloat',           'remove Meta bloatware'),
    ('remove_meta_accounts', '--remove-meta-accounts', None,                         'Remove accounts',   'remove Meta accounts'),
    ('optimize_presence',    '--optimize-presence',    '--restore-presence-profile', 'Optimize presence', 'tune presence detection'),
    ('allow_app_updates',    '--allow-app-updates',    '--restore-app-verifier',     'App updates',       'configure app update verifier'),
    ('privacy_dns',          '--privacy-dns',          '--restore-privacy-dns',      'Private DNS',       'set custom Private DNS'),
    ('shizuku',              '--shizuku',              '--remove-shizuku',           'Shizuku',           'install Shizuku helper'),
    ('disable_camera_light', '--disable-camera-light', '--restore-camera-light',    'Camera indicator',  'turn off green camera-use light'),
]
_SCREEN_OPTS += [
    ('presence_fps_cap', '--presence-fps-cap', '--restore-presence-fps', 'Presence FPS cap', 'cap analysis only (1-10 FPS)'),
]
_VALUE_ACTIONS = {'privacy_dns', 'presence_fps_cap'}
# Run modes and tuning are not device state; they stay on the command line and
# pass through unchanged. --log-dir is consumed by this wrapper.
_CLI_ONLY_OPTIONS = frozenset({'--profile', '--status', '--dry-run', '--recover', '--attempts',
                               '--skip-build', '--shizuku-apk', '--log-dir'})
# Command-line options that make an empty picker selection a valid run.
_CLI_SELECTORS = frozenset({'--profile', '--status', '--dry-run', '--recover', '--backup'})
_KIOSK_OPT_KEYS: frozenset[str] = frozenset({
    'audio', 'device_owner', 'kiosk_home', 'disable_updates',
    'debloat', 'remove_meta_accounts', 'optimize_presence', 'allow_app_updates',
})


class ConfigScreen:
    """Two-phase ANSI form: (1) IP/port entry, (2) status-aware action picker."""

    _IDX_IP = 0
    _IDX_PORT = 1
    # Actions phase: index 0 = kiosk preset row, 1..N = individual action rows
    _IDX_KIOSK_ROW = 0
    # Last row: backup switch
    _N_ACTIONS = 1 + len(_SCREEN_OPTS) + 1

    def __init__(self, ks_apk: Path | None = None, dry_run: bool = False,
                 cli_flags: list[str] | None = None) -> None:
        self.ks_apk = ks_apk
        self.dry_run = dry_run
        self.cli_flags = {flag.split('=')[0] for flag in cli_flags or []}
        self.values = {'privacy_dns': '', 'presence_fps_cap': ''}
        self.backup = False
        self._editing = None
        self.ip = ''
        self.port = '5555'
        self.action_state: dict[str, str] = {k: 'skip' for k, *_ in _SCREEN_OPTS}
        self.applied: dict[str, bool | None] = {k: None for k, *_ in _SCREEN_OPTS}
        self._cursor = 0
        self._phase = 'ip_port'
        self._device_info = ''
        self._load_config()

    def _load_config(self) -> None:
        try:
            data = json.loads((ROOT / '.env.local').read_text())
            if isinstance(data.get('ip'), str):
                self.ip = data['ip']
            if isinstance(data.get('port'), str):
                self.port = data['port']
        except (OSError, json.JSONDecodeError, ValueError):
            pass

    def _save_config(self) -> None:
        try:
            (ROOT / '.env.local').write_text(json.dumps({
                'ip': self.ip.strip(),
                'port': self.port.strip() or '5555',
            }))
        except OSError:
            pass

    def _serial(self) -> str:
        port = self.port.strip() or '5555'
        return f'{self.ip.strip()}:{port}'

    def _flags(self) -> list[str]:
        flags = []
        for key, add_flag, del_flag, _, _ in _SCREEN_OPTS:
            state = self.action_state.get(key, 'skip')
            if state == 'add' and (key in _VALUE_ACTIONS or self.applied.get(key) is not True):
                flags.append(add_flag)
                if key in _VALUE_ACTIONS:
                    flags.append(self.values[key])
            elif state == 'net':
                flags.append('--dhcp-dns')
            elif state == 'del' and del_flag:
                flags.append(del_flag)
        if self.backup:
            flags += ['--backup', str(ROOT / 'data/backups')]
        return flags

    def _apply_status(self, applied: dict[str, bool | None]) -> None:
        """Start each scan with current observations and no selected actions."""
        self.applied = {key: applied.get(key) for key in self.applied}
        self.action_state = {key: 'skip' for key in self.action_state}

    def _validate_ip_port(self) -> str:
        if not self.ip.strip():
            return 'IP address is required'
        port = self.port.strip()
        if port and not port.isdigit():
            return 'Port must be a number'
        if port and not (1 <= int(port) <= 65535):
            return 'Port must be 1-65535'
        return ''

    def _validate_actions(self) -> str:
        if not self._flags() and not self.cli_flags & _CLI_SELECTORS:
            return 'Select at least one action'
        for key in _VALUE_ACTIONS:
            if self.action_state[key] == 'add':
                value = self.values[key]
                if key == 'presence_fps_cap' and (not value.isdigit() or not 1 <= int(value) <= 10):
                    return 'Presence FPS must be 1-10'
                if key == 'privacy_dns' and (not value or not re.fullmatch(r'[A-Za-z0-9.-]+', value)):
                    return 'Private DNS requires a hostname'
        flags = set(self._flags())
        if len(flags & {'--optimize-presence', '--restore-presence-profile', '--restore-presence-fps'}) > 1:
            return 'Select only one presence profile action'
        if '--presence-fps-cap' in flags and flags & {'--restore-presence-profile', '--restore-presence-fps'}:
            return 'FPS cap conflicts with presence restoration'
        return ''

    def _render_lines(self) -> list[str]:
        size = shutil.get_terminal_size()
        sep = '-' * min(size.columns - 1, 60)
        if self._phase == 'ip_port':
            return self._render_ip_port(sep)
        return self._render_actions(sep)

    def _render_ip_port(self, sep: str) -> list[str]:
        c = self._cursor
        ip_display = self.ip + '_' if c == self._IDX_IP else (self.ip or '(enter address)')
        port_display = self.port + '_' if c == self._IDX_PORT else (self.port or '5555')
        err = self._validate_ip_port()
        hint = f'  {err}' if err else '  up/down navigate  enter: check device  q/esc cancel'
        return [
            'Portal Provisioner - Configuration',
            sep,
            '',
            'Target device',
            ('> ' if c == self._IDX_IP   else '  ') + f'IP address  {ip_display}',
            ('> ' if c == self._IDX_PORT else '  ') + f'Port        {port_display}',
            '',
            sep,
            hint,
        ]

    def _render_actions(self, sep: str) -> list[str]:
        c = self._cursor
        info = self._device_info[:72] if self._device_info else '(device status unknown)'
        lines = [
            f'Portal Provisioner - {self._serial()}',
            info,
            sep,
            '',
            'Provisioning actions',
        ]
        lines.append(('> ' if c == self._IDX_KIOSK_ROW else '  ') +
                     f'Kiosk preset  — space: set all unapplied kiosk actions to add')
        lines.append(f'    selects the eight standard kiosk actions')
        lines.append('')
        lines.append('  or individually:')
        for i, (key, _, del_flag, label, desc) in enumerate(_SCREEN_OPTS):
            idx = i + 1
            state = self.action_state.get(key, 'skip')
            applied = self.applied.get(key)
            if state == 'add':
                state_tag = '[  add ]'
            elif state == 'net':
                state_tag = '[ DHCP ]'
                desc = 'use network (DHCP) DNS servers'
            elif state == 'del':
                state_tag = '[remove]'
            elif applied is True:
                state_tag = '[ keep ]'
            else:
                state_tag = '[      ]'
            lines.append(('> ' if c == idx else '  ') +
                         f'{state_tag} {label:<22} {desc}' +
                         (f'  value: {self.values[key] or "(press e to edit)"}'
                          if key in _VALUE_ACTIONS and state != 'net' else ''))
        lines.append(f'  {"[  add ]" if self.backup else "[      ]"} {"Backup first":<22} '
                     'archive to data/backups/')
        # Keep the selected row visible without overflowing a small terminal.
        start = 9
        rows = lines[start:]
        visible = max(1, shutil.get_terminal_size().lines - 14 - bool(self._editing))
        offset = min(max(0, c - visible + 1), max(0, len(rows) - visible))
        if c > len(_SCREEN_OPTS):
            rows[c - 1] = '> ' + rows[c - 1][2:]
        lines = lines[:start] + rows[offset:offset + visible]
        lines.append(f'  rows {offset + 1}-{min(offset + visible, len(rows))}/{len(rows)}')
        lines.append('')
        lines.append(sep)
        err = self._validate_actions()
        if self._editing:
            lines.append(f'  Editing {self._editing}: {self.values[self._editing]}_ (enter finishes)')
        lines.append(f'  {err}' if err else
                     '  up/down  space cycle  e edit value  enter run  b back  q cancel')
        width = max(1, shutil.get_terminal_size().columns - 1)
        return [line[:width] for line in lines]

    def _redraw(self, prev_count: int) -> int:
        lines = self._render_lines()
        out = ''
        if prev_count:
            out += f'\x1b[{prev_count}A\r\x1b[J'
        out += '\r\n'.join(lines) + '\r\n'
        sys.stdout.write(out)
        sys.stdout.flush()
        return len(lines)

    @staticmethod
    def _read_key(fd: int) -> str:
        ch = os.read(fd, 1).decode('utf-8', errors='replace')
        if ch == '\x1b':
            ready, _, _ = select.select([fd], [], [], 0.05)
            if ready:
                ch2 = os.read(fd, 1).decode('utf-8', errors='replace')
                if ch2 == '[':
                    ready2, _, _ = select.select([fd], [], [], 0.05)
                    if ready2:
                        ch3 = os.read(fd, 1).decode('utf-8', errors='replace')
                        return '\x1b[' + ch3
            return '\x1b'
        return ch

    def _toggle_action(self) -> None:
        if self._cursor == self._IDX_KIOSK_ROW:
            for key in _KIOSK_OPT_KEYS:
                if self.applied.get(key) is not True:
                    self.action_state[key] = 'add'
            return
        if self._cursor > len(_SCREEN_OPTS):
            self.backup = not self.backup
            return
        key, _, del_flag, _, _ = _SCREEN_OPTS[self._cursor - 1]
        current = self.action_state.get(key, 'skip')
        applied = self.applied.get(key)
        if key == 'privacy_dns':
            cycle = ('skip', 'add', 'net', 'del')
        elif key in _VALUE_ACTIONS:
            cycle = ('skip', 'add', 'del')
        elif applied is True and del_flag:
            cycle = ('skip', 'del')
        elif applied is True:
            cycle = ('skip',)
        else:
            cycle = ('skip', 'add', 'del') if del_flag else ('skip', 'add')
        idx = cycle.index(current) if current in cycle else 0
        self.action_state[key] = cycle[(idx + 1) % len(cycle)]

    def _type(self, ch: str) -> None:
        if self._cursor == self._IDX_IP:
            self.ip += ch
        elif self._cursor == self._IDX_PORT:
            self.port += ch

    def _backspace(self) -> None:
        if self._cursor == self._IDX_IP:
            self.ip = self.ip[:-1]
        elif self._cursor == self._IDX_PORT:
            self.port = self.port[:-1]

    def _fetch_and_apply_status(self, fd: int, old_settings, prev_count: int) -> int:
        """Restore termios, run --status, re-enter raw. Returns new prev_count."""
        serial = self._serial()
        provisioner = ROOT / 'tools/provision_portal.py'
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        if prev_count:
            sys.stdout.write(f'\x1b[{prev_count}A\r\x1b[J')
        sys.stdout.write(f'Checking {serial}...\r\n')
        sys.stdout.flush()
        release = provisioner.parents[1]
        if not provisioner.is_file():
            raise RuntimeError('Sibling tools/provision_portal.py missing; use a complete release checkout')
        ui = Display(serial, True, False)
        old_handlers = {}
        def cancel(signum, frame):
            raise Cancelled(signum)
        for signum in (signal.SIGINT, signal.SIGTERM):
            old_handlers[signum] = signal.signal(signum, cancel)
        try:
            with device_lock(serial, ui):
                directory = Path(tempfile.mkdtemp(prefix='portal-ui-'))
                os.chmod(directory, 0o700)
                ui.update('Diagnostics', 'INFO', str(directory))
                status_dict = scan_status(serial, release, directory, ui,
                                          build_environment(dict(os.environ)),
                                          self.ks_apk, prepare=False)
        finally:
            ui.finish()
            for signum, handler in old_handlers.items():
                signal.signal(signum, handler)
        if status_dict is not None:
            target = status_dict.get('target', {})
            self._device_info = f"{target.get('device', '')} | {target.get('fingerprint', '')}"
            self._apply_status(action_states(status_dict))
        tty.setraw(fd)
        return 0

    def run(self) -> tuple[str, list[str]] | None:
        """Return (serial, provisioner_flags) or None if cancelled."""
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            return None
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        prev_count = 0
        try:
            tty.setraw(fd)
            while True:
                prev_count = self._redraw(prev_count)
                key = self._read_key(fd)
                if self._editing is not None:
                    field = self._editing
                    if key in ('\r', '\x1b'):
                        self._editing = None
                    elif key == '\x7f':
                        self.values[field] = self.values[field][:-1]
                    elif key.isprintable():
                        self.values[field] += key
                    elif key in ('\x03', '\x04'):
                        return None
                    continue
                if key in ('\x03', '\x04', 'q'):
                    return None
                if self._phase == 'ip_port':
                    if key == '\x1b':
                        return None
                    elif key == '\x1b[A':
                        self._cursor = (self._cursor - 1) % 2
                    elif key in ('\x1b[B', '\t'):
                        self._cursor = (self._cursor + 1) % 2
                    elif key == '\r':
                        if not self._validate_ip_port():
                            prev_count = self._fetch_and_apply_status(
                                fd, old_settings, prev_count)
                            self._phase = 'actions'
                            self._cursor = 0
                    elif key == '\x7f':
                        self._backspace()
                    elif key.isprintable() and self._cursor in (self._IDX_IP, self._IDX_PORT):
                        self._type(key)
                else:  # actions phase
                    if key in ('\x1b', 'b', 'B'):
                        self._phase = 'ip_port'
                        self._cursor = 0
                    elif key == '\x1b[A':
                        self._cursor = (self._cursor - 1) % self._N_ACTIONS
                    elif key in ('\x1b[B', '\t'):
                        self._cursor = (self._cursor + 1) % self._N_ACTIONS
                    elif key == ' ':
                        self._toggle_action()
                    elif key == 'e':
                        if 1 <= self._cursor <= len(_SCREEN_OPTS):
                            field = _SCREEN_OPTS[self._cursor - 1][0]
                            if field in _VALUE_ACTIONS:
                                self._editing = field
                    elif key == '\r':
                        if not self._validate_actions():
                            self._save_config()
                            return self._serial(), self._flags()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            if prev_count:
                sys.stdout.write(f'\x1b[{prev_count}A\r\x1b[J')
                sys.stdout.flush()


# ---------------------------------------------------------------------------
# Provisioning display and monitor
# ---------------------------------------------------------------------------

class Display:
    def __init__(self, serial: str, plain: bool, verbose: bool):
        self.serial = serial
        self.live = sys.stdout.isatty() and not plain and not verbose
        self.verbose = verbose
        self.rows: dict[str, tuple[str, str]] = {}
        self.start = time.monotonic()
        self.lines = 0
        self.last_draw = 0.0

    def update(self, phase: str, state: str, reason: str = '') -> None:
        value = (state, clean(reason))
        if self.rows.get(phase) == value:
            return
        self.rows[phase] = value
        if self.live:
            self.draw()
        else:
            print(f'[{state}] {phase}' + (f' — {value[1]}' if reason else ''), flush=True)

    def draw(self) -> None:
        elapsed = int(time.monotonic() - self.start)
        content = [f'Portal provisioning — {clean(self.serial)} — {elapsed // 60:02}:{elapsed % 60:02}']
        existing = [(state, reason) for phase, (state, reason) in self.rows.items() if phase.startswith('Existing:')]
        if existing:
            observed = sum(state == 'OBSERVED' for state, _ in existing)
            content.append(f'[INFO] Existing settings: {observed} observed, {len(existing) - observed} unconfirmed; details in final output')
        content += [f'[{state}] {phase}' + (f' — {reason}' if reason else '')
                    for phase, (state, reason) in self.rows.items() if not phase.startswith('Existing:')]
        size = shutil.get_terminal_size()
        width = max(10, size.columns - 1)
        content = [wrapped for line in content for wrapped in textwrap.wrap(line, width=width, subsequent_indent='  ')]
        height = max(3, size.lines - 1)
        if len(content) > height:
            content = content[:1] + ['[INFO] Full details follow at exit'] + content[-(height - 2):]
        if self.lines:
            sys.stdout.write(f'\x1b[{self.lines}A\r\x1b[J')
        sys.stdout.write('\n'.join(content) + '\n')
        sys.stdout.flush()
        self.lines = len(content)
        self.last_draw = time.monotonic()

    def finish(self) -> None:
        if not self.live:
            return
        if self.lines:
            sys.stdout.write(f'\x1b[{self.lines}A\r\x1b[J')
        self.live = False
        print('Portal result — ' + clean(self.serial))
        for phase, (state, reason) in self.rows.items():
            print(f'[{state}] {phase}' + (f' — {reason}' if reason else ''))
        sys.stdout.flush()

    def tick(self) -> None:
        if self.live and time.monotonic() - self.last_draw >= 1:
            self.draw()


class Monitor:
    def __init__(self, ui: Display):
        self.ui = ui
        self.complete = False
        self.already = False
        self.error = ''
        self.awaiting_adb = False

    def feed(self, line: str) -> None:
        line = clean(line)
        if self.ui.verbose:
            print(line, flush=True)
        if line.startswith('PROVISION_ERROR:'):
            self.error = line.partition(':')[2].strip()
            if self.error.startswith('build failed:'):
                self.ui.update('Prepare and stage files', 'FAILED', 'Build failed before staging')
            self.ui.update('Provisioning', 'FAILED', self.error)
        elif line.startswith('STOCK_ADB_REENABLE_REQUIRED'):
            self.awaiting_adb = True
            self.ui.update('Manual ADB setup', 'ACTION',
                           'Keep USB connected. Enable ADB on the selected Portal; '
                           f'from another terminal run adb -s <USB-SERIAL> tcpip 5555. '
                           'Repeat after reboots until persistent ADB is confirmed.')
        elif line.startswith('Keep USB connected.'):
            self.ui.update('Manual ADB setup', 'ACTION', line)
        elif line.startswith('make: Entering directory') or line.startswith('make['):
            self.ui.update('Prepare and stage files', 'RUNNING', 'Building payloads with configured SDK')
        elif line.startswith('STAGED '):
            self.ui.update('Prepare and stage files', 'OK', 'Files staged')
            self.ui.update('Apply provisioning', 'RUNNING')
        elif line.startswith('INSTALL_ATTEMPT='):
            self.ui.update('Apply provisioning', 'RUNNING', line)
        elif line.startswith('INSTALL_ATTEMPT_RESULT '):
            if 'success=1' in line:
                self.ui.update('Apply provisioning', 'OK', 'Attempt succeeded; verification pending')
                self.ui.update('First boot verification', 'RUNNING', 'Waiting for reconnect and requested checks')
            else:
                self.ui.update('Apply provisioning', 'RETRYING', line)
        elif '_RETRY' in line:
            self.ui.update('Apply provisioning', 'RETRYING', line)
        elif line.startswith('RUNTIME_ADDRESSES '):
            self.ui.update('Apply provisioning', 'RUNNING', 'Runtime addresses discovered; running attempt')
        elif line.startswith('NATIVE_ACTIONS_OK '):
            self.ui.update('Apply provisioning', 'OK', 'Native actions completed; verification pending')
        elif line.startswith('WIRELESS_ADB_OK '):
            if self.awaiting_adb:
                self.ui.update('Manual ADB setup', 'OK', 'Persistent ADB setting observed')
                self.awaiting_adb = False
            self.ui.update('Wireless ADB', 'OBSERVED', 'Persistent port is 5555')
        elif line.startswith('VERIFY_REBOOT '):
            self.ui.update('First boot verification', 'OK', 'Requested checks passed')
            self.ui.update('Second boot verification', 'RUNNING', 'Reboot and repeat requested checks')
        elif line.startswith('PROVISION_OK '):
            # Defer the final verdict until the process also exits successfully.
            self.complete = True
        elif line.startswith('PROVISION_ALREADY_COMPLETE '):
            self.already = True
        elif line.startswith('RECOVER_NO_STATE '):
            self.ui.update('Recovery', 'SKIPPED', 'No pending saved action set')
        elif line.startswith('RECOVER_RESUME '):
            self.ui.update('Recovery', 'RUNNING', line)
        elif line.startswith('BACKUP_OK '):
            self.ui.update('Backup', 'OK', line)
        elif '_OK ' in line:
            self.ui.update(line.split()[0].removesuffix('_OK').replace('_', ' ').title(),
                           'OBSERVED', line)
        elif any(word in line.lower() for word in ('error', 'failed', 'warning', 'deferred')):
            self.ui.update('Diagnostic', 'WARNING', line)

    def finish(self, code: int, recent: list[str]) -> None:
        if code or self.error:
            self.ui.update('Provisioning', 'FAILED', self.error or f'Process exited with status {code}')
            for name, (state, _) in list(self.ui.rows.items()):
                if state == 'RUNNING':
                    self.ui.update(name, 'INCOMPLETE', 'Provisioner stopped before confirmation')
                elif state == 'PENDING':
                    self.ui.update(name, 'BLOCKED', 'Earlier failure prevented this phase')
            for index, line in enumerate(recent[-8:], 1):
                self.ui.update(f'Recent output {index}', 'DETAIL', line)
        elif self.complete:
            self.ui.update('First boot verification', 'OK', 'Requested checks passed')
            self.ui.update('Second boot verification', 'OK', 'Requested checks passed')
            self.ui.update('Provisioning', 'OK', 'Verified across two boots')
        elif self.already:
            self.ui.update('Provisioning', 'OBSERVED', 'Already configured; no new reboot verification')
        else:
            self.ui.update('Provisioning', 'DONE', 'Process exited successfully; verification not confirmed')
        for name, (state, _) in list(self.ui.rows.items()):
            if state in ('PENDING', 'RUNNING'):
                self.ui.update(name, 'UNCONFIRMED' if state == 'RUNNING' else 'SKIPPED',
                               'No separate completion marker reported')


def stop_child(child: subprocess.Popen) -> None:
    handlers = {sig: signal.signal(sig, signal.SIG_IGN)
                for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        stop_group(child)
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)


def stop_group(child: subprocess.Popen) -> None:
    # The leader can exit while a compiler/ADB descendant still holds the pipe.
    # Signal the whole group through escalation, even after reaping the leader.
    for sig, grace in ((signal.SIGINT, 1), (signal.SIGTERM, 1), (signal.SIGKILL, 1)):
        try:
            os.killpg(child.pid, sig)
        except ProcessLookupError:
            break
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            child.poll()
            try:
                os.killpg(child.pid, 0)
            except ProcessLookupError:
                child.wait()
                return
            time.sleep(0.05)
    child.wait()


def run_child(command: list[str], path: Path, ui: Display, feed=None,
              timeout: float | None = None, env: dict[str, str] | None = None,
              timeout_message: str = 'Read-only status check timed out; provisioning was not started') -> tuple[int, str, list[str]]:
    """Drain a background child while keeping the display responsive."""
    recent: deque[str] = deque(maxlen=12)
    captured = bytearray()
    pending = b''
    with path.open('xb') as log:
        os.chmod(path, 0o600)
        child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 start_new_session=True, env=env)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                start = time.monotonic()
                while selector.get_map():
                    if timeout is not None and time.monotonic() - start > timeout:
                        raise RuntimeError(timeout_message)
                    for key, _ in selector.select(0.2):
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        log.write(chunk)
                        log.flush()
                        if feed is None:
                            captured.extend(chunk)
                            if len(captured) > 8 * 1024 * 1024:
                                raise RuntimeError('Read-only status output exceeded limit')
                        pending += chunk
                        while b'\n' in pending:
                            raw, pending = pending.split(b'\n', 1)
                            line = clean(raw.decode('utf-8', errors='replace'))
                            recent.append(line)
                            if feed:
                                feed(line)
                        if len(pending) > 65536:
                            pending = pending[-65536:]
                    ui.tick()
                if pending:
                    line = clean(pending.decode('utf-8', errors='replace'))
                    recent.append(line)
                    if feed:
                        feed(line)
            code = child.wait()
            return (code if code >= 0 else 128 - code), captured.decode('utf-8', errors='replace'), list(recent)
        except BaseException:
            stop_child(child)
            raise
        finally:
            child.stdout.close()


def decode_status(output: str, serial: str, release: Path) -> dict:
    status = None
    for match in re.finditer(r'^\s*\{', output, re.MULTILINE):
        try:
            candidate, _ = json.JSONDecoder().raw_decode(output[match.end() - 1:])
            if isinstance(candidate, dict) and 'target' in candidate:
                status = candidate
                break
        except json.JSONDecodeError:
            pass
    if status is None or status.get('serial') != serial:
        raise RuntimeError('Status response missing or serial mismatch; provisioning was not started')
    spec = importlib.util.spec_from_file_location('portal_ui_targets', release / 'tools/portal_targets.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    target = status.get('target')
    if (not isinstance(target, dict) or target.get('device') != 'terry'
            or not module.find_target(target.get('device'), target.get('fingerprint'))):
        raise RuntimeError('Unsupported model or full firmware fingerprint; only terry is supported '
                           '(omni is not supported); provisioning was not started')
    for name in ('runtime', 'audio', 'kiosk_satellite', 'updates', 'debloat',
                 'presence', 'app_updates', 'shizuku', 'meta_accounts', 'privacy_dns', 'camera_light'):
        if name in status and not isinstance(status[name], dict):
            raise RuntimeError(f'Malformed status section: {name}; provisioning was not started')
    return status


def observe_presence_runtime(serial: str, status: dict, directory: Path,
                             ui: Display, env: dict[str, str]) -> None:
    """Enrich upstream status without modifying or starting device services."""
    presence = status.setdefault('presence', {})
    presence['runtime_ready'] = None
    if presence.get('state') != 'optimized':
        return
    queries = (
        ['dumpsys', 'media.camera'],
        ['cmd', 'appops', 'get', 'com.facebook.portal.aiservice', 'CAMERA'],
        ['dumpsys', 'activity', 'service',
         'com.facebook.portal.aiservice/com.facebook.alohaapp.app.services.CameraService'],
    )
    observations = []
    try:
        for index, query in enumerate(queries):
            code, output, _ = run_child(
                ['adb', '-s', serial, 'shell', *query],
                directory / f'presence-runtime-{index}.log', ui, timeout=20, env=env,
                timeout_message='Presence runtime observation timed out')
            observations.append((code, output))
    except (RuntimeError, OSError, subprocess.SubprocessError):
        return
    if any(code for code, _ in observations):
        return
    camera, appops, metrics = [output for _, output in observations]
    explicit = re.findall(r'^\s*(?:Uid mode:\s*)?CAMERA:\s*(\w+)', appops, re.MULTILINE)
    allowed = (all(mode == 'allow' for mode in explicit) if explicit else
               re.fullmatch(r'No operations\.\s+Default mode:\s*allow\s*', appops.strip()) is not None)
    active_camera = camera.split('Active Camera Clients:', 1)
    camera_active = len(active_camera) == 2 and (
        'Client Package Name: com.facebook.portal.aiservice'
        in active_camera[1].split('Camera service events log', 1)[0])
    pose = metrics.split('[ PoseEstimatorManagerMetrics ]', 1)
    pose_ready = len(pose) == 2 and bool(re.search(
        r'\b\d+ ms - \d+ ms:\s+\d+\b', pose[1].split('[ AlohaFrameProcessor ]', 1)[0]))
    processor = metrics.split('[ AlohaFrameProcessor ]', 1)
    processor_ready = len(processor) == 2 and bool(
        processor[1].split('[ AiCameramanController ]', 1)[0].strip())
    keys = {'enable_cv_background_detector_v2', 'enable_hardware_cropping',
            'enable_liveness_metric', 'enable_color_based_reid', 'enable_face_rec_based_reid_v3'}
    activation_host = presence.get('analysis_fps_activation_host')
    activation_ready = (
        presence.get('analysis_fps_uid1000_configured') is True
        and presence.get('analysis_fps_uid1000_value') == presence.get('analysis_fps_cap')
        if activation_host == 'uid1000' else
        presence.get('analysis_fps_helper_key_authorized') is True
        if activation_host in (None, 'loopback_adb') else False)
    fps_ready = presence.get('analysis_fps_cap_installed') is not True or (
        type(presence.get('analysis_fps_cap')) is int
        and presence['analysis_fps_cap'] > 0
        and presence.get('analysis_fps_applied_this_boot') == presence['analysis_fps_cap']
        and presence.get('analysis_fps_helper_installed') is True
        and activation_ready)
    presence['runtime_ready'] = bool(
        status.get('runtime', {}).get('aiservice_pid') and camera_active and allowed
        and pose_ready and processor_ready and fps_ready
        and presence.get('analysis_frames_observed') is True
        and presence.get('roi_frames_observed') is True
        and presence.get('full_scene_profile') is True
        and isinstance(presence.get('profile_keys_loaded'), list)
        and all(isinstance(key, str) for key in presence['profile_keys_loaded'])
        and set(presence['profile_keys_loaded']) == keys)


def action_states(status: dict) -> dict[str, bool | None]:
    def flag(section: str, key: str) -> bool | None:
        value = status.get(section, {}).get(key)
        return value if isinstance(value, bool) else None

    def matches(section: str, key: str, expected) -> bool | None:
        value = status.get(section, {}).get(key)
        return None if value is None or value == 'unknown' else value == expected

    presence_configured = matches('presence', 'state', 'optimized')
    presence_ready = flag('presence', 'runtime_ready')
    presence_complete = (False if presence_configured is False or presence_ready is False
                         else True if presence_configured is True and presence_ready is True
                         else None)
    return {
        'audio': flag('audio', 'installed_marker'),
        'device_owner': flag('kiosk_satellite', 'device_owner'),
        'kiosk_home': flag('kiosk_satellite', 'home_screen'),
        'disable_updates': matches('updates', 'state', 'blocked'),
        'debloat': flag('debloat', 'complete'),
        'remove_meta_accounts': matches('meta_accounts', 'remaining', 0),
        'optimize_presence': presence_complete,
        'allow_app_updates': flag('app_updates', 'third_party_updates_allowed'),
        'privacy_dns': matches('privacy_dns', 'mode', 'hostname'),
        'shizuku': flag('shizuku', 'installed'),
        'disable_camera_light': matches('camera_light', 'state', 'installed'),
        'presence_fps_cap': flag('presence', 'analysis_fps_cap_installed'),
        'dhcp_dns': matches('privacy_dns', 'mode', 'off'),
    }


def requested_additions(options: list[str]) -> set[str]:
    flags = {option.split('=')[0] for option in options if option.startswith('--')}
    requested = {key for key, add, _, _, _ in _SCREEN_OPTS if add in flags}
    if '--dhcp-dns' in flags:
        requested.add('dhcp_dns')
    if '--profile=kiosk' in options or any(
            option == '--profile' and index + 1 < len(options) and options[index + 1] == 'kiosk'
            for index, option in enumerate(options)):
        requested.update(_KIOSK_OPT_KEYS)
    if '--presence-fps-cap' in flags:
        requested.add('optimize_presence')
    selectors = {flag for _, add, remove, _, _ in _SCREEN_OPTS for flag in (add, remove) if flag}
    selectors.update({'--profile', '--presence-fps-cap', '--restore-presence-fps',
                      '--dhcp-dns', '--status', '--dry-run', '--backup', '--recover'})
    if not flags & selectors:
        requested.add('audio')
    return requested


def final_action_summary(serial: str, status: dict | None, options: list[str], code: int,
                         run_error: str, scan_error: str, verified: bool) -> None:
    print('\nFinal action states — ' + clean(serial))
    read_only = '--status' in options or '--dry-run' in options
    states = action_states(status) if status is not None else {}
    requested = set() if read_only else requested_additions(options)
    presence = (status or {}).get('presence', {})
    runtime_ready = states.get('optimize_presence') is True
    unmet = any(states.get(key) is not True for key in requested)
    if code or run_error:
        print(f'Run: FAILED (exit {code})' + (f' — {clean(run_error)}' if run_error else ''))
    elif scan_error:
        print(f'Run: UNCONFIRMED (exit {code})')
    elif unmet:
        print(f'Run: UNCONFIRMED (exit {code}; requested action failed final observation)')
    elif read_only:
        print(f'Run: READ-ONLY (exit {code})')
    elif verified:
        print('Run: VERIFIED across two boots (exit 0)')
    else:
        print('Run: UNCONFIRMED (exit 0; full verification not reported)')
    if scan_error:
        print('Final scan failed: ' + clean(scan_error))
    rows = [(key, label) for key, _, _, label, _ in _SCREEN_OPTS]
    rows.insert(next(i for i, row in enumerate(rows) if row[0] == 'privacy_dns') + 1,
                ('dhcp_dns', 'Network DNS'))
    for key, label in rows:
        value = states.get(key)
        state = 'UNKNOWN' if value is None else 'APPLIED' if value else 'NOT APPLIED'
        reason = ''
        if value is False and key in requested:
            state, reason = 'FAILED', 'requested addition not observed'
        if key == 'optimize_presence' and presence.get('state') == 'optimized':
            if not runtime_ready:
                state = 'APPLIED'
                reason = 'runtime unconfirmed, likely because the camera shutter was closed'
        print(f'[{state}] {label}' + (f' — {reason}' if reason else ''))
    print('Applied states describe current configuration; markers alone do not prove runtime health or reboot persistence.', flush=True)


def final_status(serial: str, release: Path, directory: Path, ui: Display,
                 env: dict[str, str]) -> dict:
    ui.update('Final status scan', 'RUNNING', 'Reading action states after the run')
    command = [sys.executable, '-u', str(release / 'tools/provision_portal.py'),
               '--serial', serial, '--status', '--log-dir', str(directory / 'final-status')]
    code, output, recent = run_child(command, directory / 'final-status.log', ui,
                                     timeout=45, env=env,
                                     timeout_message='Final action-state scan timed out')
    if code:
        raise RuntimeError(f'Status scan exited {code}: ' + ' '.join(recent[-3:]))
    try:
        status = decode_status(output, serial, release)
    except RuntimeError as exc:
        raise RuntimeError(str(exc).replace('provisioning was not started', 'final state unavailable')) from exc
    observe_presence_runtime(serial, status, directory, ui, env)
    ui.update('Final status scan', 'OK', 'Fresh observations collected')
    return status


def observations(status: dict, ui: Display) -> None:
    checks = [
        ('Wireless ADB', status.get('runtime', {}).get('wireless_adb_port') == '5555', 'persistent port setting'),
        ('Audio fix', status.get('audio', {}).get('installed_marker'), 'installation marker'),
        ('Device Owner', status.get('kiosk_satellite', {}).get('device_owner'), 'policy role'),
        ('Kiosk home', status.get('kiosk_satellite', {}).get('home_screen'), 'home selection'),
        ('OTA blocking', status.get('updates', {}).get('state') == 'blocked', 'configuration/marker'),
        ('Debloat', status.get('debloat', {}).get('complete'), 'package and component profile'),
        ('Presence optimization', action_states(status)['optimize_presence'], 'configuration and runtime readiness'),
        ('Presence frame cap', status.get('presence', {}).get('analysis_fps_cap_installed'), 'installation marker'),
        ('App updates', status.get('app_updates', {}).get('third_party_updates_allowed'), 'verifier configuration'),
        ('Shizuku installed', status.get('shizuku', {}).get('installed'), 'package'),
        ('Shizuku server', status.get('shizuku', {}).get('server_running'), 'process observation'),
        ('Camera indicator control', action_states(status)['disable_camera_light'], 'installation status'),
    ]
    for name, value, reason in checks:
        ui.update('Existing: ' + name, 'OBSERVED' if value else 'UNCONFIRMED',
                  reason + (' present; persistence not tested' if value else ' not confirmed'))
    accounts = status.get('meta_accounts', {}).get('remaining')
    ui.update('Existing: Meta accounts', 'OBSERVED' if accounts == 0 else 'UNCONFIRMED',
              'No accounts reported; authenticator protection not verified' if accounts == 0 else 'Removal not confirmed')
    dns = status.get('privacy_dns', {})
    ui.update('Existing: Private DNS', 'OBSERVED' if dns.get('mode') == 'hostname' else 'UNCONFIRMED',
              'Strict DNS configuration observed; requested resolver not compared' if dns.get('mode') == 'hostname'
              else 'Strict DNS configuration not confirmed')


def adb_failure(serial: str, detail: str, kind: str = 'unreachable') -> str:
    if kind == 'unauthorized':
        remedy = 'ADB authorization is required. Unlock the Portal and accept the USB debugging authorization prompt, then retry.'
    elif kind == 'offline':
        remedy = 'ADB device is offline. Check power and the USB/network connection, unlock the Portal and enable ADB debugging, then retry.'
    elif kind == 'shell':
        remedy = 'ADB is connected but its shell is unavailable. Unlock the Portal, enable ADB debugging and check the USB/network connection, then retry.'
    else:
        remedy = ('Cannot reach ADB; it may be disabled or the address/network may be unavailable. '
                  'Enable ADB/USB debugging on the Portal. Check its power, IP address and network connection.')
    if ':' in serial and kind not in ('unauthorized', 'shell'):
        remedy += (' For wireless ADB, connect a USB data cable and run '
                   '`adb -s <USB-SERIAL> tcpip 5555` from another terminal, then retry.')
    return f'{serial}: {remedy} No provisioning started.' + (f' ADB response: {clean(detail)[:300]}' if detail else '')


def check_adb(serial: str, directory: Path, ui: Display, env: dict[str, str], release: Path) -> None:
    """Bounded read-only probes, under the caller's canonical device lock."""
    adb = shutil.which('adb', path=env.get('PATH'))
    if adb is None:
        raise RuntimeError('adb was not found on PATH. Install Android Platform Tools and add '
                           'its platform-tools directory to PATH. No provisioning started.')
    deadline = time.monotonic() + 8
    number = 0

    def probe(arguments: list[str]) -> tuple[int, str]:
        nonlocal number
        number += 1
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(adb_failure(serial, 'Connection check timed out'))
        code, output, _ = run_child([adb] + arguments, directory / f'adb-probe-{number}.log',
                                    ui, timeout=min(3, remaining), env=env,
                                    timeout_message=adb_failure(serial, 'Connection check timed out'))
        return code, output.strip()

    code, discovery = probe(['devices', '-l'])
    if code:
        raise RuntimeError(adb_failure(serial, discovery))
    state = next((fields[1] for line in discovery.splitlines()
                  if len(fields := line.split()) >= 2 and fields[0] == serial), None)
    if state in ('unauthorized', 'offline'):
        raise RuntimeError(adb_failure(serial, state, state))
    connect_output = ''
    if state != 'device' and ':' in serial:
        _, connect_output = probe(['connect', serial])
    code, state = probe(['-s', serial, 'get-state'])
    if code or state != 'device':
        detail = state or connect_output
        kind = 'unauthorized' if 'unauthorized' in detail.lower() else 'offline' if 'offline' in detail.lower() else 'unreachable'
        raise RuntimeError(adb_failure(serial, connect_output + ' ' + detail, kind))
    values = []
    for prop in ('ro.product.device', 'ro.build.fingerprint'):
        code, value = probe(['-s', serial, 'shell', 'getprop', prop])
        if code or not value:
            raise RuntimeError(adb_failure(serial, value, 'shell'))
        values.append(value)
    # Real shell responses and exact registry identity are the positive control.
    decode_status(json.dumps({'serial': serial, 'target': {
        'device': values[0], 'fingerprint': values[1]}}), serial, release)
    ui.update('ADB connection', 'OK', f'Shell ready; {values[0]} | {values[1]}')


@contextmanager
def device_lock(serial: str, ui: Display):
    # Git reports the owning outer checkout when this release is a submodule.
    # Resolve its common directory so both entry points serialize device contact.
    superproject = subprocess.check_output(
        ['git', '-C', str(ROOT), 'rev-parse', '--show-superproject-working-tree'],
        text=True).strip()
    lock_root = Path(superproject) if superproject else ROOT
    common = Path(subprocess.check_output(
        ['git', '-C', str(lock_root), 'rev-parse', '--path-format=absolute', '--git-common-dir'],
        text=True).strip())
    locks = common / 'portal-device-locks'
    locks.mkdir(exist_ok=True)
    lock_path = locks / (re.sub(r'[^a-zA-Z0-9_.-]', '_', serial) + '.lock')
    with lock_path.open('a') as lock:
        ui.update('Device lock', 'WAITING', 'Waiting for device lock')
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                time.sleep(0.2)
                ui.tick()
        ui.update('Device lock', 'OK', 'Exclusive device contact')
        yield


def download_kiosk_apk(directory: Path, ui: Display) -> Path:
    ui.update('Kiosk Satellite', 'RUNNING', 'Downloading pinned official APK')
    apk = directory / 'kiosk-satellite.apk'
    digest = hashlib.sha256()
    total = 0
    deadline = time.monotonic() + 120
    with urllib.request.urlopen(KIOSK_APK_URL, timeout=30) as response, apk.open('wb') as output:
        os.chmod(apk, 0o600)
        while chunk := response.read(1024 * 1024):
            if time.monotonic() > deadline:
                raise RuntimeError('Kiosk Satellite APK download timed out')
            ui.tick()
            total += len(chunk)
            if total > 256 * 1024 * 1024:
                raise RuntimeError('Kiosk Satellite APK exceeds download size limit')
            digest.update(chunk)
            output.write(chunk)
    if digest.hexdigest() != KIOSK_APK_SHA256:
        apk.unlink()
        raise RuntimeError('Kiosk Satellite APK SHA-256 mismatch; installation was not started')
    return apk


def active_kiosk_admin(policy: str) -> bool:
    # Scope the receiver to enabled admins for user 0, not an owner/history mention.
    section = re.search(r'^  Enabled Device Admins \(User 0[^\n]*\):\s*\n'
                        r'(.*?)(?=^  \S|\Z)', policy, re.MULTILINE | re.DOTALL)
    if not section:
        return False
    return bool(re.search(r'^\s+(?:' + re.escape(KIOSK_ADMIN) + '|' +
                          re.escape(KIOSK_PACKAGE + '/' + KIOSK_PACKAGE + '.KioskAdminReceiver') +
                          r'):\s*$', section[1], re.MULTILINE))


def prepare_kiosk(serial: str, directory: Path, ui: Display,
                  env: dict[str, str], apk: Path | None) -> None:
    ui.update('Kiosk Satellite', 'RUNNING', 'Checking installation and device admin')
    number = 0

    def adb(arguments: list[str], timeout: int = 20, *, missing_ok: bool = False) -> str:
        nonlocal number
        number += 1
        code, output, _ = run_child(['adb', '-s', serial] + arguments,
                                    directory / f'ks-{number}.log', ui,
                                    timeout=timeout, env=env,
                                    timeout_message='Kiosk Satellite setup timed out')
        # Android pm path returns 1 with no output when the package is absent.
        if code and not (missing_ok and code == 1 and not output.strip()):
            raise RuntimeError('Kiosk Satellite setup failed: ' + clean(output))
        return output

    def installed() -> bool:
        output = adb(['shell', 'pm', 'path', '--user', '0', KIOSK_PACKAGE], missing_ok=True)
        if any(line.startswith('package:') for line in output.splitlines()):
            return True
        if output.strip():
            raise RuntimeError('Cannot determine Kiosk Satellite installation: ' + clean(output))
        return False

    newly_installed = not installed()
    if newly_installed:
        apk = apk or download_kiosk_apk(directory, ui)
        if not apk.is_file():
            raise RuntimeError(f'Kiosk Satellite APK missing: {apk}')
        ui.update('Kiosk Satellite', 'RUNNING', 'Installing missing app for user 0')
        adb(['install', '--user', '0', str(apk.resolve())], timeout=120)
        if not installed():
            raise RuntimeError('Kiosk Satellite package not present after installation')
    policy = adb(['shell', 'dumpsys', 'device_policy'])
    if 'Enabled Device Admins' not in policy and 'Device Policy Manager' not in policy:
        raise RuntimeError('Cannot read device-admin policy; setup stopped')
    admin_active = active_kiosk_admin(policy)
    if newly_installed or not admin_active:
        ui.update('Kiosk Satellite', 'RUNNING', 'Opening app before device-admin setup')
        output = adb(['shell', 'am', 'start', '--user', '0', '-n',
                      KIOSK_PACKAGE + '/.MainActivity'])
        if 'Error' in output or 'Exception' in output:
            raise RuntimeError('Cannot open Kiosk Satellite: ' + clean(output))
    if not admin_active:
        ui.update('Kiosk Satellite', 'RUNNING', 'Enabling device admin for user 0')
        adb(['shell', 'dpm', 'set-active-admin', '--user', '0', KIOSK_ADMIN])
        if not active_kiosk_admin(adb(['shell', 'dumpsys', 'device_policy'])):
            raise RuntimeError('Kiosk Satellite device admin is not active after activation')
    ui.update('Kiosk Satellite', 'OK', 'Installed; active device admin verified in device_policy')


def sensor_parcel_bool(code: int, output: str, *, java: bool) -> bool | None:
    """Decode only the pinned Android 10 getter's expected boolean reply."""
    if code:
        return None
    reply = re.fullmatch(r"Result: Parcel\(([0-9a-fA-F\s]+)'[^']*'\)", output.strip())
    if reply is None:
        return None
    words = reply[1].split()
    if java:
        if len(words) != 2 or words[0] != '00000000':
            return None
        words = words[1:]
    if len(words) != 1 or words[0] not in ('00000000', '00000001'):
        return None
    return words[0] == '00000001'


def required_sensors(options: list[str]) -> set[str]:
    flags = {option.split('=')[0] for option in options if option.startswith('--')}
    if flags & {'--status', '--dry-run'}:
        return set()
    if '--recover' in flags or '--profile=kiosk' in options or any(
            value == '--profile' and index + 1 < len(options) and options[index + 1] == 'kiosk'
            for index, value in enumerate(options)):
        return {'camera', 'microphone'}
    needed = set()
    if flags & {'--optimize-presence', '--restore-presence-profile',
                '--presence-fps-cap', '--restore-presence-fps'}:
        needed.add('camera')
    if flags & {'--audio', '--restore-audio'} or 'audio' in requested_additions(options):
        needed.add('microphone')
    return needed


def sensor_preflight(serial: str, directory: Path, ui: Display,
                     env: dict[str, str], options: list[str], *, camera_confirmed: bool = False) -> None:
    """Read sensor flags before setup; never change privacy or start capture."""
    needed = required_sensors(options)
    if not needed:
        return

    def read(service: str, transaction: str, *, java: bool) -> bool | None:
        try:
            code, output, _ = run_child(
                ['adb', '-s', serial, 'shell', 'service', 'call', service, transaction],
                directory / f'sensor-{service}.log', ui, timeout=5, env=env,
                timeout_message=f'{service} sensor-state query timed out')
        except (RuntimeError, OSError, subprocess.SubprocessError):
            return None
        return sensor_parcel_bool(code, output, java=java)

    # Exact-build verification precedes these pinned, read-only Binder getters.
    private = read('sensor_privacy', '3', java=True)
    muted = read('media.audio_flinger', '18', java=False)
    ui.update('Sensor privacy', 'BLOCKED' if private else 'OBSERVED' if private is False else 'UNCONFIRMED',
              'Android sensor privacy is on' if private else 'Android sensor privacy is off'
              if private is False else 'Android sensor privacy state is unreadable')
    ui.update('Microphone', 'OBSERVED' if muted is not None else 'UNCONFIRMED',
              'Microphone is muted' if muted else 'Microphone is unmuted (AudioFlinger flag)'
              if muted is False else 'Microphone mute state is unreadable; check the privacy control')
    if private is True:
        raise RuntimeError('Sensor preflight: sensor privacy is on. Turn off the camera/microphone '
                           'privacy control and retry. No provisioning started.')
    if 'microphone' in needed and muted is True:
        raise RuntimeError('Sensor preflight: microphone is muted. Turn off microphone privacy '
                           'and retry. No provisioning started.')
    if 'camera' in needed:
        ui.update('Camera cover', 'UNCONFIRMED',
                  'ADB cannot read the physical cover state. Check that the camera cover is fully '
                  'open and camera privacy is off before continuing.')
        if not camera_confirmed:
            # Freeze redraws while reading an acknowledgement, then resume the UI.
            was_live = ui.live
            ui.live = False
            ui.lines = 0
            try:
                camera_confirmed = input(
                    'Open the camera shutter and turn camera privacy off. '
                    'Confirm the camera is ready [y/N]: ').strip().lower() in ('y', 'yes')
            except EOFError:
                camera_confirmed = False
            finally:
                ui.live = was_live
            if not camera_confirmed:
                raise RuntimeError('Camera cover confirmation required. Open the shutter and retry; '
                                   'for unattended runs explicitly acknowledge with --confirm-camera-open. '
                                   'No provisioning started.')
        ui.update('Camera cover', 'CONFIRMED',
                  'User confirmed the shutter is open and camera privacy is off; '
                  'hardware state remains unreadable via ADB.')


def scan_status(serial: str, release: Path, directory: Path, ui: Display,
                env: dict[str, str], apk: Path | None, *, prepare: bool = True,
                sensor_options: list[str] | None = None, camera_confirmed: bool = False) -> dict:
    ui.update('ADB connection', 'RUNNING', 'Checking selected device before status scan')
    check_adb(serial, directory, ui, env, release)
    if sensor_options is not None:
        sensor_preflight(serial, directory, ui, env, sensor_options, camera_confirmed=camera_confirmed)
    if prepare:
        prepare_kiosk(serial, directory, ui, env, apk)
    ui.update('Read-only preflight', 'RUNNING', 'Collecting existing settings in background')
    command = [sys.executable, '-u', str(release / 'tools/provision_portal.py'),
               '--serial', serial, '--status', '--log-dir', str(directory / 'preflight')]
    code, output, recent = run_child(command, directory / 'preflight.log', ui,
                                     timeout=180, env=env)
    if code:
        if 'did not reconnect' in output or 'unauthorized' in output.lower():
            raise RuntimeError(adb_failure(serial, 'ADB became unavailable during the status scan'))
        raise RuntimeError(f'Read-only status failed ({code}); provisioning was not started. '
                           + ' '.join(recent[-3:]))
    status = decode_status(output, serial, release)
    target = status['target']
    observe_presence_runtime(serial, status, directory, ui, env)
    ui.update('Read-only preflight', 'OK', f"{target['device']} | {target['fingerprint']}")
    return status


def build_environment(source: dict[str, str], home: Path | None = None) -> dict[str, str]:
    """Apply README SDK exports to child processes without altering the shell."""
    env = source.copy()
    home = home or Path.home()
    roots = [home / 'Android/Sdk', home / 'android-sdk', Path('/opt/android-sdk'), Path('/usr/lib/android-sdk')]
    preferred = env.get('SDK') or env.get('ANDROID_SDK_ROOT') or env.get('ANDROID_HOME')
    sdk = Path(preferred) if preferred else next((path for path in roots if
        (path / 'ndk/28.2.13676358').is_dir() and (path / 'platforms/android-36/android.jar').is_file()), roots[0])
    env.setdefault('SDK', str(sdk))
    env.setdefault('ANDROID_SDK_ROOT', str(sdk))
    env.setdefault('NDK', str(sdk / 'ndk/28.2.13676358'))
    env.setdefault('TOOLCHAIN', str(Path(env['NDK']) / 'toolchains/llvm/prebuilt/linux-x86_64'))
    env.setdefault('ANDROID_JAR', str(sdk / 'platforms/android-36/android.jar'))
    versions = sorted((path for path in (sdk / 'build-tools').glob('*')
                       if path.is_dir() and re.fullmatch(r'\d+\.\d+\.\d+', path.name)),
                      key=lambda path: tuple(map(int, path.name.split('.'))))
    env.setdefault('BUILD_TOOLS', str(versions[-1] if versions else sdk / 'build-tools/37.0.0'))
    env.setdefault('D8', str(Path(env['BUILD_TOOLS']) / 'd8'))
    return env


def read_only_run(options: list[str]) -> bool:
    """Match the provisioner's status, dry-run and backup-only run modes."""
    flags = {option.split('=')[0] for option in options if option.startswith('--')}
    if flags & {'--status', '--dry-run'}:
        return True
    actions = {flag for _, add, remove, _, _ in _SCREEN_OPTS
               for flag in (add, remove) if flag}
    actions |= {'--dhcp-dns', '--profile', '--recover'}
    return '--backup' in flags and not bool(flags & actions)


def requires_build(options: list[str]) -> bool:
    flags = {option.split('=')[0] for option in options if option.startswith('--')}
    if flags & {'--status', '--dry-run', '--skip-build'}:
        return False
    privileged = {'--audio', '--restore-audio', '--device-owner', '--disable-updates',
                  '--enable-updates', '--debloat', '--restore-bloat', '--remove-meta-accounts',
                  '--optimize-presence', '--restore-presence-profile', '--presence-fps-cap',
                  '--restore-presence-fps', '--shizuku', '--remove-shizuku',
                  '--disable-camera-light', '--restore-camera-light', '--profile', '--recover'}
    shell_only = {'--kiosk-home', '--restore-kiosk-home', '--privacy-dns',
                  '--restore-privacy-dns', '--dhcp-dns', '--allow-app-updates', '--restore-app-verifier', '--backup'}
    return bool(flags & privileged) or not bool(flags & shell_only)


def validate_build_environment(env: dict[str, str]) -> None:
    required = [Path(env['TOOLCHAIN']) / 'bin/aarch64-linux-android29-clang',
                Path(env['TOOLCHAIN']) / 'bin/armv7a-linux-androideabi29-clang',
                Path(env['ANDROID_JAR']), Path(env['D8'])]
    required += [Path(env['BUILD_TOOLS']) / tool for tool in ('aapt', 'zipalign', 'apksigner')]
    missing = [str(path) for path in required if not path.is_file()
               or (path.suffix != '.jar' and not os.access(path, os.X_OK))]
    missing += [tool for tool in ('make', 'java', 'javac', 'jar', 'keytool')
                if shutil.which(tool, path=env.get('PATH')) is None]
    if missing:
        raise RuntimeError('Missing build prerequisites: ' + ', '.join(missing)
                           + '. Set the README SDK environment variables; no device contact performed.')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False,
                                     epilog='Omit --serial to use the interactive configuration screen. '
                                            'Other arguments pass to the provisioner unchanged.')
    parser.add_argument('--serial', default=None, help='ADB serial (IP:PORT); omit to use the config screen')
    parser.add_argument('--ks-apk', type=Path, help='local Kiosk Satellite APK to install if missing')
    parser.add_argument('--confirm-camera-open', action='store_true',
                        help='acknowledge for this run that the shutter is open and camera privacy is off')
    parser.add_argument('--ui-verbose', action='store_true', help='also display child output')
    parser.add_argument('--ui-plain', action='store_true', help='disable terminal redraws')
    parser.add_argument('--log-dir', type=Path, help='parent for a new private run directory')
    args, forwarded = parser.parse_known_args(argv)
    if args.serial is not None and not args.serial.strip():
        parser.error('--serial must not be empty')
    if any(token.startswith('--') and token.split('=')[0] != '--serial'
           and '--serial'.startswith(token.split('=')[0]) for token in forwarded):
        parser.error('Use the full --serial option; abbreviated serial overrides are unsafe')

    serial = args.serial
    if serial is None:
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            parser.error('--serial is required when not running in an interactive terminal')
        screen = None
        try:
            screen = ConfigScreen(args.ks_apk, dry_run='--dry-run' in forwarded, cli_flags=forwarded)
            result = screen.run()
        except Cancelled as exc:
            print('Cancelled during device setup; inspect device state before retrying.')
            final_action_summary(screen._serial() if screen else 'not selected', None, forwarded, 128 + exc.signum,
                                 'Cancelled', 'Device state not rechecked', False)
            return 128 + exc.signum
        except KeyboardInterrupt:
            print('Cancelled during device setup; inspect device state before retrying.')
            return 130
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
            print(f'Preflight failed: {exc}')
            final_action_summary(screen._serial() if screen else 'not selected', None, forwarded, 1, str(exc),
                                 'No final scan completed', False)
            return 1
        if result is None:
            print('Cancelled.')
            return 0
        serial, screen_flags = result
        forwarded = screen_flags + forwarded

    ui = Display(serial, args.ui_plain, args.ui_verbose)
    release = ROOT
    provisioner = release / 'tools/provision_portal.py'
    if not provisioner.is_file():
        ui.update('Provisioning', 'FAILED', 'Sibling tools/provision_portal.py missing; use a complete release checkout')
        final_action_summary(serial, None, forwarded, 1, 'Sibling provisioner missing',
                             'No final scan completed', False)
        return 1
    final_snapshot = None
    final_scan_error = 'No final scan completed'
    run_error = ''
    result_code = 1
    verified = False
    old_handlers = {}
    def cancel(signum, frame):
        raise Cancelled(signum)
    for signum in (signal.SIGINT, signal.SIGTERM):
        old_handlers[signum] = signal.signal(signum, cancel)
    try:
        child_env = build_environment(dict(os.environ))
        if requires_build(forwarded):
            ui.update('Host build tools', 'RUNNING', 'Checking SDK exports before device contact')
            validate_build_environment(child_env)
            ui.update('Host build tools', 'OK',
                      f"NDK={child_env['NDK']} | BUILD_TOOLS={child_env['BUILD_TOOLS']}")
        with device_lock(serial, ui):
            if args.log_dir:
                args.log_dir.mkdir(parents=True, exist_ok=True)
            directory = Path(tempfile.mkdtemp(prefix='portal-ui-', dir=args.log_dir))
            os.chmod(directory, 0o700)
            ui.update('Diagnostics', 'INFO', str(directory))
            status = scan_status(serial, release, directory, ui, child_env,
                                 args.ks_apk, prepare=not read_only_run(forwarded),
                                 sensor_options=forwarded, camera_confirmed=args.confirm_camera_open)
            command = [sys.executable, '-u', str(provisioner), '--serial', serial]
            observations(status, ui)
            read_only = read_only_run(forwarded)
            if not read_only:
                ui.update('Prepare and stage files', 'PENDING')
                for phase in ('Apply provisioning', 'First boot verification', 'Second boot verification'):
                    ui.update(phase, 'PENDING')
            ui.update('Original provisioner', 'RUNNING', 'Routine output hidden; waiting for phase markers')
            monitor = Monitor(ui)
            # umask also protects status.json, backups and native logs made by the child.
            code, _, recent = run_child(command + forwarded + ['--log-dir', str(directory)],
                                        directory / 'provision.log', ui, monitor.feed, env=child_env)
            ui.update('Original provisioner', 'OK' if code == 0 else 'FAILED', f'Exit status {code}')
            monitor.finish(code, recent)
            result_code = code
            run_error = monitor.error or (recent[-1] if code and recent else '')
            verified = monitor.complete and not code and not monitor.error
            try:
                final_snapshot = final_status(serial, release, directory, ui, child_env)
                final_scan_error = ''
            except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
                final_scan_error = str(exc)
                ui.update('Final status scan', 'UNCONFIRMED', final_scan_error)
            return code
    except Cancelled as exc:
        result_code = 128 + exc.signum
        run_error = 'Cancelled; device state not rechecked'
        for phase, (state, _) in list(ui.rows.items()):
            if state == 'RUNNING':
                ui.update(phase, 'INCOMPLETE', 'Cancelled before completion')
        ui.update('Provisioning', 'CANCELLED', 'Child stopped; inspect device state before retrying')
        return 128 + exc.signum
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
        run_error = str(exc)
        for phase, (state, _) in list(ui.rows.items()):
            if state == 'RUNNING':
                ui.update(phase, 'FAILED', str(exc))
        if ui.rows.get('ADB connection', ('', ''))[0] == 'FAILED':
            ui.update('Provisioning', 'BLOCKED', 'ADB check failed; no provisioning started')
        else:
            ui.update('Provisioning', 'FAILED', str(exc))
        return 1
    finally:
        ui.finish()
        final_action_summary(serial, final_snapshot, forwarded, result_code,
                             run_error, final_scan_error, verified)
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)


if __name__ == '__main__':
    os.umask(0o077)
    sys.exit(main())
