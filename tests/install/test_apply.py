"""Read-only/unit coverage; actual systemd apply belongs in an isolated host."""
import argparse
import contextlib
import importlib.util
import io
import json
import os
import pty
import select
import shutil
import sys
import errno
import http.client
import http.cookies
import ssl
import textwrap
import time
from pathlib import Path
import socket
import stat
import subprocess
import tempfile
import unittest
import types
from unittest import mock
from typing import Any

ROOT = Path(__file__).resolve().parents[2]



def load_apply() -> Any:
    # Once embedded, exercise precisely the fragment shipped in install.sh.
    text = (ROOT / 'install.sh').read_text()
    begin, end = '# BEGIN AXIONPANEL APPLY ENGINE', '# END AXIONPANEL APPLY ENGINE'
    if begin in text:
        module = types.ModuleType('installer_apply_test')
        exec(compile(text.split(begin, 1)[1].split(end, 1)[0], 'embedded-apply', 'exec'), module.__dict__)
        return module
    spec = importlib.util.spec_from_file_location('installer_apply', ROOT / 'scripts/installer_apply.py')
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_args(ap, *options):
    parser = argparse.ArgumentParser()
    parser.add_argument('--apply', action='store_true')
    ap.add_apply_arguments(parser)
    return parser.parse_args(options)


class ApplyContract(unittest.TestCase):
    def setUp(self):
        self.ap = load_apply()

    def test_install_sh_embeds_the_reviewed_engine_verbatim(self):
        text = (ROOT / 'install.sh').read_text()  # standalone artifact
        begin, end = '# BEGIN AXIONPANEL APPLY ENGINE', '# END AXIONPANEL APPLY ENGINE'
        self.assertIn(begin, text)
        self.assertIn(end, text)
        reviewed = (ROOT / 'scripts/installer_apply.py').read_text()
        embedded = text.split(begin, 1)[1].split(end, 1)[0]
        expected = reviewed.split(begin, 1)[1].split(end, 1)[0]
        self.assertEqual(embedded.strip(), expected.strip())
        self.assertNotIn('apply engine pending wiring', text)

    def args(self, *options):
        return parse_args(self.ap, *options)

    def test_import_preserves_standard_tempfile_defaults_without_tmpdir(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env.pop('TMPDIR', None)
            # Portable standard-library fallback, confined to a disposable fixture.
            env['TMP'] = env['TEMP'] = tmp
            code = textwrap.dedent('''
                import pathlib, sys, tempfile
                import tests.install.test_apply
                assert tempfile.tempdir is None, 'test module overrides tempfile defaults'
                with tempfile.TemporaryDirectory() as directory:
                    assert pathlib.Path(directory).parent == pathlib.Path(sys.argv[1])
                    (pathlib.Path(directory) / 'fixture').write_text('portable')
            ''')
            result = subprocess.run([sys.executable, '-B', '-c', code, tmp],
                                    env=env, cwd=ROOT, capture_output=True,
                                    text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_defaults_and_explicit_consent(self):
        args = self.args('--apply')
        self.assertEqual((args.host, args.port, args.admin), ('auto', 8443, 'admin'))
        with mock.patch.object(self.ap, '_ap_open_tty', side_effect=RuntimeError('apply requires --yes when no terminal is available')), \
             mock.patch.object(self.ap, '_ap_detect_host', return_value='127.0.0.1'):
            with self.assertRaisesRegex(RuntimeError, '--yes|--host'):
                self.ap.validate_apply(args)
        self.ap.validate_apply(self.args())

    def test_option_guards_precede_host_checks(self):
        options = [('--host', '127.000.0.1'), ('--host', 'LOCALHOST'),
                   ('--host', '::01'), ('--host', 'fe80::1%eth0'),
                   ('--host', '::ffff:7f00:1', '--allow-public-listen'), ('--host', '255.255.255.255', '--allow-public-listen'),
                   ('--host', '192.0.2.1'), ('--port', '1023'),
                   ('--port', '65536'), ('--port', '7800'),
                   ('--admin', 'admin\nExecStart=/evil'), ('--admin=-root',),
                   ('--admin', 'a' * 65)]
        with mock.patch.object(self.ap, '_ap_fresh_checks', side_effect=AssertionError('host touched')):
            for option in options:
                with self.subTest(option=option), self.assertRaises(RuntimeError):
                    self.ap.validate_apply(self.args('--apply', '--yes', '--host', '127.0.0.1', *option))

    def test_nonroot_rejected_before_host_checks(self):
        with mock.patch.object(self.ap.ap_os, 'geteuid', return_value=1000):
            with self.assertRaisesRegex(RuntimeError, 'root'):
                self.ap.validate_apply(self.args('--apply', '--yes', '--host', '127.0.0.1'))

    def test_fake_root_and_arch_not_allowed(self):
        args = self.args('--apply', '--yes', '--host', '127.0.0.1')
        for key, value in [('root', Path('/')), ('arch', 'amd64')]:
            setattr(args, key, value)
            with self.assertRaises(RuntimeError):
                self.ap.validate_apply(args)
            delattr(args, key)

    def test_valid_options_call_read_only_checks(self):
        with mock.patch.object(self.ap.ap_os, 'geteuid', return_value=0), mock.patch.object(self.ap, '_ap_fresh_checks') as check:
            self.ap.validate_apply(self.args('--apply', '--yes', '--host', '::1', '--port', '65535'))
            check.assert_called_once()

    def test_no_systemd_pid1_denied(self):
        with mock.patch.object(self.ap.ap_os, 'readlink', return_value='/usr/bin/python3'):
            with self.assertRaisesRegex(RuntimeError, 'systemd PID1'):
                self.ap._ap_check_pid1()

    def test_occupied_port_denied_without_service_mutation(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            with self.assertRaisesRegex(RuntimeError, 'listener'):
                self.ap._ap_check_listener('127.0.0.1', listener.getsockname()[1])

    def test_trusted_directory_rejects_symlink_and_writable_ancestor(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            # The generic walker checks every ancestor, including scratch.
            if os.geteuid() != 0:
                self.skipTest('root-owned directory contract')
            parent = path / 'trusted'
            parent.mkdir(mode=0o700)
            link = path / 'link'
            link.symlink_to(parent, target_is_directory=True)
            with self.assertRaises(RuntimeError):
                self.ap._ap_open_dir(str(link))
            parent.chmod(0o777)
            with self.assertRaises(RuntimeError):
                self.ap._ap_open_dir(str(parent))

    def test_exclusive_write_refuses_existing_file_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Descriptor-based primitive is testable without a production root override.
            fd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self.ap._ap_write_at(fd, 'new', b'hello', 0o600)
                self.assertEqual((Path(tmp) / 'new').read_bytes(), b'hello')
                self.assertEqual(stat.S_IMODE((Path(tmp) / 'new').stat().st_mode), 0o600)
                with self.assertRaises(RuntimeError):
                    self.ap._ap_write_at(fd, 'new', b'replace', 0o600)
                (Path(tmp) / 'link').symlink_to('new')
                with self.assertRaises(RuntimeError):
                    self.ap._ap_write_at(fd, 'link', b'replace', 0o600)
                self.assertEqual((Path(tmp) / 'new').read_bytes(), b'hello')
            finally:
                os.close(fd)

    def test_generated_units_preserve_native_hardening_and_no_interpolation(self):
        args = self.args('--apply', '--yes', '--host', '::1')
        panel, agent = self.ap._ap_units(args)
        template = (ROOT / 'deploy/systemd/axionpanel-native.service.example').read_text()
        def directives(text):
            return dict(line.strip().split('=', 1) for line in text.splitlines()
                        if '=' in line and not line.lstrip().startswith('#'))
        actual, native = directives(panel), directives(template)
        for key in ['NoNewPrivileges', 'ProtectSystem', 'ProtectHome', 'PrivateTmp',
                    'PrivateDevices', 'ProtectKernelTunables', 'ProtectKernelModules',
                    'ProtectKernelLogs', 'ProtectControlGroups', 'ProtectClock',
                    'RestrictAddressFamilies', 'RestrictNamespaces', 'RestrictRealtime',
                    'RestrictSUIDSGID', 'LockPersonality', 'MemoryDenyWriteExecute',
                    'SystemCallArchitectures', 'SystemCallFilter', 'SystemCallErrorNumber',
                    'CapabilityBoundingSet', 'AmbientCapabilities', 'StateDirectoryMode']:
            self.assertEqual(actual[key], native[key], key)
        self.assertIn('-addr [::1]:8443 -origin https://[::1]:8443', panel)
        self.assertNotIn('bootstrap-admin', panel)
        self.assertNotIn('7800', panel)
        self.assertIn('RestrictAddressFamilies=AF_UNIX\n', agent)
        self.assertIn('CapabilityBoundingSet=CAP_CHOWN\n', agent)
        self.assertNotIn('enable-sites', agent)
        args.host = '127.0.0.1\nExecStart=/evil'
        with self.assertRaises(RuntimeError):
            self.ap._ap_units(args)

    def test_generated_units_pass_real_systemd_parser_in_disposable_root(self):
        import shutil
        analyzer = shutil.which('systemd-analyze')
        if not analyzer:
            self.skipTest('systemd-analyze unavailable')
        panel, agent = self.ap._ap_units(self.args('--apply', '--yes', '--host', '127.0.0.1'))
        with tempfile.TemporaryDirectory(prefix='apply-unit-') as tmp:
            root = Path(tmp)
            units = root / 'etc/systemd/system'
            units.mkdir(parents=True)
            (root / 'etc/passwd').write_text('root:x:0:0:root:/root:/usr/sbin/nologin\naxionpanel:x:999:999:AxionPanel:/var/lib/axionpanel:/usr/sbin/nologin\n')
            (root / 'etc/group').write_text('root:x:0:\naxionpanel:x:999:\n')
            (root / 'etc/nsswitch.conf').write_text('passwd: files\ngroup: files\n')
            for target in ('sysinit', 'basic', 'shutdown', 'multi-user', 'network-online', 'local-fs'):
                (units / (target + '.target')).write_text('[Unit]\nDescription=Static verification target\n')
            for name, data in [('axionpanel', panel), ('axionpanel-agent', agent)]:
                (units / (name + '.service')).write_text(data)
                binary = root / ('usr/local/axionpanel/bin/' + name)
                binary.parent.mkdir(parents=True, exist_ok=True)
                binary.write_text('#!/bin/sh\nexit 1\n')
                binary.chmod(0o755)
            result = subprocess.run([analyzer, '--root=' + tmp, 'verify',
                    'axionpanel.service', 'axionpanel-agent.service'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout + result.stderr, '')

    def test_checks_repeat_inside_lock_before_provision(self):
        events = []
        @contextlib.contextmanager
        def lock():
            events.append('lock')
            yield
        def fresh(args):
            events.append('fresh')
            if len(events) == 3:
                raise RuntimeError('became occupied')
        contents = {name: b'authenticated' for name in self.ap._AP_MEMBERS}
        with mock.patch.object(self.ap, '_ap_fresh_checks', side_effect=fresh), \
             mock.patch.object(self.ap, '_ap_lock', side_effect=lock), \
             mock.patch.object(self.ap, '_ap_provision') as provision:
            with self.assertRaises(RuntimeError):
                self.ap.apply_install(self.args('--apply', '--yes', '--host', '127.0.0.1'), contents)
            provision.assert_not_called()
        self.assertEqual(events, ['fresh', 'lock', 'fresh'])

    def test_commands_are_absolute_environment_isolated_and_outputs_suppressed(self):
        result = subprocess.CompletedProcess([], 1, b'SECRET', b'ENTRANCE')
        with mock.patch.object(self.ap, '_ap_check_command'), mock.patch.object(self.ap.ap_subprocess, 'run', return_value=result) as run:
            with self.assertRaises(RuntimeError) as error:
                self.ap._ap_run(['/usr/bin/systemctl', 'is-active', 'axionpanel.service'])
            self.assertNotIn('SECRET', str(error.exception))
            self.assertNotIn('ENTRANCE', str(error.exception))
            self.assertEqual(run.call_args.kwargs['env']['PATH'], '/usr/sbin:/usr/bin:/sbin:/bin')
            self.assertNotIn('LD_PRELOAD', run.call_args.kwargs['env'])
        with self.assertRaises(RuntimeError):
            self.ap._ap_run(['systemctl', 'stop', 'anything'])

    def test_apply_revalidates_before_lock_or_mutation(self):
        with mock.patch.object(self.ap, '_ap_fresh_checks', side_effect=RuntimeError('not fresh')), mock.patch.object(self.ap, '_ap_lock') as lock:
            with self.assertRaisesRegex(RuntimeError, 'not fresh'):
                self.ap.apply_install(self.args('--apply', '--yes', '--host', '127.0.0.1'), {})
            lock.assert_not_called()

    def test_apply_is_mutually_exclusive_with_inspection_modes(self):
        """`--apply --verify-only` must fail instead of silently inspecting."""
        import subprocess
        script = ROOT / 'install.sh'
        for mode in ('--preflight-only', '--verify-only'):
            completed = subprocess.run(
                ['bash', str(script), mode, '--apply', '--yes', '--version', '1.0.0',
                 '--public-key', '/etc/hostname', '--directory', tempfile.gettempdir()],
                capture_output=True, text=True, timeout=60,
                env={'PATH': '/usr/sbin:/usr/bin:/bin'})
            self.assertEqual(completed.returncode, 2, completed.stderr)
            self.assertIn('not allowed with argument', completed.stderr)

    def test_lock_error_scope_only_covers_acquisition(self):
        with tempfile.TemporaryDirectory() as tmp:
            fd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(self.ap, '_ap_open_dir', return_value=os.dup(fd)):
                    with self.assertRaisesRegex(OSError, 'provisioning disk failure'):
                        with self.ap._ap_lock():
                            raise OSError('provisioning disk failure')
                lock = Path(tmp) / 'axionpanel-install.lock'
                self.assertTrue(lock.is_file())
                self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)
                self.assertEqual(lock.read_bytes(), b'')
                self.assertEqual(list(Path(tmp).iterdir()), [lock])
            finally:
                os.close(fd)

    @contextlib.contextmanager
    def os_release_fixture(self, data):
        """Redirect only read-only OS descriptors into disposable scratch."""
        with tempfile.TemporaryDirectory(prefix='apply-os-') as tmp:
            root = Path(tmp)
            (root / 'etc').mkdir()
            (root / 'usr/lib').mkdir(parents=True)
            (root / 'etc').chmod(0o755)
            (root / 'usr').chmod(0o755)
            (root / 'usr/lib').chmod(0o755)
            if data is not None:
                (root / 'etc/os-release').write_bytes(data)
            open_dir = self.ap._ap_open_dir
            def directory(path):
                if path in ('/etc', '/usr/lib'):
                    return open_dir(str(root) + path)
                raise AssertionError('unexpected host directory: ' + path)
            with mock.patch.object(self.ap, '_ap_open_dir', side_effect=directory), \
                 mock.patch.object(self.ap.ap_os, 'geteuid', return_value=0), \
                 mock.patch.object(self.ap, '_ap_check_pid1', side_effect=RuntimeError('OS accepted')) as pid1, \
                 mock.patch.object(self.ap, '_ap_provision') as provision, \
                 mock.patch.object(self.ap, '_ap_lock') as lock, \
                 mock.patch.object(self.ap.ap_subprocess, 'run') as run:
                yield root, pid1
                provision.assert_not_called()
                lock.assert_not_called()
                run.assert_not_called()

    def test_unsupported_os_denied_before_other_checks_or_mutation(self):
        with self.os_release_fixture(b'ID=ubuntu\nVERSION_ID="22.04"\n') as (_, pid1):
            with self.assertRaisesRegex(RuntimeError, 'unsupported OS'):
                self.ap.validate_apply(self.args('--apply', '--yes', '--host', '127.0.0.1'))
            pid1.assert_not_called()

    def test_missing_os_release_denied(self):
        with self.os_release_fixture(None) as (_, pid1):
            with self.assertRaisesRegex(RuntimeError, 'prerequisites could not be checked'):
                self.ap.validate_apply(self.args('--apply', '--yes', '--host', '127.0.0.1'))
            pid1.assert_not_called()

    def test_malformed_os_release_denied(self):
        with self.os_release_fixture(b'ID=ubuntu\nVERSION_ID="24.04"\nID=ubuntu\n') as (_, pid1):
            with self.assertRaisesRegex(RuntimeError, 'ambiguous os-release'):
                self.ap.validate_apply(self.args('--apply', '--yes', '--host', '127.0.0.1'))
            pid1.assert_not_called()

    def test_unsupported_distro_denied(self):
        with self.os_release_fixture(b'ID=centos\nVERSION_ID="9"\n') as (_, pid1):
            with self.assertRaisesRegex(RuntimeError, 'unsupported OS'):
                self.ap.validate_apply(self.args('--apply', '--yes', '--host', '127.0.0.1'))
            pid1.assert_not_called()

    def test_supported_os_accepted(self):
        for data in (b'ID=ubuntu\nVERSION_ID="24.04"\n', b'ID=ubuntu\nVERSION_ID="26.04"\n',
                     b'ID=debian\nVERSION_ID="12"\n', b'ID=debian\nVERSION_ID="13"\n'):
            with self.subTest(data=data):
                with self.os_release_fixture(data) as (_, pid1):
                    with self.assertRaisesRegex(RuntimeError, 'OS accepted'):
                        self.ap.validate_apply(self.args('--apply', '--yes', '--host', '127.0.0.1'))
                    pid1.assert_called_once()

    def test_os_release_symlink_to_usr_lib_accepted(self):
        for spelling in ('../usr/lib/os-release', '/usr/lib/os-release'):
            with self.subTest(spelling=spelling), self.os_release_fixture(None) as (root, pid1):
                (root / 'usr/lib/os-release').write_bytes(b'ID=ubuntu\nVERSION_ID="24.04"\n')
                (root / 'etc/os-release').symlink_to(spelling)
                with self.assertRaisesRegex(RuntimeError, 'OS accepted'):
                    self.ap.validate_apply(self.args('--apply', '--yes', '--host', '127.0.0.1'))
                pid1.assert_called_once()

    def test_os_release_single_quotes_are_balanced(self):
        with self.os_release_fixture(b"ID='ubuntu'\nVERSION_ID='24.04'\n") as (_, pid1):
            with self.assertRaisesRegex(RuntimeError, 'OS accepted'):
                self.ap.validate_apply(self.args('--apply', '--yes', '--host', '127.0.0.1'))
            pid1.assert_called_once()
        for data in (b"ID='ubuntu\nVERSION_ID=24.04\n",
                     b"ID=ubuntu\nVERSION_ID='24.04\n"):
            with self.subTest(data=data), self.os_release_fixture(data) as (_, pid1):
                with self.assertRaisesRegex(RuntimeError, 'malformed os-release'):
                    self.ap.validate_apply(self.args('--apply', '--yes', '--host', '127.0.0.1'))
                pid1.assert_not_called()

    def test_os_release_invalid_utf8_denied(self):
        with self.os_release_fixture(b'ID=ubuntu\nVERSION_ID="24.04"\n\xff\xfe\n') as (_, pid1):
            with self.assertRaisesRegex(RuntimeError, 'malformed os-release'):
                self.ap.validate_apply(self.args('--apply', '--yes', '--host', '127.0.0.1'))
            pid1.assert_not_called()

    def test_malformed_relevant_os_assignments_cannot_hide_behind_valid_ones(self):
        for extra in (b'ID=$(touch forbidden)\n', b'VERSION_ID="24.04\n',
                      b'ID =ubuntu\n', b'export ID=ubuntu\n', b'\x00\n'):
            with self.subTest(extra=extra), self.os_release_fixture(
                    b'ID=ubuntu\nVERSION_ID="24.04"\n' + extra) as (_, pid1):
                with self.assertRaisesRegex(RuntimeError, 'malformed os-release'):
                    self.ap.validate_apply(self.args('--apply', '--yes', '--host', '127.0.0.1'))
                pid1.assert_not_called()

    def test_os_release_bounds_and_unsafe_files_fail_closed(self):
        for kind in ('oversized', 'writable', 'foreign', 'hardlink', 'fifo', 'directory',
                     'arbitrary-link', 'foreign-link', 'target-link', 'writable-target', 'unsafe-ancestor'):
            with self.subTest(kind=kind), self.os_release_fixture(None) as (root, pid1):
                path = root / 'etc/os-release'
                data = b'ID=ubuntu\nVERSION_ID="24.04"\n'
                if kind == 'fifo':
                    os.mkfifo(path)
                elif kind == 'directory':
                    path.mkdir()
                elif kind == 'arbitrary-link':
                    (root / 'etc/other').write_bytes(data)
                    path.symlink_to('other')
                elif kind in ('foreign-link', 'target-link', 'writable-target', 'unsafe-ancestor'):
                    target = root / 'usr/lib/os-release'
                    if kind == 'foreign-link':
                        target.write_bytes(data)
                        os.chmod(target.parent, 0o755)
                        os.chown(target, 65534, 65534)
                    elif kind == 'target-link':
                        (root / 'usr/lib/other').write_bytes(data)
                        target.symlink_to('other')
                    else:
                        target.write_bytes(data)
                        (target if kind == 'writable-target' else target.parent).chmod(0o777)
                    path.symlink_to('../usr/lib/os-release')
                else:
                    path.write_bytes(data + (b'#' * 65536 if kind == 'oversized' else b''))
                    if kind == 'writable':
                        path.chmod(0o666)
                    elif kind == 'foreign':
                        os.chown(path, 65534, 65534)
                    elif kind == 'hardlink':
                        os.link(path, root / 'etc/alias')
                with self.assertRaises(RuntimeError):
                    self.ap.validate_apply(self.args('--apply', '--yes', '--host', '127.0.0.1'))
                pid1.assert_not_called()

    def test_os_validation_repeats_under_lock_before_provisioning(self):
        with self.os_release_fixture(b'ID=ubuntu\nVERSION_ID="24.04"\n') as (root, _):
            events = []
            @contextlib.contextmanager
            def lock():
                events.append('lock')
                (root / 'etc/os-release').write_bytes(b'ID=ubuntu\nVERSION_ID="22.04"\n')
                yield
            def pid1():
                events.append('supported')
                raise RuntimeError('end read-only checks')
            real_checks = self.ap._ap_fresh_checks
            def fresh(args):
                try:
                    real_checks(args)
                except RuntimeError as error:
                    if str(error) != 'end read-only checks':
                        raise
            with mock.patch.object(self.ap, '_ap_check_pid1', side_effect=pid1), \
                 mock.patch.object(self.ap, '_ap_fresh_checks', side_effect=fresh), \
                 mock.patch.object(self.ap, '_ap_lock', side_effect=lock), \
                 mock.patch.object(self.ap, '_ap_provision') as provision:
                contents = {name: b'authenticated' for name in self.ap._AP_MEMBERS}
                with self.assertRaisesRegex(RuntimeError, 'refused before provisioning'):
                    self.ap.apply_install(self.args('--apply', '--yes', '--host', '127.0.0.1'), contents)
                provision.assert_not_called()
                self.assertEqual(events, ['supported', 'lock'])

    def test_main_rejects_firewall_without_apply_before_acquisition(self):
        text = (ROOT / 'install.sh').read_text().split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        text = text.split('\ntry:\n    main()\n', 1)[0]
        module = types.ModuleType('installer_main_options_test')
        exec(compile(text, 'standalone-main', 'exec'), module.__dict__)
        for mode in (('--verify-only',), ('--preflight-only',), ()):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp, \
                 mock.patch.object(module.sys, 'argv', ['install.sh', *mode,
                     '--version', '1.0.0', '--public-key', str(Path(tmp) / 'public.pem'),
                     '--stage-dir', str(Path(tmp) / 'stage'), '--open-firewall']), \
                 mock.patch.object(module, 'read_public_key', side_effect=AssertionError('key read')) as key, \
                 mock.patch.object(module, 'acquire_sources', side_effect=AssertionError('acquired')) as acquire, \
                 mock.patch.object(module, 'snapshot_inputs', side_effect=AssertionError('snapshot')) as snapshot, \
                 mock.patch.object(module, 'open_stage_parent', side_effect=AssertionError('stage')) as stage, \
                 mock.patch.object(module, '_ap_detect_host', side_effect=AssertionError('discovery')), \
                 mock.patch.object(module.ap_os, 'geteuid', side_effect=AssertionError('root')), \
                 mock.patch.object(module, '_ap_fresh_checks', side_effect=AssertionError('host')):
                with self.assertRaisesRegex(RuntimeError, '--open-firewall requires --apply'):
                    module.main()
                for operation in (key, acquire, snapshot, stage):
                    operation.assert_not_called()

    def test_main_ordinary_inspection_validates_without_host_checks(self):
        text = (ROOT / 'install.sh').read_text().split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        text = text.split('\ntry:\n    main()\n', 1)[0]
        module = types.ModuleType('installer_main_inspection_test')
        exec(compile(text, 'standalone-main', 'exec'), module.__dict__)
        for mode in (('--verify-only',), ('--preflight-only',), ()):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp, \
                 mock.patch.object(module.sys, 'argv', ['install.sh', *mode,
                     '--version', '1.0.0', '--public-key', str(Path(tmp) / 'public.pem'),
                     '--stage-dir', str(Path(tmp) / 'stage')]), \
                 mock.patch.object(module, 'validate_apply', wraps=module.validate_apply) as validate, \
                 mock.patch.object(module, 'read_public_key', side_effect=RuntimeError('key boundary')) as key, \
                 mock.patch.object(module, '_ap_detect_host', side_effect=AssertionError('discovery')), \
                 mock.patch.object(module.ap_os, 'geteuid', side_effect=AssertionError('root')), \
                 mock.patch.object(module, '_ap_fresh_checks', side_effect=AssertionError('host')):
                with self.assertRaisesRegex(RuntimeError, 'key boundary'):
                    module.main()
                validate.assert_called_once()
                key.assert_called_once()
                self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_main_refuses_unsupported_os_before_acquisition_or_stage_creation(self):
        text = (ROOT / 'install.sh').read_text().split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        text = text.split('\ntry:\n    main()\n', 1)[0]
        module = types.ModuleType('installer_main_test')
        exec(compile(text, 'standalone-main', 'exec'), module.__dict__)
        with mock.patch.object(module, 'parse_args', return_value=argparse.Namespace(
                apply=True, preflight_only=False, verify_only=False, version='1.0.0',
                arch=None, root=None, stage_dir=None, directory=None, download_base_url=None, yes=True,
                host='127.0.0.1', port=8443, admin='admin', open_firewall=False)), \
             mock.patch.object(module, '_ap_options'), \
             mock.patch.object(module, '_ap_read', return_value=b'ID=ubuntu\nVERSION_ID="22.04"\n'), \
             mock.patch.object(module, 'read_public_key') as key, \
             mock.patch.object(module, 'acquire_sources') as acquire, \
             mock.patch.object(module, 'snapshot_inputs') as snapshot, \
             mock.patch.object(module.tempfile, 'mkdtemp') as stage:
            with self.assertRaisesRegex(RuntimeError, 'unsupported OS'):
                module.main()
            for operation in (key, acquire, snapshot, stage):
                operation.assert_not_called()


    def test_state_files_created_under_runuser_are_normalized_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            uid = os.getuid()
            database = Path(tmp) / 'panel.db'
            database.write_bytes(b'sqlite')
            database.chmod(0o644)
            secret = Path(tmp) / 'secret.key'
            secret.write_bytes(b'k')
            secret.chmod(0o644)
            target = Path(tmp) / 'elsewhere'
            target.write_bytes(b'preserve')
            self.ap._ap_private_files(uid, tmp, ('panel.db', 'secret.key', 'absent'))
            self.assertEqual(stat.S_IMODE(database.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(secret.stat().st_mode), 0o600)
            (Path(tmp) / 'panel.db-wal').symlink_to(target)
            with self.assertRaisesRegex(RuntimeError, 'unavailable or unsafe'):
                self.ap._ap_private_files(uid, tmp, ('panel.db-wal',))
            self.assertEqual(target.read_bytes(), b'preserve')
            foreign = Path(tmp) / 'foreign.db'
            foreign.write_bytes(b'x')
            if os.getuid() == 0:
                os.chown(foreign, 65534, 65534)
                with self.assertRaisesRegex(RuntimeError, 'ownership'):
                    self.ap._ap_private_files(uid, tmp, ('foreign.db',))

    def test_authenticated_readiness_probes_exact_login_and_agent_data(self):
        calls = []
        def request(method, path, body=None, csrf=None):
            calls.append((method, path, body, csrf))
            if path == '/api/health':
                return 200, {'status': 'ok'}
            if path == '/login':
                return 200, b'<html></html>'
            if path == '/api/v1/auth/login':
                return 200, {'mfa_required': False, 'csrf_token': 'private'}
            if path == '/api/v1/system/info':
                return 200, {'connected': True, 'hostname': 'isolated'}
            if path == '/api/v1/auth/logout':
                return 200, {}
            # The production helper returns only the required 303 and never
            # follows the redirect itself.
            return 303, None
        self.ap._ap_probe_authenticated(request, {'username': 'admin', 'password': 'secret', 'entrance_path': '/abcdefghijkl'})
        self.assertEqual([c[:2] for c in calls], [('GET', '/abcdefghijkl'), ('GET', '/login'),
            ('GET', '/api/health'), ('POST', '/api/v1/auth/login'),
            ('GET', '/api/v1/system/info'), ('POST', '/api/v1/auth/logout')])
        self.assertEqual(calls[3][2], {'username': 'admin', 'password': 'secret'})
        self.assertEqual(calls[-1][3], 'private')

    def test_lock_rejects_symlink_and_preserves_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            target = directory / 'unrelated'
            target.write_bytes(b'preserve')
            (directory / 'axionpanel-install.lock').symlink_to(target)
            fd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(self.ap, '_ap_open_dir', return_value=os.dup(fd)):
                    with self.assertRaises(RuntimeError):
                        with self.ap._ap_lock():
                            self.fail('symlink lock granted')
                self.assertEqual(target.read_bytes(), b'preserve')
            finally:
                os.close(fd)

    def test_payload_shape_rejected_before_lock(self):
        with mock.patch.object(self.ap, '_ap_fresh_checks'), mock.patch.object(self.ap, '_ap_lock') as lock:
            with self.assertRaisesRegex(RuntimeError, 'exact installer payload'):
                self.ap.apply_install(self.args('--apply', '--yes', '--host', '127.0.0.1'), {'axionpanel': b'x'})
            lock.assert_not_called()

    def test_failure_stops_only_new_units_and_preserves_partial_state(self):
        args = self.args('--apply', '--yes', '--host', '127.0.0.1')
        contents = {name: b'authenticated' for name in self.ap._AP_MEMBERS}
        commands = []
        def run(command):
            commands.append(command)
            if 'start' in command and command[-1] == 'axionpanel.service':
                raise RuntimeError('sensitive captured output')
            return b''
        with mock.patch.object(self.ap, '_ap_fresh_checks'), \
             mock.patch.object(self.ap, '_ap_lock', return_value=contextlib.nullcontext()), \
             mock.patch.object(self.ap, '_ap_provision', return_value=991), \
             mock.patch.object(self.ap, '_ap_run', side_effect=run), \
             mock.patch.object(self.ap, '_ap_readiness') as readiness:
            with self.assertRaisesRegex(RuntimeError, 'partial data preserved; manual reconciliation') as error:
                self.ap.apply_install(args, contents)
            self.assertNotIn('sensitive', str(error.exception))
            readiness.assert_not_called()
        stopped = [c[-1] for c in commands if 'stop' in c]
        self.assertEqual(stopped, ['axionpanel.service', 'axionpanel-agent.service'])
        self.assertFalse(any('disable' in c or 'restart' in c or 'reset-failed' in c for c in commands))

    def test_failure_cleanup_happens_before_lock_release(self):
        held = False
        events = []
        @contextlib.contextmanager
        def lock():
            nonlocal held
            held = True
            try:
                yield
            finally:
                held = False
                events.append('unlock')
        def run(command):
            if 'start' in command and command[-1] == 'axionpanel.service':
                raise RuntimeError('injected start failure')
            if 'stop' in command:
                events.append(('cleanup', held))
            return b''
        with mock.patch.object(self.ap, '_ap_fresh_checks'), \
             mock.patch.object(self.ap, '_ap_lock', side_effect=lock), \
             mock.patch.object(self.ap, '_ap_provision', return_value=991), \
             mock.patch.object(self.ap, '_ap_run', side_effect=run), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, 'manual reconciliation'):
                self.ap.apply_install(self.args('--apply', '--yes', '--host', '127.0.0.1'),
                                      {name: b'x' for name in self.ap._AP_MEMBERS})
        self.assertEqual(events, [('cleanup', True), ('cleanup', True), 'unlock'])

    def test_read_only_checks_validate_optional_sysusers_ancestor_before_mutation(self):
        args = self.args('--apply', '--yes', '--host', '127.0.0.1')
        checked = []
        def directory(path):
            checked.append(path)
            if path == '/etc/sysusers.d':
                raise RuntimeError('unsafe sysusers directory')
            return 42
        with mock.patch.object(self.ap, '_ap_check_pid1'), \
             mock.patch.object(self.ap, '_ap_check_os'), \
             mock.patch.object(self.ap, '_ap_check_command'), \
             mock.patch.object(self.ap, '_ap_open_dir', side_effect=directory), \
             mock.patch.object(self.ap.ap_os, 'close'), \
             mock.patch.object(self.ap.ap_os.path, 'lexists', side_effect=lambda p: p == '/etc/sysusers.d'), \
             mock.patch.object(self.ap, '_ap_read', return_value=b''), \
             mock.patch.object(self.ap.ap_pwd, 'getpwnam', side_effect=KeyError), \
             mock.patch.object(self.ap.ap_grp, 'getgrnam', side_effect=KeyError), \
             mock.patch.object(self.ap.ap_os, 'listdir', return_value=[]), \
             mock.patch.object(self.ap, '_ap_run', return_value=b'not-found\n'), \
             mock.patch.object(self.ap, '_ap_check_listener'):
            with self.assertRaisesRegex(RuntimeError, 'unsafe sysusers'):
                self.ap._ap_fresh_checks(args)
        self.assertIn('/etc/sysusers.d', checked)

    def test_entrance_must_redirect_instead_of_returning_decoy_page(self):
        def request(method, path, body=None, csrf=None):
            return {'/api/health': (200, {'status': 'ok'}),
                    '/login': (200, b'<html></html>'),
                    '/api/v1/auth/login': (200, {'mfa_required': False, 'csrf_token': 'private'}),
                    '/api/v1/system/info': (200, {'connected': True, 'hostname': 'isolated'}),
                    '/api/v1/auth/logout': (200, {})}.get(path, (200, b'<html></html>'))
        with self.assertRaisesRegex(RuntimeError, 'entrance readiness'):
            self.ap._ap_probe_authenticated(request, {'username': 'admin', 'password': 'secret', 'entrance_path': '/abcdefghijkl'})

    def test_mfa_or_disconnected_agent_never_claim_success(self):
        for login, info in [({'mfa_required': True}, {'connected': True}),
                            ({'mfa_required': False, 'csrf_token': 'private'}, {'connected': False})]:
            def request(method, path, body=None, csrf=None):
                if path == '/abcdefghijkl':
                    return 303, b''
                return 200, {'/api/health': {'status': 'ok'}, '/api/v1/auth/login': login,
                             '/api/v1/system/info': info}.get(path, b'<html></html>')
            
            with self.subTest(login=login), self.assertRaises(RuntimeError):
                self.ap._ap_probe_authenticated(request, {'username': 'admin', 'password': 'secret', 'entrance_path': '/abcdefghijkl'})

    def _readiness_transport(self, health, replies, entrance_location='/login', seen=None):
        """Exercise the production nested request helper at the HTTPS boundary.

        Injects a fake ``HTTPSConnection`` into the real ``_ap_readiness``; the
        JSON / cookie / redirect guards live in the nested helper itself, so no
        request injection at the probe level.
        """
        with tempfile.TemporaryDirectory() as tmp:
            key, cert = Path(tmp) / 'key.pem', Path(tmp) / 'panel.crt'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ed25519', '-nodes', '-days', '1',
                            '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1',
                            '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
            pem = cert.read_bytes()
            pinned = self.ap.ap_ssl.PEM_cert_to_DER_cert(pem.decode('ascii'))
            bootstrap = {'origin': 'https://127.0.0.1:8443', 'username': 'admin',
                         'password': 'secret', 'entrance_path': '/abcdefghijkl'}
            seen = seen if seen is not None else []
            connections = []

            class Socket:
                def getpeercert(self, binary_form=False):
                    return pinned

            class Response:
                def __init__(self, status, body, headers):
                    self.status, self.body, self.headers = status, body, headers

                def getheaders(self):
                    return list(self.headers.items())

                def getheader(self, name, default=None):
                    return self.headers.get(name)

                def read(self, limit):
                    return self.body

            class Connection:
                def __init__(self, host, port, context=None, timeout=None):
                    self.sock = Socket()
                    self.closed = False
                    connections.append(self)

                def connect(self):
                    pass

                def request(self, method, path, body=None, headers=None):
                    self.requested_headers = dict(headers or {})
                    seen.append((method, path, dict(headers or {})))

                def getresponse(self):
                    path = seen[-1][1]
                    if path == '/api/health':
                        status, body = health.pop(0)
                        return Response(status, body, {})
                    if path == bootstrap['entrance_path']:
                        return Response(303, b'', {'Location': entrance_location,
                            'Set-Cookie': 'axp_entrance=private; Path=/'})
                    if path in replies:
                        return Response(*replies[path])
                    return Response(404, b'Not Found', {})

                def close(self):
                    self.closed = True

            reads = {self.ap._AP_STATE + '/bootstrap.json': self.ap.ap_json.dumps(bootstrap).encode(),
                     self.ap._AP_CERT: pem}

            def read(path, limit, uid=0, private=False):
                return reads[path]

            args = parse_args(self.ap, '--apply', '--yes', '--host', '127.0.0.1')
            with mock.patch.object(self.ap, '_ap_read', side_effect=read), \
                 mock.patch.object(self.ap.ap_http, 'HTTPSConnection', Connection):
                try:
                    fingerprint = self.ap._ap_readiness(args, os.getuid())
                finally:
                    self.assertTrue(all(connection.closed for connection in connections))
            self.assertEqual(fingerprint, self.ap.ap_hashlib.sha256(pinned).hexdigest())
            return seen, health

    def test_readiness_transport_handles_plain_text_entrance_denial(self):
        """The undiscovered entrance gate answers 404 with a bare 'Not Found' body."""
        seen, health = self._readiness_transport(
            [(404, b'Not Found\n'), (200, b'{"status": "ok"}')],
            {'/login': (200, b'<html></html>', {}),
             '/api/v1/auth/login': (200, b'{"mfa_required": false, "csrf_token": "private"}', {}),
             '/api/v1/system/info': (200, b'{"connected": true, "hostname": "isolated"}', {}),
             '/api/v1/auth/logout': (200, b'{}', {})})
        self.assertEqual([p for _, p, _ in seen], ['/api/health', '/abcdefghijkl',
                         '/login', '/api/health', '/api/v1/auth/login', '/api/v1/system/info',
                         '/api/v1/auth/logout'])
        self.assertEqual(health, [])

    def test_readiness_transport_rejects_non_object_health_json(self):
        """The nested helper must refuse a list body at /api/health, not the probe."""
        for document in (b'[]', b'null', b'"text"', b'false', b'1'):
            with self.subTest(document=document), self.assertRaisesRegex(
                    RuntimeError, 'readiness document is not an object'):
                self._readiness_transport(
                    [(404, b'Not Found\n'), (200, document)],
                    {'/login': (200, b'<html></html>', {})})

    def test_readiness_transport_rejects_wrong_entrance_location(self):
        """Refuse a wrong redirect before following it or sending credentials."""
        for location in ('/evil', 'https://elsewhere.invalid/login', None):
            seen = []
            with self.subTest(location=location), self.assertRaisesRegex(
                    RuntimeError, 'unexpected readiness redirect'):
                self._readiness_transport(
                    [(404, b'Not Found\n'), (200, b'{"status": "ok"}')],
                    {}, entrance_location=location, seen=seen)
            self.assertEqual([p for _, p, _ in seen], ['/api/health', '/abcdefghijkl'])
            # The gate cookie is received in the refused redirect response;
            # no subsequent request may replay it to a redirect-selected path.
            self.assertNotIn('Cookie', seen[-1][2])
            self.assertTrue(all(method == 'GET' for method, _, _ in seen))
            self.assertTrue(all('X-CSRF-Token' not in headers for _, _, headers in seen))
            self.assertNotIn('secret', repr(seen))

    def test_readiness_cookie_session_flows_through_nested_helper(self):
        """Set-Cookie from the transport must be replayed on the next request."""
        replies = {'/login': (200, b'<html></html>',
                              {'Set-Cookie': 'untrusted_cookie=ignored; Path=/'}),
             '/api/v1/auth/login': (200, b'{"mfa_required": false, "csrf_token": "private"}',
                                    {'Set-Cookie': 'axp_session=session-value; Path=/'}),
             '/api/v1/system/info': (200, b'{"connected": true, "hostname": "isolated"}',
                                     {'Set-Cookie': 'axp_entrance=; Max-Age=-1; Path=/'}),
             '/api/v1/auth/logout': (200, b'{}', {})}
        seen = []
        self._readiness_transport(
            [(404, b'Not Found\n'), (200, b'{"status": "ok"}')],
            replies, seen=seen)
        info_headers = [h for _, p, h in seen if p == '/api/v1/system/info'][0]
        self.assertEqual(info_headers.get('Cookie'), 'axp_entrance=private; axp_session=session-value')
        logout_headers = seen[-1][2]
        self.assertEqual(logout_headers.get('Cookie'), 'axp_session=session-value')
        self.assertEqual(logout_headers.get('X-CSRF-Token'), 'private')
        self.assertEqual(logout_headers.get('Origin'), 'https://127.0.0.1:8443')
        self.assertTrue(all('untrusted_cookie' not in headers.get('Cookie', '')
                            for _, _, headers in seen))


class DirectListenerDiscovery(unittest.TestCase):
    """Direct identity, route discovery and explicit ufw consent."""

    def setUp(self):
        self.ap = load_apply()

    def args(self, *options):
        return parse_args(self.ap, '--apply', '--yes', *options)

    def test_default_host_is_auto(self):
        args = self.args()
        self.assertEqual((args.host, args.open_firewall), ('auto', False))

    def test_auto_requires_explicit_public_listen_consent(self):
        args = self.args()
        with mock.patch.object(self.ap, '_ap_detect_host', return_value='198.51.100.7'), \
             mock.patch.object(self.ap.ap_os, 'geteuid', return_value=0), \
             mock.patch.object(self.ap, '_ap_fresh_checks') as fresh:
            with self.assertRaisesRegex(RuntimeError, '--allow-public-listen'):
                self.ap.validate_apply(args)
            fresh.assert_not_called()

    def test_auto_resolves_once_and_stays_pinned(self):
        args = self.args('--allow-public-listen')
        with mock.patch.object(self.ap, '_ap_detect_host', return_value='198.51.100.7') as detect, \
             mock.patch.object(self.ap.ap_os, 'geteuid', return_value=0), \
             mock.patch.object(self.ap, '_ap_fresh_checks'):
            self.ap.validate_apply(args)
            self.ap.validate_apply(args)
            detect.assert_called_once()
        self.assertEqual(args.host, '198.51.100.7')

    def test_unusable_detected_address_is_refused(self):
        for value in ('127.0.0.1', '::1', '0.0.0.0', '::', '169.254.1.1', 'fe80::1',
                      '224.0.0.5', '192.0.2.1.1', '198.51.100.07', '', 'localhost', '2001:db8::1'):
            args = self.args('--allow-public-listen')
            with self.subTest(value=value), \
                 mock.patch.object(self.ap, '_ap_detect_host', return_value=value), \
                 mock.patch.object(self.ap.ap_os, 'geteuid', return_value=0), \
                 mock.patch.object(self.ap, '_ap_fresh_checks') as fresh:
                with self.assertRaisesRegex(RuntimeError, '--host'):
                    self.ap.validate_apply(args)
                fresh.assert_not_called()

    def test_detection_probes_the_route_without_sending_traffic(self):
        seen = {}

        class Probe:
            def __init__(self, family, kind):
                seen['family'], seen['kind'] = family, kind

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                seen['closed'] = True

            def connect(self, address):
                seen['connect'] = address

            def getsockname(self):
                return ('198.51.100.7', 0)

        with mock.patch.object(self.ap.ap_socket, 'socket', Probe):
            self.assertEqual(self.ap._ap_detect_host(), '198.51.100.7')
        self.assertEqual((seen['family'], seen['kind']),
                         (self.ap.ap_socket.AF_INET, self.ap.ap_socket.SOCK_DGRAM))
        target = self.ap.ap_ipaddress.ip_address(seen['connect'][0])
        self.assertIn(target, self.ap.ap_ipaddress.ip_network('198.51.100.0/24'))
        self.assertTrue(seen.get('closed'))

    def test_detection_failure_names_the_explicit_alternative(self):
        def fail(*args, **kwargs):
            raise OSError('network unreachable')
        with mock.patch.object(self.ap.ap_socket, 'socket', fail):
            with self.assertRaisesRegex(RuntimeError, '--host'):
                self.ap._ap_detect_host()

    def test_explicit_loopback_host_needs_no_public_consent(self):
        args = self.args('--host', '127.0.0.1')
        with mock.patch.object(self.ap, '_ap_fresh_checks', side_effect=RuntimeError('checks reached')), \
             mock.patch.object(self.ap, '_ap_detect_host', side_effect=AssertionError('probed')), \
             mock.patch.object(self.ap.ap_os, 'geteuid', return_value=0):
            with self.assertRaisesRegex(RuntimeError, 'checks reached'):
                self.ap.validate_apply(args)
        self.assertEqual(args.host, '127.0.0.1')

    def validated(self, *options):
        args = self.args(*options)
        with mock.patch.object(self.ap, '_ap_fresh_checks'), \
             mock.patch.object(self.ap, '_ap_detect_host', side_effect=AssertionError('probed')), \
             mock.patch.object(self.ap.ap_os, 'geteuid', return_value=0), \
             contextlib.redirect_stdout(io.StringIO()):
            self.ap.validate_apply(args)
        return args

    def test_yes_displays_the_full_plan_once_before_checks(self):
        args = parse_args(self.ap, '--apply', '--yes', '--host', '127.0.0.1')
        with mock.patch.object(self.ap, '_ap_fresh_checks'), \
             mock.patch.object(self.ap.ap_os, 'geteuid', return_value=0), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.ap.validate_apply(args)
            first_run = output.getvalue()
            self.ap.validate_apply(args)
        for text in ('Listen: 127.0.0.1:8443', 'Origin: https://127.0.0.1:8443',
                     'Administrator: admin', 'Firewall: unchanged'):
            with self.subTest(text=text):
                self.assertEqual(first_run.count(text), 1)

    def test_inspection_never_discovers_or_requires_root(self):
        with mock.patch.object(self.ap, '_ap_detect_host', side_effect=AssertionError('discovery')), \
             mock.patch.object(self.ap.ap_os, 'geteuid', side_effect=AssertionError('root')):
            self.ap.validate_apply(parse_args(self.ap))

    def test_public_ip_option_is_not_supported(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.args('--public-ip', '198.51.100.7')

    def test_open_firewall_requires_apply_and_a_public_origin(self):
        for option in (('--open-firewall',),):
            with self.subTest(option=option), self.assertRaisesRegex(RuntimeError, '--apply'):
                self.ap.validate_apply(parse_args(self.ap, *option))
        for option in (('--host', '127.0.0.1', '--open-firewall'),
                       ('--host', '::1', '--open-firewall')):
            args = self.args(*option)
            with self.subTest(option=option), \
                 mock.patch.object(self.ap, '_ap_fresh_checks') as fresh, \
                 mock.patch.object(self.ap.ap_os, 'geteuid', return_value=0):
                with self.assertRaisesRegex(RuntimeError, 'loopback'):
                    self.ap.validate_apply(args)
                fresh.assert_not_called()

    def test_ufw_is_not_required_without_the_flag(self):
        checked = []
        args = self.validated('--host', '127.0.0.1')
        with mock.patch.object(self.ap, '_ap_check_os'), \
             mock.patch.object(self.ap, '_ap_check_pid1'), \
             mock.patch.object(self.ap, '_ap_check_command', side_effect=checked.append), \
             mock.patch.object(self.ap, '_ap_open_dir', return_value=7), \
             mock.patch.object(self.ap.ap_os, 'close'), \
             mock.patch.object(self.ap.ap_os.path, 'lexists', return_value=False), \
             mock.patch.object(self.ap, '_ap_read', return_value=b''), \
             mock.patch.object(self.ap.ap_pwd, 'getpwnam', side_effect=KeyError), \
             mock.patch.object(self.ap.ap_grp, 'getgrnam', side_effect=KeyError), \
             mock.patch.object(self.ap.ap_os, 'listdir', return_value=[]), \
             mock.patch.object(self.ap, '_ap_run', return_value=b'not-found\n') as run, \
             mock.patch.object(self.ap, '_ap_check_listener'):
            self.ap._ap_fresh_checks(args)
        self.assertNotIn('/usr/sbin/ufw', checked)
        self.assertFalse(any(c[0][0][0] == '/usr/sbin/ufw' for c in run.call_args_list))

    def test_ufw_preconditions_are_checked_read_only(self):
        args = self.validated('--host', '198.51.100.7', '--allow-public-listen', '--open-firewall')
        for status in (b'Status: inactive\n', b'Status: reloading\n', b'', b'Status: active extra\n',
                       b'Status: active\nTo Action From\n8443/tcp ALLOW Anywhere\n'):
            with self.subTest(status=status), \
                 mock.patch.object(self.ap, '_ap_check_command'), \
                 mock.patch.object(self.ap, '_ap_run', return_value=status) as run:
                with self.assertRaisesRegex(RuntimeError, 'ufw'):
                    self.ap._ap_check_firewall(args)
                self.assertEqual([c[0][0] for c in run.call_args_list], [['/usr/sbin/ufw', 'status']])
        with mock.patch.object(self.ap, '_ap_check_command') as command, \
             mock.patch.object(self.ap, '_ap_run', return_value=b'Status: active\n'):
            self.assertIsNone(self.ap._ap_check_firewall(args))
            command.assert_called_once_with('/usr/sbin/ufw')
        with mock.patch.object(self.ap, '_ap_check_command'), \
             mock.patch.object(self.ap, '_ap_run') as run:
            self.ap._ap_check_firewall(self.validated('--host', '198.51.100.7', '--allow-public-listen'))
            run.assert_not_called()

    def test_ufw_refuses_existing_or_ambiguous_rules(self):
        args = self.validated('--host', '198.51.100.7', '--allow-public-listen', '--open-firewall')
        for rule in ('8443/tcp ALLOW Anywhere',
                     '8443/tcp (v6) DENY Anywhere (v6)',
                     '8443/tcp LIMIT Anywhere',
                     '8443/udp ALLOW Anywhere',
                     '8443:8444/tcp ALLOW Anywhere',
                     'Anywhere ALLOW Anywhere',
                     'Panel ALLOW Anywhere',
                     '8443/tcp ALLOW 10.0.0.0/8',
                     '8443/tcp IN ALLOW Anywhere',
                     '8443/tcp ALLOW Anywhere # operator',
                     '443,8443/tcp ALLOW Anywhere',
                     '22/tcp ALLOW nonsense',
                     '22/tcp ALLOW',
                     '22/tcp ALLOW Anywhere unexpected',
                     'malformed', 'Status: inactive'):
            status = ('Status: active\n\nTo                         Action      From\n'
                      '--                         ------      ----\n' + rule + '\n').encode()
            with self.subTest(rule=rule), mock.patch.object(self.ap, '_ap_run', return_value=status), \
                 mock.patch.object(self.ap, '_ap_check_command'):
                with self.assertRaisesRegex(RuntimeError, 'ufw'):
                    self.ap._ap_check_firewall(args)

    def test_ufw_accepts_unrelated_simple_rules(self):
        args = self.validated('--host', '198.51.100.7', '--allow-public-listen', '--open-firewall')
        # Byte-for-byte the shapes a real `ufw status` prints, including a
        # port range that does not cover the selected port.
        status = (b'Status: active\n\nTo                         Action      From\n'
                  b'--                         ------      ----\n'
                  b'20/tcp                     ALLOW       Anywhere                  \n'
                  b'888/tcp                    ALLOW       Anywhere                  \n'
                  b'39000:40000/tcp            ALLOW       Anywhere                  \n'
                  b'22/tcp (v6)                ALLOW       Anywhere (v6)             \n')
        with mock.patch.object(self.ap, '_ap_run', return_value=status), \
             mock.patch.object(self.ap, '_ap_check_command'):
            self.ap._ap_check_firewall(args)

    def test_ufw_refuses_a_range_covering_the_selected_port(self):
        args = self.validated('--host', '198.51.100.7', '--allow-public-listen', '--open-firewall')
        status = (b'Status: active\n\nTo                         Action      From\n'
                  b'--                         ------      ----\n'
                  b'8440:8450/tcp              ALLOW       Anywhere                  \n')
        with mock.patch.object(self.ap, '_ap_run', return_value=status), \
             mock.patch.object(self.ap, '_ap_check_command'):
            with self.assertRaisesRegex(RuntimeError, 'already has a rule for port 8443'):
                self.ap._ap_check_firewall(args)

    def test_fresh_checks_include_the_firewall_precondition(self):
        args = self.validated('--host', '198.51.100.7', '--allow-public-listen', '--open-firewall')
        with mock.patch.object(self.ap, '_ap_check_os'), \
             mock.patch.object(self.ap, '_ap_check_pid1'), \
             mock.patch.object(self.ap, '_ap_check_command'), \
             mock.patch.object(self.ap, '_ap_open_dir', return_value=7), \
             mock.patch.object(self.ap.ap_os, 'close'), \
             mock.patch.object(self.ap.ap_os.path, 'lexists', return_value=False), \
             mock.patch.object(self.ap, '_ap_read', return_value=b''), \
             mock.patch.object(self.ap.ap_pwd, 'getpwnam', side_effect=KeyError), \
             mock.patch.object(self.ap.ap_grp, 'getgrnam', side_effect=KeyError), \
             mock.patch.object(self.ap.ap_os, 'listdir', return_value=[]), \
             mock.patch.object(self.ap, '_ap_run', return_value=b'not-found\n'), \
             mock.patch.object(self.ap, '_ap_check_listener'), \
             mock.patch.object(self.ap, '_ap_check_firewall', side_effect=RuntimeError('ufw inactive')) as firewall:
            with self.assertRaisesRegex(RuntimeError, 'ufw inactive'):
                self.ap._ap_fresh_checks(args)
            firewall.assert_called_once_with(args)

    def run_apply(self, args, fail_on=None, fail_delete=False):
        contents = {name: b'authenticated' for name in self.ap._AP_MEMBERS}
        events = []

        def run(command):
            command = list(command)
            events.append(command)
            if fail_delete and command[:2] == [self.ap._AP_UFW, 'delete']:
                raise RuntimeError('ufw refuses')
            if fail_on is not None and fail_on(command):
                raise RuntimeError('sensitive captured output')
            if command[:2] == [self.ap._AP_UFW, 'status']:
                return b'Status: active\n'
            if command[:2] == [self.ap._AP_UFW, 'allow']:
                return b'Rule added\nRule added (v6)\n'
            if command[:2] == [self.ap._AP_UFW, 'delete']:
                return b'Rule deleted\nRule deleted (v6)\n'
            return b''

        def readiness(args, uid):
            events.append(['readiness'])
            return 'ff'
        with mock.patch.object(self.ap, '_ap_fresh_checks'), \
             mock.patch.object(self.ap.ap_os, 'geteuid', return_value=0), \
             mock.patch.object(self.ap, '_ap_lock', return_value=contextlib.nullcontext()), \
             mock.patch.object(self.ap, '_ap_provision', side_effect=lambda *a: events.append(['provision']) or 991), \
             mock.patch.object(self.ap, '_ap_run', side_effect=run), \
             mock.patch.object(self.ap, '_ap_readiness', side_effect=readiness), \
             mock.patch.object(self.ap.ap_subprocess, 'run') as real_run, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            try:
                self.ap.apply_install(args, contents)
                error = None
            except RuntimeError as exc:
                error = exc
            real_run.assert_not_called()
        return events, error, output.getvalue()

    def test_firewall_rechecks_and_uses_an_owned_comment_for_rollback(self):
        args = self.validated('--host', '198.51.100.7', '--allow-public-listen', '--open-firewall')
        commands = []

        def run(command):
            commands.append(list(command))
            verb = {'allow': 'added', 'delete': 'deleted'}[command[1]]
            return ('Rule %s\nRule %s (v6)\n' % (verb, verb)).encode()
        with mock.patch.object(self.ap, '_ap_check_firewall') as check, \
             mock.patch.object(self.ap, '_ap_run', side_effect=run):
            self.ap._ap_open_firewall(args)
            check.assert_called_once_with(args)
            self.assertRegex(commands[-1][4], r'^axionpanel-install-[0-9a-f]{32}$')
            self.assertTrue(self.ap._ap_rollback_firewall(args))
        self.assertEqual(commands[0][:4], [self.ap._AP_UFW, 'allow', '8443/tcp', 'comment'])
        self.assertEqual(commands[1], [self.ap._AP_UFW, 'delete', 'allow', '8443/tcp', 'comment', commands[0][4]])
        self.assertEqual(commands[0][4], commands[1][5])
        self.assertIn('comment', commands[1])
        self.assertRegex(commands[1][5], r'^axionpanel-install-[0-9a-f]{32}$')
        self.assertEqual(commands[1][3], '8443/tcp')
        self.assertEqual(commands[1][4], 'comment')
        self.assertEqual(len(commands[1]), 6)
        self.assertTrue(self.ap._ap_rollback_firewall(args))
        self.assertEqual(len(commands), 2)

    def test_firewall_rollback_requires_explicit_delete_confirmation(self):
        args = self.validated('--host', '198.51.100.7', '--allow-public-listen', '--open-firewall')
        with mock.patch.object(self.ap, '_ap_check_firewall'), \
             mock.patch.object(self.ap, '_ap_run', return_value=b'Rule added\nRule added (v6)\n'):
            self.ap._ap_open_firewall(args)
        for outcome in (b'Could not delete non-existent rule\n', b'', b'Aborted\n', RuntimeError('delete failed')):
            def reply(*_):
                if isinstance(outcome, Exception):
                    raise outcome
                return outcome
            with self.subTest(outcome=outcome), mock.patch.object(
                    self.ap, '_ap_run', side_effect=reply) as run:
                self.assertFalse(self.ap._ap_rollback_firewall(args))
                run.assert_called_once()
            self.assertEqual(args._firewall_rule, '8443/tcp')

    def test_unconfirmed_firewall_add_is_not_reported_as_published(self):
        args = self.validated('--host', '198.51.100.7', '--allow-public-listen', '--open-firewall')
        for output in (b'Skipping adding existing rule\n', b'', b'Rules updated\n'):
            with self.subTest(output=output), mock.patch.object(self.ap, '_ap_check_firewall'), \
                 mock.patch.object(self.ap, '_ap_run', return_value=output) as run:
                with self.assertRaisesRegex(RuntimeError, 'did not confirm'):
                    self.ap._ap_open_firewall(args)
                # The intent was recorded before the command, so recovery can act.
                self.assertEqual(run.call_args.args[0][:3], [self.ap._AP_UFW, 'allow', '8443/tcp'])
                self.assertEqual(args._firewall_rule, '8443/tcp')

    def test_one_address_is_bind_origin_certificate_and_readiness_target(self):
        args = self.args('--apply', '--host', '10.0.0.219', '--port', '9443', '--allow-public-listen')
        try:
            flags = self.ap._ap_serve_flags(args)
            units = self.ap._ap_units(args)
        except Exception as error:
            self.fail('unit derivation failed: %s' % error)
        self.assertEqual(flags[:4], ['-addr', '10.0.0.219:9443', '-origin', 'https://10.0.0.219:9443'])
        self.assertNotIn('0.0.0.0', ' '.join(flags))
        self.assertNotIn('::', json.dumps(flags))
        panel, agent = units
        self.assertIn('ExecStart=/usr/local/axionpanel/bin/axionpanel ' + ' '.join(flags), panel)
        # The generated certificate SAN is the same single address.
        source = (ROOT / 'scripts/installer_apply.py').read_text()
        self.assertIn("'-init-tls', '-tls-host', args.host", source)
        self.assertNotIn('public_ip', source)
        self.assertNotIn('_ap_bind_host', source)

    def test_success_summary_labels_a_non_global_origin_local(self):
        args = self.validated('--host', '10.0.0.219', '--allow-public-listen', '--port', '9443')
        _, error, output = self.run_apply(args)
        self.assertIsNone(error)
        self.assertIn('Origin: https://10.0.0.219:9443 (LOCAL address; external reachability is not guaranteed)',
                      output)

    def test_ufw_rejects_empty_or_untrusted_script_before_execution(self):
        for content in (b'', b'#!/usr/bin/env python3\n', b'#!/bin/sh\n'):
            with self.subTest(content=content), \
                 mock.patch.object(self.ap, '_ap_check_command'), \
                 mock.patch.object(self.ap, '_ap_read', return_value=content), \
                 mock.patch.object(self.ap.ap_subprocess, 'run') as run:
                with self.assertRaisesRegex(RuntimeError, 'unsupported ufw executable'):
                    self.ap._ap_run([self.ap._AP_UFW, 'status'])
                run.assert_not_called()

    def test_ufw_executes_with_isolated_trusted_python(self):

        result = subprocess.CompletedProcess([], 0, b'Status: active\n', b'')
        with mock.patch.object(self.ap, '_ap_check_command') as check, \
             mock.patch.object(self.ap, '_ap_read', return_value=b'#!/usr/bin/python3\n'), \
             mock.patch.object(self.ap.ap_subprocess, 'run', return_value=result) as run:
            self.ap._ap_run([self.ap._AP_UFW, 'status'])
        self.assertIn(mock.call('/usr/bin/python3'), check.call_args_list)
        self.assertEqual(run.call_args.args[0], ['/usr/bin/python3', '-I', '-B', self.ap._AP_UFW, 'status'])
        self.assertEqual(run.call_args.kwargs['env'], {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin',
                                                    'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/root'})

    def test_firewall_opens_only_after_local_readiness(self):
        args = self.validated('--host', '198.51.100.7', '--allow-public-listen', '--open-firewall')
        events, error, _ = self.run_apply(args)
        self.assertIsNone(error)
        allow = next(i for i, c in enumerate(events) if c[:3] == [self.ap._AP_UFW, 'allow', '8443/tcp'])
        self.assertLess(events.index(['readiness']), allow)
        self.assertLess(events.index(['provision']), allow)
        enable = [i for i, c in enumerate(events) if 'enable' in c]
        self.assertTrue(enable and enable[0] > allow)

    def test_no_firewall_command_when_the_panel_never_became_ready(self):
        args = self.validated('--host', '198.51.100.7', '--allow-public-listen', '--open-firewall')
        events, error, _ = self.run_apply(
            args, fail_on=lambda c: 'start' in c and c[-1] == 'axionpanel.service')
        self.assertRegex(str(error), 'partial data preserved')
        self.assertNotIn('sensitive', str(error))
        self.assertFalse(any(c[0] == self.ap._AP_UFW for c in events))

    def test_firewall_rule_is_removed_when_a_later_step_fails(self):
        args = self.validated('--host', '198.51.100.7', '--allow-public-listen', '--open-firewall')
        events, error, _ = self.run_apply(args, fail_on=lambda c: 'enable' in c)
        self.assertRegex(str(error), 'partial data preserved')
        self.assertRegex(str(error), 'firewall rule 8443/tcp removed')
        self.assertNotIn('not removed', str(error))
        ufw = [c for c in events if c[0] == self.ap._AP_UFW]
        self.assertEqual(ufw[0], [self.ap._AP_UFW, 'status'])
        self.assertEqual(ufw[1][:4], [self.ap._AP_UFW, 'allow', '8443/tcp', 'comment'])
        self.assertEqual(ufw[2], [self.ap._AP_UFW, 'delete', 'allow', '8443/tcp', 'comment', ufw[1][4]])
        self.assertFalse(any(c[0] == self.ap._AP_UFW and c[1] in ('disable', 'reset', 'default', 'enable', 'reload')
                             for c in events))

    def test_firewall_rule_is_kept_on_success_and_absent_without_the_flag(self):
        for options, expected in ((('--open-firewall',), 2), ((), 0)):
            with self.subTest(options=options):
                args = self.validated('--host', '198.51.100.7', '--allow-public-listen', *options)
                events, error, output = self.run_apply(args)
                self.assertIsNone(error)
                self.assertEqual(sum(c[0] == self.ap._AP_UFW for c in events), expected)
                self.assertFalse(any('delete' in c for c in events))
                self.assertIn('Firewall: ' + ('ufw allow 8443/tcp' if expected else 'unchanged'), output)

    def test_firewall_rollback_reports_when_the_delete_command_fails(self):
        args = self.validated('--host', '198.51.100.7', '--allow-public-listen', '--open-firewall')
        _, error, _ = self.run_apply(args, fail_on=lambda c: 'enable' in c, fail_delete=True)
        self.assertRegex(str(error), 'firewall rule 8443/tcp was not removed')

    def test_failed_allow_command_is_still_rolled_back(self):
        args = self.validated('--host', '198.51.100.7', '--allow-public-listen', '--open-firewall')
        events, error, _ = self.run_apply(args, fail_on=lambda c: c[:2] == [self.ap._AP_UFW, 'allow'])
        self.assertRegex(str(error), 'partial data preserved')
        self.assertTrue(any(c[:4] == [self.ap._AP_UFW, 'delete', 'allow', '8443/tcp'] and c[4] == 'comment' for c in events))

    class Terminal:
        def __init__(self, answer):
            self.answer, self.written, self.closed = answer, '', False

        def write(self, text):
            self.written += text

        def flush(self):
            pass

        def readline(self):
            return self.answer

        def close(self):
            self.closed = True

    def test_real_controlling_terminal_confirmation_and_cancellation(self):
        # A new session acquires this private PTY; stdin deliberately disagrees
        # with the terminal answer. Only host/root checks are mocked.
        child_code = textwrap.dedent('''
            import fcntl, os, sys, termios
            from unittest import mock
            from tests.install.test_apply import load_apply, parse_args
            os.setsid()
            slave = int(sys.argv[1])
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
            # Keep the slave alive until /dev/tty is opened (no master EIO gap).
            ap = load_apply()
            args = parse_args(ap, '--apply', '--host', '127.0.0.1')
            before = len(os.listdir('/proc/self/fd'))
            with mock.patch.object(ap.ap_os, 'geteuid', return_value=0), \\
                 mock.patch.object(ap, '_ap_fresh_checks') as fresh:
                try:
                    ap.validate_apply(args)
                except RuntimeError as exc:
                    assert str(exc) == 'installation not confirmed', str(exc)
                    assert not args.yes
                    fresh.assert_not_called()
                    result = 'cancelled'
                else:
                    assert args.yes
                    fresh.assert_called_once_with(args)
                    result = 'confirmed'
            assert len(os.listdir('/proc/self/fd')) == before, 'terminal descriptor leak'
            os.close(slave)
            print(result, flush=True)
        ''')
        for answer, expected in (('INSTALL\n', 'confirmed'), ('no\n', 'cancelled')):
            with self.subTest(answer=answer):
                master, slave = pty.openpty()
                child = None
                terminal_output = b''
                try:
                    child = subprocess.Popen(
                        [sys.executable, '-B', '-c', child_code, str(slave)],
                        pass_fds=(slave,), cwd=ROOT, stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    os.close(slave)
                    slave = None
                    assert child.stdin is not None
                    # stdin disagrees with the terminal on purpose.
                    child.stdin.write(b'no\n' if expected == 'confirmed' else b'INSTALL\n')
                    child.stdin.close()
                    child.stdin = None
                    deadline = time.monotonic() + 10
                    while b'Type INSTALL to continue: ' not in terminal_output:
                        remaining = deadline - time.monotonic()
                        self.assertGreater(remaining, 0, 'terminal prompt timed out')
                        if not select.select([master], [], [], remaining)[0]:
                            self.fail('terminal prompt timed out')
                        try:
                            data = os.read(master, 65536)
                        except OSError as exc:
                            if exc.errno != errno.EIO:
                                raise
                            break
                        if not data:
                            break
                        terminal_output += data
                    if b'Type INSTALL to continue: ' in terminal_output:
                        os.write(master, answer.encode())
                    stdout, stderr = child.communicate(timeout=10)
                    self.assertEqual(child.returncode, 0, stderr.decode())
                    self.assertEqual(stdout.decode().strip(), expected)
                    self.assertIn(b'Listen: 127.0.0.1:8443', terminal_output)
                    self.assertIn(b'Firewall: unchanged', terminal_output)
                finally:
                    if child is not None:
                        if child.poll() is None:
                            child.kill()
                        child.communicate(timeout=10)
                    os.close(master)
                    if slave is not None:
                        os.close(slave)

    def test_missing_yes_without_a_terminal_is_refused(self):
        args = parse_args(self.ap, '--apply', '--host', '127.0.0.1')
        with mock.patch.object(self.ap, '_ap_open_tty', side_effect=RuntimeError('apply requires --yes when no terminal is available')), \
             mock.patch.object(self.ap.ap_os, 'geteuid', return_value=0), \
             mock.patch.object(self.ap, '_ap_fresh_checks') as fresh:
            with self.assertRaisesRegex(RuntimeError, '--yes'):
                self.ap.validate_apply(args)
            fresh.assert_not_called()
        self.assertFalse(args.yes)

    def test_interactive_confirmation_shows_the_resolved_plan(self):
        terminal = self.Terminal('INSTALL\n')
        args = parse_args(self.ap, '--apply', '--host', '10.0.0.219',
                          '--allow-public-listen', '--open-firewall')
        with mock.patch.object(self.ap, '_ap_open_tty', return_value=(terminal, terminal)), \
             mock.patch.object(self.ap.ap_os, 'geteuid', return_value=0), \
             mock.patch.object(self.ap, '_ap_fresh_checks') as fresh:
            self.ap.validate_apply(args)
            fresh.assert_called_once()
        self.assertTrue(args.yes)
        self.assertTrue(terminal.closed)
        for text in ('Listen: 10.0.0.219:8443', 'Origin: https://10.0.0.219:8443',
                     'Firewall: ufw allow 8443/tcp', 'LOCAL', 'external reachability is not guaranteed'):
            self.assertIn(text, terminal.written)

    def test_interactive_confirmation_detects_before_asking(self):
        terminal = self.Terminal('INSTALL\n')
        args = parse_args(self.ap, '--apply', '--allow-public-listen')
        with mock.patch.object(self.ap, '_ap_open_tty', return_value=(terminal, terminal)), \
             mock.patch.object(self.ap, '_ap_detect_host', return_value='10.0.0.219'), \
             mock.patch.object(self.ap.ap_os, 'geteuid', return_value=0), \
             mock.patch.object(self.ap, '_ap_fresh_checks'):
            self.ap.validate_apply(args)
        self.assertIn('Origin: https://10.0.0.219:8443', terminal.written)
        self.assertIn('Firewall: unchanged', terminal.written)

    def test_anything_but_yes_declines_before_host_checks(self):
        for answer in ('no\n', 'y\n', 'YES please\n', '', 'yes yes\n'):
            terminal = self.Terminal(answer)
            args = parse_args(self.ap, '--apply', '--host', '127.0.0.1')
            with self.subTest(answer=answer), \
                 mock.patch.object(self.ap, '_ap_open_tty', return_value=(terminal, terminal)), \
                 mock.patch.object(self.ap.ap_os, 'geteuid', return_value=0), \
                 mock.patch.object(self.ap, '_ap_fresh_checks') as fresh:
                with self.assertRaisesRegex(RuntimeError, 'not confirmed'):
                    self.ap.validate_apply(args)
                fresh.assert_not_called()
            self.assertFalse(args.yes)
            self.assertTrue(terminal.closed)

    def test_invalid_options_are_refused_before_prompting(self):
        args = parse_args(self.ap, '--apply', '--host', '198.51.100.7')
        with mock.patch.object(self.ap, '_ap_open_tty') as tty, \
             mock.patch.object(self.ap.ap_os, 'geteuid', return_value=0):
            with self.assertRaisesRegex(RuntimeError, '--allow-public-listen'):
                self.ap.validate_apply(args)
            tty.assert_not_called()
        self.assertFalse(args.yes)

    def test_ufw_path_is_trusted_but_no_other_firewall_tool_is(self):
        self.assertEqual(self.ap._AP_UFW, '/usr/sbin/ufw')
        self.assertNotIn(self.ap._AP_UFW, self.ap._AP_COMMANDS)
        for path in ('/usr/local/sbin/ufw', '/usr/sbin/iptables', '/usr/sbin/nft',
                     '/usr/bin/firewall-cmd'):
            with self.subTest(path=path), self.assertRaisesRegex(RuntimeError, 'untrusted'):
                self.ap._ap_check_command(path)


class NativeHttpsIntegration(unittest.TestCase):
    """Built panel + production readiness over real TLS; not systemd apply."""

    def test_native_https_missing_ui_build_fails_closed(self):
        if (ROOT / 'web/dist/index.html').is_file():
            self.skipTest('built UI present; missing-build gate requires placeholder-only checkout')
        self._native_https_readiness(built_ui=False)

    def test_native_https_built_ui_reaches_and_enforces_real_agent_gate(self):
        if not (ROOT / 'web/dist/index.html').is_file():
            self.skipTest('production-bundle gate requires make web; missing-build gate tested separately')
        self._native_https_readiness(built_ui=True)

    def _native_https_readiness(self, built_ui):
        if shutil.which('go') is None:
            self.skipTest('Go toolchain unavailable')
        with tempfile.TemporaryDirectory(prefix='ap-https-') as directory:
            root = Path(directory)
            binary = root / 'panel'
            build = subprocess.run(['go', 'build', '-o', str(binary), './cmd/panel'],
                                   cwd=ROOT, capture_output=True, timeout=300)
            self.assertEqual(build.returncode, 0, build.stderr[-2000:])
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0))
                port = probe.getsockname()[1]
            self.assertNotIn(port, {80, 888, 3306, 21, 35460, 7800})
            origin = 'https://127.0.0.1:%d' % port
            cert, key = root / 'panel.crt', root / 'panel.key'
            entrance, bootstrap = root / 'entrance', root / 'bootstrap.json'
            flags = ['-db', str(root / 'panel.db'), '-origin', origin,
                     '-entrance-file', str(entrance), '-secret-key', str(root / 'secret.key'),
                     '-agent-socket', str(root / 'absent.sock')]
            for command in (
                ['-init-tls', '-tls-host', '127.0.0.1', '-tls-cert', str(cert), '-tls-key', str(key)],
                ['-init-entrance', '-entrance-file', str(entrance)],
                flags + ['-bootstrap-admin', 'admin', '-bootstrap-out', str(bootstrap)],
            ):
                result = subprocess.run([str(binary)] + command, capture_output=True, timeout=60)
                self.assertEqual(result.returncode, 0, result.stderr[-2000:])
            process = subprocess.Popen([str(binary)] + flags +
                ['-addr', '127.0.0.1:%d' % port, '-tls-cert', str(cert), '-tls-key', str(key)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 15
                while True:
                    try:
                        with socket.create_connection(('127.0.0.1', port), timeout=1):
                            break
                    except OSError:
                        if time.monotonic() >= deadline or process.poll() is not None:
                            self.fail('isolated panel failed to listen')
                        time.sleep(0.1)
                module = load_apply()
                args = parse_args(module, '--apply', '--yes', '--host', '127.0.0.1', '--port', str(port))
                files = {module._AP_STATE + '/bootstrap.json': bootstrap, module._AP_CERT: cert}

                def read(path, limit, uid=0, private=False):
                    if path.endswith('/bootstrap.json'):
                        self.assertTrue(private)
                    data = files[path].read_bytes()
                    self.assertLessEqual(len(data), limit)
                    return data

                def fetch_login():
                    # Independent pinned-TLS observation of the exact response
                    # /login serves in this checkout, behind the same entrance
                    # gate; no production helper or readiness check is replaced.
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.load_verify_locations(cadata=cert.read_text())
                    entrance_path = json.loads(bootstrap.read_bytes())['entrance_path']
                    headers = {'Origin': origin, 'Host': '127.0.0.1:%d' % port}
                    for path in (entrance_path, '/login'):
                        connection = http.client.HTTPSConnection(
                            '127.0.0.1', port, context=context, timeout=5)
                        try:
                            connection.connect()
                            self.assertEqual(connection.sock.getpeercert(binary_form=True),
                                             ssl.PEM_cert_to_DER_cert(cert.read_text()))
                            connection.request('GET', path, headers=headers)
                            response = connection.getresponse()
                            body = response.read(1024 * 1024)
                            if path == entrance_path:
                                self.assertEqual(response.status, 303)
                                gate = http.cookies.SimpleCookie()
                                gate.load(response.getheader('Set-Cookie', ''))
                                headers['Cookie'] = 'axp_entrance=' + gate['axp_entrance'].value
                        finally:
                            connection.close()
                    return response.status, body

                state = 'built-production-bundle' if built_ui else 'missing-ui-build'
                expected = ('^authenticated agent-backed system information readiness failed$'
                            if built_ui else '^login UI readiness failed$')
                with self.subTest(ui=state), mock.patch.object(module, '_ap_read', side_effect=read):
                    # With a bundle, SAN/pin, entrance, UI, health and login
                    # must all pass before the absent Unix agent fails closed.
                    # A placeholder-only checkout must instead fail at the UI
                    # gate; ordinary tests do not require ignored build output.
                    with self.assertRaisesRegex(RuntimeError, expected):
                        module._ap_readiness(args, os.geteuid())
                status, body = fetch_login()
                if built_ui:
                    self.assertEqual(status, 200)
                    self.assertIn(b'<html', body.lower())
                else:
                    # Exact actionable response documented by internal/webui.
                    self.assertEqual(status, 503)
                    self.assertEqual(body, b'UI build missing; run make web and rebuild the panel.\n')
                    self.assertNotIn(b'<html', body.lower())
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)


if __name__ == '__main__':
    unittest.main()
