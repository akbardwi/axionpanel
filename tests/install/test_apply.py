"""Read-only/unit coverage; actual systemd apply belongs in an isolated host."""
import argparse
import contextlib
import importlib.util
import io
import os
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

    def test_defaults_and_explicit_consent(self):
        args = self.args('--apply')
        self.assertEqual((args.host, args.port, args.admin), ('127.0.0.1', 8443, 'admin'))
        with self.assertRaisesRegex(RuntimeError, '--yes'):
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
                    self.ap.validate_apply(self.args('--apply', '--yes', *option))

    def test_nonroot_rejected_before_host_checks(self):
        with mock.patch.object(self.ap.ap_os, 'geteuid', return_value=1000):
            with self.assertRaisesRegex(RuntimeError, 'root'):
                self.ap.validate_apply(self.args('--apply', '--yes'))

    def test_fake_root_and_arch_not_allowed(self):
        args = self.args('--apply', '--yes')
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
        panel, agent = self.ap._ap_units(self.args('--apply', '--yes'))
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
                self.ap.apply_install(self.args('--apply', '--yes'), contents)
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
                self.ap.apply_install(self.args('--apply', '--yes'), {})
            lock.assert_not_called()

    def test_apply_is_mutually_exclusive_with_inspection_modes(self):
        """`--apply --verify-only` must fail instead of silently inspecting."""
        import subprocess
        script = ROOT / 'install.sh'
        for mode in ('--preflight-only', '--verify-only'):
            completed = subprocess.run(
                ['bash', str(script), mode, '--apply', '--yes', '--version', '1.0.0',
                 '--public-key', '/etc/hostname', '--directory', '/tmp'],
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
                self.ap.validate_apply(self.args('--apply', '--yes'))
            pid1.assert_not_called()

    def test_missing_os_release_denied(self):
        with self.os_release_fixture(None) as (_, pid1):
            with self.assertRaisesRegex(RuntimeError, 'prerequisites could not be checked'):
                self.ap.validate_apply(self.args('--apply', '--yes'))
            pid1.assert_not_called()

    def test_malformed_os_release_denied(self):
        with self.os_release_fixture(b'ID=ubuntu\nVERSION_ID="24.04"\nID=ubuntu\n') as (_, pid1):
            with self.assertRaisesRegex(RuntimeError, 'ambiguous os-release'):
                self.ap.validate_apply(self.args('--apply', '--yes'))
            pid1.assert_not_called()

    def test_unsupported_distro_denied(self):
        with self.os_release_fixture(b'ID=centos\nVERSION_ID="9"\n') as (_, pid1):
            with self.assertRaisesRegex(RuntimeError, 'unsupported OS'):
                self.ap.validate_apply(self.args('--apply', '--yes'))
            pid1.assert_not_called()

    def test_supported_os_accepted(self):
        for data in (b'ID=ubuntu\nVERSION_ID="24.04"\n', b'ID=ubuntu\nVERSION_ID="26.04"\n',
                     b'ID=debian\nVERSION_ID="12"\n', b'ID=debian\nVERSION_ID="13"\n'):
            with self.subTest(data=data):
                with self.os_release_fixture(data) as (_, pid1):
                    with self.assertRaisesRegex(RuntimeError, 'OS accepted'):
                        self.ap.validate_apply(self.args('--apply', '--yes'))
                    pid1.assert_called_once()

    def test_os_release_symlink_to_usr_lib_accepted(self):
        for spelling in ('../usr/lib/os-release', '/usr/lib/os-release'):
            with self.subTest(spelling=spelling), self.os_release_fixture(None) as (root, pid1):
                (root / 'usr/lib/os-release').write_bytes(b'ID=ubuntu\nVERSION_ID="24.04"\n')
                (root / 'etc/os-release').symlink_to(spelling)
                with self.assertRaisesRegex(RuntimeError, 'OS accepted'):
                    self.ap.validate_apply(self.args('--apply', '--yes'))
                pid1.assert_called_once()

    def test_os_release_single_quotes_are_balanced(self):
        with self.os_release_fixture(b"ID='ubuntu'\nVERSION_ID='24.04'\n") as (_, pid1):
            with self.assertRaisesRegex(RuntimeError, 'OS accepted'):
                self.ap.validate_apply(self.args('--apply', '--yes'))
            pid1.assert_called_once()
        for data in (b"ID='ubuntu\nVERSION_ID=24.04\n",
                     b"ID=ubuntu\nVERSION_ID='24.04\n"):
            with self.subTest(data=data), self.os_release_fixture(data) as (_, pid1):
                with self.assertRaisesRegex(RuntimeError, 'malformed os-release'):
                    self.ap.validate_apply(self.args('--apply', '--yes'))
                pid1.assert_not_called()

    def test_os_release_invalid_utf8_denied(self):
        with self.os_release_fixture(b'ID=ubuntu\nVERSION_ID="24.04"\n\xff\xfe\n') as (_, pid1):
            with self.assertRaisesRegex(RuntimeError, 'malformed os-release'):
                self.ap.validate_apply(self.args('--apply', '--yes'))
            pid1.assert_not_called()

    def test_malformed_relevant_os_assignments_cannot_hide_behind_valid_ones(self):
        for extra in (b'ID=$(touch forbidden)\n', b'VERSION_ID="24.04\n',
                      b'ID =ubuntu\n', b'export ID=ubuntu\n', b'\x00\n'):
            with self.subTest(extra=extra), self.os_release_fixture(
                    b'ID=ubuntu\nVERSION_ID="24.04"\n' + extra) as (_, pid1):
                with self.assertRaisesRegex(RuntimeError, 'malformed os-release'):
                    self.ap.validate_apply(self.args('--apply', '--yes'))
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
                    self.ap.validate_apply(self.args('--apply', '--yes'))
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
                    self.ap.apply_install(self.args('--apply', '--yes'), contents)
                provision.assert_not_called()
                self.assertEqual(events, ['supported', 'lock'])

    def test_main_refuses_unsupported_os_before_acquisition_or_stage_creation(self):
        text = (ROOT / 'install.sh').read_text().split("<<'PY'\n", 1)[1].rsplit('\nPY', 1)[0]
        text = text.split('\ntry:\n    main()\n', 1)[0]
        module = types.ModuleType('installer_main_test')
        exec(compile(text, 'standalone-main', 'exec'), module.__dict__)
        with mock.patch.object(module, 'parse_args', return_value=argparse.Namespace(
                apply=True, preflight_only=False, verify_only=False, version='1.0.0',
                arch=None, root=None, stage_dir=None, directory=None, download_base_url=None)), \
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
                self.ap.apply_install(self.args('--apply', '--yes'), {'axionpanel': b'x'})
            lock.assert_not_called()

    def test_failure_stops_only_new_units_and_preserves_partial_state(self):
        args = self.args('--apply', '--yes')
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

    def test_read_only_checks_validate_optional_sysusers_ancestor_before_mutation(self):
        args = self.args('--apply', '--yes')
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

            args = parse_args(self.ap, '--apply', '--yes')
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


if __name__ == '__main__':
    unittest.main()
