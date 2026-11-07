# BEGIN AXIONPANEL APPLY ENGINE
"""Self-contained fresh-host apply fragment. No downloads or trust bootstrap.

Keep all private symbols prefixed: this source is embedded verbatim into the
standalone installer as well as imported by its safe unit tests. There is no
alternate root, command injection hook, environment override, or reset mode.
"""
import contextlib as ap_contextlib
import fcntl as ap_fcntl
import grp as ap_grp
import hashlib as ap_hashlib
import http.client as ap_http
import http.cookies as ap_cookies
import ipaddress as ap_ipaddress
import json as ap_json
import os as ap_os
import pwd as ap_pwd
import re as ap_re
import socket as ap_socket
import ssl as ap_ssl
import stat as ap_stat
import subprocess as ap_subprocess
import time as ap_time


_AP_BINARY = '/usr/local/axionpanel/bin/axionpanel'
_AP_AGENT = '/usr/local/axionpanel/bin/axionpanel-agent'
_AP_STATE = '/var/lib/axionpanel'
_AP_CERT = '/etc/axionpanel/tls/panel.crt'
_AP_KEY = '/etc/axionpanel/tls/panel.key'
_AP_UNITS = ('axionpanel-agent.service', 'axionpanel.service')
_AP_MEMBERS = (
    'axionpanel', 'axionpanel-agent', 'README.md',
    'deploy/nginx/axionpanel.conf.example', 'deploy/systemd/agent.toml.example',
    'deploy/systemd/axionpanel-agent.service',
    'deploy/systemd/axionpanel-native.service.example',
    'deploy/systemd/axionpanel-tls.tmpfiles.conf.example',
    'deploy/systemd/axionpanel.service', 'deploy/systemd/axionpanel.sysusers.conf',
    'deploy/systemd/axionpanel.tmpfiles.conf', 'docs/agent.md',
    'docs/deployment.md', 'docs/native-tls-systemd.md', 'docs/public-access.md',
    'docs/secure-onboarding.md',
)
_AP_DESTINATIONS = (
    '/opt/axionpanel', '/usr/local/axionpanel', '/var/lib/axionpanel',
    '/etc/axionpanel', '/run/axionpanel', '/var/log/axionpanel',
    '/etc/sysusers.d/axionpanel.conf', '/etc/tmpfiles.d/axionpanel.conf',
    '/etc/tmpfiles.d/axionpanel-tls.conf',
)
_AP_CONFLICTS = (
    '/www/server/panel', '/usr/local/cpanel', '/usr/local/psa',
    '/usr/local/hestia', '/usr/local/vesta', '/usr/local/directadmin',
    '/etc/webmin', '/usr/local/ispconfig', '/etc/cyberpanel',
)
_AP_COMMANDS = (
    '/usr/bin/systemctl', '/usr/bin/systemd-sysusers',
    '/usr/bin/systemd-analyze', '/usr/sbin/runuser', '/usr/sbin/nologin',
)


def add_apply_arguments(parser):
    parser.add_argument('--yes', action='store_true', help='consent to fresh-host provisioning')
    parser.add_argument('--host', default='127.0.0.1', help='canonical native HTTPS IP address')
    parser.add_argument('--port', type=int, default=8443, help='unprivileged native HTTPS port (not 7800)')
    parser.add_argument('--allow-public-listen', action='store_true', help='explicitly permit a non-loopback listener')
    parser.add_argument('--admin', default='admin', help='first administrator username')


def _ap_options(args):
    if not args.yes:
        raise RuntimeError('apply requires --yes')
    if getattr(args, 'root', None) is not None or getattr(args, 'arch', None) is not None:
        raise RuntimeError('--root and --arch are inspection-only')
    try:
        ip = ap_ipaddress.ip_address(args.host)
    except ValueError:
        raise RuntimeError('host must be a canonical IP address') from None
    # Canonical Python spelling rejects zero-compressed IPv6 and other aliases.
    # A fixed listener identity must not be multicast, unspecified, reserved,
    # link-local or IPv4-mapped IPv6; loopback and private unicast are valid.
    unusable = (str(ip) != args.host or '%' in args.host or ip.is_multicast or
                ip.is_unspecified or (ip.is_reserved and not ip.is_loopback) or ip.is_link_local or
                (ip.version == 6 and getattr(ip, 'ipv4_mapped', None) is not None))
    if unusable:
        raise RuntimeError('host must be a canonical unicast IP address')
    if not ip.is_loopback and not args.allow_public_listen:
        raise RuntimeError('non-loopback listener requires --allow-public-listen')
    # Unspecified binds cannot supply a usable browser origin/certificate identity.
    if ip.is_unspecified:
        raise RuntimeError('unspecified host is not a browser origin')
    if isinstance(args.port, bool) or not isinstance(args.port, int) or not 1024 <= args.port <= 65535 or args.port == 7800:
        raise RuntimeError('port must be 1024..65535 and not 7800')
    if not ap_re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,63}', args.admin, flags=ap_re.ASCII):
        raise RuntimeError('invalid administrator username')
    if ap_os.geteuid() != 0:
        raise RuntimeError('apply requires root')


def validate_apply(args):
    """Read-only; safe to call before any network access or provisioning."""
    if not args.apply:
        return
    _ap_options(args)
    try:
        _ap_fresh_checks(args)
    except (OSError, ValueError, KeyError):
        raise RuntimeError('fresh-host prerequisites could not be checked') from None


def _ap_open_dir(path):
    """Pin a root-owned, non-writable, entirely non-symlink directory chain."""
    if not path.startswith('/') or '..' in path.split('/'):
        raise RuntimeError('trusted absolute directory required')
    fd = ap_os.open('/', ap_os.O_RDONLY | ap_os.O_DIRECTORY | ap_os.O_NOFOLLOW)
    try:
        for component in path.split('/')[1:]:
            if not component:
                continue
            child = ap_os.open(component, ap_os.O_RDONLY | ap_os.O_DIRECTORY | ap_os.O_NOFOLLOW, dir_fd=fd)
            ap_os.close(fd)
            fd = child
            info = ap_os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise RuntimeError('unsafe installation directory ownership or permissions')
        return fd
    except (OSError, RuntimeError):
        ap_os.close(fd)
        raise RuntimeError('unsafe or missing installation directory') from None


def _ap_read(path, limit, uid=0, private=False):
    parent, name = path.rsplit('/', 1)
    # State is intentionally user-owned; its root-controlled parent was pinned
    # during creation. Do not reuse the root-only walker for that final directory.
    base = _ap_open_dir('/var/lib' if parent == _AP_STATE else parent)
    try:
        if parent == _AP_STATE:
            child = ap_os.open('axionpanel', ap_os.O_RDONLY | ap_os.O_DIRECTORY | ap_os.O_NOFOLLOW, dir_fd=base)
            ap_os.close(base)
            base = child
            info = ap_os.fstat(base)
            if info.st_uid != uid or info.st_mode & 0o077:
                raise RuntimeError('unsafe private state directory')
        fd = ap_os.open(name, ap_os.O_RDONLY | ap_os.O_NOFOLLOW | ap_os.O_NONBLOCK, dir_fd=base)
        with ap_os.fdopen(fd, 'rb') as stream:
            info = ap_os.fstat(stream.fileno())
            if not ap_stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1 or info.st_mode & (0o077 if private else 0o022):
                raise RuntimeError('unsafe installation file')
            data = stream.read(limit + 1)
            if len(data) > limit:
                raise RuntimeError('installation file exceeds size limit')
            return data
    except OSError:
        raise RuntimeError('installation file unavailable or unsafe') from None
    finally:
        ap_os.close(base)


def _ap_check_command(path):
    if path not in _AP_COMMANDS + (_AP_BINARY, _AP_AGENT):
        raise RuntimeError('untrusted installer command')
    # usrmerge may use fixed system executable symlinks. Resolve only these
    # trusted names, then validate every canonical ancestor and final inode.
    canonical = ap_os.path.realpath(path)
    parent, name = canonical.rsplit('/', 1)
    fd = _ap_open_dir(parent)
    try:
        command = ap_os.open(name, ap_os.O_RDONLY | ap_os.O_NOFOLLOW | ap_os.O_NONBLOCK, dir_fd=fd)
        try:
            info = ap_os.fstat(command)
            if not ap_stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or not info.st_mode & 0o111:
                raise RuntimeError('unsafe or unavailable installer command')
        finally:
            ap_os.close(command)
    except OSError:
        raise RuntimeError('required installer command unavailable') from None
    finally:
        ap_os.close(fd)
    # Also verify original ancestors, not just a possibly attacker-selected
    # resolved target. Fixed /usr/bin and /usr/sbin are canonical on supported OS.
    fd = _ap_open_dir(path.rsplit('/', 1)[0])
    ap_os.close(fd)


def _ap_run(command):
    _ap_check_command(command[0])
    try:
        result = ap_subprocess.run(command, stdin=ap_subprocess.DEVNULL,
            stdout=ap_subprocess.PIPE, stderr=ap_subprocess.DEVNULL,
            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/root'},
            cwd='/', timeout=90, check=False, umask=0o077)
    except (OSError, ap_subprocess.SubprocessError):
        raise RuntimeError('installer command failed; captured output suppressed') from None
    if result.returncode != 0:
        raise RuntimeError('installer command failed; captured output suppressed')
    return result.stdout


def _ap_check_pid1():
    try:
        executable = ap_os.readlink('/proc/1/exe')
        if executable not in ('/usr/lib/systemd/systemd', '/lib/systemd/systemd'):
            raise RuntimeError('apply requires real systemd PID1')
        info = ap_os.stat('/proc/1/exe')
        expected = ap_os.stat('/usr/lib/systemd/systemd')
        if (info.st_dev, info.st_ino) != (expected.st_dev, expected.st_ino) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError('apply requires real systemd PID1')
        fd = _ap_open_dir('/run/systemd/system')
        ap_os.close(fd)
    except OSError:
        raise RuntimeError('apply requires real systemd PID1') from None


def _ap_check_listener(host, port):
    family = ap_socket.AF_INET6 if ':' in host else ap_socket.AF_INET
    try:
        with ap_socket.socket(family, ap_socket.SOCK_STREAM) as listener:
            # Never SO_REUSEADDR: an occupied wildcard or non-listening bound
            # socket must fail too. The real daemon still owns final bind races.
            listener.bind((host, port))
    except OSError:
        raise RuntimeError('selected listener unavailable or occupied') from None


def _ap_check_os():
    # The distro-standard symlink is the only exception to no-follow reads.
    # Pin /etc first; never resolve an arbitrary symlink-selected path as root.
    etc = _ap_open_dir('/etc')
    try:
        info = ap_os.stat('os-release', dir_fd=etc, follow_symlinks=False)
        path = '/etc/os-release'
        if ap_stat.S_ISLNK(info.st_mode):
            if info.st_uid != 0 or ap_os.readlink('os-release', dir_fd=etc) not in (
                '/usr/lib/os-release', '../usr/lib/os-release'
            ):
                raise RuntimeError('unsafe os-release symlink')
            path = '/usr/lib/os-release'
    finally:
        ap_os.close(etc)
    try:
        data = _ap_read(path, 65536).decode('utf-8')
    except OSError:
        raise RuntimeError('os-release unavailable or unsafe') from None
    except UnicodeDecodeError:
        raise RuntimeError('malformed os-release') from None
    if any(ord(char) < 32 and char not in '\n\t\r' for char in data):
        raise RuntimeError('malformed os-release')
    values = {}
    # Parse data only, never source shell. Unknown fields may contain normal
    # distro display strings; every non-comment line must still be an assignment.
    assignment = ap_re.compile(r'[A-Z][A-Z0-9_]*=.*')
    pattern = ap_re.compile(r'''(ID|VERSION_ID)=(?:"([A-Za-z0-9_.-]+)"|'([A-Za-z0-9_.-]+)'|([A-Za-z0-9_.-]+))''')
    for line in data.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        if not assignment.fullmatch(line):
            raise RuntimeError('malformed os-release')
        if line.split('=', 1)[0] in ('ID', 'VERSION_ID'):
            match = pattern.fullmatch(line)
            if match is None:
                raise RuntimeError('malformed os-release')
            key = match.group(1)
            if key in values:
                raise RuntimeError('ambiguous os-release')
            values[key] = next(value for value in match.groups()[1:] if value is not None)
    if (values.get('ID'), values.get('VERSION_ID')) not in {
        ('ubuntu', '24.04'), ('ubuntu', '26.04'), ('debian', '12'), ('debian', '13')
    }:
        raise RuntimeError('unsupported OS')


def _ap_fresh_checks(args):
    _ap_check_os()
    _ap_check_pid1()
    for command in _AP_COMMANDS:
        _ap_check_command(command)
    for path in ('/usr/local', '/var/lib', '/etc', '/etc/systemd/system', '/run'):
        fd = _ap_open_dir(path)
        ap_os.close(fd)
    # /etc/sysusers.d is an optional ancestor but its existence is still a
    # trusted-directory prerequisite; it is created later under the lock only.
    if ap_os.path.lexists('/etc/sysusers.d'):
        fd = _ap_open_dir('/etc/sysusers.d')
        ap_os.close(fd)
    for path in _AP_DESTINATIONS:
        if ap_os.path.lexists(path):
            raise RuntimeError('existing AxionPanel state; refusing adoption')
    for path in _AP_CONFLICTS:
        if ap_os.path.lexists(path):
            raise RuntimeError('conflicting panel detected')
    for path in ('/etc/passwd', '/etc/group'):
        if any(line.startswith(b'axionpanel:') for line in _ap_read(path, 8 * 1024 * 1024).splitlines()):
            raise RuntimeError('existing AxionPanel local account')
    for lookup in (ap_pwd.getpwnam, ap_grp.getgrnam):
        try:
            lookup('axionpanel')
        except KeyError:
            continue
        raise RuntimeError('existing AxionPanel NSS account')
    # Querying the manager catches vendor, generated, transient and alias units,
    # not only files in /etc. A preexisting unloaded drop-in also denies adoption.
    names = _AP_UNITS + ('axionpanel-native.service',)
    for directory in ('/etc/systemd/system', '/run/systemd/system', '/usr/lib/systemd/system'):
        fd = _ap_open_dir(directory)
        try:
            for name in ap_os.listdir(fd):
                if name.startswith('axionpanel'):
                    raise RuntimeError('existing AxionPanel unit or drop-in')
        finally:
            ap_os.close(fd)
    for name in names:
        load = _ap_run(['/usr/bin/systemctl', '--system', 'show', '--property=LoadState', '--value', name]).strip()
        if load != b'not-found':
            raise RuntimeError('existing AxionPanel unit in systemd')
    _ap_check_listener(args.host, args.port)


@ap_contextlib.contextmanager
def _ap_lock():
    parent = _ap_open_dir('/run')
    lock = None
    try:
        try:
            lock = ap_os.open('axionpanel-install.lock', ap_os.O_RDWR | ap_os.O_CREAT | ap_os.O_NOFOLLOW | ap_os.O_NONBLOCK,
                              0o600, dir_fd=parent)
            info = ap_os.fstat(lock)
            if not ap_stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or ap_stat.S_IMODE(info.st_mode) != 0o600:
                raise RuntimeError('unsafe installer lock')
            try:
                ap_fcntl.flock(lock, ap_fcntl.LOCK_EX | ap_fcntl.LOCK_NB)
            except OSError:
                raise RuntimeError('another installer holds the lock') from None
        except OSError:
            # Only acquisition errors are reported as a lock failure; an OSError
            # raised later inside the guarded provisioning must surface as itself.
            raise RuntimeError('installer lock unavailable or unsafe') from None
        yield
        # Keep inode: unlinking introduces a three-installer lock race.
    finally:
        if lock is not None:
            ap_os.close(lock)
        ap_os.close(parent)


def _ap_write_at(parent, name, data, mode):
    try:
        fd = ap_os.open(name, ap_os.O_WRONLY | ap_os.O_CREAT | ap_os.O_EXCL | ap_os.O_NOFOLLOW, mode, dir_fd=parent)
        with ap_os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            ap_os.fchmod(stream.fileno(), mode)
            ap_os.fsync(stream.fileno())
    except OSError:
        raise RuntimeError('exclusive installation write failed; refusing overwrite') from None


def _ap_write(path, data, mode):
    parent, name = path.rsplit('/', 1)
    fd = _ap_open_dir(parent)
    try:
        _ap_write_at(fd, name, data, mode)
    finally:
        ap_os.close(fd)


def _ap_mkdir(path, mode=0o755, uid=0, gid=0):
    parent, name = path.rsplit('/', 1)
    fd = _ap_open_dir(parent)
    try:
        ap_os.mkdir(name, mode, dir_fd=fd)
        child = ap_os.open(name, ap_os.O_RDONLY | ap_os.O_DIRECTORY | ap_os.O_NOFOLLOW, dir_fd=fd)
        try:
            ap_os.fchmod(child, mode)
            ap_os.fchown(child, uid, gid)
        finally:
            ap_os.close(child)
    except OSError:
        raise RuntimeError('exclusive installation directory creation failed') from None
    finally:
        ap_os.close(fd)


def _ap_authority(args):
    return ('[' + args.host + ']' if ':' in args.host else args.host) + ':' + str(args.port)


def _ap_serve_flags(args):
    return ['-addr', _ap_authority(args), '-origin', 'https://' + _ap_authority(args),
            '-tls-cert', _AP_CERT, '-tls-key', _AP_KEY,
            '-entrance-file', _AP_STATE + '/entrance', '-db', _AP_STATE + '/panel.db',
            '-secret-key', _AP_STATE + '/secret.key', '-agent-socket', '/run/axionpanel/agent.sock']


def _ap_units(args):
    _ap_options(args)
    # Generate a closed set rather than executing arbitrary signed template
    # directives as root. No admin/password/entrance value enters a unit.
    shared = '''Type=simple
Group=axionpanel
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
UMask=0077
Restart=on-failure
RestartSec=3s
TimeoutStopSec=15s
StandardOutput=journal
StandardError=journal
AmbientCapabilities=
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
'''
    panel = '''[Unit]
Description=AxionPanel control panel (native HTTPS)
After=network-online.target axionpanel-agent.service
Wants=network-online.target axionpanel-agent.service
StartLimitIntervalSec=60
StartLimitBurst=3
[Service]
User=axionpanel
WorkingDirectory=/var/lib/axionpanel
StateDirectory=axionpanel
StateDirectoryMode=0700
CapabilityBoundingSet=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ExecStart=''' + _AP_BINARY + ' ' + ' '.join(_ap_serve_flags(args)) + '\n' + shared
    agent = '''[Unit]
Description=AxionPanel read-only host agent
After=local-fs.target
StartLimitIntervalSec=60
StartLimitBurst=3
[Service]
User=root
WorkingDirectory=/
RuntimeDirectory=axionpanel
RuntimeDirectoryMode=0750
RuntimeDirectoryPreserve=yes
CapabilityBoundingSet=CAP_CHOWN
RestrictAddressFamilies=AF_UNIX
ExecStart=/usr/local/axionpanel/bin/axionpanel-agent -socket /run/axionpanel/agent.sock -allow-uid axionpanel -socket-gid axionpanel -policy /etc/axionpanel/agent.toml
''' + shared
    return tuple(unit + '[Install]\nWantedBy=multi-user.target\n' for unit in (panel, agent))


def _ap_probe_authenticated(request, bootstrap):
    code, _ = request('GET', bootstrap['entrance_path'])
    # The production request helper consumes only this exact 303, without
    # blindly following a server-controlled redirect or disclosing the path.
    if code != 303:
        raise RuntimeError('entrance readiness failed')
    code, body = request('GET', '/login')
    if code != 200 or b'<html' not in body.lower():
        raise RuntimeError('login UI readiness failed')
    code, body = request('GET', '/api/health')
    if code != 200 or not isinstance(body, dict) or body.get('status') != 'ok':
        raise RuntimeError('HTTPS health readiness failed')
    code, login = request('POST', '/api/v1/auth/login',
        {'username': bootstrap['username'], 'password': bootstrap['password']})
    if code != 200 or not isinstance(login, dict) or login.get('mfa_required') is not False or not login.get('csrf_token'):
        raise RuntimeError('authenticated readiness unavailable; complete MFA manually if required')
    try:
        code, info = request('GET', '/api/v1/system/info')
        if code != 200 or not isinstance(info, dict) or info.get('connected') is not True or not info.get('hostname'):
            raise RuntimeError('authenticated agent-backed system information readiness failed')
    finally:
        code, _ = request('POST', '/api/v1/auth/logout', {}, login['csrf_token'])
        if code != 200:
            raise RuntimeError('readiness session cleanup failed')


def _ap_readiness(args, uid):
    raw = _ap_read(_AP_STATE + '/bootstrap.json', 16384, uid, private=True)
    bootstrap = ap_json.loads(raw)
    origin = 'https://' + _ap_authority(args)
    if (not isinstance(bootstrap, dict) or bootstrap.get('origin') != origin or
        bootstrap.get('username') != args.admin or not isinstance(bootstrap.get('password'), str) or
        not bootstrap['password'] or not ap_re.fullmatch(r'/[A-Za-z0-9_-]{12}', bootstrap.get('entrance_path', ''))):
        raise RuntimeError('private bootstrap artifact validation failed')
    certificate = _ap_read(_AP_CERT, 65536)
    # Trust exactly the locally generated self-signed certificate; still require
    # hostname validation. HTTPSConnection ignores ambient HTTP(S)_PROXY.
    context = ap_ssl.SSLContext(ap_ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=certificate.decode('ascii'))
    context.minimum_version = ap_ssl.TLSVersion.TLSv1_2
    expected = ap_ssl.PEM_cert_to_DER_cert(certificate.decode('ascii'))
    fingerprint = ap_hashlib.sha256(expected).hexdigest()
    jar = {}

    def request(method, path, body=None, csrf=None):
        connection = ap_http.HTTPSConnection(args.host, args.port, context=context, timeout=5)
        headers = {'Origin': origin, 'User-Agent': 'AxionPanel-installer-readiness'}
        if jar:
            headers['Cookie'] = '; '.join(name + '=' + value for name, value in jar.items())
        if csrf is not None:
            headers['X-CSRF-Token'] = csrf
        encoded = None
        if body is not None:
            encoded = ap_json.dumps(body).encode('utf-8')
            headers['Content-Type'] = 'application/json'
        try:
            connection.connect()
            if connection.sock.getpeercert(binary_form=True) != expected:
                raise RuntimeError('TLS certificate pin mismatch')
            connection.request(method, path, body=encoded, headers=headers)
            response = connection.getresponse()
            for name, value in response.getheaders():
                if name.lower() == 'set-cookie':
                    cookies = ap_cookies.SimpleCookie()
                    cookies.load(value)
                    for key, morsel in cookies.items():
                        if key in ('axp_entrance', 'axp_session', 'axp_csrf', 'axp_mfa'):
                            if morsel['max-age'] == '-1' or not morsel.value:
                                jar.pop(key, None)
                            else:
                                jar[key] = morsel.value
            data = response.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                raise RuntimeError('readiness response exceeds limit')
            if response.status == 303 and (path != bootstrap['entrance_path'] or response.getheader('Location') != '/login'):
                raise RuntimeError('unexpected readiness redirect')
            if path.startswith('/api/'):
                if response.status == 404:
                    # An undiscovered entrance answers every API path with a
                    # bare "Not Found" body; the readiness loop needs the
                    # status, so never parse a denial as JSON.
                    return response.status, None
                document = ap_json.loads(data)
                if not isinstance(document, dict):
                    raise RuntimeError('readiness document is not an object')
                return response.status, document
            return response.status, data
        finally:
            connection.close()

    # Retry transport readiness only, never password attempts or bootstrap.
    for attempt in range(30):
        try:
            code, _ = request('GET', '/api/health')
            if code == 404:
                break
            raise RuntimeError('undiscovered HTTPS health was not denied')
        except (OSError, ap_http.HTTPException):
            if attempt == 29:
                raise RuntimeError('native HTTPS listener did not become ready') from None
            ap_time.sleep(1)
    _ap_probe_authenticated(request, bootstrap)
    return fingerprint


def _ap_private_files(uid, directory, names):
    """Normalize panel-created state files to the documented private mode.

    ``runuser`` resets the umask to 0022, so files the panel creates under the
    0700 state directory can still land 0644 (SQLite database, secret key).
    """
    for name in names:
        path = directory + '/' + name
        if not ap_os.path.lexists(path):
            continue
        try:
            fd = ap_os.open(path, ap_os.O_RDONLY | ap_os.O_NOFOLLOW | ap_os.O_NONBLOCK)
        except OSError:
            raise RuntimeError('state file unavailable or unsafe') from None
        try:
            info = ap_os.fstat(fd)
            if not ap_stat.S_ISREG(info.st_mode) or info.st_uid != uid:
                raise RuntimeError('state file ownership verification failed')
            ap_os.fchmod(fd, 0o600)
        finally:
            ap_os.close(fd)


def _ap_provision(args, contents):
    panel_unit, agent_unit = _ap_units(args)
    _ap_mkdir('/usr/local/axionpanel')
    _ap_mkdir('/usr/local/axionpanel/bin')
    for name in ('axionpanel', 'axionpanel-agent'):
        _ap_write('/usr/local/axionpanel/bin/' + name, contents[name], 0o755)
    # Ship authenticated reference documentation/templates, never execute it.
    _ap_mkdir('/usr/local/axionpanel/share')
    for directory in ('deploy', 'deploy/nginx', 'deploy/systemd', 'docs'):
        _ap_mkdir('/usr/local/axionpanel/share/' + directory)
    for name in _AP_MEMBERS[2:]:
        _ap_write('/usr/local/axionpanel/share/' + name, contents[name], 0o644)
    if not ap_os.path.lexists('/etc/sysusers.d'):
        _ap_mkdir('/etc/sysusers.d')
    _ap_write('/etc/sysusers.d/axionpanel.conf',
              b'g axionpanel -\nu axionpanel - "AxionPanel service account" /var/lib/axionpanel /usr/sbin/nologin\n', 0o644)
    _ap_run(['/usr/bin/systemd-sysusers', '/etc/sysusers.d/axionpanel.conf'])
    user, group = ap_pwd.getpwnam('axionpanel'), ap_grp.getgrnam('axionpanel')
    if user.pw_uid == 0 or group.gr_gid == 0 or user.pw_gid != group.gr_gid or user.pw_dir != _AP_STATE or user.pw_shell != '/usr/sbin/nologin':
        raise RuntimeError('service account provisioning verification failed')
    uid, gid = user.pw_uid, group.gr_gid
    _ap_mkdir(_AP_STATE, 0o700, uid, gid)
    _ap_mkdir('/etc/axionpanel', 0o750, 0, gid)
    _ap_mkdir('/etc/axionpanel/tls', 0o750, 0, gid)
    _ap_write('/etc/axionpanel/agent.toml', b'# Deny-by-default: only built-in read-only operations are available.\n', 0o400)
    _ap_run([_AP_BINARY, '-init-tls', '-tls-host', args.host, '-tls-cert', _AP_CERT, '-tls-key', _AP_KEY])
    for path in (_AP_CERT, _AP_KEY):
        fd = ap_os.open(path, ap_os.O_RDONLY | ap_os.O_NOFOLLOW | ap_os.O_NONBLOCK)
        try:
            info = ap_os.fstat(fd)
            if not ap_stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
                raise RuntimeError('generated TLS file ownership verification failed')
            ap_os.fchown(fd, 0, gid)
            ap_os.fchmod(fd, 0o640)
        finally:
            ap_os.close(fd)
    _ap_run(['/usr/sbin/runuser', '-u', 'axionpanel', '--', _AP_BINARY,
             '-init-entrance', '-entrance-file', _AP_STATE + '/entrance'])
    _ap_run(['/usr/sbin/runuser', '-u', 'axionpanel', '--', _AP_BINARY] + _ap_serve_flags(args) +
             ['-bootstrap-admin', args.admin, '-bootstrap-out', _AP_STATE + '/bootstrap.json'])
    _ap_private_files(uid, _AP_STATE, ('panel.db', 'panel.db-wal', 'panel.db-shm',
                                       'secret.key', 'entrance', 'bootstrap.json'))
    _ap_read(_AP_STATE + '/bootstrap.json', 16384, uid, private=True)
    _ap_read(_AP_STATE + '/entrance', 64, uid, private=True)
    _ap_write('/etc/systemd/system/axionpanel-agent.service', agent_unit.encode(), 0o644)
    _ap_write('/etc/systemd/system/axionpanel.service', panel_unit.encode(), 0o644)
    _ap_run(['/usr/bin/systemd-analyze', 'verify', '/etc/systemd/system/axionpanel-agent.service',
             '/etc/systemd/system/axionpanel.service'])
    return uid


def apply_install(args, contents):
    """Provision authenticated bytes only; preserve partial state on any failure."""
    if not args.apply:
        raise RuntimeError('apply_install requires --apply')
    validate_apply(args)
    if set(contents) != set(_AP_MEMBERS) or any(not isinstance(value, bytes) for value in contents.values()):
        raise RuntimeError('authenticated exact installer payload required')
    started = []
    mutated = False
    try:
        with _ap_lock():
            # This is deliberately the same entire check as before authentication:
            # a second concurrent installer must not adopt the first one's state.
            _ap_options(args)
            _ap_fresh_checks(args)
            mutated = True
            uid = _ap_provision(args, contents)
            _ap_run(['/usr/bin/systemctl', '--system', 'daemon-reload'])
            for unit in _AP_UNITS:
                # A start can time out after activating the unit. Record intent
                # before the command so cleanup includes this ambiguous outcome.
                started.append(unit)
                _ap_run(['/usr/bin/systemctl', '--system', 'start', unit])
                _ap_run(['/usr/bin/systemctl', '--system', 'is-active', '--quiet', unit])
            fingerprint = _ap_readiness(args, uid)
            _ap_run(['/usr/bin/systemctl', '--system', 'enable', *_AP_UNITS])
            print('Origin: https://' + _ap_authority(args))
            print('Certificate SHA-256: ' + fingerprint)
            print('Bootstrap file: /var/lib/axionpanel/bootstrap.json')
            return {'origin': 'https://' + _ap_authority(args), 'certificate_sha256': fingerprint,
                    'bootstrap_file': _AP_STATE + '/bootstrap.json', 'authenticated_agent_ready': True}
    except (Exception, KeyboardInterrupt):
        for unit in reversed(started):
            try:
                _ap_run(['/usr/bin/systemctl', '--system', 'stop', unit])
            except Exception:
                pass
        if mutated:
            raise RuntimeError('installation failed; only newly started units were requested to stop; partial data preserved; manual reconciliation required') from None
        raise RuntimeError('installation refused before provisioning; prerequisites or lock failed') from None
# END AXIONPANEL APPLY ENGINE
