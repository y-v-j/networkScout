#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
networkScout: a read-only security and privacy self-check for Linux computers.

It answers four questions in plain language:
  1. Is my system secure?          updates, firewall, encryption, hardening, signs of tampering
  2. Is there a DNS leak?          who sees your DNS lookups; DNS hijacking or interception
  3. Is anyone in the middle?      router spoofing, proxies, extra root certificates, HTTPS/HTTP tampering
  4. Is my network exposure safe?  open ports, firewall coverage, IPv6, UPnP, what the internet sees

It changes nothing on your computer. The only file it writes is a small "baseline"
(~/.local/state/networkscout/baseline.json) used to spot changes between runs.
It needs nothing but Python 3.6+ (standard library only), so it works on normal,
immutable and atomic distributions alike. Run it as a normal user; run it with sudo
for a deeper check (firewall rules, all process names, password database).
"""

import argparse
import datetime
import glob
import grp
import hashlib
import io
import ipaddress
import json
import os
import platform
import pwd
import random
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache

VERSION = '1.0.0'
PROG = 'networkscout'
NAME = 'networkScout'

OK, INFO, WARN, RISK, SKIP = 'OK', 'INFO', 'WARN', 'RISK', 'SKIP'
RANK = {RISK: 0, WARN: 1, INFO: 2, SKIP: 3, OK: 4}

SECTIONS = [
    ('system', '1. Is my system secure?'),
    ('dns', '2. Is there a DNS leak?'),
    ('mitm', '3. Is anyone in the middle of my connections?'),
    ('network', '4. Is my network exposure safe (open ports)?'),
]

# Internet services contacted when online checks are on (shown in --help and the README).
ONLINE_ENDPOINTS = [
    '1.1.1.1 / 2606:4700:4700::1111 (Cloudflare): your public IP, clock, DNS interception test',
    '8.8.8.8 (Google DNS) and 9.9.9.9 (Quad9): DNS interception test',
    'whoami.akamai.net, o-o.myaddr.l.google.com: which DNS resolver reaches the internet for you',
    'rdap.org: who owns an IP address (your ISP, your DNS provider)',
    'internetdb.shodan.io: ports internet scanners have seen open on your public IP',
    '10 well-known HTTPS sites (google, github, wikipedia, ...): certificate check',
    'detectportal.firefox.com, connectivitycheck.gstatic.com, msftconnecttest.com: plain-HTTP tampering test',
    'your OS / Flatpak / Snap update servers: update check',
]

ENV_C = dict(os.environ, LC_ALL='C', LANG='C', LANGUAGE='C')
EXTRA_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'


# --------------------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------------------

def which(name):
    return shutil.which(name, path=os.environ.get('PATH', '') + ':' + EXTRA_PATH)


def run(cmd, timeout=20):
    """Run a command. Returns (returncode, stdout, stderr), or None if the program isn't installed."""
    if isinstance(cmd, str):
        cmd = cmd.split()
    exe = which(cmd[0])
    if not exe:
        return None
    try:
        p = subprocess.run([exe] + list(cmd[1:]), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           stdin=subprocess.DEVNULL, timeout=timeout, env=ENV_C,
                           encoding='utf-8', errors='replace')
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, '', 'timed out'
    except (OSError, ValueError) as e:
        return 127, '', str(e)


def stdout_of(cmd, timeout=20):
    r = run(cmd, timeout)
    return r[1] if r and r[0] == 0 else ''


def read(path, default=None):
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()
    except (OSError, ValueError):
        return default


def is_root():
    return os.geteuid() == 0


def target_user():
    """The human user the check is about (the sudo caller when run with sudo)."""
    for var in ('SUDO_USER', 'PKEXEC_UID'):
        v = os.environ.get(var)
        if v and is_root():
            try:
                return pwd.getpwuid(int(v)) if v.isdigit() else pwd.getpwnam(v)
            except (KeyError, ValueError):
                pass
    return pwd.getpwuid(os.geteuid())


def human_age(seconds):
    seconds = max(0, int(seconds))
    days = seconds // 86400
    if days >= 2:
        return plural(days, 'day')
    hours = seconds // 3600
    if hours >= 2:
        return plural(hours, 'hour')
    return plural(seconds // 60, 'minute')


def plural(n, word, words=None):
    return '%d %s' % (n, word if n == 1 else (words or word + 's'))


def ip_obj(text):
    try:
        return ipaddress.ip_address(text.split('%')[0].strip('[]'))
    except ValueError:
        return None


def in_container():
    return os.path.exists('/run/.containerenv') or os.path.exists('/.dockerenv')


# --------------------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------------------

class Output:
    def __init__(self, color, unicode_ok):
        self.color = color
        if unicode_ok:
            self.sym = {OK: '✔', INFO: 'i', WARN: '!', RISK: '✖', SKIP: '–'}
            self.arrow = '→'
        else:
            self.sym = {OK: '+', INFO: 'i', WARN: '!', RISK: 'X', SKIP: '-'}
            self.arrow = '->'
        self.codes = {OK: '32', INFO: '36', WARN: '33;1', RISK: '31;1', SKIP: '90'}
        self.width = max(60, min(110, shutil.get_terminal_size((100, 24)).columns))

    def paint(self, code, text):
        return '\033[%sm%s\033[0m' % (code, text) if self.color else text

    def bold(self, text):
        return self.paint('1', text)

    def dim(self, text):
        return self.paint('90', text)

    def wrap(self, text, indent):
        lines = []
        for para in str(text).split('\n'):
            if not para.strip():
                lines.append('')
                continue
            if para.startswith('    ') or para.startswith('$ ') or para.startswith('sudo '):
                lines.append(indent + para)          # keep commands and file snippets as they are
                continue
            lines.extend(textwrap.wrap(para, self.width - len(indent), initial_indent=indent,
                                       subsequent_indent=indent) or [indent])
        return '\n'.join(lines)


class Report:
    def __init__(self, out, verbose):
        self.out = out
        self.verbose = verbose
        self.findings = []
        self.section = None
        self.facts = {}           # values reused across sections

    def start(self, key, title):
        self.section = key
        o = self.out
        print()
        print(o.bold(title))
        print(o.dim('-' * min(len(title) + 10, o.width)))

    def progress(self, text):
        if sys.stdout.isatty():
            sys.stdout.write(self.out.dim('  … ' + text) + '\r')
            sys.stdout.flush()

    def _clear(self):
        if sys.stdout.isatty():
            sys.stdout.write(' ' * (self.out.width - 1) + '\r')

    def add(self, level, title, detail='', fix='', data=None):
        f = {'section': self.section, 'level': level, 'title': title, 'detail': detail.strip(),
             'fix': fix.strip()}
        if data is not None:
            f['data'] = data
        self.findings.append(f)
        self._clear()
        o = self.out
        print('  %s %s' % (o.paint(o.codes[level], o.sym[level]), title))
        show_detail = f['detail'] and (level in (WARN, RISK, INFO) or self.verbose)
        if show_detail:
            print(o.wrap(f['detail'], '      '))
        if f['fix'] and level in (WARN, RISK):
            print(o.wrap(o.bold('What to do: ') + f['fix'] if '\n' not in f['fix'] else
                         o.bold('What to do:') + '\n' + f['fix'], '      '))
        return f


# --------------------------------------------------------------------------------------
# network helpers (no proxy: a security check must talk to the network directly)
# --------------------------------------------------------------------------------------

UA = '%s/%s (read-only security self-check)' % (PROG, VERSION)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def http_get(url, timeout=10, follow=True, headers=None, context=None):
    """Returns (status, headers{lowercase}, body bytes). Raises OSError/URLError on network failure."""
    handlers = [urllib.request.ProxyHandler({})]
    if not follow:
        handlers.append(_NoRedirect())
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers=dict({'User-Agent': UA}, **(headers or {})))
    try:
        resp = opener.open(req, timeout=timeout)
        status, hdrs, body = resp.status, resp.headers, resp.read(200000)
    except urllib.error.HTTPError as e:
        status, hdrs, body = e.code, e.headers, (e.read(200000) if hasattr(e, 'read') else b'')
    return status, {k.lower(): v for k, v in (hdrs or {}).items()}, body


def http_json(url, timeout=10):
    status, _, body = http_get(url, timeout=timeout, headers={'Accept': 'application/json'})
    return status, json.loads(body.decode('utf-8', 'replace') or 'null')


@lru_cache(maxsize=None)
def cloudflare_trace(family):
    """Your public IP as seen by Cloudflare, plus its clock. family: 4 or 6."""
    url = 'https://1.1.1.1/cdn-cgi/trace' if family == 4 else 'https://[2606:4700:4700::1111]/cdn-cgi/trace'
    try:
        sent = time.time()
        status, _, body = http_get(url, timeout=8)
        if status != 200:
            raise OSError('status %s' % status)
        d = dict(line.split('=', 1) for line in body.decode().splitlines() if '=' in line)
        d['_local'] = (sent + time.time()) / 2
        return d
    except Exception:
        pass
    try:  # fallback
        status, _, body = http_get('https://api.ipify.org' if family == 4 else 'https://api6.ipify.org', timeout=8)
        ip = body.decode().strip()
        return {'ip': ip} if ip_obj(ip) else None
    except Exception:
        return None


def public_ip(family):
    t = cloudflare_trace(family)
    return t.get('ip') if t else None


# well-known DNS providers (saves an ownership lookup for the common cases)
PROVIDERS = [
    ('Google Public DNS', ['8.8.8.0/24', '8.8.4.0/24', '74.125.0.0/16', '172.217.0.0/16', '172.253.0.0/16',
                           '173.194.0.0/16', '192.178.0.0/15', '108.177.0.0/17', '2001:4860::/32',
                           '2404:6800::/32', '2607:f8b0::/32', '2800:3f0::/32', '2a00:1450::/32', '2c0f:fb50::/32']),
    ('Cloudflare DNS', ['1.1.1.0/24', '1.0.0.0/24', '162.158.0.0/15', '172.64.0.0/13', '104.16.0.0/13',
                        '108.162.192.0/18', '2400:cb00::/32', '2606:4700::/32', '2a06:98c0::/29']),
    ('Quad9', ['9.9.9.0/24', '149.112.112.0/24', '74.63.16.0/20', '2620:fe::/48', '2620:171::/48']),
    ('OpenDNS (Cisco)', ['208.67.216.0/21', '146.112.0.0/16', '2620:119::/32', '2620:0:ccc::/48']),
    ('AdGuard DNS', ['94.140.14.0/23', '176.103.130.0/24', '2a10:50c0::/29']),
    ('NextDNS', ['45.90.28.0/22', '2a07:a8c0::/29']),
    ('Mullvad DNS', ['194.242.2.0/24', '2a07:e340::/32']),
]
_PROVIDER_NETS = [(name, [ipaddress.ip_network(n) for n in nets]) for name, nets in PROVIDERS]


def known_provider(ip):
    a = ip_obj(ip)
    if a is None:
        return None
    for name, nets in _PROVIDER_NETS:
        for n in nets:
            if a.version == n.version and a in n:
                return name
    return None


@lru_cache(maxsize=None)
def ip_owner(ip, online=True):
    """'Owner name (CC)' from RDAP, or a well-known provider name."""
    k = known_provider(ip)
    if k:
        return k
    if not online:
        return None
    try:
        status, data = http_json('https://rdap.org/ip/' + ip, timeout=12)
    except Exception:
        return None
    if status != 200 or not isinstance(data, dict):
        return None
    found = {}

    def walk(ents):
        for e in ents or []:
            v = e.get('vcardArray')
            if v and len(v) > 1:
                for item in v[1]:
                    if item and item[0] == 'fn' and len(item) > 3:
                        for role in e.get('roles', []):
                            found.setdefault(role, str(item[3]))
            walk(e.get('entities'))
    walk(data.get('entities'))
    org = found.get('registrant') or found.get('administrative')
    if org:
        org = re.sub(r'\s+(administrator|admin|noc|technical|tech|abuse|contact|role|team|hostmaster)s?$', '',
                     org.strip(), flags=re.I) or org
    name = data.get('name') or ''
    cc = data.get('country') or ''
    label = org or name or None
    if label and name and org and name.lower() not in org.lower():
        label = '%s / %s' % (org, name)
    return ('%s (%s)' % (label, cc) if cc else label) if label else None


# --------------------------------------------------------------------------------------
# a tiny DNS client (so the tool does not need dig/nslookup)
# --------------------------------------------------------------------------------------

QTYPE = {'A': 1, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12, 'MX': 15, 'TXT': 16, 'AAAA': 28}
QTYPE_NAME = {v: k for k, v in QTYPE.items()}
RCODES = {0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED'}


def _encode_name(name):
    out = b''
    for label in name.rstrip('.').split('.'):
        b = label.encode('ascii')
        out += bytes([len(b)]) + b
    return out + b'\x00'


def _read_name(msg, off):
    labels, jumped, end, hops = [], False, off, 0
    while True:
        n = msg[off]
        if n & 0xC0 == 0xC0:
            if not jumped:
                end = off + 2
            jumped, hops = True, hops + 1
            if hops > 30:
                raise ValueError('compression loop')
            off = ((n & 0x3F) << 8) | msg[off + 1]
            continue
        if n == 0:
            if not jumped:
                end = off + 1
            return '.'.join(labels), end
        labels.append(msg[off + 1:off + 1 + n].decode('ascii', 'replace'))
        off += 1 + n


def _recv_exact(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError('connection closed')
        buf += chunk
    return buf


def dns_query(name, qtype='A', server='127.0.0.53', timeout=3.0, qclass=1, tcp=False, port=53):
    """Returns {'rcode_name', 'answers': [(type, value)], 'ad'} or {'error': ...}."""
    tid = random.randint(0, 0xFFFF)
    pkt = (struct.pack('>HHHHHH', tid, 0x0100, 1, 0, 0, 1) + _encode_name(name) +
           struct.pack('>HH', QTYPE[qtype], qclass) + b'\x00' + struct.pack('>HHIH', 41, 1232, 0, 0))
    try:
        fam, stype, proto, _, sa = socket.getaddrinfo(server, port, 0,
                                                      socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)[0]
    except (socket.gaierror, IndexError, UnicodeError) as e:
        return {'error': 'bad server address (%s)' % e}
    s = socket.socket(fam, stype, proto)
    s.settimeout(timeout)
    try:
        if tcp:
            s.connect(sa)
            s.sendall(struct.pack('>H', len(pkt)) + pkt)
            msg = _recv_exact(s, struct.unpack('>H', _recv_exact(s, 2))[0])
        else:
            s.sendto(pkt, sa)
            deadline = time.time() + timeout
            while True:
                msg, _ = s.recvfrom(65535)
                if len(msg) >= 12 and struct.unpack('>H', msg[:2])[0] == tid:
                    break
                if time.time() > deadline:
                    raise socket.timeout()
    except socket.timeout:
        return {'error': 'timeout'}
    except OSError as e:
        return {'error': str(e)}
    finally:
        s.close()
    try:
        _, flags, qd, an, _, _ = struct.unpack('>HHHHHH', msg[:12])
        if flags & 0x0200 and not tcp:
            return dns_query(name, qtype, server, timeout, qclass, True, port)
        off = 12
        for _ in range(qd):
            _, off = _read_name(msg, off)
            off += 4
        answers = []
        for _ in range(an):
            _, off = _read_name(msg, off)
            rtype, _, _, rdlen = struct.unpack('>HHIH', msg[off:off + 10])
            off += 10
            rdata = msg[off:off + rdlen]
            if rtype == 1 and rdlen == 4:
                val = socket.inet_ntop(socket.AF_INET, rdata)
            elif rtype == 28 and rdlen == 16:
                val = socket.inet_ntop(socket.AF_INET6, rdata)
            elif rtype == 16:
                parts, i = [], 0
                while i < len(rdata):
                    ln = rdata[i]
                    parts.append(rdata[i + 1:i + 1 + ln].decode('utf-8', 'replace'))
                    i += 1 + ln
                val = ' '.join(parts)
            elif rtype in (2, 5, 12):
                val = _read_name(msg, off)[0]
            else:
                val = rdata.hex()
            answers.append((QTYPE_NAME.get(rtype, str(rtype)), val))
            off += rdlen
        return {'rcode': flags & 0xF, 'rcode_name': RCODES.get(flags & 0xF, str(flags & 0xF)),
                'answers': answers, 'ad': bool(flags & 0x20)}
    except (struct.error, IndexError, ValueError) as e:
        return {'error': 'bad reply (%s)' % e}


def dns_values(res, qtype=None):
    return [v for t, v in res.get('answers', []) if qtype is None or t == qtype]


# --------------------------------------------------------------------------------------
# facts about this machine
# --------------------------------------------------------------------------------------

@lru_cache(maxsize=None)
def os_release():
    d = {}
    for line in (read('/etc/os-release') or read('/usr/lib/os-release') or '').splitlines():
        if '=' in line and not line.startswith('#'):
            k, v = line.split('=', 1)
            d[k.strip()] = v.strip().strip('"').strip("'")
    return d


@lru_cache(maxsize=None)
def package_system():
    osr = os_release()
    ids = (osr.get('ID', '') + ' ' + osr.get('ID_LIKE', '')).lower()
    if os.path.exists('/run/ostree-booted'):
        if which('rpm-ostree'):
            return 'rpm-ostree'
        return 'ostree'
    if which('transactional-update'):
        return 'transactional-update'
    if os.path.exists('/etc/NIXOS') or 'nixos' in ids:
        return 'nixos'
    if 'steamos' in ids:
        return 'steamos'
    for exe, fam in (('apt-get', 'apt'), ('dnf', 'dnf'), ('yum', 'yum'), ('pacman', 'pacman'),
                     ('zypper', 'zypper'), ('apk', 'apk'), ('xbps-install', 'xbps'), ('emerge', 'portage'),
                     ('eopkg', 'eopkg'), ('swupd', 'swupd')):
        if which(exe):
            return fam
    return 'unknown'


UPDATE_CMD = {
    'rpm-ostree': 'rpm-ostree upgrade   (then restart the computer)',
    'ostree': 'use your system\'s software updater, then restart',
    'transactional-update': 'sudo transactional-update up   (then restart)',
    'nixos': 'sudo nixos-rebuild switch --upgrade',
    'steamos': 'Settings > System > Check for updates',
    'apt': 'sudo apt update && sudo apt full-upgrade',
    'dnf': 'sudo dnf upgrade --refresh',
    'yum': 'sudo yum update',
    'pacman': 'sudo pacman -Syu',
    'zypper': 'sudo zypper refresh && sudo zypper update   (Tumbleweed: sudo zypper dup)',
    'apk': 'sudo apk upgrade -U',
    'xbps': 'sudo xbps-install -Su',
    'portage': 'sudo emerge --sync && sudo emerge -auDN @world',
    'eopkg': 'sudo eopkg upgrade',
    'swupd': 'sudo swupd update',
}


def update_command():
    fam = package_system()
    if fam == 'rpm-ostree' and which('ujust'):
        return 'ujust update   (then restart the computer)'
    return UPDATE_CMD.get(fam, 'use your distribution\'s software updater')


def default_routes_v4():
    routes = []
    for line in (read('/proc/net/route') or '').splitlines()[1:]:
        f = line.split()
        if len(f) >= 8 and f[1] == '00000000' and f[7] == '00000000':
            gw = socket.inet_ntoa(struct.pack('<I', int(f[2], 16)))
            routes.append({'iface': f[0], 'gateway': gw, 'metric': int(f[6])})
    return sorted(routes, key=lambda r: r['metric'])


def default_routes_v6():
    routes = []
    for line in (read('/proc/net/ipv6_route') or '').splitlines():
        f = line.split()
        if len(f) >= 10 and f[0] == '0' * 32 and f[1] == '00':
            hop = f[4]
            flags = int(f[8], 16)
            if hop == '0' * 32 or flags & 0x0200:          # no next hop / reject route
                continue
            addr = str(ipaddress.IPv6Address(bytes.fromhex(hop)))
            routes.append({'iface': f[9], 'gateway': addr, 'metric': int(f[5], 16)})
    return routes


@lru_cache(maxsize=None)
def route_dev(dest):
    """Network interface used to reach dest (uses `ip route get`, falls back to the default route)."""
    out = stdout_of(['ip', 'route', 'get', dest], 5)
    m = re.search(r'\bdev\s+(\S+)', out)
    if m:
        return m.group(1)
    a = ip_obj(dest)
    routes = default_routes_v6() if a and a.version == 6 else default_routes_v4()
    return routes[0]['iface'] if routes else None


VPN_NAME = re.compile(r'^(tun|tap|wg|ppp|ipsec|vti|gpd|cscotun|utun|nordlynx|proton|pvpn|mullvad|'
                      r'tailscale|zt|ztun|vpn|expressvpn|surfshark|nebula|warp|cloudflare)', re.I)


def vpn_interfaces():
    found = []
    for path in glob.glob('/sys/class/net/*'):
        name = os.path.basename(path)
        if name == 'lo':
            continue
        kind = read(os.path.join(path, 'type'), '').strip()
        flags = (read(os.path.join(path, 'tun_flags'), '') or '').strip()
        try:
            is_tun = bool(int(flags, 16) & 0x0001) if flags else False     # IFF_TUN; taps (0x0002) are VM/container NICs
        except ValueError:
            is_tun = False
        uevent = read(os.path.join(path, 'uevent'), '')
        if VPN_NAME.match(name) or is_tun or 'DEVTYPE=wireguard' in uevent or kind in ('65534', '512'):
            found.append(name)
    return found


def active_vpn():
    """The VPN interface carrying your internet traffic, or None."""
    vpns = set(vpn_interfaces())
    for dest in ('1.1.1.1', '2606:4700:4700::1111'):
        dev = route_dev(dest)
        if dev and (dev in vpns or VPN_NAME.match(dev)) and not dev.startswith('tailscale'):
            return dev
    return None


def global_ipv6_addresses():
    addrs = []
    for line in (read('/proc/net/if_inet6') or '').splitlines():
        f = line.split()
        if len(f) < 6:
            continue
        a = ipaddress.IPv6Address(bytes.fromhex(f[0]))
        scope, flags, iface = int(f[3], 16), int(f[4], 16), f[5]
        if scope == 0 and not a.is_private and not a.is_link_local and not (flags & 0x20) and iface != 'lo':
            addrs.append((str(a), iface, bool(flags & 0x01)))
    return addrs


# ---- listening sockets --------------------------------------------------------------

TCP_LISTEN = '0A'


def _hex_addr(h):
    ip, port = h.split(':')
    port = int(port, 16)
    raw = bytes.fromhex(ip)
    if len(raw) == 4:
        return socket.inet_ntop(socket.AF_INET, raw[::-1]), port
    words = b''.join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
    a = ipaddress.IPv6Address(words)
    if a.ipv4_mapped:
        return str(a.ipv4_mapped), port
    return str(a), port


def _inode_owners():
    owners = {}
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        fd_dir = '/proc/%s/fd' % pid
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        comm = (read('/proc/%s/comm' % pid, '') or '').strip()
        for fd in fds:
            try:
                link = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if link.startswith('socket:['):
                owners.setdefault(link[8:-1], (comm, int(pid)))
    return owners


def _ss_details():
    """uid / systemd cgroup / process for each listening socket, via `ss` when available."""
    info = {}
    out = stdout_of(['ss', '-H', '-tulnpe'], 10)
    for line in out.splitlines():
        f = line.split()
        if len(f) < 5:
            continue
        local = f[4]
        port = local.rsplit(':', 1)[-1]
        host = local.rsplit(':', 1)[0].split('%')[0].strip('[]')
        host = '' if host in ('*', '0.0.0.0', '::') else host
        m_ino = re.search(r'\bino:(\d+)', line)
        m_uid = re.search(r'\buid:(\d+)', line)
        m_cg = re.search(r'\bcgroup:(\S+)', line)
        m_user = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
        d = {'uid': int(m_uid.group(1)) if m_uid else 0, 'cgroup': m_cg.group(1) if m_cg else '',
             'process': m_user.group(1) if m_user else '', 'pid': int(m_user.group(2)) if m_user else None}
        if m_ino:
            info[('ino', m_ino.group(1))] = d
        info[(f[0], host, port)] = d
    return info


def unit_from_cgroup(cg):
    for part in reversed(cg.split('/')):
        if part.endswith('.service') or part.endswith('.scope'):
            name = part.rsplit('.', 1)[0]
            name = re.sub(r'^app-', '', name)
            name = re.sub(r'@[0-9a-f]{16,}$', '', name)
            name = re.sub(r'-\d+$', '', name)
            return name.replace('\\x2d', '-')
    return ''


def listening_sockets():
    rng = (read('/proc/sys/net/ipv4/ip_local_port_range') or '32768 60999').split()
    eph_lo, eph_hi = int(rng[0]), int(rng[1])
    owners = _inode_owners()
    ssd = _ss_details()
    result, seen = [], set()
    for proto, path in (('tcp', '/proc/net/tcp'), ('tcp', '/proc/net/tcp6'),
                        ('udp', '/proc/net/udp'), ('udp', '/proc/net/udp6')):
        for line in (read(path) or '').splitlines()[1:]:
            f = line.split()
            if len(f) < 10:
                continue
            if proto == 'tcp' and f[3] != TCP_LISTEN:
                continue
            if proto == 'udp' and f[3] != '07':        # 07 = unconnected (bound) UDP socket
                continue
            try:
                addr, port = _hex_addr(f[1])
            except (ValueError, IndexError):
                continue
            uid, inode = int(f[7]), f[9]
            key = (proto, addr, port)
            if key in seen:
                continue
            seen.add(key)
            a = ipaddress.ip_address(addr)
            if a.is_unspecified:
                scope = 'all'
            elif a.is_loopback:
                scope = 'loopback'
            elif a.is_link_local:
                scope = 'link-local'
            elif a.is_private:
                scope = 'lan'
            else:
                scope = 'public'
            proc, pid = owners.get(inode, ('', None))
            d = ssd.get(('ino', inode)) or ssd.get((proto, '' if a.is_unspecified else addr, str(port))) or {}
            unit = unit_from_cgroup(d.get('cgroup', ''))
            proc = proc or d.get('process', '')
            try:
                user = pwd.getpwuid(uid).pw_name
            except KeyError:
                user = str(uid)
            result.append({'proto': proto, 'addr': addr, 'port': port, 'scope': scope, 'process': proc,
                           'pid': pid or d.get('pid'), 'unit': unit, 'user': user,
                           'ephemeral': proto == 'udp' and eph_lo <= port <= eph_hi})
    return result


def describe_owner(s):
    who = s['process'] or s['unit'] or ('a program of user ' + s['user'])
    if s['unit'] and s['process'] and s['unit'] not in s['process']:
        who = '%s (%s)' % (s['process'], s['unit'])
    return who


# --------------------------------------------------------------------------------------
# certificates
# --------------------------------------------------------------------------------------

SCT_OID = bytes.fromhex('060a2b06010401d679020402')      # Certificate Transparency proof (embedded SCTs)

INTERCEPTION_VENDORS = [
    'fortinet', 'fortigate', 'zscaler', 'kaspersky', 'avast', 'avg ', 'eset', 'bitdefender', 'sophos',
    'palo alto', 'blue coat', 'bluecoat', 'netskope', 'mitmproxy', 'charles proxy', 'fiddler',
    'portswigger', 'burp', 'cisco umbrella', 'forcepoint', 'websense', 'barracuda', 'check point',
    'checkpoint', 'untangle', 'watchguard', 'sonicwall', 'deeper', 'adguard', 'superfish', 'privdog',
    'komodia', 'lightspeed', 'securly', 'contentkeeper', 'smoothwall', 'iboss', 'cyberoam', 'qustodio',
    'norton', 'mcafee', 'trend micro', 'webroot', 'g data', 'f-secure', 'menlo', 'squid', 'proxy',
]

PUBLIC_CA_HINTS = [
    'google trust services', "let's encrypt", 'digicert', 'sectigo', 'comodo', 'globalsign', 'amazon',
    'microsoft', 'entrust', 'godaddy', 'starfield', 'identrust', 'certainly', 'zerossl', 'buypass',
    'ssl.com', 'apple', 'baltimore', 'quovadis', 'certum', 'actalis', 'harica', 'telia', 'swisssign',
    'deutsche telekom', 't-systems', 'cloudflare', 'thawte', 'geotrust', 'rapidssl', 'trustwave',
    'internet security research group', 'isrg', 'usertrust', 'cybertrust', 'verisign', 'network solutions',
    'emsign', 'e-tugra', 'secom', 'gts ', 'wr1', 'wr2', 'we1', 'we2',
]


def _flat_name(seq):
    d = {}
    for rdn in seq or ():
        for k, v in rdn:
            d.setdefault(k, v)
    return d


def cert_info_from_pem(pem):
    """Subject/issuer/expiry/fingerprint for a PEM certificate, using only the standard library."""
    der = ssl.PEM_cert_to_DER_cert(pem)
    info = {'sha256': hashlib.sha256(der).hexdigest(), 'sct': SCT_OID in der}
    decoded = None
    tmp = tempfile.NamedTemporaryFile('w', suffix='.pem', delete=False)
    try:
        tmp.write(pem)
        tmp.close()
        try:
            decoded = ssl._ssl._test_decode_cert(tmp.name)          # pylint: disable=protected-access
        except Exception:
            decoded = None
        if decoded is None and which('openssl'):
            out = stdout_of(['openssl', 'x509', '-in', tmp.name, '-noout', '-subject', '-issuer', '-enddate',
                             '-nameopt', 'sep_multiline,utf8'])
            info['openssl'] = out
    finally:
        os.unlink(tmp.name)
    if decoded:
        subj, iss = _flat_name(decoded.get('subject')), _flat_name(decoded.get('issuer'))
        info.update(subject_cn=subj.get('commonName', ''), subject_o=subj.get('organizationName', ''),
                    issuer_cn=iss.get('commonName', ''), issuer_o=iss.get('organizationName', ''),
                    not_after=decoded.get('notAfter', ''), self_signed=subj == iss)
    else:
        o = info.get('openssl', '')
        cn = re.search(r'subject=.*?commonName=([^\n]+)', o, re.S)
        org = re.search(r'subject=.*?organizationName=([^\n]+)', o, re.S)
        info.update(subject_cn=cn.group(1).strip() if cn else '', subject_o=org.group(1).strip() if org else '',
                    issuer_cn='', issuer_o='', not_after='', self_signed=None)
    return info


def certs_in_file(path):
    try:
        with open(path, 'rb') as f:
            raw = f.read(2000000)
    except OSError:
        return []
    text = raw.decode('utf-8', 'replace')
    pems = re.findall(r'-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----', text, re.S)
    if not pems and raw[:1] == b'\x30':
        pems = [ssl.DER_cert_to_PEM_cert(raw)]
    out = []
    for pem in pems:
        try:
            out.append(cert_info_from_pem(pem))
        except Exception:
            continue
    return out


ANCHOR_DIRS = [
    '/etc/pki/ca-trust/source/anchors', '/etc/pki/ca-trust/source',            # Fedora, RHEL, Bazzite...
    '/usr/local/share/ca-certificates',                                        # Debian, Ubuntu, Alpine
    '/etc/ca-certificates/trust-source/anchors', '/etc/ca-certificates/trust-source',   # Arch
    '/etc/pki/trust/anchors',                                                  # openSUSE
]


def local_ca_anchors():
    found = []
    for d in ANCHOR_DIRS:
        if not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d)):
            path = os.path.join(d, name)
            if not os.path.isfile(path) or name.lower().startswith('readme'):
                continue
            shipped = os.path.exists('/usr' + path)          # atomic images keep their own /etc defaults in /usr/etc
            for c in certs_in_file(path):
                c.update(path=path, shipped_by_os=shipped,
                         mtime=datetime.datetime.fromtimestamp(os.path.getmtime(path)).strftime('%Y-%m-%d'))
                found.append(c)
    return found


TLS_SITES = ['www.google.com', 'github.com', 'www.wikipedia.org', 'www.cloudflare.com', 'www.mozilla.org',
             'www.microsoft.com', 'www.apple.com', 'www.amazon.com', 'www.paypal.com', 'letsencrypt.org']


def tls_probe(host):
    res = {'host': host}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=8) as s:
            with ctx.wrap_socket(s, server_hostname=host) as t:
                cert, der = t.getpeercert(), t.getpeercert(True)
                iss = _flat_name(cert.get('issuer'))
                res.update(ok=True, issuer_o=iss.get('organizationName', ''), issuer_cn=iss.get('commonName', ''),
                           sct=SCT_OID in der, sha256=hashlib.sha256(der).hexdigest(), ip=t.getpeername()[0])
        return res
    except ssl.SSLError as e:
        res.update(ok=False, error=str(e), verify_failed='CERTIFICATE_VERIFY_FAILED' in str(e))
    except (OSError, socket.timeout) as e:
        res.update(ok=False, error=str(e), network=True)
        return res
    # verification failed: see who signed what we were given
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, 443), timeout=8) as s:
            with ctx.wrap_socket(s, server_hostname=host) as t:
                info = cert_info_from_pem(ssl.DER_cert_to_PEM_cert(t.getpeercert(True)))
                res.update(issuer_o=info.get('issuer_o', ''), issuer_cn=info.get('issuer_cn', ''),
                           sct=info.get('sct'))
    except Exception:
        pass
    return res


# --------------------------------------------------------------------------------------
# baseline (to notice changes between runs)
# --------------------------------------------------------------------------------------

def elevated_for_user():
    """True when running as root on behalf of a normal user (sudo/pkexec): files then go to that user's home."""
    return is_root() and any(os.environ.get(v) for v in ('SUDO_USER', 'PKEXEC_UID'))


def baseline_path():
    u = target_user()
    base = None if elevated_for_user() else os.environ.get('XDG_STATE_HOME')
    base = base or os.path.join(u.pw_dir, '.local', 'state')
    return os.path.join(base, PROG, 'baseline.json')


def load_baseline():
    try:
        with open(baseline_path(), 'r', encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def save_baseline(data):
    path = baseline_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=1, sort_keys=True)
        if is_root():
            u = target_user()
            for p in (path, os.path.dirname(path)):
                try:
                    os.chown(p, u.pw_uid, u.pw_gid)
                except OSError:
                    pass
        return path
    except OSError:
        return None


# ======================================================================================
# 1. SYSTEM
# ======================================================================================

def check_updates(R, online):
    fam = package_system()
    fix = update_command()
    osr = os_release()

    if fam == 'rpm-ostree':
        r = run(['rpm-ostree', 'status', '--json'], 30)
        try:
            deps = json.loads(r[1])['deployments'] if r and r[0] == 0 else []
        except ValueError:
            deps = []
        booted = next((d for d in deps if d.get('booted')), None)
        if not booted:
            R.add(SKIP, 'Could not read the system image status (rpm-ostree)')
            return
        staged = next((d for d in deps if d.get('staged')), None)
        ref = booted.get('container-image-reference', '') or ''
        ver = booted.get('version') or '?'
        age = time.time() - (booted.get('timestamp') or time.time())
        m = re.search(r'(20\d{2})(\d{2})(\d{2})', ver)          # image versions carry their build date
        if m:
            try:
                age = time.time() - time.mktime(datetime.date(*map(int, m.groups())).timetuple())
            except ValueError:
                pass
        R.facts['os_image'] = {'version': ver, 'ref': ref}
        if ref and 'unverified' in ref:
            R.add(INFO, 'Your system image is installed without signature checking',
                  'The image reference is "%s". Signed images ("ostree-image-signed") make sure updates '
                  'really come from your distribution.' % ref)
        if staged:
            R.add(WARN, 'An update is already downloaded but not active yet',
                  'Version %s is waiting. It only takes effect after a restart.' % (staged.get('version') or '?'),
                  'Restart the computer.')
            return
        image = ''
        if 'docker://' in ref:
            image = ref.split('docker://', 1)[1]
        elif 'registry:' in ref:
            image = ref.split('registry:', 1)[1]
        if online and image and which('skopeo'):
            R.progress('asking the image registry for the newest version')
            r2 = run(['skopeo', 'inspect', '--no-tags', 'docker://' + image], 120)
            try:
                remote = json.loads(r2[1]) if r2 and r2[0] == 0 else None
            except ValueError:
                remote = None
            if remote:
                rver = (remote.get('Labels') or {}).get('org.opencontainers.image.version') or remote.get('Created', '?')
                rdig, bdig = remote.get('Digest'), booted.get('container-image-reference-digest')
                if rdig and bdig and rdig != bdig:
                    R.add(WARN, 'Operating-system updates are available',
                          'You run image version %s (%s old); the newest published version is %s. '
                          'Updates contain security fixes, so install them soon.' % (ver, human_age(age), rver),
                          fix)
                    return
                if rdig and bdig:
                    R.add(OK, 'Operating system is up to date (image %s)' % ver)
                    return
        if fam == 'rpm-ostree' and not image and online:
            r2 = run(['rpm-ostree', 'upgrade', '--check'], 180)
            if r2 and 'AvailableUpdate' in (r2[1] + r2[2]):
                R.add(WARN, 'Operating-system updates are available', 'Version %s is installed.' % ver, fix)
                return
            if r2 and r2[0] in (0, 77):
                R.add(OK, 'Operating system is up to date (%s)' % ver)
                return
        level = WARN if age > 21 * 86400 else INFO
        R.add(level, 'System image %s was built %s ago' % (ver, human_age(age)),
              'Could not ask the update server directly. Images older than about 3 weeks usually '
              'miss security fixes.', fix)
        return

    if fam == 'dnf' or fam == 'yum':
        R.progress('checking for updates with %s (this can take a minute)' % fam)
        r = run([fam, '-q', 'check-update'], 240) if online else run([fam, '-q', '-C', 'check-update'], 60)
        if r is None or r[0] not in (0, 100):
            R.add(SKIP, 'Could not check for updates (%s)' % ((r[2].strip().splitlines() or ['error'])[-1] if r else 'not found'))
        elif r[0] == 100:
            pkgs = [l for l in r[1].splitlines() if l and not l.startswith(('Obsoleting', 'Last metadata', ' '))
                    and len(l.split()) >= 3]
            R.add(WARN, '%s waiting to be installed' % plural(len(pkgs), 'update'),
                  'Updates contain security fixes.', fix)
        else:
            R.add(OK, 'All packages are up to date')
        r = run(['needs-restarting', '-r'], 30) or run(['dnf', 'needs-restarting', '-r'], 30)
        if r and r[0] == 1:
            R.add(WARN, 'A restart is needed to finish installing updates',
                  'Core components (like the kernel) were updated but the old ones are still running.',
                  'Restart the computer.')
    elif fam == 'apt':
        lists = glob.glob('/var/lib/apt/lists/*_Packages') + glob.glob('/var/lib/apt/lists/*_InRelease')
        newest = max([os.path.getmtime(p) for p in lists] or [0])
        r = run(['apt', 'list', '--upgradable'], 60)
        pkgs = [l for l in (r[1] if r else '').splitlines() if '/' in l and 'upgradable' in l]
        sec = [l for l in pkgs if '-security' in l]
        stale = time.time() - newest > 7 * 86400 if newest else True
        note = (' (package lists were last refreshed %s ago, so there may be more)' % human_age(time.time() - newest)
                if stale and newest else '')
        if pkgs:
            R.add(RISK if sec else WARN, '%s waiting to be installed%s' % (
                plural(len(pkgs), 'update'), ', %d of them security updates' % len(sec) if sec else ''),
                'Updates contain security fixes%s.' % note, fix)
        elif stale:
            R.add(WARN, 'Package lists are out of date', 'They were last refreshed %s.' % (
                human_age(time.time() - newest) + ' ago' if newest else 'never'), fix)
        else:
            R.add(OK, 'All packages are up to date')
        if os.path.exists('/var/run/reboot-required'):
            R.add(WARN, 'A restart is needed to finish installing updates', '', 'Restart the computer.')
    elif fam == 'pacman':
        if online and which('checkupdates'):
            R.progress('checking for updates (checkupdates)')
            r = run(['checkupdates'], 180)
            pkgs = [l for l in (r[1] if r else '').splitlines() if l.strip()]
        else:
            r = run(['pacman', '-Qu'], 60)
            pkgs = [l for l in (r[1] if r else '').splitlines() if l.strip()]
        sync = glob.glob('/var/lib/pacman/sync/*.db')
        newest = max([os.path.getmtime(p) for p in sync] or [0])
        if pkgs:
            R.add(WARN, '%s waiting to be installed' % plural(len(pkgs), 'update'), 'Updates contain security fixes.', fix)
        elif newest and time.time() - newest > 14 * 86400 and not which('checkupdates'):
            R.add(WARN, 'Package database not refreshed for %s' % human_age(time.time() - newest), '', fix)
        else:
            R.add(OK, 'All packages are up to date')
    elif fam in ('zypper', 'transactional-update'):
        r = run(['zypper', '--non-interactive', '--quiet', 'list-updates'], 180)
        pkgs = [l for l in (r[1] if r else '').splitlines() if l.startswith('v ')]
        if r is None or r[0] != 0:
            R.add(SKIP, 'Could not check for updates (run with sudo to let zypper refresh)')
        elif pkgs:
            R.add(WARN, '%s waiting to be installed' % plural(len(pkgs), 'update'), 'Updates contain security fixes.', fix)
        else:
            R.add(OK, 'All packages are up to date')
    elif fam == 'apk':
        r = run(['apk', 'version', '-l', '<'], 60)
        pkgs = [l for l in (r[1] if r else '').splitlines()[1:] if '<' in l]
        R.add(WARN if pkgs else OK, '%s waiting to be installed' % plural(len(pkgs), 'update') if pkgs
              else 'All packages are up to date (as of the last index refresh)', '', fix)
    elif fam == 'xbps':
        r = run(['xbps-install', '-Mun'], 120)
        pkgs = [l for l in (r[1] if r else '').splitlines() if l.strip()]
        R.add(WARN if pkgs else OK, '%s waiting to be installed' % plural(len(pkgs), 'update') if pkgs
              else 'All packages are up to date', '', fix)
    elif fam == 'portage':
        stamp = read('/var/db/repos/gentoo/metadata/timestamp.chk') or read('/usr/portage/metadata/timestamp.chk')
        try:
            synced = datetime.datetime.strptime((stamp or '').strip(), '%a, %d %b %Y %H:%M:%S %z').timestamp()
        except ValueError:
            synced = None
        if synced is None:
            R.add(INFO, 'Gentoo: could not read when the package tree was last synced', '', fix)
        elif time.time() - synced > 14 * 86400:
            R.add(WARN, 'Gentoo package tree last synced %s ago' % human_age(time.time() - synced),
                  'Without a recent sync, security updates are not even seen.', fix)
        else:
            R.add(INFO, 'Gentoo package tree synced %s ago' % human_age(time.time() - synced),
                  'See pending updates with: emerge -pvuDN @world', fix)
    elif fam == 'nixos':
        ver = stdout_of(['nixos-version']).strip()
        R.add(INFO, 'NixOS %s: update with your usual rebuild' % ver, 'This tool does not check NixOS channels.', fix)
    else:
        R.add(SKIP, 'Update check not supported for this system (%s)' % (osr.get('PRETTY_NAME') or fam),
              'Use your distribution\'s software updater regularly.')

    # kernel updated but not rebooted (classic distributions)
    if fam not in ('rpm-ostree', 'ostree', 'nixos') and not in_container() and \
            not os.path.isdir('/lib/modules/' + platform.release()) and \
            not os.path.isdir('/usr/lib/modules/' + platform.release()):
        R.add(WARN, 'The running kernel was updated: restart to use the new one',
              'The files for the running kernel (%s) were replaced by an update.' % platform.release(),
              'Restart the computer.')


def check_app_updates(R, online):
    if not online:
        return
    if which('flatpak'):
        R.progress('checking Flatpak apps for updates')
        r = run(['flatpak', 'remote-ls', '--updates', '--columns=application'], 120)
        apps = sorted(set(l.strip() for l in (r[1] if r else '').splitlines() if l.strip()))
        if r and r[0] == 0:
            if apps:
                R.add(WARN, '%s waiting' % plural(len(apps), 'Flatpak app update'),
                      'Apps and runtimes: %s%s.' % (', '.join(apps[:8]), ' ...' if len(apps) > 8 else ''),
                      'flatpak update')
            else:
                R.add(OK, 'Flatpak apps are up to date')
    if which('snap') and os.path.exists('/run/snapd.socket'):
        r = run(['snap', 'refresh', '--list'], 60)
        if r and r[0] == 0:
            rows = [l for l in r[1].splitlines()[1:] if l.strip()]
            if rows:
                R.add(WARN, '%s waiting' % plural(len(rows), 'Snap update'), '', 'sudo snap refresh')
            else:
                R.add(OK, 'Snap packages are up to date')


def secure_boot_state():
    if not os.path.isdir('/sys/firmware/efi'):
        return 'bios'
    for p in glob.glob('/sys/firmware/efi/efivars/SecureBoot-*'):
        try:
            with open(p, 'rb') as f:
                data = f.read()
            return 'on' if data[-1:] == b'\x01' else 'off'
        except OSError:
            pass
    out = stdout_of(['mokutil', '--sb-state'])
    if 'enabled' in out:
        return 'on'
    if 'disabled' in out:
        return 'off'
    return 'unknown'


def _dm_is_crypt(dev, depth=0):
    """True if a block device is (or sits on top of) a dm-crypt/LUKS device."""
    if depth > 8:
        return False
    try:
        real = os.path.realpath(dev)
    except OSError:
        return False
    name = os.path.basename(real)
    uuid = read('/sys/block/%s/dm/uuid' % name, '') or ''
    if uuid.startswith('CRYPT-'):
        return True
    for slave in glob.glob('/sys/block/%s/slaves/*' % name):
        if _dm_is_crypt('/dev/' + os.path.basename(slave), depth + 1):
            return True
    return False


def mounts():
    res = {}
    for line in (read('/proc/self/mountinfo') or '').splitlines():
        left, _, right = line.partition(' - ')
        lf, rf = left.split(), right.split()
        if len(lf) >= 5 and len(rf) >= 2:
            res[lf[4].replace('\\040', ' ')] = {'fstype': rf[0], 'source': rf[1]}
    return res


def check_encryption(R):
    m = mounts()
    laptop = bool(glob.glob('/sys/class/power_supply/BAT*'))
    checks = []
    for mp in ('/var/home', '/home', '/sysroot', '/'):
        info = m.get(mp)
        if not info:
            continue
        src, fs = info['source'], info['fstype']
        if fs in ('ecryptfs',) or fs.startswith('fuse.gocryptfs'):
            checks.append((mp, True))
        elif src.startswith('/dev/'):
            checks.append((mp, _dm_is_crypt(src)))
        elif fs == 'zfs':
            checks.append((mp, None))
    if not checks:
        R.add(SKIP, 'Could not tell whether your disk is encrypted')
        return
    home = next((c for c in checks if c[0] in ('/var/home', '/home')), None) or \
        next((c for c in checks if c[0] in ('/sysroot', '/')), None)
    plain = [mp for mp, enc in checks if enc is False]
    if home and home[1]:
        R.add(OK, 'Your files are on an encrypted disk (%s)' % home[0])
        if plain and any(p in ('/', '/sysroot') for p in plain) and home[0] not in ('/', '/sysroot'):
            R.add(INFO, 'The system part of the disk is not encrypted',
                  'Your personal files are encrypted, which is what matters most.')
    elif home and home[1] is None:
        R.add(INFO, 'Disk encryption status unknown (ZFS)', 'Check with: zfs get encryption')
    else:
        R.add(WARN if laptop else INFO, 'Your disk is not encrypted',
              'If this %s is lost or stolen, anyone can read your files by removing the disk.'
              % ('laptop' if laptop else 'computer'),
              'Encryption is chosen when installing Linux (LUKS / "encrypt disk" option). For an existing '
              'system, back up and reinstall with encryption, or encrypt sensitive folders (e.g. gocryptfs).')
    for line in (read('/proc/swaps') or '').splitlines()[1:]:
        dev = line.split()[0]
        if dev.startswith('/dev/zram'):
            continue
        if dev.startswith('/dev/') and not _dm_is_crypt(dev):
            R.add(INFO, 'Swap space (%s) is not encrypted' % dev,
                  'Memory contents written to swap could be read from the disk.')


def check_mac_lockdown(R):
    sb = secure_boot_state()
    if sb == 'on':
        R.add(OK, 'Secure Boot is on')
    elif sb == 'off':
        R.add(INFO, 'Secure Boot is off', 'Secure Boot stops tampered boot software from loading. It is optional '
              'on Linux, but worth enabling if your distribution supports it.')
    elif sb == 'bios':
        R.add(INFO, 'The computer starts in legacy BIOS mode (no Secure Boot)')
    lock = read('/sys/kernel/security/lockdown')
    if lock:
        mode = re.search(r'\[(\w+)\]', lock)
        if mode and mode.group(1) != 'none':
            R.add(OK, 'Kernel lockdown is on (%s)' % mode.group(1))
    se = read('/sys/fs/selinux/enforce')
    aa = (read('/sys/module/apparmor/parameters/enabled') or '').strip()
    if se is not None:
        if se.strip() == '1':
            R.add(OK, 'SELinux is enforcing (limits what hacked programs can do)')
        else:
            R.add(WARN, 'SELinux is installed but only in permissive mode',
                  'It logs problems but does not block them.',
                  'sudo setenforce 1   and set SELINUX=enforcing in /etc/selinux/config')
    elif aa == 'Y':
        R.add(OK, 'AppArmor is enabled (limits what hacked programs can do)')
    else:
        R.add(INFO, 'No mandatory access control (SELinux/AppArmor) active',
              'Common on some distributions; it is an extra safety layer, not a must.')


SYSCTLS = [
    ('kernel.randomize_va_space', ('2',), RISK, 'memory address randomization (ASLR) is weakened', '2'),
    ('fs.protected_symlinks', ('1',), WARN, 'protection against symlink tricks in shared folders is off', '1'),
    ('fs.protected_hardlinks', ('1',), WARN, 'protection against hard-link tricks is off', '1'),
    ('net.ipv4.conf.all.accept_source_route', ('0',), WARN, 'source-routed packets are accepted', '0'),
    ('fs.protected_fifos', ('1', '2'), INFO, 'FIFO protection in shared folders is off', '1'),
    ('fs.protected_regular', ('1', '2'), INFO, 'file protection in shared folders is off', '2'),
    ('kernel.yama.ptrace_scope', ('1', '2', '3'), INFO,
     'any of your programs may read the memory of your other programs', '1'),
    ('kernel.kptr_restrict', ('1', '2'), INFO, 'kernel memory addresses are not hidden', '1'),
    ('kernel.dmesg_restrict', ('1',), INFO, 'every user can read the kernel log', '1'),
    ('kernel.unprivileged_bpf_disabled', ('1', '2'), INFO, 'unprivileged programs may load BPF code', '2'),
    ('net.ipv4.tcp_syncookies', ('1',), INFO, 'SYN-flood protection is off', '1'),
    ('net.ipv4.conf.all.accept_redirects', ('0',), INFO, 'ICMP redirects are accepted (IPv4)', '0'),
    ('net.ipv6.conf.all.accept_redirects', ('0',), INFO, 'ICMP redirects are accepted (IPv6)', '0'),
    ('net.ipv4.icmp_echo_ignore_broadcasts', ('1',), INFO, 'broadcast pings are answered', '1'),
    ('net.ipv4.tcp_timestamps', ('0',), INFO, 'TCP timestamps can reveal your uptime to websites', '0'),
]


def check_sysctls(R):
    bad = []
    for key, good, level, text, rec in SYSCTLS:
        val = read('/proc/sys/' + key.replace('.', '/'))
        if val is None:
            continue
        val = val.strip()
        if val not in good:
            bad.append((level, key, val, text, rec))
    if not bad:
        R.add(OK, 'Kernel hardening settings look good')
        return
    level = min((b[0] for b in bad), key=lambda l: RANK[l])
    detail = '\n'.join('%s = %s: %s' % (k, v, t) for _, k, v, t, _ in bad)
    snippet = '\n'.join('    %s = %s' % (k, r) for _, k, _, _, r in bad)
    if level == INFO:
        R.add(INFO, '%s could be stricter (optional)' % plural(len(bad), 'kernel setting'), detail +
              '\nOptional hardening: put these lines in /etc/sysctl.d/60-hardening.conf and run '
              '"sudo sysctl --system":\n' + snippet)
    else:
        R.add(level, 'Some kernel safety settings are weakened', detail,
              'Put these lines in /etc/sysctl.d/60-hardening.conf and run "sudo sysctl --system":\n' + snippet)


def check_cpu(R):
    vuln = []
    for p in sorted(glob.glob('/sys/devices/system/cpu/vulnerabilities/*')):
        v = (read(p) or '').strip()
        if v.lower().startswith('vulnerable'):
            vuln.append('%s: %s' % (os.path.basename(p), v))
    if vuln:
        R.add(WARN, 'The processor is unprotected against %s' % plural(len(vuln), 'known flaw'),
              '\n'.join(vuln), 'Install system and firmware (BIOS/microcode) updates.')
    elif glob.glob('/sys/devices/system/cpu/vulnerabilities/*'):
        R.add(OK, 'Processor security flaws are mitigated')


def check_accounts(R):
    users = pwd.getpwall()
    uid0 = [u.pw_name for u in users if u.pw_uid == 0 and u.pw_name != 'root']
    if uid0:
        R.add(RISK, 'Extra administrator (UID 0) accounts exist: %s' % ', '.join(uid0),
              'Only "root" should have user ID 0. A second one is a classic backdoor.',
              'If you did not create them on purpose, remove them (sudo userdel NAME) and investigate.')
    logins = [u.pw_name for u in users if not re.search(r'(nologin|false|sync|shutdown|halt)$', u.pw_shell or '')
              and (u.pw_uid == 0 or u.pw_uid >= 1000) and u.pw_uid != 65534]
    admins = set()
    for g in ('wheel', 'sudo', 'admin'):
        try:
            admins.update(grp.getgrnam(g).gr_mem)
        except KeyError:
            pass
    shadow = read('/etc/shadow') if is_root() else None
    if shadow:
        empty = [l.split(':')[0] for l in shadow.splitlines() if l.count(':') >= 2 and l.split(':')[1] == ''
                 and l.split(':')[0] in logins]
        if empty:
            R.add(RISK, 'Accounts without any password: %s' % ', '.join(empty),
                  'Anyone can log in to these accounts.', 'sudo passwd NAME   (or lock it: sudo passwd -l NAME)')
    R.add(INFO, 'Accounts that can log in: %s' % ', '.join(logins) + (
        '; administrators: %s' % ', '.join(sorted(admins)) if admins else ''),
        'Make sure you recognise every name in this list.')


def _sshd_settings():
    if is_root():
        out = stdout_of(['sshd', '-T'], 10)
        if out:
            return dict(l.split(None, 1) for l in out.splitlines() if ' ' in l)
    cfg = {}
    files = sorted(glob.glob('/etc/ssh/sshd_config.d/*.conf')) + ['/etc/ssh/sshd_config']
    for path in files:
        for line in (read(path) or '').splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if line.lower().startswith('match '):
                break
            parts = line.split(None, 1)
            if len(parts) == 2:
                cfg.setdefault(parts[0].lower(), parts[1].strip())
    return cfg


def check_ssh(R, listeners):
    listening = [s for s in listeners if s['proto'] == 'tcp' and s['port'] == 22 and s['scope'] != 'loopback']
    active = any(stdout_of(['systemctl', 'is-active', n]).strip() == 'active' for n in ('sshd', 'ssh')) \
        if which('systemctl') else False
    u = target_user()
    keys = os.path.join(u.pw_dir, '.ssh', 'authorized_keys')
    nkeys = len([l for l in (read(keys) or '').splitlines() if l.strip() and not l.startswith('#')])
    if not listening and not active:
        R.add(OK, 'No remote-login (SSH) server is running')
        if nkeys:
            R.add(INFO, '%s can log in to your account if you turn SSH on' % plural(nkeys, 'SSH key'),
                  'They are listed in %s.' % keys)
        return
    cfg = _sshd_settings()
    prl = cfg.get('permitrootlogin', 'prohibit-password').lower()
    pwa = cfg.get('passwordauthentication', 'yes').lower()
    problems = []
    if prl == 'yes':
        problems.append('the root account may log in with a password (PermitRootLogin yes)')
    if pwa == 'yes':
        problems.append('password logins are allowed (PasswordAuthentication yes); passwords can be guessed')
    level = RISK if prl == 'yes' else (WARN if problems else INFO)
    R.add(level, 'A remote-login (SSH) server is running and accepts connections',
          'If you do not use it, turn it off. ' + ('Settings to improve: ' + '; '.join(problems) + '.' if problems
                                                   else 'It only allows key-based logins, which is good.') +
          (' %s can log in to your account.' % plural(nkeys, 'SSH key') if nkeys else ''),
          'Not needed? sudo systemctl disable --now sshd   (Debian/Ubuntu: ssh)\n'
          'Needed? use keys and set "PasswordAuthentication no" and "PermitRootLogin no" in /etc/ssh/sshd_config.')


TAINT = {0: ('P', 'proprietary driver loaded', INFO), 1: ('F', 'a module was force-loaded', WARN),
         3: ('R', 'a module was force-unloaded', WARN), 4: ('M', 'the processor reported a hardware error', INFO),
         5: ('B', 'bad memory page found', INFO), 7: ('D', 'the kernel crashed (oops) since boot', INFO),
         9: ('W', 'the kernel logged a warning', INFO), 12: ('O', 'out-of-tree drivers loaded', INFO),
         13: ('E', 'an UNSIGNED kernel module is loaded', WARN), 15: ('K', 'live-patched', INFO)}


def check_integrity(R):
    preload = (read('/etc/ld.so.preload') or '').strip()
    if preload:
        R.add(RISK, '/etc/ld.so.preload forces code into every program',
              'Contents:\n    ' + preload.replace('\n', '\n    ') +
              '\nThis is rarely legitimate and is a common rootkit trick.',
              'If you do not recognise these files, get expert help; consider reinstalling.')
    else:
        R.add(OK, 'No code is forced into every program (/etc/ld.so.preload is empty)')
    if os.environ.get('LD_PRELOAD'):
        R.add(WARN, 'LD_PRELOAD is set in your environment: %s' % os.environ['LD_PRELOAD'],
              'It injects a library into programs you start from this shell.',
              'Find where it is set (~/.bashrc, ~/.profile, /etc/environment) and remove it if unknown.')

    odd = []
    for top in ('/tmp', '/var/tmp', '/dev/shm'):
        for root, _, files in os.walk(top):
            if root.count('/') > 6:
                continue
            for name in files:
                p = os.path.join(root, name)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if st.st_mode & 0o6000 and os.path.isfile(p):
                    odd.append(p)
    if odd:
        R.add(RISK, 'Programs with administrator powers (setuid) in temporary folders',
              '\n'.join(odd[:10]), 'Real software never lives there. Get expert help; consider reinstalling.')

    sus, deleted = [], []
    for pid in os.listdir('/proc'):
        if not pid.isdigit():
            continue
        try:
            exe = os.readlink('/proc/%s/exe' % pid)
        except OSError:
            continue
        comm = (read('/proc/%s/comm' % pid, '') or '').strip()
        if re.match(r'^(/tmp|/var/tmp|/dev/shm)/', exe):
            sus.append('pid %s %s: %s' % (pid, comm, exe))
        elif exe.endswith(' (deleted)') and not exe.startswith(('/memfd:', '/SYSV')):
            deleted.append('%s (%s)' % (comm, exe[:-10]))
    if sus:
        R.add(RISK, 'Programs are running from temporary folders',
              '\n'.join(sus[:10]), 'Malware often runs from /tmp or /dev/shm. Investigate these processes.')
    if deleted:
        R.add(INFO, '%s running from files that were since replaced' % plural(len(deleted), 'program'),
              'Usually just programs updated while running: restart them (or the computer). '
              'Examples: ' + ', '.join(sorted(set(deleted))[:6]))
    if not sus and not odd:
        R.add(OK, 'No programs running from suspicious places%s' % ('' if is_root() else ' (your own programs; '
                                                                       'run with sudo to check all)'))

    taint = int((read('/proc/sys/kernel/tainted') or '0').strip() or 0)
    if taint:
        flags = [(b, TAINT[b]) for b in sorted(TAINT) if taint & (1 << b)]
        level = min([t[2] for _, t in flags] or [INFO], key=lambda l: RANK[l])
        R.add(level, 'Kernel status flags: ' + ', '.join(t[1] for _, t in flags),
              'Out-of-tree or proprietary drivers (graphics, VirtualBox, gaming devices) are normal. '
              'An unsigned module on a Secure Boot system deserves a look.' if level == INFO else
              'An unsigned or force-loaded kernel module can be a rootkit.',
              'List modules: lsmod. Investigate any you do not recognise.' if level != INFO else '')

    if which('systemctl'):
        failed = [l.split()[0] for l in stdout_of(['systemctl', '--failed', '--no-legend', '--plain']).splitlines()
                  if l.strip()]
        if failed:
            R.add(INFO, '%s failed to start: %s' % (plural(len(failed), 'system service'), ', '.join(failed[:6])),
                  'Not necessarily a security problem, but security services (firewall, updates) should not fail. '
                  'Details: systemctl status NAME')


def check_autostart(R):
    u = target_user()
    items = []
    for p in sorted(glob.glob(os.path.join(u.pw_dir, '.config', 'autostart', '*.desktop'))):
        txt = read(p, '')
        if re.search(r'^Hidden\s*=\s*true', txt, re.M):
            continue
        m = re.search(r'^Exec\s*=\s*(.+)$', txt, re.M)
        items.append('autostart %s: %s' % (os.path.basename(p), m.group(1)[:100] if m else '?'))
    udir = os.path.join(u.pw_dir, '.config', 'systemd', 'user')
    for p in sorted(glob.glob(os.path.join(udir, '*.service')) + glob.glob(os.path.join(udir, '*.timer'))):
        if not os.path.islink(p):
            m = re.search(r'^ExecStart\s*=\s*(.+)$', read(p, ''), re.M)
            items.append('user service %s: %s' % (os.path.basename(p), m.group(1)[:100] if m else '?'))
    cron = stdout_of(['crontab', '-l'] if not is_root() else ['crontab', '-l', '-u', u.pw_name])
    for line in cron.splitlines():
        if line.strip() and not line.startswith('#'):
            items.append('cron: ' + line.strip()[:110])
    if items:
        R.add(INFO, '%s start automatically for you' % plural(len(items), 'program'),
              'Make sure you recognise each one (malware often hides here):\n' + '\n'.join(items[:15]))
    else:
        R.add(OK, 'No personal autostart entries, user services or cron jobs')


def section_system(R, online, listeners):
    osr = os_release()
    R.add(INFO, '%s, kernel %s, up %s' % (osr.get('PRETTY_NAME', 'Linux'), platform.release(),
                                          human_age(float((read('/proc/uptime') or '0').split()[0]))))
    R.progress('checking for operating-system updates')
    check_updates(R, online)
    check_app_updates(R, online)
    check_mac_lockdown(R)
    check_encryption(R)
    check_cpu(R)
    check_sysctls(R)
    check_accounts(R)
    check_ssh(R, listeners)
    check_integrity(R)
    check_autostart(R)


# ======================================================================================
# 2. DNS
# ======================================================================================

def resolv_conf():
    ns, search = [], []
    for line in (read('/etc/resolv.conf') or '').splitlines():
        f = line.split()
        if len(f) >= 2 and f[0] == 'nameserver':
            ns.append(f[1])
        elif f and f[0] in ('search', 'domain'):
            search.extend(f[1:])
    return ns, search


RESOLVED_LABELS = ('Protocols', 'resolv.conf mode', 'Current Scopes', 'Current DNS Server', 'DNS Servers',
                   'Fallback DNS Servers', 'DNS Domain', 'Default Route', 'LLMNR setting', 'MulticastDNS setting',
                   'DNSOverTLS setting', 'DNSSEC setting', 'DNSSEC supported', 'DNSSEC NTA')


def resolved_status():
    out = stdout_of(['resolvectl', 'status'], 10)
    if not out:
        return None
    st = {'global': {}, 'links': []}
    cur, last = st['global'], None
    for line in out.splitlines():
        if not line.strip():
            continue
        m = re.match(r'^Link \d+ \(([^)]+)\)', line)
        if m:
            cur = {'name': m.group(1)}
            st['links'].append(cur)
            last = None
            continue
        if line.startswith('Global'):
            cur, last = st['global'], None
            continue
        m = re.match(r'^\s*([A-Za-z][A-Za-z .]+?):\s*(.*)$', line)
        if m and m.group(1).strip() in RESOLVED_LABELS:
            last = m.group(1).strip()
            cur[last] = m.group(2).strip()
        elif last in ('DNS Servers', 'Fallback DNS Servers', 'DNS Domain', 'DNSSEC NTA'):
            cur[last] = (cur.get(last, '') + ' ' + line.strip()).strip()
    return st


def _flag(text, name):
    """Value of a resolvectl protocol flag: '+DNSOverTLS' -> 'yes', 'DNSSEC=no/unsupported' -> 'no'."""
    if not text:
        return None
    m = re.search(r'([+-])%s\b' % name, text)
    if m:
        return 'yes' if m.group(1) == '+' else 'no'
    m = re.search(r'%s=([\w-]+)' % name, text)
    return m.group(1) if m else None


ENCRYPTED_DNS_PROGRAMS = ('dnscrypt-proxy', 'stubby', 'cloudflared', 'adguardhome', 'dnsproxy', 'nextdns',
                          'blocky', 'unbound', 'coredns', 'doh-client', 'https_dns_proxy', 'routedns')


def check_dns(R, online, listeners):
    ns, search = resolv_conf()
    rs = resolved_status() if which('resolvectl') else None
    upstream, dot, llmnr = [], None, None
    if rs and any(n in ('127.0.0.53', '127.0.0.54') for n in ns):
        g = rs['global']
        dot = _flag(g.get('Protocols', ''), 'DNSOverTLS') or g.get('DNSOverTLS setting')
        llmnr = _flag(g.get('Protocols', ''), 'LLMNR') or g.get('LLMNR setting')
        for src in [g] + rs['links']:
            for s in (src.get('DNS Servers') or '').split():
                s = s.split('#')[0]
                if s not in upstream:
                    upstream.append(s)
            ldot = _flag(src.get('Protocols', ''), 'DNSOverTLS') or src.get('DNSOverTLS setting')
            if ldot in ('yes', 'opportunistic') and dot not in ('yes',):
                dot = ldot
        manager = 'systemd-resolved'
    else:
        upstream = [n for n in ns if not (ip_obj(n) and ip_obj(n).is_loopback)]
        manager = 'resolv.conf'
    local_dns = [s for s in listeners if s['port'] == 53 and s['scope'] == 'loopback']
    enc_proxy = sorted(set(describe_owner(s) for s in local_dns
                           if any(p in (s['process'] + s['unit']).lower() for p in ENCRYPTED_DNS_PROGRAMS)))
    R.facts['dns'] = {'nameservers': ns, 'upstream': upstream, 'dot': dot, 'llmnr': llmnr}

    names = []
    for u in upstream:
        prov = known_provider(u)
        a = ip_obj(u)
        names.append('%s (%s)' % (u, prov or ('your router / local network' if a and (a.is_private or a.is_link_local)
                                              else 'provider: ' + (ip_owner(u, online) or 'unknown'))))
    R.add(INFO, 'Your computer asks these DNS servers: %s' % ('; '.join(names) or ', '.join(ns) or 'none found'),
          'DNS turns names like "example.com" into addresses. Whoever answers can see every site you visit. '
          'Managed by %s%s.' % (manager, ', local encrypted DNS program: ' + ', '.join(enc_proxy) if enc_proxy else ''))

    # --- encryption ---
    if dot == 'yes':
        R.add(OK, 'DNS lookups are encrypted (DNS-over-TLS)')
    elif enc_proxy:
        R.add(OK, 'DNS goes through a local encrypted-DNS program (%s)' % ', '.join(enc_proxy))
    elif dot == 'opportunistic':
        R.add(INFO, 'DNS encryption is only "opportunistic"', 'It falls back to unencrypted DNS when the server '
              'does not support encryption, and does not check the server\'s identity.')
    else:
        fix = ('Turn on DNS-over-TLS in systemd-resolved. Create /etc/systemd/resolved.conf.d/dns-over-tls.conf:\n'
               '    [Resolve]\n'
               '    DNS=1.1.1.1#cloudflare-dns.com 1.0.0.1#cloudflare-dns.com 2606:4700:4700::1111#cloudflare-dns.com\n'
               '    DNSOverTLS=yes\n'
               '    Domains=~.\n'
               'then stop using the router\'s DNS and restart:\n'
               '    sudo nmcli connection modify "<your connection>" ipv4.ignore-auto-dns yes ipv6.ignore-auto-dns yes\n'
               '    sudo systemctl restart systemd-resolved NetworkManager\n'
               '(Google 8.8.8.8#dns.google and Quad9 9.9.9.9#dns.quad9.net work too.) Alternatively enable '
               '"DNS over HTTPS" in your web browser.') if rs else \
              'Use an encrypted DNS service: enable "DNS over HTTPS" in your browser, or install dnscrypt-proxy.'
        R.add(WARN, 'DNS lookups are not encrypted',
              'Your internet provider (and anyone on your network path) can see every site name you look up, '
              'and could change the answers.', fix)

    # --- who answers on the internet side / leak verdict ---
    vpn = active_vpn()
    R.facts['vpn'] = vpn
    if not online:
        if vpn:
            leaking = [u for u in upstream if route_dev(u) and route_dev(u) != vpn and not ip_obj(u).is_loopback]
            if leaking:
                R.add(RISK, 'DNS leak: lookups go around your VPN (%s)' % vpn,
                      'These DNS servers are reached outside the VPN tunnel: %s.' % ', '.join(leaking),
                      'Turn on your VPN app\'s "DNS leak protection" / "use VPN DNS" option.')
        return
    R.progress('finding out which DNS servers reach the internet for you')
    resolver = ns[0] if ns else '127.0.0.53'
    egress = []
    for name, qt in (('whoami.akamai.net', 'A'), ('whoami.akamai.net', 'AAAA'), ('o-o.myaddr.l.google.com', 'TXT')):
        res = dns_query(name, qt, resolver, timeout=4)
        for v in dns_values(res):
            for tok in v.replace('"', ' ').split():
                if ip_obj(tok) and tok not in egress:
                    egress.append(tok)
    pub4, pub6 = public_ip(4), public_ip(6)
    R.facts['public_ip'] = {'v4': pub4, 'v6': pub6}
    isp = ip_owner(pub4 or pub6, online) if (pub4 or pub6) else None
    R.facts['isp'] = isp
    if not egress:
        R.add(SKIP, 'Could not identify which DNS servers reach the internet for you')
        return
    owners = sorted(set(ip_owner(e, online) or e for e in egress))
    detail = 'Seen by the outside world as: %s (%s).' % (', '.join(egress[:6]), '; '.join(owners))
    if vpn:
        vpn_org = isp
        leaking = [u for u in upstream if route_dev(u) and route_dev(u) != vpn and not (ip_obj(u) and ip_obj(u).is_loopback)]
        mismatch = vpn_org and not any(vpn_org.split(' (')[0].lower()[:12] in o.lower() for o in owners) and \
            not all(known_provider(e) for e in egress)
        if leaking:
            R.add(RISK, 'DNS leak: lookups go around your VPN (%s)' % vpn,
                  detail + ' These DNS servers are reached outside the tunnel: %s.' % ', '.join(leaking),
                  'Turn on your VPN app\'s "DNS leak protection" / "use VPN DNS" option, then run this check again.')
        elif mismatch:
            R.add(WARN, 'Possible DNS leak: your DNS answers do not come from your VPN provider',
                  detail + ' Your VPN exit belongs to %s.' % vpn_org,
                  'Check that your VPN app uses its own DNS ("DNS leak protection").')
        else:
            R.add(OK, 'No DNS leak: your lookups stay inside the VPN (%s)' % vpn, detail)
    else:
        same_as_isp = isp and any(isp.split(' (')[0].lower()[:12] in o.lower() for o in owners)
        R.add(INFO, 'No VPN in use, so there is nothing to leak around: your DNS is handled by %s'
              % ('your internet provider' if same_as_isp else '; '.join(owners)),
              detail + ' Your public IP belongs to %s.' % (isp or 'unknown') +
              (' Your DNS provider passes part of your address (%s) on to websites\' DNS servers.'
               % re.search(r'edns0-client-subnet (\S+)', ' '.join(
                   dns_values(dns_query('o-o.myaddr.l.google.com', 'TXT', resolver)))).group(1)
               if 'edns0-client-subnet' in ' '.join(dns_values(dns_query('o-o.myaddr.l.google.com', 'TXT', resolver)))
               else ''))
    R.facts['dns_egress'] = egress


def check_dns_integrity(R, online):
    ns, _ = resolv_conf()
    resolver = ns[0] if ns else '127.0.0.53'
    upstream = (R.facts.get('dns') or {}).get('upstream') or []

    # /etc/hosts
    hosts = []
    hostname = socket.gethostname()
    for line in (read('/etc/hosts') or '').splitlines():
        f = line.split('#')[0].split()
        if len(f) >= 2:
            for name in f[1:]:
                if name in ('localhost', 'localhost.localdomain', 'localhost4', 'localhost6', hostname,
                            'ip6-localhost', 'ip6-loopback', 'ip6-allnodes', 'ip6-allrouters', 'ip6-localnet',
                            'ip6-mcastprefix', 'localhost4.localdomain4', 'localhost6.localdomain6') or \
                        name.startswith(hostname + '.'):
                    continue
                hosts.append((f[0], name))
    popular = re.compile(r'(^|\.)(google|gstatic|youtube|facebook|microsoft|windowsupdate|apple|icloud|amazon|'
                         r'github|paypal|whatsapp|instagram|twitter|x|cloudflare|mozilla|fedoraproject|debian|'
                         r'ubuntu|archlinux|flathub|sbi|hdfcbank|icicibank|bank\w*)\.\w+$', re.I)
    redirected = [(ip, n) for ip, n in hosts if popular.search(n) and ip not in ('0.0.0.0', '127.0.0.1', '::', '::1')]
    blocked = [(ip, n) for ip, n in hosts if ip in ('0.0.0.0', '127.0.0.1', '::', '::1')]
    if redirected:
        R.add(RISK, '/etc/hosts sends well-known sites to other addresses',
              '\n'.join('%s -> %s' % (n, ip) for ip, n in redirected[:10]) +
              '\nThis bypasses DNS completely and is a common phishing/malware trick.',
              'Remove these lines from /etc/hosts (sudo nano /etc/hosts) unless you added them yourself.')
    if blocked and len(blocked) > 20:
        R.add(INFO, '/etc/hosts blocks %d names (looks like an ad/tracker block list)' % len(blocked))
    others = [(ip, n) for ip, n in hosts if (ip, n) not in redirected and (ip, n) not in blocked]
    if others:
        R.add(INFO, '/etc/hosts has %s' % plural(len(others), 'custom entry', 'custom entries'),
              '\n'.join('%s -> %s' % (n, ip) for ip, n in others[:10]))
    if not redirected and not others and not (blocked and len(blocked) > 20):
        R.add(OK, '/etc/hosts is clean (no sites redirected)')

    # answers for names with fixed, well-known addresses
    known = {'one.one.one.one': {'1.1.1.1', '1.0.0.1'}, 'dns.google': {'8.8.8.8', '8.8.4.4'}}
    bad, got_any = [], False
    for name, good in known.items():
        res = dns_query(name, 'A', resolver, timeout=4)
        vals = set(dns_values(res, 'A'))
        if vals:
            got_any = True
            if not vals <= good:
                bad.append('%s -> %s (should be %s)' % (name, ', '.join(sorted(vals)), ', '.join(sorted(good))))
    if bad:
        R.add(RISK, 'Your DNS gives wrong answers for well-known names (DNS tampering)',
              '\n'.join(bad), 'Switch to a trusted DNS provider with encryption (see the DNS-over-TLS advice above), '
              'and check your router for changed DNS settings.')
    elif got_any:
        R.add(OK, 'DNS answers for well-known names are correct')

    # NXDOMAIN hijacking and DNSSEC, per upstream server where possible
    targets = [u for u in upstream if ip_obj(u) and not ip_obj(u).is_loopback][:4] or [resolver]
    hijack, nodnssec, validating, unreachable = [], [], [], []
    for srv in targets:
        name = 'lsc-%08x%08x.com' % (random.getrandbits(32), random.getrandbits(32))
        res = dns_query(name, 'A', srv, timeout=4)
        if 'error' in res:
            unreachable.append(srv)
            continue
        if res.get('rcode_name') == 'NOERROR' and dns_values(res, 'A'):
            hijack.append('%s answered %s for a name that does not exist' % (srv, ', '.join(dns_values(res, 'A'))))
        res = dns_query('dnssec-failed.org', 'A', srv, timeout=5)
        if res.get('rcode_name') == 'SERVFAIL':
            validating.append(srv)
        elif dns_values(res, 'A'):
            nodnssec.append(srv)
    if hijack:
        R.add(WARN, 'DNS hijacking: mistyped or non-existent names are redirected',
              '\n'.join(hijack) + '\nOften an internet provider showing ads or search pages instead of an error.',
              'Use a different DNS provider (see the DNS-over-TLS advice above).')
    elif len(unreachable) < len(targets):
        R.add(OK, 'Non-existent names correctly return "not found" (no DNS hijacking)')
    if unreachable:
        R.add(INFO, 'DNS server(s) did not answer test queries: %s' % ', '.join(unreachable),
              'Some of your configured DNS servers are slow or unreachable; lookups then fall back to the others.')
    if nodnssec:
        R.add(INFO, 'DNS server(s) that do not check DNSSEC signatures: %s' % ', '.join(nodnssec),
              'DNSSEC lets a resolver detect forged answers. %s' % (
                  'These do check: ' + ', '.join(validating) + '. Because your computer uses both, some lookups '
                  'are not protected.' if validating else 'Encrypted DNS with a validating provider fixes this.'))
    elif validating:
        R.add(OK, 'Your DNS provider rejects forged (bad DNSSEC) answers')

    if not online:
        return
    # interception: are queries to public resolvers really answered by them?
    R.progress('testing whether DNS traffic is intercepted on the way')
    pub4 = (R.facts.get('public_ip') or {}).get('v4') or public_ip(4)
    pub6 = (R.facts.get('public_ip') or {}).get('v6') or public_ip(6)
    findings = []
    if pub4:
        res = dns_query('whoami.cloudflare', 'TXT', '1.1.1.1', timeout=4, qclass=3)
        vals = [v.strip('"') for v in dns_values(res, 'TXT')]
        if 'error' in res:
            findings.append((WARN, '1.1.1.1 (Cloudflare) did not answer on the DNS port; plain DNS may be filtered.'))
        elif vals and vals[0] != pub4:
            findings.append((RISK, 'DNS sent to 1.1.1.1 was answered by someone else (they saw %s, your public IP '
                                   'is %s).' % (vals[0], pub4)))
        elif vals:
            pop = dns_values(dns_query('id.server', 'TXT', '1.1.1.1', timeout=4, qclass=3), 'TXT')
            findings.append((OK, '1.1.1.1 answered genuinely%s.' % (' (Cloudflare site %s)' % pop[0].strip('"')
                                                                   if pop else '')))
        res = dns_query('o-o.myaddr.l.google.com', 'TXT', '8.8.8.8', timeout=4)
        ips = [t for v in dns_values(res, 'TXT') for t in v.replace('"', ' ').split() if ip_obj(t)]
        if 'error' in res:
            findings.append((WARN, '8.8.8.8 (Google) did not answer on the DNS port.'))
        elif ips and not all(known_provider(i) == 'Google Public DNS' for i in ips):
            findings.append((RISK, 'DNS sent to 8.8.8.8 was answered by %s instead of Google.' % ', '.join(ips)))
        elif ips:
            findings.append((OK, '8.8.8.8 answered genuinely.'))
        res = dns_query('example.com', 'A', '9.9.9.9', timeout=4)
        if 'error' in res:
            findings.append((INFO, '9.9.9.9 (Quad9) did not answer over IPv4; it may be blocked on your network path.'))
    if pub6:
        res = dns_query('whoami.cloudflare', 'TXT', '2606:4700:4700::1111', timeout=4, qclass=3)
        vals = [v.strip('"') for v in dns_values(res, 'TXT')]
        if vals and vals[0] != pub6 and ip_obj(vals[0]) and ip_obj(vals[0]).version == 6:
            if vals[0].split(':')[:4] != pub6.split(':')[:4]:
                findings.append((RISK, 'IPv6 DNS sent to Cloudflare was answered by someone else (%s).' % vals[0]))
    if any(l == RISK for l, _ in findings):
        R.add(RISK, 'DNS traffic is being intercepted on the way to the internet',
              '\n'.join(t for _, t in findings) +
              '\nSomething (router, internet provider, or an attacker) answers DNS queries meant for public '
              'DNS servers.', 'Use encrypted DNS (DNS-over-TLS / DNS-over-HTTPS): it cannot be intercepted '
                              'without an error. Check your router\'s DNS settings.')
    elif any(l == OK for l, _ in findings):
        R.add(OK, 'No DNS interception: public DNS servers answer genuinely',
              '\n'.join(t for _, t in findings))
    for l, t in findings:
        if l in (WARN, INFO) and not any(x == RISK for x, _ in findings):
            R.add(INFO, t)


def section_dns(R, online, listeners):
    check_dns(R, online, listeners)
    check_dns_integrity(R, online)


# ======================================================================================
# 3. MAN IN THE MIDDLE
# ======================================================================================

def arp_table():
    rows = []
    for line in (read('/proc/net/arp') or '').splitlines()[1:]:
        f = line.split()
        if len(f) >= 6 and f[3] != '00:00:00:00:00:00' and int(f[2], 16) & 0x2:
            rows.append({'ip': f[0], 'mac': f[3].lower(), 'iface': f[5]})
    return rows


def ipv6_router_macs():
    macs = {}
    for line in stdout_of(['ip', '-6', 'neigh', 'show'], 5).splitlines():
        m = re.match(r'^(\S+) dev (\S+) lladdr (\S+) router', line)
        if m:
            macs[m.group(1)] = m.group(3).lower()
    return macs


def check_router(R, baseline, newbase):
    v4 = default_routes_v4()
    v6 = default_routes_v6()
    arp = arp_table()
    if not v4 and not v6:
        R.add(SKIP, 'No default route: are you offline?')
        return
    issues = []
    gw_mac = None
    if v4:
        gw = v4[0]
        entry = next((a for a in arp if a['ip'] == gw['gateway'] and a['iface'] == gw['iface']), None)
        if entry:
            gw_mac = entry['mac']
            twins = [a['ip'] for a in arp if a['mac'] == gw_mac and a['ip'] != gw['gateway'] and a['iface'] == gw['iface']]
            if twins:
                issues.append((RISK, 'Your router\'s hardware address (%s) is also claimed by %s. This is the classic '
                                     'sign of ARP spoofing: another device pretending to be the router to read your '
                                     'traffic.' % (gw_mac, ', '.join(twins))))
        key = '%s@%s' % (gw['gateway'], gw['iface'])
        if gw_mac:
            newbase.setdefault('routers', {})[key] = gw_mac
            old = ((baseline or {}).get('routers') or {}).get(key)
            if old and old != gw_mac:
                issues.append((WARN, 'Your router (%s) has a different hardware address than last time (%s, now %s). '
                                     'Fine if you replaced the router; otherwise it can mean someone is '
                                     'impersonating it.' % (gw['gateway'], old, gw_mac)))
        dup = {}
        for a in arp:
            dup.setdefault((a['iface'], a['mac']), []).append(a['ip'])
        for (_iface, mac), ips in dup.items():
            if len(ips) > 1 and mac != gw_mac:
                issues.append((INFO, 'Device %s answers for several addresses: %s (usually harmless).' % (mac, ', '.join(ips))))
    routers6 = sorted(set((r['gateway'], r['iface']) for r in v6))
    if len(set(r[0] for r in routers6)) > 1:
        issues.append((WARN, 'More than one IPv6 router announces itself on your network: %s. Normal with a mesh '
                             'system or a second router; otherwise it can be a rogue router redirecting your '
                             'traffic.' % ', '.join('%s (%s)' % r for r in routers6)))
    macs6 = ipv6_router_macs()
    if gw_mac and macs6:
        other = [ip for ip, mac in macs6.items() if mac != gw_mac]
        if other:
            issues.append((INFO, 'IPv6 traffic goes through a different device (%s) than IPv4 (%s).'
                                 % (', '.join('%s %s' % (ip, macs6[ip]) for ip in other), gw_mac)))
    if not [i for i in issues if i[0] in (RISK, WARN)]:
        R.add(OK, 'Router identity looks normal (no ARP spoofing signs%s)' % (
            ', one IPv6 router' if routers6 else ''),
            'Router %s%s.' % (v4[0]['gateway'] if v4 else routers6[0][0], ' (%s)' % gw_mac if gw_mac else ''))
    for level, text in issues:
        R.add(level, text.split('. ')[0] + '.', text, 'Disconnect from this network if you do not trust it; '
              'on a home network, restart the router and check which devices are connected.'
              if level in (RISK, WARN) else '')


def proxy_settings():
    found = []
    for k in ('http_proxy', 'https_proxy', 'all_proxy', 'ftp_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'):
        if os.environ.get(k):
            found.append('environment %s=%s' % (k, os.environ[k]))
    for line in (read('/etc/environment') or '').splitlines():
        if re.match(r'^\s*(export\s+)?(http|https|all|ftp)_proxy\s*=', line, re.I):
            found.append('/etc/environment: ' + line.strip())
    u = target_user()
    kio = read(os.path.join(u.pw_dir, '.config', 'kioslaverc'), '')
    m = re.search(r'^\[Proxy Settings\](.*?)(^\[|\Z)', kio, re.S | re.M)
    if m:
        t = re.search(r'^ProxyType\s*=\s*(\d)', m.group(1), re.M)
        kinds = {'1': 'manual proxy', '2': 'proxy script (PAC)', '3': 'automatic proxy detection (WPAD)',
                 '4': 'proxy from environment'}
        if t and t.group(1) in kinds:
            addr = re.search(r'^httpsProxy\s*=\s*(.+)$', m.group(1), re.M) or \
                re.search(r'^Proxy Config Script\s*=\s*(.+)$', m.group(1), re.M)
            found.append('KDE system settings: %s%s' % (kinds[t.group(1)], ' ' + addr.group(1).strip() if addr else ''))
    if which('gsettings') and not is_root():
        mode = stdout_of(['gsettings', 'get', 'org.gnome.system.proxy', 'mode'], 5).strip().strip("'")
        if mode in ('manual', 'auto'):
            host = stdout_of(['gsettings', 'get', 'org.gnome.system.proxy.https', 'host'], 5).strip()
            url = stdout_of(['gsettings', 'get', 'org.gnome.system.proxy', 'autoconfig-url'], 5).strip()
            found.append('GNOME system settings: %s proxy %s' % (mode, host if mode == 'manual' else (url or 'WPAD')))
    for path, pat in (('/etc/dnf/dnf.conf', r'^\s*proxy\s*=\s*(\S+)'), ('/etc/yum.conf', r'^\s*proxy\s*=\s*(\S+)')):
        mm = re.search(pat, read(path, ''), re.M)
        if mm:
            found.append('%s: proxy=%s' % (path, mm.group(1)))
    for path in glob.glob('/etc/apt/apt.conf') + glob.glob('/etc/apt/apt.conf.d/*'):
        mm = re.search(r'Acquire::https?::Proxy\s+"([^"]+)"', read(path, ''), re.I)
        if mm:
            found.append('%s: %s' % (path, mm.group(1)))
    return found


def check_proxies(R):
    found = proxy_settings()
    wpad = [f for f in found if 'WPAD' in f or 'auto proxy' in f]
    if not found:
        R.add(OK, 'No proxy is configured (traffic goes straight to the internet)')
        return
    R.add(WARN, 'Your traffic is set to go through a proxy',
          '\n'.join(found) + '\nA proxy sees (and can change) unencrypted traffic and the names of every site. '
          'Fine if you set it up on purpose (work, school, a VPN app).' +
          (' Automatic proxy detection (WPAD) is risky: any device on the network can offer itself as your proxy.'
           if wpad else ''),
          'If you did not set this up, remove it in your system\'s network/proxy settings.')


def check_ca_anchors(R, baseline, newbase):
    anchors = local_ca_anchors()
    newbase['ca_anchors'] = sorted(a['sha256'] for a in anchors)
    if not anchors:
        R.add(OK, 'No extra root certificates were added to your system')
        return anchors
    old = set((baseline or {}).get('ca_anchors') or [])
    for a in anchors:
        name = a.get('subject_o') or a.get('subject_cn') or os.path.basename(a['path'])
        label = ', '.join(x for x in (a.get('subject_cn'), a.get('subject_o')) if x) or name
        vendor = next((v for v in INTERCEPTION_VENDORS if v in label.lower()), None)
        new = baseline is not None and a['sha256'] not in old
        detail = ('File: %s (added %s)%s\nCertificate: %s; valid until %s; SHA-256 %s...\n'
                  'A root certificate lets its owner create a valid-looking certificate for ANY website. Whoever '
                  'holds its private key can read and change your encrypted (HTTPS) traffic without warnings, '
                  'for every program that uses the system certificate store (curl, Python, package managers, '
                  'most apps; some browsers use their own list).' %
                  (a['path'], a['mtime'], ' NEW since last check!' if new else '', label, a.get('not_after') or '?',
                   a['sha256'][:24]))
        if vendor:
            detail += ' "%s" makes security/filtering products that inspect HTTPS traffic this way.' % name
        if a['shipped_by_os']:
            R.add(INFO, 'Extra root certificate shipped with your OS image: %s' % label, detail)
            continue
        fam = package_system()
        if os.path.dirname(a['path']).startswith('/etc/pki/ca-trust'):
            fix = 'sudo rm "%s" && sudo update-ca-trust' % a['path']
        elif a['path'].startswith('/usr/local/share/ca-certificates'):
            fix = 'sudo rm "%s" && sudo update-ca-certificates --fresh' % a['path']
        elif a['path'].startswith('/etc/pki/trust'):
            fix = 'sudo rm "%s" && sudo update-ca-certificates' % a['path']
        else:
            fix = 'sudo rm "%s" && sudo update-ca-trust' % a['path']
        R.add(WARN, 'An extra root certificate is trusted by your system: %s' % label, detail,
              'Keep it only if you knowingly installed it for a product you still use. Otherwise remove it:\n'
              '    ' + fix + ('\n(on %s this works the same; /etc is writable)' % fam if fam in
                              ('rpm-ostree', 'ostree', 'transactional-update') else ''))
    return anchors


def check_tls(R, anchors):
    R.progress('checking HTTPS certificates of %d well-known websites' % len(TLS_SITES))
    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(tls_probe, TLS_SITES))
    anchor_names = set()
    for a in anchors or []:
        for k in ('subject_cn', 'subject_o'):
            if a.get(k):
                anchor_names.add(a[k].lower())
    intercepted, failed, odd, good, net = [], [], [], [], []
    for r in results:
        iss = ' / '.join(x for x in (r.get('issuer_o'), r.get('issuer_cn')) if x)
        if r.get('network'):
            net.append(r['host'])
        elif not r.get('ok'):
            failed.append('%s: certificate rejected%s (%s)' % (r['host'], ', signed by ' + iss if iss else '',
                                                              r.get('error', '')[:80]))
        elif (r.get('issuer_o', '').lower() in anchor_names or r.get('issuer_cn', '').lower() in anchor_names):
            intercepted.append('%s: signed by "%s", one of the extra root certificates on this computer' % (r['host'], iss))
        elif not r.get('sct') and not any(h in iss.lower() for h in PUBLIC_CA_HINTS):
            odd.append('%s: signed by "%s" with no Certificate Transparency proof' % (r['host'], iss))
        else:
            good.append('%s: %s' % (r['host'], iss))
    R.facts['tls'] = results
    if intercepted:
        R.add(RISK, 'Your HTTPS traffic is being intercepted', '\n'.join(intercepted) +
              '\nA product or person with that root certificate is decrypting your "secure" connections.',
              'Remove the root certificate (see above) unless this is a security product you chose, and check '
              'proxy/VPN/antivirus software and your router.')
    if failed:
        R.add(RISK, 'Some secure websites show certificate errors', '\n'.join(failed) +
              '\nCauses: a man-in-the-middle, a hotel/airport Wi-Fi login page, or a wrong computer clock.',
              'Do not log in anywhere on this network. Check the clock; if it is right, use another network.')
    if odd:
        R.add(WARN, 'Unusual certificates on some websites', '\n'.join(odd),
              'Compare on another network (e.g. phone hotspot). If they differ, this network intercepts HTTPS.')
    if good and not (intercepted or failed or odd):
        R.add(OK, 'HTTPS certificates are genuine on all %d test sites (no interception)' % len(good),
              '\n'.join(good))
    if net and not good:
        R.add(SKIP, 'Could not reach the test websites (offline?)')


HTTP_PROBES = [
    ('http://detectportal.firefox.com/success.txt', 200, b'success'),
    ('http://connectivitycheck.gstatic.com/generate_204', 204, b''),
    ('http://www.msftconnecttest.com/connecttest.txt', 200, b'Microsoft Connect Test'),
]


def http_probe(probe):
    url, want_status, want_body = probe
    try:
        status, hdrs, body = http_get(url, timeout=8, follow=False)
    except Exception as e:
        return {'url': url, 'error': str(e)}
    good = status == want_status and body.strip() == want_body
    suspicious_hdrs = [k for k in hdrs if k.startswith(('x-squid', 'x-proxy', 'proxy-')) or k == 'x-bluecoat-via']
    return {'url': url, 'status': status, 'good': good, 'location': hdrs.get('location'),
            'proxy_headers': suspicious_hdrs, 'body': body[:80].decode('utf-8', 'replace')}


def check_http(R):
    with ThreadPoolExecutor(max_workers=3) as ex:
        res = list(ex.map(http_probe, HTTP_PROBES))
    reached = [r for r in res if 'error' not in r]
    if not reached:
        R.add(SKIP, 'Could not test plain web traffic (offline?)')
        return
    bad = [r for r in reached if not r['good']]
    proxied = [r for r in reached if r['proxy_headers']]
    if bad:
        loc = next((r['location'] for r in bad if r.get('location')), None)
        R.add(WARN, 'Plain (non-HTTPS) web traffic is being redirected or changed',
              '\n'.join('%s -> HTTP %s %s' % (r['url'], r['status'], r.get('location') or r['body'][:40]) for r in bad) +
              ('\nYou are being sent to %s: probably a Wi-Fi login page (captive portal).' % loc if loc else
               '\nAn internet provider or network device modifies unencrypted traffic.'),
              'Only use HTTPS sites on this network; log in to the Wi-Fi portal if there is one.')
    elif proxied:
        R.add(WARN, 'A transparent proxy handles your plain web traffic',
              'Headers: %s' % ', '.join(sorted(set(h for r in proxied for h in r['proxy_headers']))),
              'Prefer HTTPS sites; ask your network administrator / internet provider.')
    else:
        R.add(OK, 'Plain web traffic arrives unchanged (no injection, no captive portal)')


def check_clock(R):
    t = cloudflare_trace(4) or cloudflare_trace(6)
    if not t or 'ts' not in t:
        return
    try:
        offset = t.get('_local', time.time()) - float(t['ts'])
    except ValueError:
        return
    if abs(offset) > 86400:
        R.add(RISK, 'Your clock is wrong by %s' % human_age(abs(offset)),
              'A wrong clock breaks certificate checks and can be exploited.',
              'Turn on automatic time: sudo timedatectl set-ntp true')
    elif abs(offset) > 300:
        R.add(WARN, 'Your clock is off by %s' % human_age(abs(offset)), '',
              'Turn on automatic time: sudo timedatectl set-ntp true')
    else:
        R.add(OK, 'Your clock is correct (within %s)' % plural(max(1, int(round(abs(offset)))), 'second'))


def check_wifi(R):
    v4 = default_routes_v4()
    dev = v4[0]['iface'] if v4 else None
    if not dev or not os.path.isdir('/sys/class/net/%s/wireless' % dev):
        if dev:
            R.add(INFO, 'You are connected by cable (%s)' % dev)
        return
    out = stdout_of(['nmcli', '-t', '-f', 'ACTIVE,SSID,SECURITY', 'device', 'wifi', 'list', '--rescan', 'no'], 10)
    for line in out.splitlines():
        parts = re.split(r'(?<!\\):', line)
        if parts and parts[0] == 'yes':
            ssid = parts[1].replace('\\:', ':') if len(parts) > 1 else '?'
            sec = parts[2] if len(parts) > 2 else ''
            if not sec or sec == '--':
                R.add(RISK, 'You are on an OPEN Wi-Fi network ("%s")' % ssid,
                      'Anyone nearby can see your unencrypted traffic and impersonate the network.',
                      'Use a VPN on open networks, or switch to a password-protected network.')
            elif 'WEP' in sec:
                R.add(RISK, 'Your Wi-Fi ("%s") uses WEP, which can be cracked in minutes' % ssid, '',
                      'Change the router to WPA2 or WPA3.')
            elif sec.strip() in ('WPA1', 'WPA'):
                R.add(WARN, 'Your Wi-Fi ("%s") uses old WPA1 security' % ssid, '', 'Change the router to WPA2 or WPA3.')
            else:
                R.add(OK, 'Wi-Fi "%s" is encrypted (%s)' % (ssid, sec))
            return
    R.add(INFO, 'Connected by Wi-Fi (%s); could not read its security type' % dev)


def section_mitm(R, online, baseline, newbase):
    check_router(R, baseline, newbase)
    check_wifi(R)
    check_proxies(R)
    anchors = check_ca_anchors(R, baseline, newbase)
    if online:
        check_clock(R)
        check_tls(R, anchors)
        check_http(R)


# ======================================================================================
# 4. NETWORK EXPOSURE
# ======================================================================================

PORTS = {
    21: ('FTP file server', RISK), 22: ('SSH remote login', WARN), 23: ('Telnet (unencrypted remote login)', RISK),
    25: ('mail server', WARN), 53: ('DNS server', WARN), 67: ('DHCP server', WARN), 68: ('DHCP client', OK),
    69: ('TFTP file server', RISK), 80: ('web server', WARN), 111: ('RPC portmapper (NFS)', WARN),
    137: ('NetBIOS name service (Windows sharing)', INFO), 138: ('NetBIOS (Windows sharing)', INFO),
    139: ('Windows file sharing (SMB)', WARN), 443: ('web server (HTTPS)', WARN), 445: ('Windows file sharing (SMB)', WARN),
    546: ('DHCPv6 client', OK), 631: ('printing service (CUPS)', WARN), 1716: ('KDE Connect / GSConnect', INFO),
    1900: ('UPnP/SSDP', WARN), 2049: ('NFS file sharing', WARN), 2375: ('Docker API WITHOUT encryption', RISK),
    2376: ('Docker API', WARN), 3000: ('development web server', WARN), 3306: ('MySQL/MariaDB database', RISK),
    3389: ('Remote Desktop (RDP)', WARN), 4713: ('PulseAudio network sound', WARN), 5000: ('development web server', WARN),
    5037: ('Android debug bridge', WARN), 5353: ('mDNS / Bonjour (announces this computer on the LAN)', INFO),
    5355: ('LLMNR name resolution', INFO), 5432: ('PostgreSQL database', RISK), 5555: ('Android debugging over network', RISK),
    5900: ('VNC remote desktop', RISK), 5901: ('VNC remote desktop', RISK), 6000: ('X11 display', RISK),
    6379: ('Redis database', RISK), 6600: ('MPD music player control', WARN), 7860: ('AI web UI (Gradio)', WARN),
    8000: ('development web server', WARN), 8080: ('web server / proxy', WARN), 8188: ('ComfyUI', WARN),
    8384: ('Syncthing web interface', WARN), 8888: ('Jupyter / web server', WARN), 9090: ('Cockpit web admin', WARN),
    9100: ('printer port', INFO), 9200: ('Elasticsearch database', RISK), 10000: ('Webmin admin', WARN),
    11211: ('memcached', RISK), 11434: ('Ollama AI server (no password)', RISK), 21027: ('Syncthing discovery', INFO),
    22000: ('Syncthing file sync', INFO), 27017: ('MongoDB database', RISK), 27036: ('Steam remote play', INFO),
    51413: ('BitTorrent', INFO), 6771: ('BitTorrent local peer discovery', INFO), 3702: ('WS-Discovery', INFO), 5357: ('Windows network discovery', INFO),
}


def firewall_state():
    """What the firewall allows in. Returns dict(tool, active, allows(proto, port)->True/False/None, notes...)."""
    st = {'tool': None, 'active': None, 'zone': None, 'rules': [], 'wide': [], 'target': None}

    def unknown(proto, port):
        return None
    st['allows'] = unknown

    r = run(['firewall-cmd', '--state'], 10)
    if r is not None and (r[0] == 0 or 'not running' in (r[1] + r[2])):
        st['tool'] = 'firewalld'
        if r[0] != 0:
            st['active'] = False
            return st
        st['active'] = True
        dev = (default_routes_v4() or default_routes_v6() or [{}])[0].get('iface')
        zone = stdout_of(['firewall-cmd', '--get-zone-of-interface=%s' % dev], 10).strip() if dev else ''
        zone = zone or stdout_of(['firewall-cmd', '--get-default-zone'], 10).strip()
        st['zone'] = zone
        info = stdout_of(['firewall-cmd', '--zone=%s' % zone, '--list-all'], 10)
        kv = {}
        for line in info.splitlines():
            m = re.match(r'^\s+([\w-]+):\s*(.*)$', line)
            if m:
                kv[m.group(1)] = m.group(2).strip()
        st['target'] = kv.get('target', 'default')
        allowed = []
        for spec in kv.get('ports', '').split():
            if '/' in spec:
                p, proto = spec.split('/', 1)
                lo, _, hi = p.partition('-')
                allowed.append((proto, int(lo), int(hi or lo), 'port ' + spec))
        for svc in kv.get('services', '').split():
            sinfo = stdout_of(['firewall-cmd', '--info-service=%s' % svc], 10)
            m = re.search(r'^\s*ports:\s*(.*)$', sinfo, re.M)
            for spec in (m.group(1).split() if m else []):
                if '/' in spec:
                    p, proto = spec.split('/', 1)
                    lo, _, hi = p.partition('-')
                    allowed.append((proto, int(lo), int(hi or lo), 'service ' + svc))
        st['rules'] = ['services: ' + (kv.get('services') or 'none'), 'ports: ' + (kv.get('ports') or 'none')]
        st['rich'] = kv.get('rich rules', '')
        st['wide'] = [a for a in allowed if a[2] - a[1] >= 1000]
        target = st['target'].upper()

        def allows(proto, port):
            if target in ('ACCEPT', 'TRUSTED'):
                return True
            return any(a[0] == proto and a[1] <= port <= a[2] for a in allowed) or (None if st.get('rich') else False)
        st['allows'] = allows
        return st

    conf = read('/etc/ufw/ufw.conf')
    if conf is not None and which('ufw'):
        st['tool'] = 'ufw'
        st['active'] = bool(re.search(r'^\s*ENABLED\s*=\s*yes', conf, re.M))
        if is_root():
            out = stdout_of(['ufw', 'status', 'verbose'], 10)
            st['active'] = 'Status: active' in out
            deny_default = bool(re.search(r'Default:\s*(deny|reject)\s*\(incoming\)', out))
            rules = []
            for line in out.splitlines():
                m = re.match(r'^(\d+)(?::(\d+))?(?:/(tcp|udp))?(?: \(v6\))?\s+ALLOW IN\s+(.+)$', line.strip())
                if m:
                    lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
                    rules.append((m.group(3), lo, hi, line.strip()))
            st['rules'] = [r[3] for r in rules]
            st['wide'] = [r for r in rules if r[2] - r[1] >= 1000]

            def allows(proto, port):
                if not deny_default:
                    return True
                return any((r[0] in (None, proto)) and r[1] <= port <= r[2] for r in rules)
            st['allows'] = allows
        return st

    if is_root():
        out = stdout_of(['nft', 'list', 'ruleset'], 15)
        if out:
            st['tool'] = 'nftables'
            hooks = re.findall(r'type filter hook input priority [^;]+; policy (\w+);', out)
            st['active'] = bool(hooks) and ('drop' in hooks or re.search(r'\b(drop|reject)\b', out) is not None)
            return st
        out = stdout_of(['iptables', '-S', 'INPUT'], 10)
        if out:
            st['tool'] = 'iptables'
            st['active'] = '-P INPUT DROP' in out or bool(re.search(r'-j (DROP|REJECT)', out))
            return st
        st['tool'] = 'none'
        st['active'] = False
    return st


def check_listeners(R, listeners, fw, baseline, newbase):
    exposed = [s for s in listeners if s['scope'] in ('all', 'lan', 'public') and not s['ephemeral']]
    local = [s for s in listeners if s['scope'] == 'loopback']
    newbase['exposed'] = sorted(set('%s/%d %s' % (s['proto'], s['port'], s['process'] or s['unit']) for s in exposed))
    old = set((baseline or {}).get('exposed') or [])
    groups = {}
    for s in exposed:
        groups.setdefault((s['port'], describe_owner(s)), []).append(s)
    rows = []
    for (port, who), socks in sorted(groups.items()):
        protos = '/'.join(sorted(set(s['proto'] for s in socks)))
        name, level = PORTS.get(port, ('unknown service', WARN))
        allowed = [fw['allows'](s['proto'], port) for s in socks]
        reach = True if any(a is True for a in allowed) else (False if all(a is False for a in allowed) else None)
        if port in (68, 546) or (port == 5353 and reach is not False and level == INFO):
            pass
        if reach is False:
            level = INFO if level != OK else OK
        new = baseline is not None and '%s/%d %s' % (socks[0]['proto'], port, socks[0]['process'] or socks[0]['unit']) not in old
        rows.append({'port': port, 'protos': protos, 'who': who, 'name': name, 'level': level, 'reach': reach, 'new': new,
                     'scope': socks[0]['scope']})
    R.facts['exposed'] = rows
    if local:
        names = sorted(set('%d %s' % (s['port'], describe_owner(s)) for s in local if not s['ephemeral']))
        R.add(OK, '%s only accept connections from this computer itself (safe)' % plural(len(names), 'service'),
              ', '.join(names[:20]))
    if not rows:
        R.add(OK, 'Nothing on this computer accepts connections from the network')
        return rows
    for r in rows:
        reach_txt = {True: 'allowed through your firewall: devices on your network CAN connect',
                     False: 'blocked by your firewall', None: 'firewall status unknown'}[r['reach']]
        title = 'Port %d/%s open to the network: %s (%s)%s' % (r['port'], r['protos'], r['name'], r['who'],
                                                                ' NEW since last check' if r['new'] else '')
        if r['level'] == OK:
            R.add(OK, title + ', normal')
            continue
        level = r['level']
        if r['new'] and level == INFO and r['reach'] is not False:
            level = WARN
        fix = ''
        if level in (RISK, WARN):
            fix = ('Block it: %s ports block %d   (or allow it only for a while: %s ports allow %d --for 1h). '
                   'If you do not need the program, quit or disable it.' % (PROG, r['port'], PROG, r['port']))
        R.add(level, title, reach_txt + '.', fix)
    return rows


def check_firewall(R, fw, rows):
    exposed_allowed = [r for r in rows if r['reach'] is True and r['level'] in (RISK, WARN)]
    if fw['tool'] is None:
        R.add(INFO if not rows else WARN, 'Could not determine your firewall status',
              'No firewalld or ufw found, and reading nftables/iptables rules needs administrator rights.',
              'Run this check with sudo for a complete answer.')
        return
    if fw['tool'] == 'none':
        R.add(RISK if rows else WARN, 'No firewall software found',
              'Neither firewalld, ufw, nftables nor iptables rules are present, so nothing filters incoming '
              'connections.', 'Install a firewall with your package manager (firewalld or ufw) and turn it on: '
                              '%s firewall on' % PROG)
        return
    if fw['active'] is False:
        R.add(RISK if rows else WARN, 'Your firewall is OFF (%s)' % fw['tool'],
              'Every service that listens on the network is reachable by other devices.',
              {'firewalld': '%s firewall on' % PROG,
               'ufw': '%s firewall on   (or: sudo ufw default deny incoming && sudo ufw enable)' % PROG}.get(
                  fw['tool'], 'Install and enable a firewall (firewalld or ufw).'))
        return
    if fw['tool'] == 'firewalld':
        t = (fw.get('target') or '').upper()
        if t in ('ACCEPT', 'TRUSTED') or fw.get('zone') == 'trusted':
            R.add(RISK, 'Your firewall zone "%s" lets everything in' % fw['zone'], 'Its target is %s.' % t,
                  '%s firewall profile public   (or home / work)' % PROG)
            return
        if fw['wide']:
            spans = ', '.join('%d-%d/%s' % (w[1], w[2], w[0]) for w in fw['wide'])
            R.add(WARN, 'Your firewall (zone "%s") allows almost every port in: %s' % (fw['zone'], spans),
                  'Any program that opens a port becomes reachable from your network. This is the default of '
                  'some desktop distributions (e.g. Fedora Workstation and its derivatives) for convenience, '
                  'but it means the firewall barely protects you.',
                  'Close the range and allow only the apps you use:\n'
                  '    %s ports close-unused        (asks about each app; can be undone)\n'
                  'Later, open things only when needed, e.g.:\n'
                  '    %s ports allow kdeconnect --for 1h' % (PROG, PROG))
            return
        R.add(OK, 'Firewall is on (firewalld, zone "%s")' % fw['zone'], '; '.join(fw['rules']))
        return
    if fw['wide']:
        R.add(WARN, 'Your firewall (%s) allows wide port ranges' % fw['tool'], '\n'.join(str(w[3]) for w in fw['wide']),
              'Remove the wide rules and allow only the ports you need.')
        return
    R.add(OK if not exposed_allowed else INFO, 'Firewall is on (%s)' % fw['tool'],
          '\n'.join(fw['rules'][:10]) if fw['rules'] else ('Run with sudo to see the rules.' if not is_root() else ''))


def check_ipv6_exposure(R, rows):
    addrs = global_ipv6_addresses()
    if not addrs:
        return
    stable = [a for a in addrs if not a[2]]
    reachable = [r for r in rows if r['reach'] is not False and r['level'] in (RISK, WARN, INFO) and r['port'] not in (546, 5353, 5355)]
    detail = ('Your computer has %s (%s). IPv6 has no "NAT", so devices on the internet can address your computer '
              'directly; only your router\'s IPv6 firewall and your own firewall stand in between.'
              % (plural(len(addrs), 'public IPv6 address', 'public IPv6 addresses'),
                 ', '.join(a[0] for a in addrs[:3]) + (' ...' if len(addrs) > 3 else '')))
    if reachable:
        R.add(WARN, 'Ports open on your network may also be reachable from the internet over IPv6',
              detail + ' Ports your firewall lets in: %s.' % ', '.join('%d (%s)' % (r['port'], r['name']) for r in reachable),
              'Make sure your router\'s IPv6 firewall blocks incoming connections (usually "IPv6 firewall" or '
              '"block unsolicited inbound IPv6" in the router settings), and tighten your own firewall.')
    else:
        R.add(INFO, 'You have public IPv6 addresses (no open ports to worry about)', detail)
    if stable and not any(a[2] for a in addrs):
        R.add(INFO, 'IPv6 privacy addresses are off',
              'Your IPv6 address stays the same everywhere, so websites can recognise this computer over time.',
              'Enable them in NetworkManager: nmcli connection modify "<connection>" ipv6.ip6-privacy 2')


def upnp_location_ok(url, responder):
    """A UPnP device may only point us at itself, on the local network (no requests to other hosts)."""
    try:
        u = urllib.parse.urlsplit(url)
        host = u.hostname or ''
        u.port                                        # noqa: B018  (raises on a malformed port)
    except ValueError:
        return False
    a = ip_obj(responder)
    return (u.scheme == 'http' and host == responder and a is not None and not a.is_loopback
            and (a.is_private or a.is_link_local))


def upnp_check(timeout=3):
    found = {}
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.settimeout(timeout)
    try:
        for st in ('urn:schemas-upnp-org:device:InternetGatewayDevice:1',
                   'urn:schemas-upnp-org:device:InternetGatewayDevice:2'):
            msg = ('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\n'
                   'ST: %s\r\n\r\n' % st).encode()
            s.sendto(msg, ('239.255.255.250', 1900))
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                break
            m = re.search(rb'(?im)^location:\s*(\S+)', data)
            if m and upnp_location_ok(m.group(1).decode('ascii', 'replace'), addr[0]):
                found[m.group(1).decode('ascii', 'replace')] = addr[0]
    except OSError:
        pass
    finally:
        s.close()
    devices = []
    for loc, ip in found.items():
        dev = {'ip': ip, 'location': loc, 'mappings': [], 'model': ''}
        try:
            _, _, xml = http_get(loc, timeout=5)
            xml = xml.decode('utf-8', 'replace')
            mf = re.search(r'<manufacturer>([^<]*)', xml)
            md = re.search(r'<modelName>([^<]*)', xml)
            dev['model'] = ' '.join(x.group(1) for x in (mf, md) if x)
            base = '/'.join(loc.split('/')[:3])
            for svc in re.findall(r'<service>(.*?)</service>', xml, re.S):
                stype = re.search(r'<serviceType>([^<]*)', svc)
                ctl = re.search(r'<controlURL>([^<]*)', svc)
                if not stype or not ctl or not re.search(r'WAN(IP|PPP)Connection', stype.group(1)):
                    continue
                url = ctl.group(1) if ctl.group(1).startswith('http') else base + '/' + ctl.group(1).lstrip('/')
                if not upnp_location_ok(url, ip):
                    continue
                for i in range(100):
                    body = ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
                            '<u:GetGenericPortMappingEntry xmlns:u="%s"><NewPortMappingIndex>%d</NewPortMappingIndex>'
                            '</u:GetGenericPortMappingEntry></s:Body></s:Envelope>' % (stype.group(1), i)).encode()
                    req = urllib.request.Request(url, body, {'Content-Type': 'text/xml; charset="utf-8"',
                                                             'SOAPAction': '"%s#GetGenericPortMappingEntry"' % stype.group(1)})
                    try:
                        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                        resp = opener.open(req, timeout=5).read().decode('utf-8', 'replace')
                    except Exception:
                        break
                    f = dict(re.findall(r'<(New\w+)>([^<]*)</', resp))
                    dev['mappings'].append(f)
        except Exception:
            pass
        devices.append(dev)
    return devices


def natpmp_check(gateway):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.5)
    try:
        s.sendto(b'\x00\x00', (gateway, 5351))
        data, _ = s.recvfrom(64)
        return len(data) >= 12 and data[1] == 128
    except OSError:
        return False
    finally:
        s.close()


def my_lan_ips():
    ips = set()
    for line in stdout_of(['ip', '-4', '-o', 'addr', 'show'], 5).splitlines():
        m = re.search(r'inet (\d+\.\d+\.\d+\.\d+)/', line)
        if m:
            ips.add(m.group(1))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('192.0.2.1', 9))
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    return ips


def check_router_ports(R):
    R.progress('asking your router about automatic port forwarding (UPnP)')
    devices = upnp_check()
    v4 = default_routes_v4()
    pmp = natpmp_check(v4[0]['gateway']) if v4 else False
    mine = my_lan_ips()
    if not devices and not pmp:
        R.add(OK, 'Your router does not accept automatic port-opening requests (UPnP/NAT-PMP off)')
        return
    for d in devices:
        maps = d['mappings']
        to_me = [m for m in maps if m.get('NewInternalClient') in mine]
        lines = ['%s port %s -> %s:%s "%s"%s' % (m.get('NewProtocol'), m.get('NewExternalPort'), m.get('NewInternalClient'),
                                                 m.get('NewInternalPort'), m.get('NewPortMappingDescription', ''),
                                                 '' if m.get('NewEnabled', '1') == '1' else ' (disabled)') for m in maps]
        if to_me:
            R.add(WARN, '%s on your router point at THIS computer' % plural(len(to_me), 'open internet port'),
                  '\n'.join(l for l, m in zip(lines, maps) if m in to_me) +
                  '\nThese ports are reachable from the whole internet.',
                  'Close the program that opened them, or remove the forwarding in your router\'s settings.')
        R.add(WARN if maps else INFO, 'UPnP is ON on your router%s: programs can open internet ports automatically'
              % (' (%s)' % d['model'] if d['model'] else ''),
              ('Current port forwardings:\n' + '\n'.join(lines) if lines else 'No port forwardings at the moment.') +
              '\nConvenient for games and calls, but malware on any device can use it too.',
              'Turn UPnP off in your router\'s settings if you do not need it.' if maps else '')
    if pmp and not devices:
        R.add(INFO, 'Your router answers NAT-PMP/PCP requests (programs can open internet ports automatically)')


def check_internetdb(R):
    pubs = R.facts.get('public_ip') or {'v4': public_ip(4), 'v6': public_ip(6)}
    any_checked = False
    for fam in ('v4', 'v6'):
        ip = pubs.get(fam)
        if not ip:
            continue
        try:
            status, data = http_json('https://internetdb.shodan.io/' + ip, timeout=12)
        except Exception:
            continue
        any_checked = True
        if status == 404 or not isinstance(data, dict) or not data.get('ports'):
            R.add(OK, 'Internet scanners (Shodan) know of no open ports on your public IPv%s address %s' % (fam[1], ip),
                  'Based on Shodan\'s regular internet-wide scans; a changing IP or provider NAT can hide results.')
            continue
        vulns = data.get('vulns') or []
        R.add(RISK if vulns else WARN, 'Internet scanners found open ports on your public IP %s: %s' % (
            ip, ', '.join(str(p) for p in data['ports'])),
              'Usually these belong to your router (remote management, port forwarding). %s%s' % (
                  'Known vulnerabilities reported: %s. ' % ', '.join(vulns[:8]) if vulns else '',
                  'Hostnames: %s.' % ', '.join(data.get('hostnames', [])[:3]) if data.get('hostnames') else ''),
              'Turn off remote management and unused port forwarding in your router; update its firmware.')
    if not any_checked:
        R.add(SKIP, 'Could not ask internet scanners about your public IP')


def check_lan_leaks(R, listeners):
    names = {describe_owner(s) for s in listeners if s['port'] == 5353 and s['scope'] != 'loopback'}
    llmnr = [s for s in listeners if s['port'] == 5355 and s['scope'] != 'loopback']
    kdc = [s for s in listeners if s['port'] == 1716 and s['scope'] != 'loopback']
    nb = [s for s in listeners if s['port'] in (137, 138) and s['scope'] != 'loopback']
    host = socket.gethostname()
    if names:
        R.add(INFO, 'This computer announces itself on the local network as "%s" (mDNS by %s)' % (host, ', '.join(sorted(names))),
              'Other devices on the same network can see its name and shared services. Normal at home; on public '
              'Wi-Fi it tells others who you are.', '')
    if llmnr:
        R.add(WARN, 'LLMNR name lookups are switched on',
              'When a name is not found in DNS, your computer asks the whole local network. On public or shared '
              'networks an attacker can answer and redirect you ("LLMNR poisoning").',
              'Turn it off: create /etc/systemd/resolved.conf.d/no-llmnr.conf with\n'
              '    [Resolve]\n    LLMNR=no\nthen: sudo systemctl restart systemd-resolved')
    if kdc:
        R.add(INFO, 'KDE Connect / GSConnect is listening on the network',
              'Only paired devices can control it, but it announces your device name to the local network. Pair '
              'only devices you own, and turn it off on public networks if you do not need it.')
    if nb:
        R.add(INFO, 'Windows-style network name service (NetBIOS) is on',
              'It announces this computer to Windows machines on the network.')


def check_containers(R, listeners):
    sock = '/var/run/docker.sock'
    if os.path.exists(sock):
        mode = os.stat(sock).st_mode
        if mode & 0o006:
            R.add(RISK, 'The Docker control socket can be used by every user', 'Anyone with an account can become root.',
                  'sudo chmod 660 /var/run/docker.sock   (and find out who changed it)')
    try:
        u = target_user()
        if u.pw_name in grp.getgrnam('docker').gr_mem:
            R.add(INFO, 'Your account is in the "docker" group',
                  'That is equivalent to administrator rights: any program you run can take over the computer '
                  'through Docker. Rootless Docker or Podman avoid this.')
    except KeyError:
        pass
    pub = [s for s in listeners if s['scope'] in ('all', 'lan', 'public') and
           re.search(r'docker-proxy|rootlessport|conmon|containerd|pasta|slirp4netns', (s['process'] + s['unit']), re.I)]
    if pub:
        R.add(WARN, 'Containers publish %s to the network' % plural(len(pub), 'port'),
              ', '.join('%d/%s' % (s['port'], s['proto']) for s in pub) +
              '. Docker-published ports can bypass ufw/firewalld rules.',
              'Publish container ports on 127.0.0.1 only (e.g. -p 127.0.0.1:8080:80) unless other devices need them.')


def section_network(R, online, listeners, baseline, newbase):
    fw = firewall_state()
    R.facts['firewall'] = {k: v for k, v in fw.items() if k != 'allows'}
    rows = check_listeners(R, listeners, fw, baseline, newbase)
    check_firewall(R, fw, rows)
    check_ipv6_exposure(R, rows)
    check_lan_leaks(R, listeners)
    check_containers(R, listeners)
    check_router_ports(R)
    if online:
        check_internetdb(R)


# ======================================================================================
# CHANGING THINGS: shared helpers for "ports" and "fix" (these need administrator rights)
# ======================================================================================

SYSTEM_CORE = '/usr/local/lib/networkscout/networkscout.py'   # root-owned copy (install.sh --system-core)
SYSTEM_BACKUPS = '/var/lib/networkscout/backups'               # root-only: undo scripts are run as root


def trusted_core():
    """The root-owned copy of networkscout.py, if it is safe to run as root (owned by root and not writable
    by anyone else, nor its folders). Code in your home folder could be changed by any program you run."""
    try:
        for p in (SYSTEM_CORE, os.path.dirname(SYSTEM_CORE), os.path.dirname(os.path.dirname(SYSTEM_CORE))):
            st = os.stat(p)
            if st.st_uid != 0 or st.st_mode & 0o022:
                return None
    except OSError:
        return None
    return SYSTEM_CORE


def state_dir():
    u = target_user()
    base = None if elevated_for_user() else os.environ.get('XDG_STATE_HOME')
    return os.path.join(base or os.path.join(u.pw_dir, '.local', 'state'), PROG)


def become_root(argv):
    """Re-run this command with administrator rights (asks for your password). Returns False if impossible."""
    if is_root():
        return True
    if not sys.stdin.isatty():
        print('This needs administrator rights. Run it again with sudo:\n  sudo %s %s %s'
              % (sys.executable, os.path.abspath(__file__), ' '.join(shlex_quote(a) for a in argv)))
        return False
    exe = which('sudo') or which('doas') or which('pkexec')
    if not exe:
        print('This needs administrator rights, but neither sudo, doas nor pkexec is available.')
        return False
    print('Administrator rights are needed: asking for your password (%s)...' % os.path.basename(exe))
    script = trusted_core() or os.path.abspath(__file__)
    if script == SYSTEM_CORE:
        m = re.search(r"^VERSION = '([^']+)'", read(SYSTEM_CORE, '') or '', re.M)
        if m and m.group(1) != VERSION:
            print('Note: the root-owned copy is version %s, this one is %s. Update it with: '
                  'sudo ./install.sh --system-core' % (m.group(1), VERSION))
    python = '/usr/bin/python3' if script == SYSTEM_CORE and os.path.exists('/usr/bin/python3') else sys.executable
    sys.stdout.flush()
    os.execv(exe, [exe, python, '-I', script] + list(argv))
    return False


class Changer:
    """Runs commands (or only shows them with --dry-run), keeps backups and writes an undo script."""

    def __init__(self, out, assume_yes=False, dry_run=False, label='change'):
        self.out, self.yes, self.dry = out, assume_yes, dry_run
        self.stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
        name = '%s-%s' % (self.stamp, label)
        self.dir = os.path.join(SYSTEM_BACKUPS if is_root() else os.path.join(state_dir(), 'backups'), name)
        self.undo = []            # shell commands, run in reverse order by undo.sh
        self.undo_after = []      # reload/restart steps, run once at the end of undo.sh
        self.log = []

    def ask(self, question, default=False):
        hint = '[Y/n]' if default else '[y/N]'
        if self.yes:
            print('  %s %s %s (recommended)' % (question, hint, 'yes' if default else 'no'))
            return default
        if not sys.stdin.isatty():
            print('  %s %s %s (no keyboard: using the default)' % (question, hint, 'yes' if default else 'no'))
            return default
        while True:
            try:
                ans = input('  %s %s ' % (question, hint)).strip().lower()
            except EOFError:
                return default
            if not ans:
                return default
            if ans in ('y', 'yes'):
                return True
            if ans in ('n', 'no'):
                return False

    def run(self, cmd, stream=False, timeout=600, quiet=False):
        """Returns True on success."""
        shown = ' '.join(shlex_quote(c) for c in cmd)
        if self.dry:
            print(self.out.dim('    would run: ' + shown))
            return True
        if not quiet:
            print(self.out.dim('    $ ' + shown))
        exe = which(cmd[0])
        if not exe:
            print('    (%s is not installed)' % cmd[0])
            return False
        try:
            if stream:
                rc = subprocess.call([exe] + cmd[1:], timeout=timeout)
                out = ''
            else:
                p = subprocess.run([exe] + cmd[1:], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   timeout=timeout, encoding='utf-8', errors='replace')
                rc, out = p.returncode, p.stdout
        except subprocess.TimeoutExpired:
            print('    timed out')
            return False
        except OSError as e:
            print('    failed: %s' % e)
            return False
        self.log.append((shown, rc))
        if rc != 0 and out.strip() and not quiet:
            print(self.out.wrap(out.strip()[-600:], '      '))
        return rc == 0

    def add_undo(self, *cmds, **kw):
        for c in cmds:
            line = c if isinstance(c, str) else ' '.join(shlex_quote(x) for x in c)
            if kw.get('after'):
                if line not in self.undo_after:
                    self.undo_after.append(line)
            else:
                self.undo.append(line)

    def backup(self, path):
        """Copy a file into the backup folder and remember how to put it back."""
        if self.dry or not os.path.exists(path):
            return None
        dest = os.path.join(self.dir, 'files', path.lstrip('/'))
        self._make_dir()
        os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
        shutil.copy2(path, dest)
        self.add_undo(['cp', '-a', dest, path])
        return dest

    def write_file(self, path, content, mode=0o644):
        if self.dry:
            print(self.out.dim('    would write %s:' % path))
            print(self.out.dim('\n'.join('      ' + l for l in content.rstrip().splitlines())))
            return True
        existed = os.path.exists(path)
        if existed:
            self.backup(path)
        else:
            self.add_undo(['rm', '-f', path])
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        os.chmod(path, mode)
        print(self.out.dim('    wrote %s' % path))
        return True

    def finish(self):
        if self.dry or not self.undo:
            return None
        self._make_dir()
        path = os.path.join(self.dir, 'undo.sh')
        lines = ['#!/bin/sh', '# Undo the changes networkScout made on %s.' % self.stamp,
                 '# Run:  sudo sh %s' % shlex_quote(path), 'set -u', '']
        lines += list(reversed(self.undo)) + self.undo_after
        lines += ['', 'echo "networkScout: changes from %s undone."' % self.stamp, '']
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        os.chmod(path, 0o700)
        return path

    def _make_dir(self):
        """Backups/undo scripts are run as root later, so only their owner may touch them."""
        parent = os.path.dirname(self.dir)
        os.makedirs(parent, mode=0o700, exist_ok=True)
        os.chmod(parent, 0o700)
        if is_root():
            os.chmod(os.path.dirname(parent), 0o700)
        os.makedirs(self.dir, mode=0o700, exist_ok=True)


def shlex_quote(s):
    import shlex
    return shlex.quote(str(s))


# ---- firewall helpers ------------------------------------------------------------------

APPS = {
    'transmission': {'label': 'Transmission (BitTorrent)', 'services': ['transmission-client', 'bittorrent-lsd'],
                     'ports': ['51413/tcp', '51413/udp', '6771/udp'], 'proc': r'^transmission',
                     'flatpak': 'com.transmissionbt.Transmission',
                     'why': 'Lets other BitTorrent users connect to you. Downloads still work when blocked '
                            '(sometimes slower). Allowing it exposes the port to your network and, over IPv6, '
                            'possibly to the internet.'},
    'qbittorrent': {'label': 'qBittorrent', 'services': [], 'ports': [], 'proc': r'^qbittorrent',
                    'flatpak': 'org.qbittorrent.qBittorrent', 'why': 'BitTorrent: lets other users connect to you.'},
    'deluge': {'label': 'Deluge (BitTorrent)', 'services': [], 'ports': [], 'proc': r'^deluge',
               'flatpak': 'org.deluge_torrent.deluge', 'why': 'BitTorrent: lets other users connect to you.'},
    'kdeconnect': {'label': 'KDE Connect / GSConnect', 'services': ['kdeconnect'],
                   'ports': ['1714-1764/tcp', '1714-1764/udp'], 'proc': r'^(kdeconnect|gsconnect)',
                   'why': 'Lets your paired phone find and talk to this computer.'},
    'syncthing': {'label': 'Syncthing', 'services': ['syncthing'], 'ports': ['22000/tcp', '22000/udp', '21027/udp'],
                  'proc': r'^syncthing', 'why': 'Lets your other devices sync with this one directly.'},
    'steam': {'label': 'Steam (Remote Play / LAN transfer)', 'services': ['steam-streaming', 'steam-lan-transfer'],
              'ports': ['27031-27036/udp', '27036-27037/tcp', '24070/tcp'], 'proc': r'^steam',
              'why': 'Remote Play and game transfers between your own computers.'},
    'localsend': {'label': 'LocalSend', 'services': [], 'ports': ['53317/tcp', '53317/udp'], 'proc': r'^localsend',
                  'flatpak': 'org.localsend.localsend_app', 'why': 'Receive files from nearby devices.'},
    'ssh': {'label': 'SSH remote login', 'services': ['ssh'], 'ports': ['22/tcp'], 'proc': r'^sshd',
            'why': 'Log in to this computer from another one.'},
    'samba': {'label': 'Windows file sharing (Samba server)', 'services': ['samba'],
              'ports': ['139/tcp', '445/tcp', '137/udp', '138/udp'], 'proc': r'^(smbd|nmbd)',
              'why': 'Share folders from this computer with others.'},
    'mdns': {'label': 'mDNS / Bonjour discovery', 'services': ['mdns'], 'ports': ['5353/udp'], 'proc': r'^avahi',
             'why': 'Finds printers and other devices on your network.'},
    'printing': {'label': 'Printer sharing (CUPS server)', 'services': ['ipp'], 'ports': ['631/tcp'], 'proc': r'^cups',
                 'why': 'Shares your printers with other computers.'},
}

# what each standard firewalld service is for, and whether to keep it when nothing uses it
SERVICE_HINTS = {
    'dhcpv6-client': ('needed to get an IPv6 address from your router', 'always'),
    'dhcp': ('DHCP server', 'unused'),
    'mdns': ('finds printers and other devices on your network', 'keep'),
    'samba-client': ('only needed to browse Windows file shares on your network', 'keep'),
    'ipp-client': ('finds network printers', 'keep'),
    'ssh': ('only needed if you log in to this computer from another one', 'unused'),
    'llmnr': ('Windows-style name lookups (LLMNR)', 'unused'),
    'llmnr-udp': ('Windows-style name lookups (LLMNR)', 'unused'),
    'llmnr-tcp': ('Windows-style name lookups (LLMNR)', 'unused'),
}

DURATION = re.compile(r'^(\d+)\s*([smhd]?)$')


def parse_duration(text):
    """'30m' -> (1800, '30m'); firewalld understands s/m/h only."""
    m = DURATION.match(text.strip().lower())
    if not m:
        raise ValueError('use a duration like 30m, 2h or 90s')
    n, unit = int(m.group(1)), m.group(2) or 'm'
    secs = n * {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}[unit]
    return secs, ('%dh' % (secs // 3600) if unit == 'd' else '%d%s' % (n, unit))


def port_specs_cover(specs, proto, port):
    for spec in specs:
        p, _, pr = spec.partition('/')
        lo, _, hi = p.partition('-')
        if (not pr or pr == proto) and int(lo) <= port <= int(hi or lo):
            return True
    return False


def fwd_running():
    r = run(['firewall-cmd', '--state'], 10)
    return bool(r and r[0] == 0)


def fwd_zone():
    dev = (default_routes_v4() or default_routes_v6() or [{}])[0].get('iface')
    z = stdout_of(['firewall-cmd', '--get-zone-of-interface=%s' % dev], 10).strip() if dev else ''
    return z or stdout_of(['firewall-cmd', '--get-default-zone'], 10).strip(), dev


def fwd_zone_info(zone, permanent=False):
    cmd = ['firewall-cmd'] + (['--permanent'] if permanent else []) + ['--zone=%s' % zone, '--list-all']
    kv = {}
    for line in stdout_of(cmd, 15).splitlines():
        m = re.match(r'^\s+([\w-]+):\s*(.*)$', line)
        if m:
            kv[m.group(1)] = m.group(2).strip()
    rich = re.findall(r'rule [^\n]+', stdout_of(cmd, 15)) if kv.get('rich rules') is not None else []
    return {'target': kv.get('target', 'default'), 'services': kv.get('services', '').split(),
            'ports': kv.get('ports', '').split(), 'rich': rich}


@lru_cache(maxsize=None)
def fwd_service_ports(svc):
    m = re.search(r'^\s*ports:\s*(.*)$', stdout_of(['firewall-cmd', '--info-service=%s' % svc], 10), re.M)
    return tuple(m.group(1).split()) if m else ()


@lru_cache(maxsize=None)
def fwd_known_services():
    return frozenset(stdout_of(['firewall-cmd', '--get-services'], 10).split())


def fwd_ops(action, zone, items, timeout=None, source=None):
    """firewall-cmd command lines for adding/removing services or ports (runtime AND permanent)."""
    cmds = []
    for kind, val in items:
        if source:
            fam = 'ipv6' if ':' in source else 'ipv4'
            what = 'service name="%s"' % val if kind == 'service' else 'port port="%s" protocol="%s"' % tuple(val.split('/'))
            opt = '--%s-rich-rule=rule family="%s" source address="%s" %s accept' % (action, fam, source, what)
        else:
            opt = '--%s-%s=%s' % (action, kind, val)
        if timeout and action == 'add':
            cmds.append(['firewall-cmd', '--zone=%s' % zone, opt, '--timeout=%s' % timeout])
        else:
            cmds.append(['firewall-cmd', '--zone=%s' % zone, opt])
            cmds.append(['firewall-cmd', '--permanent', '--zone=%s' % zone, opt])
    return cmds


def resolve_target(name, listeners):
    """An app name, a port ('8080', '8080/udp', '6881-6889/tcp') or the name of a listening program."""
    t = name.strip().lower()
    if t in APPS:
        app = dict(APPS[t])
        mine = sorted(set('%d/%s' % (s['port'], s['proto']) for s in listeners
                          if re.search(app['proc'], (s['process'] or s['unit']).lower())
                          and s['scope'] != 'loopback' and not s['ephemeral']))
        extra = [p for p in mine if not port_specs_cover(app['ports'], p.split('/')[1], int(p.split('/')[0]))]
        app['ports'] = list(app['ports']) + extra
        app['detected'] = mine
        app['key'] = t
        return app
    m = re.match(r'^(\d+)(?:-(\d+))?(?:/(tcp|udp))?$', t)
    if m:
        lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
        if not (0 < lo <= hi <= 65535):
            raise ValueError('port numbers go from 1 to 65535')
        p = '%d-%d' % (lo, hi) if hi != lo else str(lo)
        protos = [m.group(3)] if m.group(3) else ['tcp']
        return {'key': t, 'label': 'port %s' % ', '.join('%s/%s' % (p, pr) for pr in protos), 'services': [],
                'ports': ['%s/%s' % (p, pr) for pr in protos], 'proc': None, 'why': ''}
    mine = sorted(set('%d/%s' % (s['port'], s['proto']) for s in listeners
                      if t in (s['process'] + ' ' + s['unit']).lower() and s['scope'] != 'loopback'
                      and not s['ephemeral']))
    if mine:
        return {'key': t, 'label': '%s (ports %s)' % (t, ', '.join(mine)), 'services': [], 'ports': mine,
                'proc': re.escape(t), 'why': ''}
    raise ValueError('"%s" is not a known app (%s), a port number, or a program that is listening right now'
                     % (name, ', '.join(sorted(APPS))))


def app_items(app, tool):
    """What to open/close for an app: firewalld services when they exist, otherwise ports."""
    items = []
    if tool == 'firewalld':
        known = fwd_known_services()
        covered = []
        for svc in app['services']:
            if svc in known:
                items.append(('service', svc))
                covered.extend(fwd_service_ports(svc))
        for p in app['ports']:
            port, proto = p.split('/')
            if not port_specs_cover(covered, proto, int(port.split('-')[0])):
                items.append(('port', p))
    else:
        items = [('port', p) for p in app['ports']]
    return items


def ufw_spec(port_spec):
    port, proto = port_spec.split('/')
    return '%s/%s' % (port.replace('-', ':'), proto)


# ---- networkscout ports ----------------------------------------------------------------

def ports_list(out, listeners):
    fw = firewall_state()
    print(out.bold('Firewall'))
    if fw['tool'] == 'firewalld' and fw['active']:
        zone, dev = fwd_zone()
        perm = fwd_zone_info(zone, permanent=True)
        rt = fwd_zone_info(zone)
        print('  firewalld is on. Zone "%s" applies to %s.' % (zone, dev or 'your network'))
        print('  Always allowed in:   services %s; ports %s' % (', '.join(perm['services']) or 'none',
                                                              ', '.join(perm['ports']) or 'none'))
        temp_s = [s for s in rt['services'] if s not in perm['services']]
        temp_p = [p for p in rt['ports'] if p not in perm['ports']]
        temp_r = [r for r in rt['rich'] if r not in perm['rich']]
        if temp_s or temp_p or temp_r:
            print('  Temporarily allowed: %s (until the timer runs out or the next restart)' %
                  ', '.join(temp_s + temp_p + temp_r))
        for r in perm['rich']:
            print('  Rule: ' + r)
        wide = [p for p in perm['ports'] if '-' in p.split('/')[0] and
                int(p.split('/')[0].split('-')[1]) - int(p.split('/')[0].split('-')[0]) >= 1000]
        if wide:
            print(out.paint(out.codes[WARN], '  ! Wide-open range(s) %s: almost every program is reachable. '
                                             'Fix: %s ports close-unused' % (', '.join(wide), PROG)))
    elif fw['tool']:
        print('  %s is %s.%s' % (fw['tool'], 'on' if fw['active'] else ('OFF' if fw['active'] is False else 'in an unknown state'),
                                 '' if is_root() else ' (run with sudo to see its rules)'))
        for r in fw.get('rules') or []:
            print('  ' + r)
    else:
        print('  Unknown (no firewalld/ufw; run with sudo to read nftables/iptables).')
    print()
    print(out.bold('Programs that accept connections from the network'))
    exposed = [s for s in listeners if s['scope'] in ('all', 'lan', 'public') and not s['ephemeral']]
    if not exposed:
        print('  none')
    groups = {}
    for s in exposed:
        groups.setdefault((s['port'], s['proto']), []).append(s)
    if exposed:
        print(out.dim('  %-11s %-18s %-34s %s' % ('PORT', 'PROGRAM', 'WHAT IT IS', 'FIREWALL')))
    for (port, proto), socks in sorted(groups.items()):
        a = fw['allows'](proto, port)
        state = {True: out.paint(out.codes[WARN], 'reachable (allowed)'),
                 False: out.paint(out.codes[OK], 'blocked'),
                 None: 'unknown'}[a]
        s0 = socks[0]
        prog = s0['process'] or s0['unit'] or s0['user']
        what = next((app['label'] for app in APPS.values()
                     if re.search(app['proc'], (s0['process'] or s0['unit']).lower())), None) or \
            PORTS.get(port, ('unknown service', ''))[0]
        print('  %-11s %-18s %-34s %s' % ('%d/%s' % (port, proto), prog[:18], what[:34], state))
    print()
    print(out.bold('Apps'))
    for key, app in sorted(APPS.items()):
        running = [s for s in listeners if re.search(app['proc'], (s['process'] or s['unit']).lower())]
        if not running and key not in ('kdeconnect', 'transmission', 'ssh'):
            continue
        allowed = None
        if fw['tool'] == 'firewalld' and fw['active']:
            zone, _ = fwd_zone()
            info = fwd_zone_info(zone)
            items = app_items(app, 'firewalld')
            allowed = any((k == 'service' and v in info['services']) or (k == 'port' and v in info['ports'])
                          for k, v in items)
            via_range = any(port_specs_cover(info['ports'], p.split('/')[1], int(p.split('/')[0].split('-')[0]))
                            for p in app['ports'])
        print('  %-14s %-12s incoming: %s' % (key, 'running' if running else 'not running',
                                             'allowed' if allowed else ('allowed by a wide port range' if allowed is False and via_range
                                                                        else ('blocked' if allowed is False else 'unknown'))))
    print()
    print(out.dim('Commands:\n'
                  '  %s ports allow transmission             allow an app (or a port: 8080, 6881/udp)\n'
                  '  %s ports allow kdeconnect --for 1h      allow only for a while\n'
                  '  %s ports allow 8080 --from 192.168.1.0/24   only from your home network\n'
                  '  %s ports block transmission [--stop]    block it (and --stop quits the app)\n'
                  '  %s ports close-unused                   remove rules nothing needs\n'
                  '  %s firewall                             on/off and profiles (public, home, work, ...)\n'
                  'Changes ask for your password by themselves.' % ((PROG,) * 6)))


def ports_change(out, action, target, duration=None, source=None, stop=False, assume_yes=False, dry=False):
    listeners = listening_sockets()
    try:
        app = resolve_target(target, listeners)
    except ValueError as e:
        print(str(e))
        return 2
    fw = firewall_state()
    tool = fw['tool']
    ch = Changer(out, assume_yes, dry, label='ports')
    timeout_txt = None
    if duration:
        try:
            secs, timeout_txt = parse_duration(duration)
        except ValueError as e:
            print('--for: %s' % e)
            return 2
    verb = 'Allowing' if action == 'allow' else 'Blocking'
    print('%s incoming connections for %s%s%s.' % (
        verb, app['label'], ' for %s' % timeout_txt if timeout_txt else '', ' from %s' % source if source else ''))
    if app.get('why'):
        print(out.wrap(app['why'], '  '))
    if app.get('detected'):
        print('  It is listening on: %s' % ', '.join(app['detected']))
    ok = True
    if tool == 'firewalld':
        if not fw['active']:
            print('firewalld is not running, so nothing is blocked anyway. Start it: sudo systemctl enable --now firewalld')
            return 1
        zone, dev = fwd_zone()
        items = app_items(app, 'firewalld')
        if action == 'allow':
            for cmd in fwd_ops('add', zone, items, timeout_txt, source):
                ok = ch.run(cmd) and ok
        else:
            info_rt, info_pm = fwd_zone_info(zone), fwd_zone_info(zone, True)
            for cmd in fwd_ops('remove', zone, items):
                opt = cmd[-1]
                val = opt.split('=', 1)[1]
                present = val in info_rt['services'] + info_rt['ports'] + info_pm['services'] + info_pm['ports']
                if present:
                    ok = ch.run(cmd) and ok
            # rich rules mentioning these ports/services
            for r in set(info_rt['rich'] + info_pm['rich']):
                if any(('"%s"' % v) in r or ('port="%s"' % v.split('/')[0]) in r for _, v in items):
                    ch.run(['firewall-cmd', '--zone=%s' % zone, '--remove-rich-rule=%s' % r])
                    ch.run(['firewall-cmd', '--permanent', '--zone=%s' % zone, '--remove-rich-rule=%s' % r])
            info = fwd_zone_info(zone)
            still = [p for p in app['ports'] if port_specs_cover(info['ports'], p.split('/')[1], int(p.split('/')[0].split('-')[0]))]
            if still:
                print(out.paint(out.codes[WARN], '  ! A wide port range in zone "%s" still lets %s in. Remove it with: '
                                                 '%s ports close-unused' % (zone, ', '.join(still), PROG)))
    elif tool == 'ufw':
        for _, p in app_items(app, 'ufw'):
            spec = ufw_spec(p)
            if action == 'allow':
                if source:
                    port, proto = spec.split('/')
                    rule = ['from', source, 'to', 'any', 'port', port, 'proto', proto]
                else:
                    rule = [spec]
                ok = ch.run(['ufw', 'allow'] + rule) and ok
                if timeout_txt:
                    ch.run(['systemd-run', '--on-active=%d' % secs, '--unit=networkscout-expire-%d' % random.randint(1000, 99999),
                            which('ufw') or 'ufw', 'delete', 'allow'] + rule)
            else:
                ch.run(['ufw', 'delete', 'allow', spec], quiet=True)
    else:
        print('Automatic port control works with firewalld or ufw. Your firewall: %s.' % (tool or 'unknown'))
        return 1
    if stop and action == 'block' and app.get('proc'):
        u = target_user()
        if app.get('flatpak') and which('flatpak'):
            ch.run(['runuser', '-u', u.pw_name, '--', 'flatpak', 'kill', app['flatpak']], quiet=True)
        ch.run(['pkill', '-u', u.pw_name, app['proc'].lstrip('^').split('|')[0].strip('()')], quiet=True)
    if not dry:
        print(out.paint(out.codes[OK] if ok else out.codes[WARN], '  Done.' if ok else '  Done, with errors (see above).'))
        if timeout_txt and action == 'allow':
            print('  It closes again automatically after %s (or at the next restart).' % timeout_txt)
    return 0 if ok else 1


def plan_close_unused(out, ch, listeners, zone):
    """Remove wide port ranges and rules nothing uses; keep (or narrow down to) what running apps need."""
    perm = fwd_zone_info(zone, permanent=True)
    exposed = [s for s in listeners if s['scope'] in ('all', 'lan', 'public') and not s['ephemeral']]

    def in_use(specs):
        return [s for s in exposed if port_specs_cover(specs, s['proto'], s['port'])]

    removals, additions, decided = [], [], {}
    wide = [p for p in perm['ports'] if '-' in p.split('/')[0] and
            int(p.split('/')[0].split('-')[1]) - int(p.split('/')[0].split('-')[0]) >= 1000]
    for p in perm['ports']:
        users = in_use([p])
        if p in wide:
            print('  Port range %s lets in %d ports%s.' % (p, int(p.split('/')[0].split('-')[1]) -
                                                       int(p.split('/')[0].split('-')[0]) + 1,
                                                       ' (used right now by: %s)' % ', '.join(sorted(set(
                                                           '%d %s' % (s['port'], describe_owner(s)) for s in users))) if users else ''))
            if ch.ask('Remove this range?', default=True):
                removals.append(('port', p))
                # offer to keep the running apps that relied on it, individually
                for key, app in sorted(APPS.items()):
                    if any(re.search(app['proc'], (s['process'] or s['unit']).lower()) for s in users):
                        if key in decided:
                            continue
                        a = resolve_target(key, listeners)
                        print('    %s uses it. %s' % (a['label'], a.get('why', '')))
                        decided[key] = ch.ask('    Keep allowing %s?' % a['label'], default=(key in ('kdeconnect', 'mdns')))
                        if decided[key]:
                            additions.extend(i for i in app_items(a, 'firewalld') if i not in additions)
                handled = set()
                for _key, app in APPS.items():
                    handled.update(s['port'] for s in users if re.search(app['proc'], (s['process'] or s['unit']).lower()))
                for s in users:
                    if s['port'] in handled or PORTS.get(s['port'], ('', OK))[1] == OK:
                        continue
                    spec = '%d/%s' % (s['port'], s['proto'])
                    if spec in [v for _, v in additions]:
                        continue
                    if s['port'] in (5355,) or spec in decided:
                        continue
                    decided[spec] = ch.ask('    Keep allowing port %s (%s)?' % (spec, describe_owner(s)), default=False)
                    if decided[spec]:
                        additions.append(('port', spec))
        elif not users:
            if ch.ask('  Port %s is allowed but nothing uses it. Remove?' % p, default=True):
                removals.append(('port', p))
    for svc in perm['services']:
        hint, policy = SERVICE_HINTS.get(svc, ('', 'unused'))
        if policy == 'always':
            continue
        users = in_use(list(fwd_service_ports(svc)))
        if users:
            continue
        if ch.ask('  Service "%s" is allowed%s and nothing uses it now. Remove?' % (svc, ' (%s)' % hint if hint else ''),
                  default=(policy != 'keep')):
            removals.append(('service', svc))
    return removals, additions


def ports_close_unused(out, assume_yes=False, dry=False):
    fw = firewall_state()
    listeners = listening_sockets()
    ch = Changer(out, assume_yes, dry, label='ports')
    if fw['tool'] == 'firewalld' and fw['active']:
        zone, dev = fwd_zone()
        print('Firewall zone "%s" (%s):' % (zone, dev))
        removals, additions = plan_close_unused(out, ch, listeners, zone)
        if not removals and not additions:
            print('  Nothing to change.')
            return 0
        for cmd in fwd_ops('add', zone, additions):
            ch.run(cmd)
            ch.add_undo(['firewall-cmd', '--permanent', '--zone=%s' % zone, cmd[-1].replace('--add-', '--remove-')])
        for cmd in fwd_ops('remove', zone, removals):
            ch.run(cmd)
            if '--permanent' in cmd:
                ch.add_undo(['firewall-cmd', '--permanent', '--zone=%s' % zone, cmd[-1].replace('--remove-', '--add-')])
        ch.add_undo(['firewall-cmd', '--reload'], after=True)
        path = ch.finish()
        if path:
            print('  Undo later with: sudo sh %s' % path)
        return 0
    if fw['tool'] == 'ufw':
        print('With ufw, list rules with "sudo ufw status numbered" and delete what you do not need '
              '("sudo ufw delete NUMBER"). Make sure "sudo ufw default deny incoming" is set.')
        return 0
    print('Automatic port control works with firewalld or ufw. Your firewall: %s.' % (fw['tool'] or 'unknown'))
    return 1


def cmd_ports(argv, out):
    ap = argparse.ArgumentParser(prog='%s ports' % PROG, description='See and control which ports other devices can reach.')
    sub = ap.add_subparsers(dest='action')
    sub.add_parser('list', help='show open ports, which app owns them and what the firewall does (default)')
    for name, hlp in (('allow', 'let incoming connections in for an app or port'),
                      ('block', 'stop incoming connections for an app or port')):
        p = sub.add_parser(name, help=hlp, aliases=['open'] if name == 'allow' else ['close', 'deny'])
        p.add_argument('target', help='app (%s), port (8080, 6881/udp, 6881-6889/tcp) or listening program name'
                                      % ', '.join(sorted(APPS)))
        if name == 'allow':
            p.add_argument('--for', dest='duration', metavar='TIME', help='only for a while: 30m, 2h, 90s')
            p.add_argument('--from', dest='source', metavar='ADDRESS', help='only from this address/network, '
                                                                            'e.g. 192.168.1.0/24')
        else:
            p.add_argument('--stop', action='store_true', help='also quit the app')
        p.add_argument('--yes', '-y', action='store_true', help=argparse.SUPPRESS)
        p.add_argument('--dry-run', action='store_true', help='only show what would be done')
    p = sub.add_parser('close-unused', help='remove wide port ranges and rules nothing uses (asks first)')
    p.add_argument('--yes', '-y', action='store_true', help='accept the recommended answer to every question')
    p.add_argument('--dry-run', action='store_true', help='only show what would be done')
    args = ap.parse_args(argv)
    action = {'open': 'allow', 'close': 'block', 'deny': 'block'}.get(args.action, args.action)
    if action in (None, 'list'):
        ports_list(out, listening_sockets())
        return 0
    if not getattr(args, 'dry_run', False) and not become_root(['ports'] + argv):
        return 1
    if action == 'close-unused':
        return ports_close_unused(out, args.yes, args.dry_run)
    return ports_change(out, action, args.target, getattr(args, 'duration', None), getattr(args, 'source', None),
                        getattr(args, 'stop', False), args.yes, args.dry_run)


# ---- networkscout firewall ---------------------------------------------------------------

ZONE_INFO = {
    'drop': ('Strictest: silently ignores every incoming connection. Outgoing traffic works normally.', 1),
    'block': ('Very strict: refuses every incoming connection (with a "rejected" reply).', 2),
    'public': ('For public places and networks you do not control (cafés, airports, hotels, mobile hotspots). '
               'Only selected services are let in.', 3),
    'external': ('For a computer that acts as a router with NAT. Rarely needed on a desktop.', 9),
    'dmz': ('For a computer in a "demilitarized zone" that is reachable from outside. Rarely needed.', 9),
    'work': ('For your workplace: you mostly trust the other computers there.', 4),
    'home': ('For your home network: you mostly trust the other devices there.', 5),
    'internal': ('For internal networks that you mostly trust (like "home").', 6),
    'trusted': ('No protection: every incoming connection is accepted. Use only on a fully trusted network.', 8),
    'FedoraWorkstation': ('Fedora desktop default: lets in every port from 1025 to 65535, plus SSH and Windows '
                          'browsing. Convenient, but barely protects you.', 7),
    'FedoraServer': ('Fedora server default: SSH, Cockpit and DHCPv6.', 9),
}
ZONE_ALIASES = {'workplace': 'work', 'office': 'work', 'cafe': 'public', 'café': 'public', 'travel': 'public',
                'hotel': 'public', 'airport': 'public', 'strict': 'drop', 'stealth': 'drop', 'lockdown': 'drop',
                'open': 'trusted', 'fedora': 'FedoraWorkstation', 'default': 'FedoraWorkstation'}
SYSTEM_ZONES = ('libvirt', 'libvirt-routed', 'docker', 'nm-shared', 'podman', 'virbr0')


def fwd_zones():
    return stdout_of(['firewall-cmd', '--get-zones'], 10).split()


def active_connection():
    """(uuid, name, device) of the NetworkManager connection carrying the default route."""
    dev = (default_routes_v4() or default_routes_v6() or [{}])[0].get('iface')
    for line in stdout_of(['nmcli', '-t', '-f', 'UUID,NAME,DEVICE', 'connection', 'show', '--active'], 10).splitlines():
        parts = re.split(r'(?<!\\):', line)
        if len(parts) >= 3 and parts[2] == dev:
            return parts[0], parts[1].replace('\\:', ':'), dev
    return None, None, dev


def firewall_status(out):
    fw = firewall_state()
    print(out.bold('Firewall'))
    if fw['tool'] == 'firewalld':
        if not fw['active']:
            print('  ' + out.paint(out.codes[RISK], 'OFF') + ' (firewalld is installed but not running). '
                  'Turn it on: %s firewall on' % PROG)
            return
        default = stdout_of(['firewall-cmd', '--get-default-zone'], 10).strip()
        zone, dev = fwd_zone()
        uuid, name, _ = active_connection()
        pinned = stdout_of(['nmcli', '-g', 'connection.zone', 'connection', 'show', uuid], 10).strip() if uuid else ''
        print('  ' + out.paint(out.codes[OK], 'ON') + ' (firewalld). Profile in use on %s: %s%s' % (
            dev or 'your network', out.bold(zone),
            ' (set for the network "%s")' % name if pinned else ' (the default profile)'))
        print('  Default profile for other networks: %s' % default)
        ld = stdout_of(['firewall-cmd', '--get-log-denied'], 10).strip()
        print('  Logging of blocked attempts: %s' % ('off' if ld in ('', 'off') else 'on (%s)' % ld))
        print()
        print(out.bold('Profiles') + out.dim('  (choose with: %s firewall profile NAME [--this-network])' % PROG))
        zones = [z for z in fwd_zones() if z not in SYSTEM_ZONES]
        for z in sorted(zones, key=lambda z: (ZONE_INFO.get(z, ('', 9))[1], z)):
            info = fwd_zone_info(z, permanent=True)
            lets_in = ', '.join(info['services'] + info['ports']) or 'nothing'
            if info['target'].upper() in ('ACCEPT',):
                lets_in = 'EVERYTHING'
            elif info['target'].upper() in ('DROP', '%%REJECT%%', 'REJECT') and lets_in == 'nothing':
                lets_in = 'nothing'
            mark = out.paint(out.codes[OK], '●') if z == zone else ' '
            desc = textwrap.wrap(ZONE_INFO.get(z, ('Custom profile.', 9))[0], max(30, out.width - 23))
            print('  %s %-18s %s' % (mark, z, desc[0]))
            for line in desc[1:]:
                print(' ' * 23 + line)
            print(out.dim(' ' * 23 + 'lets in: %s' % lets_in))
        aliases = ', '.join('%s=%s' % (a, z) for a, z in sorted(ZONE_ALIASES.items()) if a != 'café')
        print(out.dim('\n  Also understood: ' + aliases))
    elif fw['tool'] == 'ufw':
        print('  ufw is %s.' % ('ON' if fw['active'] else ('OFF' if fw['active'] is False else 'in an unknown state')))
        print('  ufw has no profiles/zones: it blocks incoming connections except the rules you add '
              '(%s ports allow ...).' % PROG)
    else:
        print('  No firewalld or ufw found%s.' % ('' if is_root() else ' (run with sudo to inspect nftables/iptables)'))
        print('  Install one with your package manager: firewalld (Fedora, openSUSE, Arch) or ufw (Debian, Ubuntu, Mint).')


def firewall_onoff(out, ch, on, duration=None):
    fw = firewall_state()
    tool = fw['tool']
    if tool not in ('firewalld', 'ufw'):
        print('No firewalld or ufw found. Install one with your package manager first.')
        return 1
    if on:
        if tool == 'firewalld':
            ch.run(['systemctl', 'unmask', 'firewalld'], quiet=True)
            ok = ch.run(['systemctl', 'enable', '--now', 'firewalld'])
        else:
            ok = ch.run(['ufw', '--force', 'enable'])
        if not ch.dry:
            print(out.paint(out.codes[OK] if ok else out.codes[RISK], '  Firewall is ON.' if ok else '  Could not turn it on.'))
        return 0 if ok else 1
    print(out.wrap(out.paint(out.codes[WARN], 'Turning the firewall off lets every device on your network (and, over '
                                              'IPv6, possibly the internet) connect to any program that listens.'), '  '))
    secs = None
    if duration:
        secs, txt = parse_duration(duration)
        print('  It will turn itself back on after %s.' % txt)
    if not ch.ask('Turn the firewall off?', True):
        print('  Nothing changed.')
        return 0
    if tool == 'firewalld':
        ok = ch.run(['systemctl', 'stop', 'firewalld']) if secs else ch.run(['systemctl', 'disable', '--now', 'firewalld'])
        back = ['systemctl', 'start', 'firewalld']
    else:
        ok = ch.run(['ufw', 'disable'])
        back = [which('ufw') or 'ufw', '--force', 'enable']
    if ok and secs:
        ch.run(['systemd-run', '--on-active=%d' % secs, '--unit=networkscout-firewall-on-%d' % random.randint(1000, 99999),
                '--description=networkScout: turn the firewall back on'] + back)
    if not ch.dry:
        print(out.paint(out.codes[WARN], '  Firewall is OFF%s. Turn it on again: %s firewall on' % (
            ' for %s' % parse_duration(duration)[1] if secs else '', PROG)))
    return 0 if ok else 1


def firewall_profile(out, ch, name, this_network=False):
    fw = firewall_state()
    if fw['tool'] != 'firewalld':
        print('Profiles (zones) need firewalld. Your firewall: %s.' % (fw['tool'] or 'none found'))
        return 1
    if not fw['active']:
        print('firewalld is off. Turn it on first: %s firewall on' % PROG)
        return 1
    zones = fwd_zones()
    z = ZONE_ALIASES.get(name.lower(), name)
    match = [x for x in zones if x.lower() == z.lower()]
    if not match:
        print('Unknown profile "%s". Available: %s' % (name, ', '.join(x for x in zones if x not in SYSTEM_ZONES)))
        return 2
    z = match[0]
    cur, dev = fwd_zone()
    default = stdout_of(['firewall-cmd', '--get-default-zone'], 10).strip()
    print('Profile "%s": %s' % (z, ZONE_INFO.get(z, ('Custom profile.', 9))[0]))
    if z == 'trusted' or fwd_zone_info(z, True)['target'].upper() == 'ACCEPT':
        print(out.paint(out.codes[RISK], '  Warning: this profile accepts every incoming connection.'))
        if not ch.ask('Use it anyway?', False):
            return 0
    # carry over the apps the user allowed in the current profile
    cur_info, new_info = fwd_zone_info(cur, True), fwd_zone_info(z, True)
    carry = [s for s in cur_info['services'] if s not in new_info['services'] and s not in ('ssh', 'samba-client')
             and any(s in a['services'] for a in APPS.values())]
    if carry and z not in ('drop', 'block', 'trusted'):
        print('  Your current profile "%s" allows: %s' % (cur, ', '.join(carry)))
        if ch.ask('Allow them in "%s" too?' % z, True):
            for svc in carry:
                for cmd in fwd_ops('add', z, [('service', svc)]):
                    ch.run(cmd)
                ch.add_undo(['firewall-cmd', '--permanent', '--zone=%s' % z, '--remove-service=%s' % svc])
    if this_network:
        uuid, cname, _ = active_connection()
        if not uuid:
            print('  Could not find the active network connection (NetworkManager).')
            return 1
        old = stdout_of(['nmcli', '-g', 'connection.zone', 'connection', 'show', uuid], 10).strip()
        print('  Using "%s" whenever you are connected to "%s"; other networks keep "%s".' % (z, cname, default))
        ok = ch.run(['nmcli', 'connection', 'modify', uuid, 'connection.zone', z])
        if ok and dev:
            ch.run(['firewall-cmd', '--zone=%s' % z, '--change-interface=%s' % dev], quiet=True)
        ch.add_undo(['nmcli', 'connection', 'modify', uuid, 'connection.zone', old])
        ch.add_undo(['nmcli', 'device', 'reapply', dev], after=True)
    else:
        ok = ch.run(['firewall-cmd', '--set-default-zone=%s' % z])
        ch.add_undo(['firewall-cmd', '--set-default-zone=%s' % default])
        uuid, cname, _ = active_connection()
        pinned = stdout_of(['nmcli', '-g', 'connection.zone', 'connection', 'show', uuid], 10).strip() if uuid else ''
        if pinned and pinned != z:
            print('  Note: the network "%s" has its own profile "%s", which still applies there. Change it with: '
                  '%s firewall profile %s --this-network' % (cname, pinned, PROG, z))
    if not ch.dry:
        now, _ = fwd_zone()
        print(out.paint(out.codes[OK] if now == z or this_network else out.codes[WARN],
                        '  Profile in use on %s: %s' % (dev, now)))
    return 0 if ok else 1


def cmd_firewall(argv, out):
    ap = argparse.ArgumentParser(prog='%s firewall' % PROG, description='Turn the firewall on/off and choose its profile.')
    sub = ap.add_subparsers(dest='action')
    sub.add_parser('status', help='show whether the firewall is on and which profile is used (default)')
    p = sub.add_parser('on', help='turn the firewall on')
    p.add_argument('--yes', '-y', action='store_true', help=argparse.SUPPRESS)
    p.add_argument('--dry-run', action='store_true')
    p = sub.add_parser('off', help='turn the firewall off (asks first)')
    p.add_argument('--for', dest='duration', metavar='TIME', help='turn it back on automatically after 10m, 1h, ...')
    p.add_argument('--yes', '-y', action='store_true', help=argparse.SUPPRESS)
    p.add_argument('--dry-run', action='store_true')
    p = sub.add_parser('log-blocked', help='log blocked connection attempts (shown live in the networkScout app)')
    p.add_argument('state', choices=['on', 'off'])
    p.add_argument('--yes', '-y', action='store_true', help=argparse.SUPPRESS)
    p.add_argument('--dry-run', action='store_true')
    p = sub.add_parser('profile', aliases=['zone'], help='choose a profile: public, home, work, drop, block, ...')
    p.add_argument('name', help='public, home, work (workplace), internal, block, drop (strict), trusted (open), ...')
    p.add_argument('--this-network', action='store_true',
                   help='use it only on the network you are connected to now (others keep the default)')
    p.add_argument('--yes', '-y', action='store_true', help='accept the recommended answer to every question')
    p.add_argument('--dry-run', action='store_true')
    args = ap.parse_args(argv)
    if args.action in (None, 'status'):
        firewall_status(out)
        return 0
    if args.action == 'off' and args.duration:
        try:
            parse_duration(args.duration)
        except ValueError as e:
            print('--for: %s' % e)
            return 2
    if not args.dry_run and not become_root(['firewall'] + argv):
        return 1
    ch = Changer(out, getattr(args, 'yes', False), args.dry_run, label='firewall')
    if args.action == 'log-blocked':
        if firewall_state()['tool'] != 'firewalld':
            print('Logging blocked attempts is supported with firewalld.')
            return 1
        old = stdout_of(['firewall-cmd', '--get-log-denied'], 10).strip() or 'off'
        new = 'unicast' if args.state == 'on' else 'off'
        rc = 0 if ch.run(['firewall-cmd', '--set-log-denied=%s' % new]) else 1
        if old != new:
            ch.add_undo(['firewall-cmd', '--set-log-denied=%s' % old])
        if not ch.dry and rc == 0:
            print('  Blocked connection attempts are %s logged.' % ('now' if new != 'off' else 'no longer'))
    elif args.action == 'on':
        rc = firewall_onoff(out, ch, True)
    elif args.action == 'off':
        rc = firewall_onoff(out, ch, False, args.duration)
    else:
        rc = firewall_profile(out, ch, args.name, args.this_network)
    path = ch.finish()
    if path:
        print('  Undo: sudo sh %s' % path)
    return rc


# ---- networkscout fix --------------------------------------------------------------------

DOT_PROVIDERS = [
    ('Cloudflare', 'cloudflare-dns.com', ['1.1.1.1', '1.0.0.1', '2606:4700:4700::1111', '2606:4700:4700::1001']),
    ('Quad9', 'dns.quad9.net', ['9.9.9.9', '149.112.112.112', '2620:fe::fe', '2620:fe::9']),
    ('Google', 'dns.google', ['8.8.8.8', '8.8.4.4', '2001:4860:4860::8888', '2001:4860:4860::8844']),
]


def tcp_reachable(host, port, timeout=4):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def fix_updates(ch, out):
    fam = package_system()
    print(out.bold('\n• Software updates'))
    if fam == 'rpm-ostree':
        r = run(['rpm-ostree', 'status', '--json'], 30)
        try:
            staged = any(d.get('staged') for d in json.loads(r[1])['deployments'])
        except Exception:
            staged = False
        if staged:
            print('  A system update is already downloaded. Restart the computer to finish installing it.')
        elif ch.ask('Download and stage the newest system image now (it takes effect at the next restart)?', True):
            ch.run(['rpm-ostree', 'upgrade'], stream=True, timeout=7200)
    elif fam in ('dnf', 'yum'):
        if ch.ask('Install all package updates now (%s upgrade)?' % fam, True):
            ch.run([fam, '-y', 'upgrade', '--refresh'], stream=True, timeout=7200)
    elif fam == 'apt':
        if ch.ask('Install all package updates now (apt)?', True):
            ch.run(['apt-get', 'update'], stream=True, timeout=1800)
            ch.run(['apt-get', '-y', 'upgrade'], stream=True, timeout=7200)
    elif fam == 'pacman':
        if ch.ask('Install all package updates now (pacman -Syu)?', True):
            ch.run(['pacman', '-Syu', '--noconfirm'], stream=True, timeout=7200)
    elif fam == 'zypper':
        if ch.ask('Install all package updates now (zypper)?', True):
            ch.run(['zypper', '--non-interactive', 'update'], stream=True, timeout=7200)
    elif fam == 'transactional-update':
        if ch.ask('Install updates now (transactional-update)?', True):
            ch.run(['transactional-update', '--non-interactive', 'up'], stream=True, timeout=7200)
    else:
        print('  Update your system with: %s' % update_command())
    if which('flatpak') and ch.ask('Update Flatpak apps now?', True):
        ch.run(['flatpak', 'update', '-y', '--noninteractive', '--system'], stream=True, timeout=3600)
        u = target_user()
        if u.pw_uid != 0 and run(['runuser', '-u', u.pw_name, '--', 'flatpak', 'list', '--user', '--app']) is not None:
            ch.run(['runuser', '-u', u.pw_name, '--', 'flatpak', 'update', '-y', '--noninteractive', '--user'],
                   stream=True, timeout=3600)
    if which('snap') and os.path.exists('/run/snapd.socket') and ch.ask('Update Snap packages now?', True):
        ch.run(['snap', 'refresh'], stream=True, timeout=3600)


def fix_auto_updater(ch, out):
    """Universal Blue's uupd skips updates when the network is 'busy' (torrents, downloads, streaming)."""
    if not which('uupd') or not which('journalctl'):
        return
    log = stdout_of(['journalctl', '-u', 'uupd.service', '--since', '-21d', '--no-pager', '-o', 'cat'], 30)
    busy = len(re.findall(r'network is busy', log))
    if not busy:
        return
    print(out.bold('\n• Automatic updates (uupd)'))
    print(out.wrap('The automatic updater skipped %d times in the last 3 weeks because the network was "busy" '
                   '(more than 700 KB received during its check; a running torrent client or download does this). '
                   'Raising that limit lets updates run even then. The battery, CPU and memory checks stay on.'
                   % busy, '  '))
    if not ch.ask('Raise the network limit to 50 MB?', True):
        return
    path = '/etc/uupd/config.json'
    try:
        cfg = json.loads(read(path) or '{}')
    except ValueError:
        print('  %s is not valid JSON; leaving it alone.' % path)
        return
    hw = cfg.setdefault('checks', {}).setdefault('hardware', {})
    hw.setdefault('enable', True)
    hw['net-max-bytes'] = 50000000
    ch.write_file(path, json.dumps(cfg, indent=4) + '\n')
    if stdout_of(['systemctl', 'is-enabled', 'uupd.timer']).strip() != 'enabled' and ch.ask('Turn the daily update timer on?', True):
        ch.run(['systemctl', 'enable', '--now', 'uupd.timer'])


def fix_ca_anchors(ch, out):
    anchors = [a for a in local_ca_anchors() if not a['shipped_by_os']]
    if not anchors:
        return
    print(out.bold('\n• Extra trusted root certificates'))
    changed = False
    for a in anchors:
        label = ', '.join(x for x in (a.get('subject_cn'), a.get('subject_o')) if x) or os.path.basename(a['path'])
        print(out.wrap('%s (file %s, added %s). It can be used to read your encrypted traffic. Keep it only if '
                       'you knowingly installed it for a product you still use.' % (label, a['path'], a['mtime']), '  '))
        if ch.ask('Remove it (a backup is kept for undo)?', True):
            if ch.backup(a['path']) or ch.dry:
                ch.run(['rm', '-f', a['path']])
                changed = True
    if changed:
        if which('update-ca-trust'):
            ch.run(['update-ca-trust', 'extract'])
            ch.add_undo(['update-ca-trust', 'extract'], after=True)
        elif which('update-ca-certificates'):
            ch.run(['update-ca-certificates', '--fresh'])
            ch.add_undo(['update-ca-certificates', '--fresh'], after=True)
        elif which('trust'):
            ch.run(['trust', 'extract-compat'])
            ch.add_undo(['trust', 'extract-compat'], after=True)


def fix_firewall(ch, out):
    fw = firewall_state()
    listeners = listening_sockets()
    print(out.bold('\n• Firewall'))
    if fw['tool'] == 'firewalld':
        if not fw['active']:
            if ch.ask('firewalld is off. Turn it on?', True):
                ch.run(['systemctl', 'enable', '--now', 'firewalld'])
                ch.add_undo(['systemctl', 'disable', '--now', 'firewalld'])
            return
        zone, dev = fwd_zone()
        if fwd_zone_info(zone)['target'].upper() in ('ACCEPT',) or zone == 'trusted':
            if ch.ask('Zone "%s" lets everything in. Switch to the "public" zone?' % zone, True):
                ch.run(['firewall-cmd', '--set-default-zone=public'])
                ch.add_undo(['firewall-cmd', '--set-default-zone=%s' % zone])
                zone = 'public'
        removals, additions = plan_close_unused(out, ch, listeners, zone)
        for cmd in fwd_ops('add', zone, additions):
            ch.run(cmd)
            if '--permanent' in cmd:
                ch.add_undo(['firewall-cmd', '--permanent', '--zone=%s' % zone, cmd[-1].replace('--add-', '--remove-')])
        for cmd in fwd_ops('remove', zone, removals):
            ch.run(cmd)
            if '--permanent' in cmd:
                ch.add_undo(['firewall-cmd', '--permanent', '--zone=%s' % zone, cmd[-1].replace('--remove-', '--add-')])
        if removals or additions:
            ch.add_undo(['firewall-cmd', '--reload'], after=True)
        else:
            print('  No changes needed.')
    elif fw['tool'] == 'ufw':
        if not fw['active'] and ch.ask('ufw is off. Turn it on, blocking incoming connections by default?', True):
            ch.run(['ufw', 'default', 'deny', 'incoming'])
            ch.run(['ufw', 'default', 'allow', 'outgoing'])
            ch.run(['ufw', '--force', 'enable'])
            ch.add_undo(['ufw', 'disable'])
        else:
            print('  ufw is on. Review rules with: sudo ufw status numbered')
    else:
        print('  No firewalld or ufw found. Install one with your package manager (e.g. firewalld or ufw) '
              'and turn it on.')


def _nm_connections_with_auto_dns():
    out = stdout_of(['nmcli', '-t', '-f', 'UUID,TYPE,DEVICE', 'connection', 'show', '--active'], 10)
    res = []
    for line in out.splitlines():
        parts = re.split(r'(?<!\\):', line)
        if len(parts) < 3 or parts[1] in ('loopback', 'bridge', 'wireguard', 'vpn', 'tun') or not parts[2]:
            continue
        if parts[2].startswith(('docker', 'virbr', 'veth', 'br-', 'podman')):
            continue
        vals = stdout_of(['nmcli', '-g', 'ipv4.ignore-auto-dns,ipv6.ignore-auto-dns', 'connection', 'show', parts[0]], 10).split('\n')
        res.append({'uuid': parts[0], 'dev': parts[2], 'v4': (vals + ['no'])[0].strip() or 'no',
                    'v6': (vals + ['no', 'no'])[1].strip() or 'no'})
    return res


def _dns_works():
    for _ in range(20):
        if dns_values(dns_query('example.com', 'A', '127.0.0.53', timeout=3), 'A'):
            return True
        time.sleep(1)
    return False


DNS_DROPIN = '/etc/systemd/resolved.conf.d/60-networkscout-dns.conf'
LLMNR_DROPIN = '/etc/systemd/resolved.conf.d/61-networkscout-llmnr.conf'


def uses_resolved():
    ns, _ = resolv_conf()
    return bool(which('resolvectl')) and '127.0.0.53' in ns


def dns_state():
    """Current DNS settings in plain terms (used by `dns status` and the app)."""
    rs = resolved_status() if uses_resolved() else None
    st = {'resolved': bool(rs), 'encrypted': False, 'llmnr': None, 'servers': [], 'current': None,
          'ours': os.path.exists(DNS_DROPIN), 'provider': None}
    if not rs:
        st['servers'] = resolv_conf()[0]
        return st
    g = rs['global']
    st['encrypted'] = _flag(g.get('Protocols', ''), 'DNSOverTLS') == 'yes' or g.get('DNSOverTLS setting') == 'yes'
    st['llmnr'] = (_flag(g.get('Protocols', ''), 'LLMNR') or g.get('LLMNR setting') or 'yes') not in ('no',)
    for src in [g] + rs['links']:
        for s in (src.get('DNS Servers') or '').split():
            s = s.split('#')[0]                    # "1.1.1.1#cloudflare-dns.com": address + TLS name
            if s not in st['servers']:
                st['servers'].append(s)
        st['current'] = st['current'] or (src.get('Current DNS Server') or '').split('#')[0] or None
    m = re.search(r'#([\w.-]+)', read(DNS_DROPIN, '') or '')
    if m:
        st['provider'] = next((n for n, h, _ in DOT_PROVIDERS if h == m.group(1)), m.group(1))
    return st


def _rollback(ch, mark_undo, mark_after):
    """Undo (now) the steps recorded since the marks; used when DNS stops working."""
    for line in reversed(ch.undo[mark_undo:]):
        ch.run(['sh', '-c', line], quiet=True)
    for line in ch.undo_after[mark_after:]:
        ch.run(['sh', '-c', line], quiet=True)
    del ch.undo[mark_undo:]
    del ch.undo_after[mark_after:]


def dns_apply(ch, out, mode=None, provider=None, llmnr=None):
    """mode: 'encrypt' | 'plain' | None. llmnr: True / False / None (leave). Restarts systemd-resolved once,
    checks that names still resolve and undoes the change at once if they do not."""
    if not uses_resolved():
        print(out.wrap('This system does not use systemd-resolved, so networkScout cannot change DNS. Turn on '
                       '"DNS over HTTPS" in your web browser instead.', '  '))
        return False
    mark_u, mark_a = len(ch.undo), len(ch.undo_after)
    changed, nm_changes = False, []
    conns = _nm_connections_with_auto_dns() if which('nmcli') else []
    if mode == 'encrypt':
        order = [p for p in DOT_PROVIDERS if not provider or p[0].lower() == provider.lower()]
        if provider and not order:
            print('  Unknown provider "%s". Choose: %s' % (provider, ', '.join(p[0].lower() for p in DOT_PROVIDERS)))
            return False
        choice = next((p for p in order if tcp_reachable(p[2][0], 853)), None)
        if not choice:
            print('  %s is not reachable on the encrypted-DNS port (853) from this network.' %
                  (provider or 'No encrypted-DNS provider'))
            return False
        print('  Encrypted DNS: %s (%s)' % (choice[0], choice[1]))
        ch.write_file(DNS_DROPIN, '# Written by networkScout on %s. Delete this file to undo.\n'
                                  '[Resolve]\nDNS=%s\nDNSOverTLS=yes\nDomains=~.\n'
                      % (ch.stamp, ' '.join('%s#%s' % (ip, choice[1]) for ip in choice[2])))
        changed = True
        for c in conns:
            if c['v4'] != 'yes' or c['v6'] != 'yes':
                nm_changes.append(c)
                ch.run(['nmcli', 'connection', 'modify', c['uuid'], 'ipv4.ignore-auto-dns', 'yes',
                        'ipv6.ignore-auto-dns', 'yes'])
                ch.add_undo(['nmcli', 'connection', 'modify', c['uuid'], 'ipv4.ignore-auto-dns', c['v4'],
                             'ipv6.ignore-auto-dns', c['v6']])
                ch.add_undo(['nmcli', 'device', 'reapply', c['dev']], after=True)
    elif mode == 'plain':
        if os.path.exists(DNS_DROPIN):
            ch.backup(DNS_DROPIN)
            ch.run(['rm', '-f', DNS_DROPIN])
            changed = True
        for c in conns:
            if c['v4'] == 'yes' or c['v6'] == 'yes':
                nm_changes.append(c)
                ch.run(['nmcli', 'connection', 'modify', c['uuid'], 'ipv4.ignore-auto-dns', 'no',
                        'ipv6.ignore-auto-dns', 'no'])
                ch.add_undo(['nmcli', 'connection', 'modify', c['uuid'], 'ipv4.ignore-auto-dns', c['v4'],
                             'ipv6.ignore-auto-dns', c['v6']])
                ch.add_undo(['nmcli', 'device', 'reapply', c['dev']], after=True)
                changed = True
    if llmnr is False:
        ch.write_file(LLMNR_DROPIN, '# Written by networkScout on %s. Delete this file to undo.\n'
                                    '[Resolve]\nLLMNR=no\n' % ch.stamp)
        changed = True
    elif llmnr is True and os.path.exists(LLMNR_DROPIN):
        ch.backup(LLMNR_DROPIN)
        ch.run(['rm', '-f', LLMNR_DROPIN])
        changed = True
    if not changed:
        print('  Nothing to change.')
        return True
    for c in nm_changes:
        if not ch.run(['nmcli', 'device', 'reapply', c['dev']]):
            ch.run(['nmcli', 'connection', 'up', c['uuid']])
    ch.run(['systemctl', 'restart', 'systemd-resolved'])
    ch.add_undo(['systemctl', 'restart', 'systemd-resolved'], after=True)
    if ch.dry:
        return True
    if _dns_works():
        res = dns_query('dnssec-failed.org', 'A', '127.0.0.53', timeout=6)
        print(out.paint(out.codes[OK], '  DNS works%s.' % (
            ' and forged (bad DNSSEC) answers are rejected' if res.get('rcode_name') == 'SERVFAIL' else '')))
        return True
    print(out.paint(out.codes[RISK], '  DNS stopped working, so this change is being undone right away.'))
    _rollback(ch, mark_u, mark_a)
    print('  ' + ('DNS works again.' if _dns_works() else 'DNS still fails: check your network connection.'))
    return False


def fix_dns(ch, out):
    print(out.bold('\n• DNS (encryption, forged-answer protection, LLMNR)'))
    if not uses_resolved():
        dns_apply(ch, out)
        return
    st = dns_state()
    mode = llmnr = None
    if not st['encrypted']:
        print(out.wrap('Your DNS lookups are not encrypted, and your router\'s DNS server may not check DNSSEC '
                       'signatures. Encrypted DNS (DNS-over-TLS) to a provider that checks signatures fixes both. '
                       'Local names served only by your router (like "printer.home") may stop resolving.', '  '))
        if ch.ask('Use encrypted DNS for everything?', True):
            mode = 'encrypt'
    else:
        print('  DNS is already encrypted.')
    if st['llmnr'] and ch.ask('Turn off LLMNR (name lookups answered by any device on the network)?', True):
        llmnr = False
    if mode or llmnr is not None:
        dns_apply(ch, out, mode, llmnr=llmnr)


def cmd_dns(argv, out):
    ap = argparse.ArgumentParser(prog='%s dns' % PROG, description='See and change how this computer looks up names.')
    sub = ap.add_subparsers(dest='action')
    sub.add_parser('status', help='show the current DNS settings (default)')
    p = sub.add_parser('encrypt', help='use encrypted DNS (DNS-over-TLS) for everything')
    p.add_argument('--provider', choices=[n.lower() for n, _, _ in DOT_PROVIDERS],
                   help='default: the first one reachable (cloudflare, quad9, google)')
    sub.add_parser('plain', help='go back to the DNS servers your network hands out (unencrypted)')
    p = sub.add_parser('llmnr', help='turn LLMNR name lookups on or off')
    p.add_argument('state', choices=['on', 'off'])
    for name in ('encrypt', 'plain', 'llmnr'):
        sp = sub.choices[name]
        sp.add_argument('--yes', '-y', action='store_true', help=argparse.SUPPRESS)
        sp.add_argument('--dry-run', action='store_true', help='only show what would be done')
    args = ap.parse_args(argv)
    if args.action in (None, 'status'):
        st = dns_state()
        print(out.bold('DNS'))
        if not st['resolved']:
            print('  Managed outside systemd-resolved. Servers: %s' % (', '.join(st['servers']) or 'unknown'))
            return 0
        print('  Encrypted (DNS-over-TLS): %s%s' % (
            out.paint(out.codes[OK], 'yes') if st['encrypted'] else out.paint(out.codes[WARN], 'no'),
            ' via %s (set by networkScout)' % st['provider'] if st['ours'] and st['provider'] else ''))
        print('  Servers: %s%s' % (', '.join(st['servers']) or 'none', '; in use: %s' % st['current'] if st['current'] else ''))
        print('  LLMNR: %s' % ('on' if st['llmnr'] else 'off'))
        res = dns_query('dnssec-failed.org', 'A', '127.0.0.53', timeout=6)
        print('  Forged (bad DNSSEC) answers: %s' % ('rejected' if res.get('rcode_name') == 'SERVFAIL' else
                                                    ('ACCEPTED' if dns_values(res, 'A') else 'could not test')))
        print(out.dim('\nChange: %s dns encrypt [--provider quad9] | %s dns plain | %s dns llmnr on|off'
                      % (PROG, PROG, PROG)))
        return 0
    if not args.dry_run and not become_root(['dns'] + argv):
        return 1
    ch = Changer(out, args.yes, args.dry_run, label='dns')
    if args.action == 'encrypt':
        ok = dns_apply(ch, out, 'encrypt', provider=args.provider)
    elif args.action == 'plain':
        ok = dns_apply(ch, out, 'plain')
    else:
        ok = dns_apply(ch, out, None, llmnr=(args.state == 'on'))
    path = ch.finish()
    if path:
        print('  Undo: sudo sh %s' % path)
    return 0 if ok else 1


def fix_sysctl(ch, out):
    bad = []
    for key, good, _level, text, rec in SYSCTLS:
        val = read('/proc/sys/' + key.replace('.', '/'))
        if val is not None and val.strip() not in good:
            bad.append((key, val.strip(), rec, text))
    if not bad:
        return
    print(out.bold('\n• Optional kernel hardening'))
    for key, val, rec, text in bad:
        print('  %s: %s -> %s (%s)' % (key, val, rec, text))
    print(out.wrap('Optional. ptrace_scope=1 can stop some debuggers, game trainers or anti-cheat tools from '
                   'attaching to other programs.', '  '))
    if ch.ask('Apply these stricter settings?', False):
        ch.write_file('/etc/sysctl.d/60-networkscout-hardening.conf',
                      '# Written by networkScout on %s. Delete this file and reboot to undo.\n' % ch.stamp +
                      ''.join('%s = %s\n' % (k, r) for k, _, r, _ in bad))
        ch.run(['sysctl', '--system'], quiet=True)
        ch.add_undo(['sysctl', '--system'], after=True)


def cmd_fix(argv, out):
    ap = argparse.ArgumentParser(prog='%s fix' % PROG,
                                 description='Fix the problems the check finds, asking before every change. '
                                             'Everything can be undone with the undo script it writes.')
    ap.add_argument('--yes', '-y', action='store_true', help='accept the recommended answer to every question')
    ap.add_argument('--dry-run', action='store_true', help='only show what would be done')
    ap.add_argument('--only', metavar='STEPS', help='comma-separated: updates,updater,certs,firewall,dns,sysctl')
    ap.add_argument('--pause', action='store_true', help='wait for Enter at the end (when started from the app)')
    args = ap.parse_args(argv)
    if not args.dry_run and not become_root(['fix'] + argv):
        return 1
    steps = set((args.only or 'updates,updater,certs,firewall,dns,sysctl').split(','))
    ch = Changer(out, args.yes, args.dry_run, label='fix')
    print(out.bold('%s fix' % NAME) + out.dim('  (asks before every change%s)' % ('; dry run: nothing is changed'
                                                                                 if args.dry_run else '')))
    if 'certs' in steps:
        fix_ca_anchors(ch, out)
    if 'firewall' in steps:
        fix_firewall(ch, out)
    if 'dns' in steps:
        fix_dns(ch, out)
    if 'updater' in steps:
        fix_auto_updater(ch, out)
    if 'sysctl' in steps:
        fix_sysctl(ch, out)          # optional: the recommended answer is "no"
    if 'updates' in steps:
        fix_updates(ch, out)
    path = ch.finish()
    print()
    if path:
        print(out.bold('Undo: ') + 'sudo sh %s' % path)
    print('Run "%s" again to check the result.' % PROG)
    if args.pause and sys.stdin.isatty():
        try:
            input('\nPress Enter to close...')
        except EOFError:
            pass
    return 0


# ======================================================================================
# summary, reports, main
# ======================================================================================

def summary(R, started):
    o = R.out
    counts = {l: sum(1 for f in R.findings if f['level'] == l) for l in (RISK, WARN, INFO, OK, SKIP)}
    print()
    print(o.bold('Summary'))
    print(o.dim('-------'))
    print('  %s  %s  %s  %s' % (o.paint(o.codes[RISK], '%d serious' % counts[RISK]),
                                o.paint(o.codes[WARN], '%d to improve' % counts[WARN]),
                                o.paint(o.codes[INFO], '%d for your information' % counts[INFO]),
                                o.paint(o.codes[OK], '%d fine' % counts[OK])))
    if counts[RISK]:
        verdict = o.paint(o.codes[RISK], 'Action needed: fix the serious items first.')
    elif counts[WARN]:
        verdict = o.paint(o.codes[WARN], 'Mostly fine, with some things worth improving.')
    else:
        verdict = o.paint(o.codes[OK], 'Looks good: no problems found.')
    print('  ' + verdict)
    todo = [f for f in R.findings if f['level'] in (RISK, WARN)]
    todo.sort(key=lambda f: RANK[f['level']])
    if todo:
        print()
        print(o.bold('  What to do, most important first:'))
        for i, f in enumerate(todo, 1):
            print('  %2d. %s %s' % (i, o.paint(o.codes[f['level']], o.sym[f['level']]), f['title']))
        print()
        print('  ' + o.bold('Fix them step by step: ') + '%s fix   (asks before every change; can be undone)' % PROG)
        print('  ' + o.bold('Control ports:          ') + '%s ports  (allow/block apps, open ports only for a while)' % PROG)
        print('  ' + o.bold('Firewall on/off/profile: ') + '%s firewall' % PROG)
    print()
    print(o.wrap(o.dim('This check looks for common problems and signs of tampering. It cannot prove that a computer '
                       'is free of malware. Took %d seconds.' % (time.time() - started)), '  '))
    return counts


def markdown_report(R, args, started):
    osr = os_release()
    lines = ['# networkScout security report', '',
             '- Computer: `%s` (%s)' % (socket.gethostname(), osr.get('PRETTY_NAME', 'Linux')),
             '- Date: %s' % datetime.datetime.now().strftime('%Y-%m-%d %H:%M'),
             '- Tool: %s %s, run as %s, online checks %s' % (NAME, VERSION, 'administrator' if is_root() else 'normal user',
                                                             'off' if args.offline else 'on'), '']
    label = {RISK: '✖ Serious', WARN: '! Improve', INFO: 'i Info', OK: '✔ Fine', SKIP: '– Skipped'}
    for key, title in SECTIONS:
        items = [f for f in R.findings if f['section'] == key]
        if not items:
            continue
        lines += ['## ' + title, '']
        for f in items:
            lines.append('### %s: %s' % (label[f['level']], f['title']))
            if f['detail']:
                lines += ['', '```text' if '\n    ' in f['detail'] else '', f['detail'], '```' if '\n    ' in f['detail'] else '']
            if f['fix'] and f['level'] in (RISK, WARN):
                lines += ['', '**What to do:**', '', '```text', f['fix'], '```']
            lines.append('')
    todo = sorted([f for f in R.findings if f['level'] in (RISK, WARN)], key=lambda f: RANK[f['level']])
    if todo:
        lines += ['## What to do, most important first', '']
        lines += ['%d. %s %s' % (i, label[f['level']], f['title']) for i, f in enumerate(todo, 1)]
    return '\n'.join(l for l in lines if l is not None) + '\n'


def make_output(no_color=False):
    enc = (getattr(sys.stdout, 'encoding', '') or '').lower()
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding=sys.stdout.encoding or 'utf-8',
                                      errors='replace', line_buffering=True)
    except (AttributeError, ValueError):
        pass
    color = sys.stdout.isatty() and not no_color and os.environ.get('TERM') != 'dumb' and 'NO_COLOR' not in os.environ
    return Output(color, 'utf' in enc)


def main(argv=None):
    """Entry point (also used by the pip/pipx `networkscout` command)."""
    try:
        return _main(argv)
    except KeyboardInterrupt:
        print('\nStopped.')
        return 130
    except BrokenPipeError:                      # output piped into "head" etc.
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except (OSError, ValueError):
            pass
        return 0


def _main(argv=None):
    if platform.system() != 'Linux':
        print('This tool only works on Linux.')
        return 3
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in ('fix', 'ports', 'firewall', 'dns'):
        out = make_output('--no-color' in argv)
        argv = [a for a in argv if a != '--no-color']
        return {'fix': cmd_fix, 'ports': cmd_ports, 'firewall': cmd_firewall, 'dns': cmd_dns}[argv[0]](argv[1:], out)
    if argv and argv[0] == 'check':
        argv = argv[1:]
    ap = argparse.ArgumentParser(
        prog=PROG, formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Read-only security and privacy self-check for Linux: system security, DNS leaks, '
                    'man-in-the-middle signs and open ports. Changes nothing on your computer.',
        epilog='Other commands:\n'
               '  %s fix               fix the problems found (asks first; can be undone)\n'
               '  %s ports             see open ports; allow/block apps; open ports only for a while\n'
               '  %s firewall          firewall on/off; profiles: public, home, work, drop, ...\n'
               '  %s dns               encrypted DNS on/off, LLMNR on/off\n'
               '                       (add --help to any of them)\n\n' % (PROG, PROG, PROG, PROG) +
               'Online checks contact:\n  - ' + '\n  - '.join(ONLINE_ENDPOINTS) +
               '\nUse --offline to skip them.\n\nExit code: 0 = fine, 1 = things to improve, 2 = serious problems.')
    ap.add_argument('--offline', action='store_true', help='skip every check that needs the internet')
    ap.add_argument('--only', metavar='SECTIONS', help='comma-separated: system,dns,mitm,network')
    ap.add_argument('--report', metavar='FILE', help='also save the results as a Markdown report')
    ap.add_argument('--save', action='store_true', help='save a Markdown report in ~/networkscout-reports/')
    ap.add_argument('--json', metavar='FILE', help='also save the results as JSON ("-" for stdout)')
    ap.add_argument('--verbose', '-v', action='store_true', help='show details for passed checks too')
    ap.add_argument('--no-color', action='store_true', help='plain output without colours')
    ap.add_argument('--no-baseline', action='store_true', help='do not read or update the change-tracking baseline')
    ap.add_argument('--pause', action='store_true', help='wait for Enter before closing (for desktop launchers)')
    ap.add_argument('--version', action='version', version='%s %s' % (PROG, VERSION))
    args = ap.parse_args(argv)

    out = make_output(args.no_color)
    R = Report(out, args.verbose)
    started = time.time()
    online = not args.offline
    only = set((args.only or 'system,dns,mitm,network').replace(' ', '').split(','))

    print(out.bold('%s %s' % (NAME, VERSION)) + out.dim('  (read-only: nothing on your computer is changed)'))
    who = 'administrator (full check)' if is_root() else 'normal user (run with sudo for a deeper check)'
    print(out.dim('Running as %s; online checks %s.' % (who, 'off' if args.offline else 'on (see --help for what is contacted)')))
    if in_container():
        print(out.paint(out.codes[WARN], 'Note: this is running inside a container, so results describe the container, '
                                         'not the computer it runs on.'))

    baseline = None if args.no_baseline else load_baseline()
    newbase = {'time': datetime.datetime.now().isoformat(timespec='seconds') if sys.version_info >= (3, 6) else ''}
    try:
        listeners = listening_sockets()
    except Exception:
        listeners = []

    jobs = [('system', lambda: section_system(R, online, listeners)),
            ('dns', lambda: section_dns(R, online, listeners)),
            ('mitm', lambda: section_mitm(R, online, baseline, newbase)),
            ('network', lambda: section_network(R, online, listeners, baseline, newbase))]
    titles = dict(SECTIONS)
    for key, job in jobs:
        if key not in only:
            continue
        R.start(key, titles[key])
        try:
            job()
        except KeyboardInterrupt:
            raise
        except Exception as e:                       # one broken check must not stop the others
            R.add(SKIP, 'Part of this section could not run (%s: %s)' % (type(e).__name__, str(e)[:100]))

    if baseline and baseline.get('time'):
        print(out.dim('\nCompared with the previous check from %s (baseline: %s).' % (baseline['time'], baseline_path())))
    counts = summary(R, started)

    if not args.no_baseline and only >= {'mitm', 'network'}:
        save_baseline(newbase)
    report_path = args.report
    if args.save and not report_path:
        u = target_user()
        report_path = os.path.join(u.pw_dir, 'networkscout-reports',
                                   'report-%s.md' % datetime.datetime.now().strftime('%Y%m%d-%H%M'))
    if report_path:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(report_path)), exist_ok=True)
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(markdown_report(R, args, started))
            print('  Report saved: ' + report_path)
        except OSError as e:
            print('  Could not save the report: %s' % e)
    if args.json:
        data = {'tool': PROG, 'version': VERSION, 'time': newbase['time'], 'root': is_root(), 'online': online,
                'findings': R.findings, 'counts': counts}
        text = json.dumps(data, indent=1, default=str)
        if args.json == '-':
            print(text)
        else:
            with open(args.json, 'w', encoding='utf-8') as f:
                f.write(text)
            print('  JSON saved: ' + args.json)
    if args.pause and sys.stdin.isatty():
        try:
            input('\nPress Enter to close...')
        except EOFError:
            pass
    return 2 if counts[RISK] else (1 if counts[WARN] else 0)


if __name__ == '__main__':
    sys.exit(main())
