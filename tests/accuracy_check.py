#!/usr/bin/env python3
"""
Accuracy check: compares what networkScout reports with the same facts read independently through the
system's own tools (firewall-cmd, ss, resolvectl, rpm-ostree, getenforce, mokutil, sysctl, an outside
IP service). Read-only. Prints one line per comparison; exit code 1 if anything disagrees.

Run:  python3 tests/accuracy_check.py
"""
import contextlib
import io
import json
import os
import re
import subprocess
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import networkscout as ns  # noqa: E402

results = []


def sh(cmd, timeout=60):
    try:
        return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout,
                              encoding='utf-8', errors='replace').stdout.strip()
    except subprocess.TimeoutExpired:
        return ''


def compare(what, scout, system):
    ok = scout == system
    results.append((ok, what, scout, system))
    print('%s  %-34s networkScout: %-28s system: %s' % ('MATCH   ' if ok else 'MISMATCH', what, str(scout)[:28],
                                                          str(system)[:60]))


def quiet(fn, *a):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*a)


# --- firewall ----------------------------------------------------------------------------
fw = ns.firewall_state()
dev = (ns.default_routes_v4() or [{}])[0].get('iface')
if fw['tool'] == 'firewalld':
    compare('firewall running', fw['active'], sh('firewall-cmd --state') == 'running')
    compare('firewall zone of ' + str(dev), fw['zone'], sh('firewall-cmd --get-zone-of-interface=%s' % dev))
    info = ns.fwd_zone_info(fw['zone'])
    compare('zone services (runtime)', sorted(info['services']),
            sorted(sh('firewall-cmd --zone=%s --list-services' % fw['zone']).split()))
    compare('zone ports (runtime)', sorted(info['ports']),
            sorted(sh('firewall-cmd --zone=%s --list-ports' % fw['zone']).split()))
    compare('wide port ranges', bool(fw['wide']), bool(re.search(r'\d+-\d+/', sh('firewall-cmd --zone=%s --list-ports' % fw['zone']))))

# --- open ports ----------------------------------------------------------------------------
rng = [int(x) for x in ns.read('/proc/sys/net/ipv4/ip_local_port_range').split()]
system_exposed = set()
for line in sh('ss -H -tuln').splitlines():
    f = line.split()
    local = f[4]
    host, port = local.rsplit(':', 1)
    host = host.split('%')[0].strip('[]')
    if host.startswith('127.') or host == '::1' or host.startswith('fe80'):
        continue
    port = int(port)
    if f[0] == 'udp' and rng[0] <= port <= rng[1]:
        continue
    system_exposed.add((f[0], port))
scout_exposed = set((s['proto'], s['port']) for s in ns.listening_sockets()
                    if s['scope'] in ('all', 'lan', 'public') and not s['ephemeral'])
compare('ports open to the network', sorted(scout_exposed), sorted(system_exposed))

# --- DNS -----------------------------------------------------------------------------------
if ns.uses_resolved():
    st = ns.dns_state()
    rs = sh('resolvectl status')
    compare('DNS-over-TLS on', st['encrypted'], '+DNSOverTLS' in rs.split('Link')[0])
    compare('LLMNR on', st['llmnr'], not re.search(r'-LLMNR\b|LLMNR=no', rs.split('Link')[0]))
    servers = []
    for m in re.finditer(r'DNS Servers:\s*(.+(?:\n\s{10,}\S+)*)', rs):
        for s in m.group(1).split():
            s = s.split('#')[0]
            if s not in servers:
                servers.append(s)
    compare('DNS servers', sorted(st['servers']), sorted(servers))
    res = ns.dns_query('dnssec-failed.org', 'A', '127.0.0.53', timeout=6)
    dig = sh('dig +time=6 dnssec-failed.org A | grep -o "status: [A-Z]*"').replace('status: ', '')
    if dig:
        compare('forged DNSSEC answer status', res.get('rcode_name'), dig)

# --- updates (rpm-ostree) ----------------------------------------------------------------------
if ns.package_system() == 'rpm-ostree':
    deps = json.loads(sh('rpm-ostree status --json'))['deployments']
    staged = any(d.get('staged') for d in deps)
    R = ns.Report(ns.Output(False, True), False)
    R.section = 'system'
    quiet(ns.check_updates, R, False)
    scout_staged = any('already downloaded' in f['title'] for f in R.findings)
    compare('OS update staged', scout_staged, staged)

# --- certificates, Secure Boot, SELinux, sysctl -----------------------------------------------------
anchors = [a for a in ns.local_ca_anchors() if not a['shipped_by_os']]
system_anchors = sh('ls /etc/pki/ca-trust/source/anchors/ /usr/local/share/ca-certificates/ '
                    '/etc/ca-certificates/trust-source/anchors/ /etc/pki/trust/anchors/ 2>/dev/null | grep -vE ":$|^$"')
compare('extra root certificates', len(anchors), len([l for l in system_anchors.splitlines() if l.strip()]))
sb = sh('mokutil --sb-state 2>/dev/null')
if sb:
    compare('Secure Boot', ns.secure_boot_state(), 'on' if 'enabled' in sb else 'off')
ge = sh('getenforce 2>/dev/null')
if ge:
    compare('SELinux enforcing', (ns.read('/sys/fs/selinux/enforce') or '').strip() == '1', ge == 'Enforcing')
for key in ('kernel.yama.ptrace_scope', 'net.ipv4.tcp_timestamps', 'kernel.randomize_va_space'):
    compare('sysctl ' + key, (ns.read('/proc/sys/' + key.replace('.', '/')) or '').strip(), sh('sysctl -n ' + key))

# --- public IP ---------------------------------------------------------------------------------
try:
    outside = urllib.request.urlopen('https://api.ipify.org', timeout=10).read().decode().strip()
    trace = ns.cloudflare_trace(4) or {}
    compare('public IPv4 address', trace.get('ip'), outside)
except Exception as e:
    print('SKIPPED   public IPv4 address (%s)' % e)

bad = [r for r in results if not r[0]]
print('\n%d comparisons, %d match, %d mismatch' % (len(results), len(results) - len(bad), len(bad)))
sys.exit(1 if bad else 0)
