#!/usr/bin/env python3
"""
networkScout core tests: pure functions, the DNS client and every detector, using simulated
attack/problem scenarios (fake system data), so nothing on the computer is changed.

Run:  python3 -m unittest discover -s tests -v
Set NETWORKSCOUT_TEST_OFFLINE=1 to skip the tests that need the internet.
"""
import contextlib
import io
import json
import os
import pwd
import shutil
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import networkscout as ns  # noqa: E402

OFFLINE = os.environ.get('NETWORKSCOUT_TEST_OFFLINE') == '1'
REAL_READ = ns.read


def new_report():
    R = ns.Report(ns.Output(False, True), False)
    R.section = 'test'
    return R


def run(fn, *args, **kw):
    """Run a check with its printing silenced; returns the Report."""
    R = kw.pop('R', None) or new_report()
    with contextlib.redirect_stdout(io.StringIO()):
        fn(R, *args)
    return R


def found(R, text, level=None):
    """Findings whose title or detail contains text (and optionally have this level)."""
    t = text.lower()
    return [f for f in R.findings if t in (f['title'] + ' ' + f['detail']).lower()
            and (level is None or f['level'] == level)]


def fake_read(mapping):
    def _read(path, default=None):
        if path in mapping:
            return mapping[path]
        return REAL_READ(path, default)
    return _read


def listener(port, proto='tcp', scope='all', process='', unit='', ephemeral=False, addr='0.0.0.0'):
    return {'proto': proto, 'addr': addr, 'port': port, 'scope': scope, 'process': process, 'pid': None,
            'unit': unit, 'user': 'root', 'ephemeral': ephemeral}


# ======================================================================================
class PureFunctions(unittest.TestCase):

    def test_hex_addr(self):
        self.assertEqual(ns._hex_addr('0100007F:0035'), ('127.0.0.1', 53))
        self.assertEqual(ns._hex_addr('00000000000000000000000001000000:1F90'), ('::1', 8080))
        self.assertEqual(ns._hex_addr('0000000000000000FFFF00000100007F:0050'), ('127.0.0.1', 80))

    def test_parse_duration(self):
        self.assertEqual(ns.parse_duration('30m'), (1800, '30m'))
        self.assertEqual(ns.parse_duration('2h'), (7200, '2h'))
        self.assertEqual(ns.parse_duration('90s'), (90, '90s'))
        self.assertEqual(ns.parse_duration('15'), (900, '15m'))
        self.assertEqual(ns.parse_duration('1d'), (86400, '24h'))      # firewalld has no "d"
        for bad in ('abc', '-5m', '1w', ''):
            with self.assertRaises(ValueError):
                ns.parse_duration(bad)

    def test_port_specs_cover(self):
        self.assertTrue(ns.port_specs_cover(['1025-65535/tcp'], 'tcp', 51413))
        self.assertFalse(ns.port_specs_cover(['1025-65535/tcp'], 'udp', 51413))
        self.assertFalse(ns.port_specs_cover(['1025-65535/tcp'], 'tcp', 22))
        self.assertTrue(ns.port_specs_cover(['22/tcp', '631/tcp'], 'tcp', 631))
        self.assertFalse(ns.port_specs_cover([], 'tcp', 80))

    def test_flag_parsing(self):
        p = 'LLMNR=resolve -mDNS +DNSOverTLS DNSSEC=no/unsupported'
        self.assertEqual(ns._flag(p, 'DNSOverTLS'), 'yes')
        self.assertEqual(ns._flag(p, 'mDNS'), 'no')
        self.assertEqual(ns._flag(p, 'LLMNR'), 'resolve')
        self.assertEqual(ns._flag(p, 'DNSSEC'), 'no')
        self.assertIsNone(ns._flag('', 'LLMNR'))

    def test_known_provider(self):
        self.assertEqual(ns.known_provider('8.8.8.8'), 'Google Public DNS')
        self.assertEqual(ns.known_provider('2606:4700:4700::1111'), 'Cloudflare DNS')
        self.assertEqual(ns.known_provider('9.9.9.9'), 'Quad9')
        self.assertEqual(ns.known_provider('74.125.178.148'), 'Google Public DNS')
        self.assertIsNone(ns.known_provider('192.168.1.1'))
        self.assertIsNone(ns.known_provider('not an ip'))

    def test_unit_from_cgroup(self):
        self.assertEqual(ns.unit_from_cgroup('/system.slice/avahi-daemon.service'), 'avahi-daemon')
        self.assertEqual(ns.unit_from_cgroup('/system.slice/system-cups.slice/cups.service'), 'cups')
        self.assertIn('kdeconnect', ns.unit_from_cgroup(
            '/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.kde.kdeconnect.daemon@autostart.service'))
        self.assertEqual(ns.unit_from_cgroup(''), '')

    def test_fwd_ops(self):
        cmds = ns.fwd_ops('add', 'home', [('service', 'ssh')])
        self.assertEqual(cmds, [['firewall-cmd', '--zone=home', '--add-service=ssh'],
                                ['firewall-cmd', '--permanent', '--zone=home', '--add-service=ssh']])
        cmds = ns.fwd_ops('add', 'home', [('port', '8080/tcp')], timeout='1h')
        self.assertEqual(cmds, [['firewall-cmd', '--zone=home', '--add-port=8080/tcp', '--timeout=1h']])
        cmds = ns.fwd_ops('remove', 'home', [('port', '8080/tcp')], timeout='1h')   # removal is never timed
        self.assertEqual(len(cmds), 2)
        cmds = ns.fwd_ops('add', 'public', [('port', '8080/tcp')], source='192.168.1.0/24')
        self.assertIn('family="ipv4" source address="192.168.1.0/24" port port="8080" protocol="tcp" accept', cmds[0][-1])
        cmds = ns.fwd_ops('add', 'public', [('service', 'ssh')], source='fd00::/8')
        self.assertIn('family="ipv6"', cmds[0][-1])

    def test_ufw_spec(self):
        self.assertEqual(ns.ufw_spec('6881-6889/udp'), '6881:6889/udp')
        self.assertEqual(ns.ufw_spec('22/tcp'), '22/tcp')

    def test_resolve_target(self):
        app = ns.resolve_target('Transmission', [])
        self.assertEqual(app['key'], 'transmission')
        self.assertIn('transmission-client', app['services'])
        self.assertEqual(ns.resolve_target('8080', [])['ports'], ['8080/tcp'])
        self.assertEqual(ns.resolve_target('6881-6889/udp', [])['ports'], ['6881-6889/udp'])
        mine = ns.resolve_target('myserver', [listener(9999, process='myserver')])
        self.assertEqual(mine['ports'], ['9999/tcp'])
        moved = ns.resolve_target('transmission', [listener(51999, process='transmission-gt')])
        self.assertIn('51999/tcp', moved['ports'])          # a changed peer port is picked up
        for bad in ('0', '70000', '10-5', 'nosuchapp'):
            with self.assertRaises(ValueError):
                ns.resolve_target(bad, [])

    def test_app_items_firewalld(self):
        app = ns.resolve_target('transmission', [listener(51999, process='transmission-gt')])
        svc = {'transmission-client': ('51413/tcp', '51413/udp'), 'bittorrent-lsd': ('6771/udp',)}
        with mock.patch.object(ns, 'fwd_known_services', return_value=frozenset(svc)), \
                mock.patch.object(ns, 'fwd_service_ports', side_effect=lambda s: svc[s]):
            items = ns.app_items(app, 'firewalld')
        self.assertIn(('service', 'transmission-client'), items)
        self.assertIn(('service', 'bittorrent-lsd'), items)
        self.assertIn(('port', '51999/tcp'), items)            # not covered by any service
        self.assertNotIn(('port', '51413/tcp'), items)         # covered by the service
        self.assertTrue(all(k == 'port' for k, _ in ns.app_items(app, 'ufw')))

    def test_parse_unit_show(self):
        text = ('Id=avahi-daemon.socket\nLoadState=loaded\nActiveState=active\nUnitFileState=enabled\n\n'
                'Id=ssh.service\nLoadState=not-found\nActiveState=inactive\nUnitFileState=\n')
        units = ns.parse_unit_show(text)
        self.assertEqual(units[0], {'id': 'avahi-daemon.socket', 'load': 'loaded', 'file': 'enabled', 'active': 'active'})
        self.assertEqual(units[1]['load'], 'not-found')
        self.assertEqual(ns.parse_unit_show(''), [])

    def test_service_stop_plan(self):
        def unit(i, f, a):
            return {'id': i, 'load': 'loaded', 'file': f, 'active': a}
        cmds, undo = ns.service_stop_plan([unit('a.socket', 'enabled', 'active'), unit('a.service', 'enabled', 'active')])
        self.assertEqual(cmds, [['systemctl', 'disable', '--now', 'a.socket', 'a.service']])
        self.assertEqual(undo, [['systemctl', 'enable', 'a.socket', 'a.service'],
                                ['systemctl', 'start', 'a.socket', 'a.service']])
        # running but not enabled (static): stopped now, started again by undo, never enabled by undo
        cmds, undo = ns.service_stop_plan([unit('b.service', 'static', 'active'), unit('c.service', 'disabled', 'inactive')])
        self.assertEqual(cmds, [['systemctl', 'stop', 'b.service']])
        self.assertEqual(undo, [['systemctl', 'start', 'b.service']])
        # enabled but not running: disabled, and undo does not start it
        cmds, undo = ns.service_stop_plan([unit('d.service', 'enabled', 'failed')])
        self.assertEqual(undo, [['systemctl', 'enable', 'd.service']])
        self.assertEqual(ns.service_stop_plan([unit('e.service', 'disabled', 'inactive')]), ([], []))

    def test_human_texts(self):
        self.assertEqual(ns.plural(1, 'port'), '1 port')
        self.assertEqual(ns.plural(3, 'entry', 'entries'), '3 entries')
        self.assertEqual(ns.human_age(3 * 86400 + 5), '3 days')
        self.assertEqual(ns.human_age(5 * 3600), '5 hours')
        self.assertEqual(ns.human_age(90), '1 minute')
        self.assertEqual(ns.human_age(300), '5 minutes')
        self.assertEqual(ns.human_age(1.5 * 86400), '36 hours')

    def test_dns_name_encoding(self):
        self.assertEqual(ns._encode_name('example.com'), b'\x07example\x03com\x00')
        self.assertEqual(ns._encode_name('example.com.'), b'\x07example\x03com\x00')

    def test_cert_parsing(self):
        bundle = next((p for p in ('/etc/pki/tls/certs/ca-bundle.crt', '/etc/ssl/certs/ca-certificates.crt',
                                   '/etc/ssl/cert.pem', '/etc/ssl/ca-bundle.pem') if os.path.exists(p)), None)
        if not bundle:
            self.skipTest('no system CA bundle')
        certs = ns.certs_in_file(bundle)
        self.assertGreater(len(certs), 50)
        self.assertTrue(all(len(c['sha256']) == 64 for c in certs))
        self.assertTrue(any(c.get('subject_o') or c.get('subject_cn') for c in certs))


# ======================================================================================
@unittest.skipIf(OFFLINE, 'needs the internet')
class DnsClientLive(unittest.TestCase):

    def test_a_aaaa(self):
        r = ns.dns_query('one.one.one.one', 'A', '1.1.1.1', timeout=4)
        self.assertIn('1.1.1.1', ns.dns_values(r, 'A'))
        r = ns.dns_query('one.one.one.one', 'AAAA', '1.1.1.1', timeout=4)
        self.assertIn('2606:4700:4700::1111', ns.dns_values(r, 'AAAA'))

    def test_chaos_txt_and_nxdomain(self):
        r = ns.dns_query('whoami.cloudflare', 'TXT', '1.1.1.1', timeout=4, qclass=3)
        self.assertTrue(ns.ip_obj(ns.dns_values(r, 'TXT')[0].strip('"')))
        r = ns.dns_query('lsc-%d-nonexistent.com' % time.time(), 'A', '1.1.1.1', timeout=4)
        self.assertEqual(r['rcode_name'], 'NXDOMAIN')

    def test_tcp_and_system_resolver(self):
        r = ns.dns_query('example.com', 'A', '1.1.1.1', timeout=4, tcp=True)
        self.assertTrue(ns.dns_values(r, 'A'))
        ns_list, _ = ns.resolv_conf()
        r = ns.dns_query('example.com', 'A', ns_list[0] if ns_list else '127.0.0.53', timeout=4)
        self.assertTrue(ns.dns_values(r, 'A'))

    def test_timeout(self):
        t = time.time()
        r = ns.dns_query('example.com', 'A', '192.0.2.1', timeout=1)    # documentation address: no answer
        self.assertIn('error', r)
        self.assertLess(time.time() - t, 3)


# ======================================================================================
class SystemScenarios(unittest.TestCase):

    def test_aslr_disabled_is_serious(self):
        with mock.patch.object(ns, 'read', fake_read({'/proc/sys/kernel/randomize_va_space': '0\n'})):
            R = run(ns.check_sysctls)
        self.assertTrue(found(R, 'randomize_va_space', ns.RISK))

    def test_ld_preload_rootkit_sign(self):
        with mock.patch.object(ns, 'read', fake_read({'/etc/ld.so.preload': '/usr/lib/libevil.so\n'})):
            R = run(ns.check_integrity)
        self.assertTrue(found(R, 'ld.so.preload', ns.RISK))

    def test_unsigned_kernel_module(self):
        with mock.patch.object(ns, 'read', fake_read({'/proc/sys/kernel/tainted': str(1 << 13)})):
            R = run(ns.check_integrity)
        self.assertTrue(found(R, 'UNSIGNED', ns.WARN))

    def test_second_uid0_account(self):
        users = [pwd.struct_passwd(('root', 'x', 0, 0, '', '/root', '/bin/bash')),
                 pwd.struct_passwd(('toor', 'x', 0, 0, '', '/root', '/bin/bash'))]
        with mock.patch.object(ns.pwd, 'getpwall', return_value=users):
            R = run(ns.check_accounts)
        self.assertTrue(found(R, 'toor', ns.RISK))

    def test_ssh_root_password_login(self):
        with mock.patch.object(ns, '_sshd_settings', return_value={'permitrootlogin': 'yes',
                                                                  'passwordauthentication': 'yes'}):
            R = run(ns.check_ssh, [listener(22)])
        self.assertTrue(found(R, 'SSH', ns.RISK))
        with mock.patch.object(ns, '_sshd_settings', return_value={'permitrootlogin': 'no',
                                                                  'passwordauthentication': 'no'}):
            R = run(ns.check_ssh, [listener(22)])
        self.assertTrue(found(R, 'key-based', ns.INFO))

    def test_selinux_permissive(self):
        with mock.patch.object(ns, 'read', fake_read({'/sys/fs/selinux/enforce': '0'})), \
                mock.patch.object(ns, 'secure_boot_state', return_value='on'):
            R = run(ns.check_mac_lockdown)
        self.assertTrue(found(R, 'permissive', ns.WARN))

    def test_unencrypted_laptop_disk(self):
        real_glob = ns.glob.glob
        with mock.patch.object(ns, 'mounts', return_value={'/home': {'fstype': 'ext4', 'source': '/dev/sda3'},
                                                           '/': {'fstype': 'ext4', 'source': '/dev/sda2'}}), \
                mock.patch.object(ns, '_dm_is_crypt', return_value=False), \
                mock.patch.object(ns.glob, 'glob', side_effect=lambda p: ['/x/BAT0'] if 'BAT' in p else real_glob(p)):
            R = run(ns.check_encryption)
        self.assertTrue(found(R, 'not encrypted', ns.WARN))

    def test_cpu_vulnerable(self):
        real_glob = ns.glob.glob
        path = '/sys/devices/system/cpu/vulnerabilities/spectre_v2'
        with mock.patch.object(ns.glob, 'glob', side_effect=lambda p: [path] if 'vulnerabilities' in p else real_glob(p)), \
                mock.patch.object(ns, 'read', fake_read({path: 'Vulnerable: no microcode'})):
            R = run(ns.check_cpu)
        self.assertTrue(found(R, 'spectre_v2', ns.WARN))

    def test_rpm_ostree_staged_update(self):
        status = {'deployments': [{'booted': True, 'version': '44.20260929', 'timestamp': time.time(),
                                   'container-image-reference': 'ostree-image-signed:docker://x/y:stable'},
                                  {'staged': True, 'version': '44.20261012'}]}
        with mock.patch.object(ns, 'package_system', return_value='rpm-ostree'), \
                mock.patch.object(ns, 'run', return_value=(0, json.dumps(status), '')):
            R = run(ns.check_updates, False)
        self.assertTrue(found(R, 'already downloaded', ns.WARN))

    def test_rpm_ostree_newer_image(self):
        status = {'deployments': [{'booted': True, 'version': '44.20260929', 'timestamp': time.time(),
                                   'container-image-reference': 'ostree-image-signed:docker://x/y:stable',
                                   'container-image-reference-digest': 'sha256:old'}]}
        remote = {'Digest': 'sha256:new', 'Labels': {'org.opencontainers.image.version': '44.20261012'}}

        def fake_run(cmd, timeout=20):
            return (0, json.dumps(status if cmd[0] == 'rpm-ostree' else remote), '')
        with mock.patch.object(ns, 'package_system', return_value='rpm-ostree'), \
                mock.patch.object(ns, 'run', side_effect=fake_run), mock.patch.object(ns, 'which', return_value='/x'):
            R = run(ns.check_updates, True)
        self.assertTrue(found(R, '44.20261012', ns.WARN))
        self.assertIn('days', found(R, '44.20261012')[0]['detail'])       # age comes from the version date

    def test_gentoo_tree_age(self):
        old = 'Mon, 01 Jun 2026 00:45:01 +0000'
        recent = time.strftime('%a, %d %b %Y %H:%M:%S +0000', time.gmtime(time.time() - 86400))
        for stamp, level in ((old, ns.WARN), (recent, ns.INFO)):
            with mock.patch.object(ns, 'package_system', return_value='portage'), \
                    mock.patch.object(ns, 'read', fake_read({'/var/db/repos/gentoo/metadata/timestamp.chk': stamp + '\n'})):
                R = run(ns.check_updates, False)
            self.assertTrue(found(R, 'Gentoo package tree', level), stamp)

    def test_dnf_updates(self):
        def fake_run(cmd, timeout=20):
            if cmd[0] == 'dnf':
                return (100, 'openssl.x86_64  3.2.4-1.fc44  updates\nvim.x86_64  9.1-2.fc44  updates\n', '')
            return None
        with mock.patch.object(ns, 'package_system', return_value='dnf'), mock.patch.object(ns, 'run', side_effect=fake_run):
            R = run(ns.check_updates, True)
        self.assertTrue(found(R, '2 updates', ns.WARN))

    def test_apt_security_updates(self):
        out = ('Listing...\nopenssl/noble-security 3.0.13 amd64 [upgradable from: 3.0.12]\n'
               'vim/noble-updates 9.1 amd64 [upgradable from: 9.0]\n')
        with mock.patch.object(ns, 'package_system', return_value='apt'), \
                mock.patch.object(ns, 'run', return_value=(0, out, '')):
            R = run(ns.check_updates, False)
        self.assertTrue(found(R, 'security update', ns.RISK))


# ======================================================================================
class DnsScenarios(unittest.TestCase):

    def fake_dns(self, overrides):
        def _q(name, qtype='A', server='127.0.0.53', timeout=3.0, qclass=1, tcp=False, port=53):
            for (n, t), res in overrides.items():
                if (n == name or (n.endswith('*') and name.startswith(n[:-1]))) and t == qtype:
                    return res
            return {'rcode': 0, 'rcode_name': 'NOERROR', 'answers': [], 'ad': False}
        return _q

    def run_integrity(self, overrides, online=False, hosts=None, facts=None):
        R = new_report()
        R.facts['dns'] = {'upstream': ['192.0.2.53']}
        R.facts.update(facts or {})
        patches = [mock.patch.object(ns, 'dns_query', side_effect=self.fake_dns(overrides)),
                   mock.patch.object(ns, 'public_ip', return_value=None)]
        if hosts is not None:
            patches.append(mock.patch.object(ns, 'read', fake_read({'/etc/hosts': hosts})))
        with contextlib.ExitStack() as st:
            for p in patches:
                st.enter_context(p)
            run(ns.check_dns_integrity, online, R=R)
        return R

    def test_hosts_redirect(self):
        R = self.run_integrity({}, hosts='127.0.0.1 localhost\n6.6.6.6 www.paypal.com\n')
        self.assertTrue(found(R, 'paypal', ns.RISK))

    def test_hosts_adblock_list(self):
        R = self.run_integrity({}, hosts='\n'.join('0.0.0.0 ads%d.example' % i for i in range(30)))
        self.assertTrue(found(R, 'ad/tracker block list', ns.INFO))
        self.assertFalse(found(R, 'hosts', ns.RISK))

    def test_wrong_answers_for_known_names(self):
        R = self.run_integrity({('one.one.one.one', 'A'): {'rcode_name': 'NOERROR', 'answers': [('A', '6.6.6.6')]}})
        self.assertTrue(found(R, 'wrong answers', ns.RISK))

    def test_nxdomain_hijacking(self):
        R = self.run_integrity({('lsc-*', 'A'): {'rcode_name': 'NOERROR', 'answers': [('A', '198.51.100.7')]}})
        self.assertTrue(found(R, 'hijacking', ns.WARN))

    def test_no_dnssec_validation(self):
        R = self.run_integrity({('dnssec-failed.org', 'A'): {'rcode_name': 'NOERROR', 'answers': [('A', '1.2.3.4')]},
                                ('lsc-*', 'A'): {'rcode_name': 'NXDOMAIN', 'answers': []}})
        self.assertTrue(found(R, 'DNSSEC', ns.INFO))

    def test_dns_interception(self):
        over = {('whoami.cloudflare', 'TXT'): {'rcode_name': 'NOERROR', 'answers': [('TXT', '"198.51.100.9"')]},
                ('o-o.myaddr.l.google.com', 'TXT'): {'rcode_name': 'NOERROR', 'answers': [('TXT', '"198.51.100.9"')]},
                ('lsc-*', 'A'): {'rcode_name': 'NXDOMAIN', 'answers': []}}
        R = self.run_integrity(over, online=True, facts={'public_ip': {'v4': '203.0.113.5', 'v6': None}})
        self.assertTrue(found(R, 'intercepted', ns.RISK))

    def test_no_interception(self):
        over = {('whoami.cloudflare', 'TXT'): {'rcode_name': 'NOERROR', 'answers': [('TXT', '"203.0.113.5"')]},
                ('o-o.myaddr.l.google.com', 'TXT'): {'rcode_name': 'NOERROR', 'answers': [('TXT', '"172.217.1.1"')]},
                ('example.com', 'A'): {'rcode_name': 'NOERROR', 'answers': [('A', '93.184.215.14')]},
                ('lsc-*', 'A'): {'rcode_name': 'NXDOMAIN', 'answers': []}}
        R = self.run_integrity(over, online=True, facts={'public_ip': {'v4': '203.0.113.5', 'v6': None}})
        self.assertTrue(found(R, 'No DNS interception', ns.OK))
        self.assertFalse(found(R, 'intercepted', ns.RISK))

    def run_check_dns(self, vpn, dev_for_dns, protocols='-DNSOverTLS'):
        rs = {'global': {'Protocols': protocols}, 'links': [{'name': 'eth0', 'DNS Servers': '192.168.1.1'}]}
        with mock.patch.object(ns, 'resolv_conf', return_value=(['127.0.0.53'], [])), \
                mock.patch.object(ns, 'which', return_value='/usr/bin/resolvectl'), \
                mock.patch.object(ns, 'resolved_status', return_value=rs), \
                mock.patch.object(ns, 'active_vpn', return_value=vpn), \
                mock.patch.object(ns, 'route_dev', return_value=dev_for_dns):
            return run(ns.check_dns, False, [])

    def test_dns_leak_around_vpn(self):
        R = self.run_check_dns('wg0', 'eth0')
        self.assertTrue(found(R, 'DNS leak', ns.RISK))

    def test_dns_inside_vpn(self):
        R = self.run_check_dns('wg0', 'wg0')
        self.assertFalse(found(R, 'DNS leak', ns.RISK))

    def test_unencrypted_and_encrypted_dns(self):
        self.assertTrue(found(self.run_check_dns(None, 'eth0'), 'not encrypted', ns.WARN))
        self.assertTrue(found(self.run_check_dns(None, 'eth0', '+DNSOverTLS'), 'encrypted (DNS-over-TLS)', ns.OK))


# ======================================================================================
class MitmScenarios(unittest.TestCase):

    def router(self, arp, v6=(), baseline=None):
        newbase = {}
        with mock.patch.object(ns, 'default_routes_v4', return_value=[{'iface': 'eth0', 'gateway': '192.168.1.1', 'metric': 100}]), \
                mock.patch.object(ns, 'default_routes_v6', return_value=list(v6)), \
                mock.patch.object(ns, 'arp_table', return_value=arp), \
                mock.patch.object(ns, 'ipv6_router_macs', return_value={}):
            return run(ns.check_router, baseline, newbase), newbase

    def test_arp_spoofing(self):
        arp = [{'ip': '192.168.1.1', 'mac': 'aa:bb:cc:dd:ee:ff', 'iface': 'eth0'},
               {'ip': '192.168.1.66', 'mac': 'aa:bb:cc:dd:ee:ff', 'iface': 'eth0'}]
        R, _ = self.router(arp)
        self.assertTrue(found(R, 'ARP spoofing', ns.RISK))

    def test_router_mac_changed_since_last_run(self):
        arp = [{'ip': '192.168.1.1', 'mac': 'aa:bb:cc:dd:ee:ff', 'iface': 'eth0'}]
        R, newbase = self.router(arp, baseline={'routers': {'192.168.1.1@eth0': '11:22:33:44:55:66'}})
        self.assertTrue(found(R, 'different hardware address', ns.WARN))
        self.assertEqual(newbase['routers']['192.168.1.1@eth0'], 'aa:bb:cc:dd:ee:ff')

    def test_rogue_ipv6_router(self):
        arp = [{'ip': '192.168.1.1', 'mac': 'aa:bb:cc:dd:ee:ff', 'iface': 'eth0'}]
        v6 = [{'iface': 'eth0', 'gateway': 'fe80::1', 'metric': 100}, {'iface': 'eth0', 'gateway': 'fe80::bad', 'metric': 100}]
        R, _ = self.router(arp, v6)
        self.assertTrue(found(R, 'More than one IPv6 router', ns.WARN))

    def test_normal_router(self):
        R, _ = self.router([{'ip': '192.168.1.1', 'mac': 'aa:bb:cc:dd:ee:ff', 'iface': 'eth0'}])
        self.assertTrue(found(R, 'Router identity looks normal', ns.OK))

    def test_proxy_in_environment(self):
        with mock.patch.dict(os.environ, {'https_proxy': 'http://10.6.6.6:3128'}):
            R = run(ns.check_proxies)
        self.assertTrue(found(R, '10.6.6.6', ns.WARN))

    def anchor(self, org='Fortinet', cn='FortiGate CA', shipped=False):
        return {'sha256': 'ab' * 32, 'subject_cn': cn, 'subject_o': org, 'path': '/etc/pki/ca-trust/source/anchors/x.crt',
                'mtime': '2026-01-01', 'not_after': 'Jan 1 2030', 'shipped_by_os': shipped, 'sct': False}

    def test_extra_root_certificate(self):
        with mock.patch.object(ns, 'local_ca_anchors', return_value=[self.anchor()]):
            R = run(ns.check_ca_anchors, {'ca_anchors': []}, {})
        f = found(R, 'Fortinet', ns.WARN)
        self.assertTrue(f)
        self.assertIn('NEW since last check', f[0]['detail'])
        self.assertIn('inspect HTTPS', f[0]['detail'])
        with mock.patch.object(ns, 'local_ca_anchors', return_value=[self.anchor(shipped=True)]):
            R = run(ns.check_ca_anchors, None, {})
        self.assertTrue(found(R, 'shipped with your OS', ns.INFO))

    def test_tls_interception(self):
        def probe(host):
            return {'host': host, 'ok': True, 'issuer_o': 'Fortinet', 'issuer_cn': 'FortiGate CA', 'sct': False}
        with mock.patch.object(ns, 'tls_probe', side_effect=probe):
            R = run(ns.check_tls, [self.anchor()])
        self.assertTrue(found(R, 'intercepted', ns.RISK))

    def test_tls_certificate_errors(self):
        def probe(host):
            return {'host': host, 'ok': False, 'verify_failed': True, 'issuer_o': 'Evil Proxy', 'issuer_cn': 'x',
                    'error': '[SSL: CERTIFICATE_VERIFY_FAILED]'}
        with mock.patch.object(ns, 'tls_probe', side_effect=probe):
            R = run(ns.check_tls, [])
        self.assertTrue(found(R, 'certificate errors', ns.RISK))

    def test_tls_unknown_issuer_without_ct(self):
        def probe(host):
            return {'host': host, 'ok': True, 'issuer_o': 'Corp Inspect', 'issuer_cn': 'Inspect CA', 'sct': False}
        with mock.patch.object(ns, 'tls_probe', side_effect=probe):
            R = run(ns.check_tls, [])
        self.assertTrue(found(R, 'Unusual certificates', ns.WARN))

    def test_tls_genuine(self):
        def probe(host):
            return {'host': host, 'ok': True, 'issuer_o': "Let's Encrypt", 'issuer_cn': 'R11', 'sct': True}
        with mock.patch.object(ns, 'tls_probe', side_effect=probe):
            R = run(ns.check_tls, [])
        self.assertTrue(found(R, 'genuine', ns.OK))

    def test_captive_portal(self):
        def probe(p):
            return {'url': p[0], 'status': 302, 'good': False, 'location': 'http://login.hotel.example/',
                    'proxy_headers': [], 'body': ''}
        with mock.patch.object(ns, 'http_probe', side_effect=probe):
            R = run(ns.check_http)
        self.assertTrue(found(R, 'captive portal', ns.WARN))

    def test_wrong_clock(self):
        for offset, level in ((2 * 86400, ns.RISK), (900, ns.WARN), (3, ns.OK)):
            now = time.time()
            with mock.patch.object(ns, 'cloudflare_trace', return_value={'ts': str(now - offset), '_local': now}):
                R = run(ns.check_clock)
            self.assertEqual(R.findings[0]['level'], level, offset)

    def wifi(self, line):
        real_isdir = os.path.isdir
        with mock.patch.object(ns, 'default_routes_v4', return_value=[{'iface': 'wlan9', 'gateway': '10.0.0.1', 'metric': 1}]), \
                mock.patch('os.path.isdir', side_effect=lambda p: True if p == '/sys/class/net/wlan9/wireless' else real_isdir(p)), \
                mock.patch.object(ns, 'stdout_of', return_value=line):
            return run(ns.check_wifi)

    def test_wifi_security(self):
        self.assertTrue(found(self.wifi('yes:CafeWiFi:\n'), 'OPEN', ns.RISK))
        self.assertTrue(found(self.wifi('yes:OldRouter:WEP\n'), 'WEP', ns.RISK))
        self.assertTrue(found(self.wifi('yes:Home\\:5G:WPA2\n'), 'Home:5G', ns.OK))


# ======================================================================================
class ExposureScenarios(unittest.TestCase):

    def fw(self, **kw):
        st = {'tool': 'firewalld', 'active': True, 'zone': 'home', 'rules': [], 'wide': [], 'target': 'default',
              'allows': lambda proto, port: True}
        st.update(kw)
        return st

    def test_firewall_off_with_open_ports(self):
        R = run(ns.check_firewall, self.fw(active=False), [{'port': 22, 'reach': True, 'level': ns.WARN}])
        self.assertTrue(found(R, 'firewall is OFF', ns.RISK))

    def test_no_firewall_software(self):
        R = run(ns.check_firewall, self.fw(tool='none', active=False), [{'port': 22, 'reach': True, 'level': ns.WARN}])
        self.assertTrue(found(R, 'No firewall software', ns.RISK))

    def test_wide_open_zone(self):
        R = run(ns.check_firewall, self.fw(zone='FedoraWorkstation', wide=[('tcp', 1025, 65535, 'port 1025-65535/tcp')]), [])
        self.assertTrue(found(R, 'almost every port', ns.WARN))

    def test_trusted_zone(self):
        R = run(ns.check_firewall, self.fw(zone='trusted', target='ACCEPT'), [])
        self.assertTrue(found(R, 'lets everything in', ns.RISK))

    def test_good_firewall(self):
        R = run(ns.check_firewall, self.fw(rules=['services: dhcpv6-client', 'ports: none']), [])
        self.assertTrue(found(R, 'Firewall is on', ns.OK))

    def listeners(self, socks, allow=True):
        fw = self.fw()
        fw['allows'] = lambda proto, port: allow
        return run(ns.check_listeners, socks, fw, None, {})

    def test_exposed_database(self):
        R = self.listeners([listener(6379, process='redis-server')])
        self.assertTrue(found(R, 'Redis', ns.RISK))

    def test_exposed_docker_api(self):
        R = self.listeners([listener(2375, process='dockerd')])
        self.assertTrue(found(R, 'Docker API', ns.RISK))

    def test_blocked_port_is_only_info(self):
        R = self.listeners([listener(6379, process='redis-server')], allow=False)
        self.assertTrue(found(R, 'blocked by your firewall', ns.INFO))
        self.assertFalse(found(R, 'Redis', ns.RISK))

    def test_loopback_only(self):
        R = self.listeners([listener(3306, scope='loopback', addr='127.0.0.1', process='mariadbd')])
        self.assertTrue(found(R, 'only accept connections from this computer', ns.OK))
        self.assertTrue(found(R, 'Nothing on this computer accepts connections', ns.OK))

    def test_ipv6_exposure(self):
        rows = [{'port': 8080, 'name': 'web server', 'level': ns.WARN, 'reach': True}]
        with mock.patch.object(ns, 'global_ipv6_addresses', return_value=[('2001:db8::5', 'eth0', False)]):
            R = run(ns.check_ipv6_exposure, rows)
        self.assertTrue(found(R, 'over IPv6', ns.WARN))
        self.assertTrue(found(R, 'privacy addresses are off', ns.INFO))

    def test_upnp_mapping_to_this_computer(self):
        dev = {'ip': '192.168.1.1', 'location': 'http://192.168.1.1:5000/desc.xml', 'model': 'TestRouter 1',
               'mappings': [{'NewProtocol': 'TCP', 'NewExternalPort': '8080', 'NewInternalClient': '192.168.1.20',
                             'NewInternalPort': '8080', 'NewPortMappingDescription': 'game', 'NewEnabled': '1'}]}
        with mock.patch.object(ns, 'upnp_check', return_value=[dev]), mock.patch.object(ns, 'natpmp_check', return_value=False), \
                mock.patch.object(ns, 'my_lan_ips', return_value={'192.168.1.20'}), \
                mock.patch.object(ns, 'default_routes_v4', return_value=[{'iface': 'eth0', 'gateway': '192.168.1.1', 'metric': 1}]):
            R = run(ns.check_router_ports)
        self.assertTrue(found(R, 'point at THIS computer', ns.WARN))
        self.assertTrue(found(R, 'UPnP is ON', ns.WARN))

    def test_upnp_off(self):
        with mock.patch.object(ns, 'upnp_check', return_value=[]), mock.patch.object(ns, 'natpmp_check', return_value=False), \
                mock.patch.object(ns, 'default_routes_v4', return_value=[{'iface': 'eth0', 'gateway': '192.168.1.1', 'metric': 1}]):
            R = run(ns.check_router_ports)
        self.assertTrue(found(R, 'UPnP/NAT-PMP off', ns.OK))

    def test_internet_scanners_found_vulns(self):
        R = new_report()
        R.facts['public_ip'] = {'v4': '203.0.113.5', 'v6': None}
        with mock.patch.object(ns, 'http_json', return_value=(200, {'ports': [22, 7547], 'vulns': ['CVE-2020-1234'],
                                                                    'hostnames': []})):
            run(ns.check_internetdb, R=R)
        self.assertTrue(found(R, '7547', ns.RISK))

    def test_world_writable_docker_socket(self):
        real_exists = os.path.exists
        st = os.stat_result((0o140666, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        with mock.patch('os.path.exists', side_effect=lambda p: True if p == '/var/run/docker.sock' else real_exists(p)), \
                mock.patch('os.stat', return_value=st):
            R = run(ns.check_containers, [])
        self.assertTrue(found(R, 'Docker control socket', ns.RISK))

    def test_container_published_port(self):
        R = run(ns.check_containers, [listener(8080, process='docker-proxy')])
        self.assertTrue(found(R, 'Containers publish', ns.WARN))

    def test_llmnr_listener(self):
        R = run(ns.check_lan_leaks, [listener(5355, proto='udp', unit='systemd-resolved')])
        self.assertTrue(found(R, 'LLMNR', ns.WARN))


# ======================================================================================
class ChangesAndUndo(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nstest-')
        self.env = mock.patch.dict(os.environ, {'XDG_STATE_HOME': os.path.join(self.tmp, 'state')})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_dry_run_changes_nothing(self):
        ch = ns.Changer(ns.Output(False, True), dry_run=True)
        target = os.path.join(self.tmp, 'cfg.conf')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(ch.write_file(target, 'x=1\n'))
            self.assertTrue(ch.run(['false']))
        self.assertFalse(os.path.exists(target))
        self.assertIsNone(ch.finish())

    def test_undo_script_order(self):
        ch = ns.Changer(ns.Output(False, True))
        existing = os.path.join(self.tmp, 'existing.conf')
        with open(existing, 'w') as f:
            f.write('old\n')
        new = os.path.join(self.tmp, 'new.conf')
        with contextlib.redirect_stdout(io.StringIO()):
            ch.write_file(existing, 'changed\n')
            ch.write_file(new, 'brand new\n')
            ch.add_undo(['echo', 'reload-firewall'], after=True)
            ch.add_undo(['echo', 'reload-firewall'], after=True)          # deduplicated
            path = ch.finish()
        with open(path) as f:
            body = [l for l in f.read().splitlines() if l and not l.startswith('#')]
        actions = [l for l in body if l.startswith(('cp ', 'rm '))]
        self.assertTrue(actions[0].startswith('rm -f') and new in actions[0])        # last change undone first
        self.assertTrue(actions[1].startswith('cp -a') and existing in actions[1])
        self.assertEqual(body.count('echo reload-firewall'), 1)
        self.assertGreater(body.index('echo reload-firewall'), body.index(actions[-1]))  # after-steps run last
        # running the undo script restores the original state
        os.system('sh %s >/dev/null' % path)
        with open(existing) as f:
            self.assertEqual(f.read(), 'old\n')
        self.assertFalse(os.path.exists(new))

    def test_rollback(self):
        ch = ns.Changer(ns.Output(False, True))
        marker = os.path.join(self.tmp, 'marker')
        with contextlib.redirect_stdout(io.StringIO()):
            mu, ma = len(ch.undo), len(ch.undo_after)
            ch.write_file(marker, 'x\n')
            self.assertTrue(os.path.exists(marker))
            ns._rollback(ch, mu, ma)
        self.assertFalse(os.path.exists(marker))
        self.assertEqual(ch.undo, [])

    def test_baseline_roundtrip(self):
        self.assertIsNone(ns.load_baseline())
        self.assertTrue(ns.save_baseline({'time': 'now', 'exposed': ['tcp/22 sshd']}))
        self.assertEqual(ns.load_baseline()['exposed'], ['tcp/22 sshd'])

    def test_markdown_report(self):
        R = new_report()
        R.section = 'dns'
        R.findings.append({'section': 'dns', 'level': ns.WARN, 'title': 'DNS lookups are not encrypted',
                           'detail': 'detail', 'fix': 'do this'})
        args = mock.Mock(offline=False)
        md = ns.markdown_report(R, args, time.time())
        self.assertIn('## 2. Is there a DNS leak?', md)
        self.assertIn('**What to do:**', md)
        self.assertIn('## What to do, most important first', md)


# ======================================================================================
class StopApps(unittest.TestCase):
    """`ports block APP --stop`: services and login entries are turned off, and undo.sh brings them back.
    pkill and runuser are never really run, so nothing on this computer is stopped."""

    AVAHI = [{'id': 'avahi-daemon.socket', 'load': 'loaded', 'file': 'enabled', 'active': 'active'},
             {'id': 'avahi-daemon.service', 'load': 'loaded', 'file': 'enabled', 'active': 'active'}]
    ENTRY = 'org.kde.kdeconnect.daemon.desktop'

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix='nstest-')
        me = pwd.getpwuid(os.geteuid())
        self.user = mock.Mock(pw_name=me.pw_name, pw_uid=me.pw_uid, pw_dir=os.path.join(self.tmp, 'home'))
        self.mine = os.path.join(self.user.pw_dir, '.config', 'autostart', self.ENTRY)
        sysdir = os.path.join(self.tmp, 'xdg-autostart')
        os.makedirs(sysdir)
        with open(os.path.join(sysdir, self.ENTRY), 'w') as f:
            f.write('[Desktop Entry]\nExec=kdeconnectd\n')
        self.calls = []
        real_run = ns.Changer.run

        def fake_run(ch, cmd, **kw):
            self.calls.append(cmd)
            return True if cmd[0] in ('pkill', 'runuser') else real_run(ch, cmd, **kw)
        self.patches = [mock.patch.dict(os.environ, {'XDG_STATE_HOME': os.path.join(self.tmp, 'state')}),
                        mock.patch.object(ns, 'target_user', return_value=self.user),
                        mock.patch.object(ns, 'SYSTEM_AUTOSTART', sysdir),
                        mock.patch.object(ns.Changer, 'run', fake_run)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def stop(self, key, dry=True, states=None):
        ch = ns.Changer(ns.Output(False, True), dry_run=dry)
        buf = io.StringIO()
        with mock.patch.object(ns, 'unit_states', return_value=states), contextlib.redirect_stdout(buf):
            ok = ns.stop_app(ns.Output(False, True), ch, ns.resolve_target(key, []))
        return ok, buf.getvalue(), ch

    def undo_lines(self, path):
        with open(path) as f:
            return [l for l in f.read().splitlines() if l and not l.startswith(('#', 'set ', 'echo '))]

    def test_system_service_is_disabled_not_killed(self):
        ok, out, ch = self.stop('mdns', states=self.AVAHI)
        self.assertTrue(ok)
        self.assertIn('would run: systemctl disable --now avahi-daemon.socket avahi-daemon.service', out)
        self.assertNotIn('pkill', out)                      # avahi runs as its own user: pkill -u USER would miss it
        ch.dry = False
        self.assertEqual(self.undo_lines(ch.finish()), ['systemctl enable avahi-daemon.socket avahi-daemon.service',
                                                        'systemctl start avahi-daemon.socket avahi-daemon.service'])

    def test_service_states_without_changes(self):
        off = [dict(u, file='disabled', active='inactive') for u in self.AVAHI]
        self.assertIn('already off', self.stop('mdns', states=off)[1])
        self.assertIn('No service for it is installed', self.stop('mdns', states=[])[1])
        ok, out, ch = self.stop('ssh', states=None)
        self.assertTrue(ok)
        self.assertIn('needs systemd', out)
        self.assertEqual(ch.undo, [])

    def test_cups_keeps_running(self):
        ok, out, ch = self.stop('printing', states=[{'id': 'cups.service', 'load': 'loaded', 'file': 'enabled',
                                                     'active': 'active'}])
        self.assertIn('CUPS keeps running', out)
        self.assertNotIn('systemctl', out)
        self.assertEqual(ch.undo, [])

    def test_login_entry_switched_off_and_undone(self):
        ok, out, ch = self.stop('kdeconnect', dry=False)
        self.assertTrue(ok)
        self.assertIn(['pkill', '-u', self.user.pw_name, 'kdeconnect'], self.calls)
        with open(self.mine) as f:
            self.assertRegex(f.read(), r'(?m)^\[Desktop Entry\]\nHidden=true$')
        path = ch.finish()
        self.assertEqual(self.undo_lines(path), ['rm -f %s' % self.mine])   # same user: no runuser needed
        os.system('sh %s >/dev/null' % path)
        self.assertFalse(os.path.exists(self.mine))

    def test_own_login_entries_are_left_alone(self):
        os.makedirs(os.path.dirname(self.mine))
        with open(self.mine, 'w') as f:
            f.write('[Desktop Entry]\nHidden=true\n')
        self.assertIn('already does not start at login', self.stop('kdeconnect')[1])
        with open(self.mine, 'w') as f:
            f.write('[Desktop Entry]\nExec=kdeconnectd --my-option\n')
        ok, out, ch = self.stop('kdeconnect', dry=False)
        self.assertIn('left as it is', out)
        self.assertEqual(ch.undo, [])
        # a symlink planted in its place is never written through, even if it says Hidden=true
        target = os.path.join(self.tmp, 'elsewhere')
        with open(target, 'w') as f:
            f.write('[Desktop Entry]\nHidden=true\n')
        os.remove(self.mine)
        os.symlink(target, self.mine)
        ok, out, ch = self.stop('kdeconnect', dry=False)
        self.assertIn('left as it is', out)
        with open(target) as f:
            self.assertEqual(f.read(), '[Desktop Entry]\nHidden=true\n')

    def block_mdns(self, runtime, permanent, stop=False):
        """`ports block mdns` against a fake firewalld zone "home" with these runtime / permanent services."""
        def zone_info(zone, perm=False):
            return {'target': 'default', 'services': permanent if perm else runtime, 'ports': [], 'rich': []}
        buf = io.StringIO()
        with mock.patch.object(ns, 'listening_sockets', return_value=[]), \
                mock.patch.object(ns, 'firewall_state', return_value={'tool': 'firewalld', 'active': True}), \
                mock.patch.object(ns, 'fwd_zone', return_value=('home', 'eth0')), \
                mock.patch.object(ns, 'fwd_zone_info', side_effect=zone_info), \
                mock.patch.object(ns, 'fwd_known_services', return_value=frozenset({'mdns'})), \
                mock.patch.object(ns, 'fwd_service_ports', return_value=('5353/udp',)), \
                mock.patch.object(ns, 'unit_states', return_value=self.AVAHI), \
                mock.patch.object(ns.Changer, 'run', lambda ch, cmd, **kw: self.calls.append(cmd) or True), \
                contextlib.redirect_stdout(buf):
            rc = ns.ports_change(ns.Output(False, True), 'block', 'mdns', stop=stop, assume_yes=True)
        return rc, buf.getvalue()

    def test_ports_block_stop_writes_one_undo_script(self):
        rc, out = self.block_mdns(['dhcpv6-client', 'mdns'], ['dhcpv6-client', 'mdns'], stop=True)
        self.assertEqual(rc, 0)
        self.assertIn(['firewall-cmd', '--permanent', '--zone=home', '--remove-service=mdns'], self.calls)
        self.assertIn(['systemctl', 'disable', '--now', 'avahi-daemon.socket', 'avahi-daemon.service'], self.calls)
        self.assertNotIn('already blocks', out)
        path = out.split('Undo: sudo sh ')[1].strip()
        self.assertEqual(self.undo_lines(path), ['systemctl enable avahi-daemon.socket avahi-daemon.service',
                                                 'systemctl start avahi-daemon.socket avahi-daemon.service',
                                                 'firewall-cmd --permanent --zone=home --add-service=mdns',
                                                 'firewall-cmd --reload'])

    def test_temporary_rule_is_not_made_permanent_by_undo(self):
        rc, out = self.block_mdns(['mdns'], [])
        self.assertIn(['firewall-cmd', '--zone=home', '--remove-service=mdns'], self.calls)
        self.assertNotIn('Undo:', out)                        # nothing permanent changed, nothing to undo

    def test_already_blocked_says_so(self):
        rc, out = self.block_mdns(['dhcpv6-client'], ['dhcpv6-client'])
        self.assertEqual(rc, 0)
        self.assertIn('The firewall already blocks it (zone "home")', out)
        self.assertFalse([c for c in self.calls if c[0] == 'firewall-cmd'])
        self.assertNotIn('Undo:', out)


# ======================================================================================
class SecurityHardening(unittest.TestCase):
    """Regression tests for the issues found in networkScout's own security review."""

    def test_upnp_only_follows_the_answering_local_device(self):
        ok = ns.upnp_location_ok
        self.assertTrue(ok('http://192.168.1.1:5000/rootDesc.xml', '192.168.1.1'))
        self.assertTrue(ok('http://192.168.1.1/ctl/IPConn', '192.168.1.1'))
        self.assertFalse(ok('http://127.0.0.1:631/admin', '192.168.1.1'))        # another host
        self.assertFalse(ok('http://evil.example/x.xml', '192.168.1.1'))
        self.assertFalse(ok('http://8.8.8.8/x.xml', '8.8.8.8'))                 # not on the local network
        self.assertFalse(ok('file:///etc/passwd', '192.168.1.1'))
        self.assertFalse(ok('http://192.168.1.1:bad/x', '192.168.1.1'))
        self.assertFalse(ok('http://127.0.0.1/x', '127.0.0.1'))

    def test_trusted_core_rejects_user_owned_copy(self):
        tmp = tempfile.mkdtemp()
        try:
            path = os.path.join(tmp, 'lib', 'networkscout.py')
            os.makedirs(os.path.dirname(path))
            open(path, 'w').close()
            with mock.patch.object(ns, 'SYSTEM_CORE', path):
                if os.geteuid() != 0:                       # a copy owned by a normal user is never trusted
                    self.assertIsNone(ns.trusted_core())
                os.chmod(os.path.dirname(path), 0o777)       # a folder anyone can write to: never trusted
                self.assertIsNone(ns.trusted_core())
        finally:
            shutil.rmtree(tmp)

    def test_trusted_core_needs_root_owner_and_no_group_write(self):
        good = os.stat_result((0o100644, 0, 0, 1, 0, 0, 0, 0, 0, 0))
        with mock.patch('os.stat', return_value=good):
            self.assertEqual(ns.trusted_core(), ns.SYSTEM_CORE)
        for bad in (os.stat_result((0o100664, 0, 0, 1, 0, 0, 0, 0, 0, 0)),       # group-writable
                    os.stat_result((0o100644, 0, 0, 1, 1000, 0, 0, 0, 0, 0))):   # owned by a user
            with mock.patch('os.stat', return_value=bad):
                self.assertIsNone(ns.trusted_core())
        with mock.patch.object(ns, 'SYSTEM_CORE', '/nonexistent/networkscout.py'):
            self.assertIsNone(ns.trusted_core())

    def test_backups_go_to_root_only_folder_when_root(self):
        with mock.patch.object(ns, 'is_root', return_value=True):
            ch = ns.Changer(ns.Output(False, True), dry_run=True)
        self.assertTrue(ch.dir.startswith(ns.SYSTEM_BACKUPS + '/'))

    def test_undo_script_and_backups_are_private(self):
        tmp = tempfile.mkdtemp()
        try:
            with mock.patch.dict(os.environ, {'XDG_STATE_HOME': tmp}):
                ch = ns.Changer(ns.Output(False, True))
                target = os.path.join(tmp, 'x.conf')
                open(target, 'w').close()
                with contextlib.redirect_stdout(io.StringIO()):
                    ch.write_file(target, 'y\n')
                    path = ch.finish()
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o700)
            self.assertEqual(os.stat(ch.dir).st_mode & 0o777, 0o700)
            self.assertEqual(os.stat(os.path.dirname(ch.dir)).st_mode & 0o777, 0o700)
        finally:
            shutil.rmtree(tmp)



class LanDevices(unittest.TestCase):
    """The devices command / Devices tab, with simulated neighbours (documentation addresses only)."""

    def setUp(self):
        ns._VENDOR_CACHE.clear()
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def oui_file(self):
        path = os.path.join(self.tmp, 'oui.txt')
        with open(path, 'w') as f:
            f.write('00-00-5E   (hex)\t\tICANN, IANA Department\n00005E     (base 16)\t\tICANN, IANA Department\n'
                    'A0-B1-C2   (hex)\t\tExample Phones Co., Ltd.\n')
        return path

    def test_vendor_from_the_ieee_list(self):
        with mock.patch.object(ns, 'OUI_FILES', (self.oui_file(),)):
            self.assertEqual(ns.mac_vendor('00:00:5e:00:53:01'), 'ICANN, IANA Department')
            self.assertEqual(ns.mac_vendor('a0:b1:c2:00:00:01'), 'Example Phones')       # "Co., Ltd." trimmed
            self.assertEqual(ns.mac_vendor('00:11:22:33:44:55'), '')
            self.assertEqual(ns.mac_vendor('not-a-mac'), '')

    def test_random_mac_is_reported_as_private(self):
        self.assertTrue(ns.mac_is_random('02:00:5e:00:53:42'))
        self.assertFalse(ns.mac_is_random('00:00:5e:00:53:42'))
        self.assertEqual(ns.mac_vendor('da:a1:19:00:00:01'), 'private address')

    def test_kind_from_vendor(self):
        self.assertEqual(ns.device_kind('Xiaomi Communications'), 'phone')
        self.assertEqual(ns.device_kind('Hewlett Packard'), 'printer')
        self.assertEqual(ns.device_kind('Whatever', is_router=True), 'router')
        self.assertEqual(ns.device_kind(''), 'unknown')

    def test_netbios_node_status_reply(self):
        names = (b'NAS-BOX'.ljust(15) + b'\x00' + b'\x04\x00') + (b'WORKGROUP'.ljust(15) + b'\x00' + b'\x84\x00')
        reply = (b'\x12\x34\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00' + b'\x20' + b'CK' + b'A' * 30 + b'\x00' +
                 b'\x00\x21\x00\x01' + b'\x00\x00\x00\x00' + struct_pack_h(len(names) + 1) + bytes([2]) + names)
        self.assertEqual(ns.parse_nbstat(reply), 'NAS-BOX')
        self.assertEqual(ns.parse_nbstat(b'\x00\x01'), '')

    def test_neighbours_keep_live_entries_only(self):
        data = json.dumps([
            {'dst': '10.0.0.1', 'dev': 'eth0', 'lladdr': '00:00:5e:00:53:01', 'state': ['REACHABLE']},
            {'dst': '10.0.0.31', 'dev': 'eth0', 'lladdr': '00:00:5e:00:53:31', 'state': ['STALE']},
            {'dst': '10.0.0.77', 'dev': 'eth0', 'state': ['FAILED']},
            {'dst': '10.0.0.78', 'dev': 'eth0', 'lladdr': '00:00:5e:00:53:78', 'state': ['INCOMPLETE']},
        ])
        with mock.patch.object(ns, 'stdout_of', return_value=data):
            got = ns.neighbours('eth0')
        self.assertEqual([n['ip'] for n in got], ['10.0.0.1', '10.0.0.31'])
        self.assertEqual(got[1]['state'], 'STALE')

    def test_labels_are_private_and_can_be_forgotten(self):
        with mock.patch.dict(os.environ, {'XDG_CONFIG_HOME': self.tmp}), \
                mock.patch.object(ns, 'elevated_for_user', return_value=False):
            ns.save_device_label('00:00:5E:00:53:31', 'Living room TV')
            self.assertEqual(ns.load_device_labels()['00:00:5e:00:53:31']['name'], 'Living room TV')
            self.assertEqual(os.stat(ns.devices_path()).st_mode & 0o777, 0o600)
            ns.save_device_label('00:00:5e:00:53:31', '')
            self.assertEqual(ns.load_device_labels(), {})

    def test_lan_devices_names_and_order(self):
        neigh = [{'ip': '10.0.0.31', 'mac': '00:00:5e:00:53:31', 'iface': 'eth0', 'state': 'REACHABLE'},
                 {'ip': '10.0.0.1', 'mac': '00:00:5e:00:53:01', 'iface': 'eth0', 'state': 'REACHABLE'},
                 {'ip': '10.0.0.42', 'mac': '02:00:5e:00:53:42', 'iface': 'eth0', 'state': 'STALE'}]
        with mock.patch.dict(os.environ, {'XDG_CONFIG_HOME': self.tmp}), \
                mock.patch.object(ns, 'elevated_for_user', return_value=False), \
                mock.patch.object(ns, 'default_routes_v4', return_value=[{'iface': 'eth0', 'gateway': '10.0.0.1', 'metric': 0}]), \
                mock.patch.object(ns, 'lan_prefix', return_value=('10.0.0.20', 24)), \
                mock.patch.object(ns, 'neighbours', return_value=neigh), \
                mock.patch.object(ns, 'read', side_effect=lambda p, d=None: '00:00:5e:00:53:20\n' if p.endswith('/address') else d), \
                mock.patch.object(ns, 'device_names', return_value={'10.0.0.42': ('Pixel-8', 'mdns')}) as names, \
                mock.patch.object(ns, 'OUI_FILES', (self.oui_file(),)):
            ns.save_device_label('00:00:5e:00:53:31', 'Living room TV')
            res = ns.lan_devices(scan=False)
        devs = res['devices']
        self.assertEqual([d['ip'] for d in devs], ['10.0.0.1', '10.0.0.20', '10.0.0.31', '10.0.0.42'])
        by = {d['ip']: d for d in devs}
        self.assertTrue(by['10.0.0.1']['router'])
        self.assertEqual(by['10.0.0.1']['kind'], 'router')
        self.assertTrue(by['10.0.0.20']['self'])
        self.assertEqual((by['10.0.0.31']['name'], by['10.0.0.31']['source']), ('Living room TV', 'you'))
        self.assertEqual((by['10.0.0.42']['name'], by['10.0.0.42']['source']), ('Pixel-8', 'mdns'))
        self.assertTrue(by['10.0.0.42']['random_mac'])
        # labelled devices and this computer are not asked for names
        self.assertEqual(sorted(names.call_args[0][0]), ['10.0.0.1', '10.0.0.42'])
        self.assertEqual(res['names'], {'02:00:5e:00:53:42': ('Pixel-8', 'mdns')})

    def test_sweep_stays_inside_the_subnet(self):
        sent = []

        class FakeSock:
            def __init__(self, *a): pass
            def setblocking(self, v): pass
            def setsockopt(self, *a): raise OSError('no rights')
            def sendto(self, data, addr): sent.append(addr[0])
            def close(self): pass
        with mock.patch.object(ns, 'lan_prefix', return_value=('192.0.2.20', 24)), \
                mock.patch.object(ns.socket, 'socket', FakeSock):
            n = ns.sweep('eth0', pace=0)
        self.assertEqual(n, 253)                                  # 254 hosts minus this computer
        self.assertNotIn('192.0.2.20', sent)
        self.assertTrue(all(a.startswith('192.0.2.') for a in sent))


def struct_pack_h(n):
    return bytes([(n >> 8) & 0xff, n & 0xff])

if __name__ == '__main__':
    unittest.main(verbosity=2)
