#!/usr/bin/env python3
"""
networkScout command-line tests: runs networkscout.py as a separate process, the way people use it.
Only read-only commands and --dry-run changes are used, with a temporary state folder.

Run:  python3 -m unittest discover -s tests -p 'test_cli.py' -v
Set NETWORKSCOUT_TEST_OFFLINE=1 to skip the full online check.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), 'networkscout.py')
OFFLINE = os.environ.get('NETWORKSCOUT_TEST_OFFLINE') == '1'


def load(path):
    with open(path, encoding='utf-8') as f:
        return json.load(f) if path.endswith('.json') else f.read()


class CLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix='nscli-')
        cls.env = dict(os.environ, XDG_STATE_HOME=os.path.join(cls.tmp, 'state'),
                       XDG_CONFIG_HOME=os.path.join(cls.tmp, 'config'), NO_COLOR='1')

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def ns(self, *args, timeout=300, stdin=subprocess.DEVNULL, env=None):
        p = subprocess.run([sys.executable, '-I', SCRIPT] + list(args), stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, stdin=stdin, timeout=timeout, env=env or self.env,
                           encoding='utf-8', errors='replace')
        return p.returncode, p.stdout

    # -- basics ------------------------------------------------------------------------
    def test_version_and_help(self):
        rc, out = self.ns('--version')
        self.assertEqual(rc, 0)
        self.assertRegex(out, r'networkscout \d+\.\d+\.\d+')
        for args in (['--help'], ['fix', '--help'], ['ports', '--help'], ['ports', 'allow', '--help'],
                     ['ports', 'block', '--help'], ['ports', 'close-unused', '--help'], ['firewall', '--help'],
                     ['firewall', 'off', '--help'], ['firewall', 'profile', '--help'], ['dns', '--help'],
                     ['dns', 'encrypt', '--help']):
            rc, out = self.ns(*args)
            self.assertEqual(rc, 0, args)
            self.assertIn('usage:', out, args)

    def test_unknown_option(self):
        rc, out = self.ns('--no-such-option')
        self.assertEqual(rc, 2)
        self.assertIn('unrecognized arguments', out)

    # -- the check ----------------------------------------------------------------------
    def test_offline_check_json_and_report(self):
        js, md = os.path.join(self.tmp, 'off.json'), os.path.join(self.tmp, 'off.md')
        t = time.time()
        rc, out = self.ns('--offline', '--no-baseline', '--json', js, '--report', md)
        self.assertIn(rc, (0, 1, 2))
        self.assertLess(time.time() - t, 120)
        self.assertNotIn('\x1b[', out)                       # NO_COLOR / not a terminal: no colour codes
        data = load(js)
        self.assertEqual(data['online'], False)
        self.assertEqual(rc, 2 if data['counts']['RISK'] else (1 if data['counts']['WARN'] else 0))  # exit code rule
        sections = set(f['section'] for f in data['findings'])
        self.assertEqual(sections, {'system', 'dns', 'mitm', 'network'})
        for f in data['findings']:
            self.assertIn(f['level'], ('OK', 'INFO', 'WARN', 'RISK', 'SKIP'))
            self.assertTrue(f['title'])
        titles = ' '.join(f['title'] for f in data['findings'])
        self.assertNotIn('HTTPS certificates', titles)       # online-only checks are skipped
        report = load(md)
        for h in ('# networkScout security report', '## 1. Is my system secure?', '## 2. Is there a DNS leak?',
                  '## 3. Is anyone in the middle of my connections?', '## 4. Is my network exposure safe (open ports)?'):
            self.assertIn(h, report)

    def test_only_one_section(self):
        js = os.path.join(self.tmp, 'only.json')
        rc, out = self.ns('--offline', '--no-baseline', '--only', 'dns', '--json', js)
        data = load(js)
        self.assertEqual(set(f['section'] for f in data['findings']), {'dns'})
        self.assertNotIn('1. Is my system secure?', out)

    def test_baseline_tracks_changes(self):
        env = dict(self.env, XDG_STATE_HOME=os.path.join(self.tmp, 'basestate'))
        rc, out = self.ns('--offline', '--only', 'mitm,network', env=env)
        self.assertNotIn('Compared with the previous check', out)
        base = os.path.join(self.tmp, 'basestate', 'networkscout', 'baseline.json')
        self.assertTrue(os.path.exists(base))
        data = load(base)
        self.assertIn('exposed', data)
        self.assertIn('ca_anchors', data)
        rc, out = self.ns('--offline', '--only', 'mitm,network', env=env)
        self.assertIn('Compared with the previous check', out)

    @unittest.skipIf(OFFLINE, 'needs the internet')
    def test_full_online_check(self):
        js = os.path.join(self.tmp, 'full.json')
        t = time.time()
        rc, out = self.ns('--no-baseline', '--json', js, timeout=600)
        took = time.time() - t
        data = load(js)
        self.assertEqual(data['online'], True)
        titles = ' '.join(f['title'] for f in data['findings'])
        for expected in ('HTTPS certificates', 'clock', 'Internet scanners', 'DNS'):
            self.assertIn(expected, titles)
        self.assertLess(took, 180)
        skipped = [f['title'] for f in data['findings'] if f['level'] == 'SKIP']
        self.assertLessEqual(len(skipped), 2, skipped)
        print('\n    full online check: %.0f s, %s' % (took, data['counts']))

    # -- ports ---------------------------------------------------------------------------
    def test_ports_list(self):
        rc, out = self.ns('ports')
        self.assertEqual(rc, 0)
        for h in ('Firewall', 'Programs that accept connections from the network', 'Apps', 'Commands:'):
            self.assertIn(h, out)

    def test_ports_dry_runs(self):
        rc, out = self.ns('firewall')
        if 'ON (firewalld)' not in out and 'ufw is ON' not in out:
            self.skipTest('needs firewalld or ufw')
        cases = [(['ports', 'allow', 'transmission', '--dry-run'], 'would run'),
                 (['ports', 'allow', '8080', '--for', '1h', '--dry-run'], '--timeout=1h'),
                 (['ports', 'allow', '8080', '--from', '192.168.1.0/24', '--dry-run'], 'source address="192.168.1.0/24"'),
                 (['ports', 'open', '6881-6889/udp', '--for', '30m', '--dry-run'], '6881-6889/udp'),
                 (['ports', 'block', 'kdeconnect', '--dry-run'], 'Blocking incoming connections for KDE Connect'),
                 (['ports', 'block', 'mdns', '--stop', '--dry-run'], 'Blocking incoming connections for mDNS'),
                 (['ports', 'close', 'printing', '--stop', '--dry-run'], 'CUPS keeps running'),
                 (['ports', 'close-unused', '--dry-run', '--yes'], 'Firewall zone')]
        for args, expect in cases:
            rc, out = self.ns(*args)
            self.assertEqual(rc, 0, (args, out[-500:]))
            self.assertIn(expect, out, args)

    def test_ports_bad_input(self):
        rc, out = self.ns('ports', 'block', 'nosuchapp', '--dry-run')
        self.assertEqual(rc, 2)
        self.assertIn('not a known app', out)
        rc, out = self.ns('ports', 'allow', '99999', '--dry-run')
        self.assertEqual(rc, 2)
        rc, out = self.ns('ports', 'allow', '8080', '--for', 'soon', '--dry-run')
        self.assertEqual(rc, 2)
        self.assertIn('duration', out)

    def test_changes_need_admin_rights(self):
        """Without a terminal it must refuse (and not hang on a password prompt)."""
        if os.geteuid() == 0:
            self.skipTest('running as root: changes would really be made')
        for args in (['ports', 'allow', '8080'], ['firewall', 'off'], ['dns', 'plain'], ['fix']):
            t = time.time()
            rc, out = self.ns(*args, timeout=60)
            self.assertEqual(rc, 1, args)
            self.assertIn('needs administrator rights', out, args)
            self.assertLess(time.time() - t, 20, args)

    # -- firewall ------------------------------------------------------------------------
    def test_firewall_status_and_dry_runs(self):
        rc, out = self.ns('firewall')
        self.assertEqual(rc, 0)
        self.assertIn('Firewall', out)
        if 'No firewalld or ufw found' in out or 'ON (firewalld)' not in out:
            self.skipTest('firewalld not running here')
        self.assertIn('Profiles', out)
        rc, out = self.ns('firewall', 'profile', 'workplace', '--dry-run', '--yes')
        self.assertEqual(rc, 0)
        self.assertIn('Profile "work"', out)
        rc, out = self.ns('firewall', 'profile', 'home', '--this-network', '--dry-run', '--yes')
        self.assertIn('connection.zone home', out)
        rc, out = self.ns('firewall', 'off', '--for', '10m', '--dry-run', '--yes')
        self.assertIn('--on-active=600', out)
        rc, out = self.ns('firewall', 'log-blocked', 'on', '--dry-run')
        self.assertIn('--set-log-denied=unicast', out)
        rc, out = self.ns('firewall', 'profile', 'nonsense', '--dry-run')
        self.assertEqual(rc, 2)
        rc, out = self.ns('firewall', 'off', '--for', 'later', '--dry-run')
        self.assertEqual(rc, 2)

    # -- dns ---------------------------------------------------------------------------------
    def test_dns_status_and_dry_runs(self):
        rc, out = self.ns('dns')
        self.assertEqual(rc, 0)
        self.assertIn('DNS', out)
        if 'Managed outside systemd-resolved' in out:
            self.skipTest('no systemd-resolved here')
        for args in (['dns', 'llmnr', 'on', '--dry-run'], ['dns', 'plain', '--dry-run'],
                     ['dns', 'encrypt', '--provider', 'quad9', '--dry-run']):
            rc, out = self.ns(*args)
            self.assertIn(rc, (0, 1), (args, out))
        rc, out = self.ns('dns', 'encrypt', '--provider', 'nosuch', '--dry-run')
        self.assertEqual(rc, 2)

    # -- fix ------------------------------------------------------------------------------------
    def test_devices_list_json_and_names(self):
        code, out = self.ns('devices', '--help')
        self.assertEqual(code, 0)
        self.assertIn('--scan', out)
        code, out = self.ns('devices', '--json', '--no-names', timeout=60)
        self.assertEqual(code, 0)
        devs = json.loads(out)
        self.assertIsInstance(devs, list)
        for d in devs:
            self.assertTrue({'ip', 'mac', 'vendor', 'name', 'kind', 'router', 'self'} <= set(d))
        # naming needs an address and a name; names live in the (temporary) config folder only
        code, out = self.ns('devices', 'name')
        self.assertNotEqual(code, 0)
        code, out = self.ns('devices', 'name', '00:00:5e:00:53:31', 'Living', 'room', 'TV')
        self.assertEqual(code, 0)
        self.assertIn('Living room TV', out)
        code, out = self.ns('devices', 'forget', '00:00:5e:00:53:31')
        self.assertEqual(code, 0)

    def test_fix_dry_run(self):
        rc, out = self.ns('fix', '--dry-run', '--yes', '--only', 'certs,firewall,dns,updater,sysctl')
        self.assertEqual(rc, 0, out[-800:])
        self.assertIn('networkScout fix', out)
        self.assertNotIn('Traceback', out)


if __name__ == '__main__':
    unittest.main(verbosity=2)
