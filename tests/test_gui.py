#!/usr/bin/env python3
"""
networkScout app tests: the event monitor (with simulated system data and journal lines) and the
Tk window (layouts, filters, dialogs, background actions, speed). Uses a temporary state folder and
never asks for a password. The window tests need a display and a Python with tkinter.

Run:  <python with tkinter> -m unittest discover -s tests -p 'test_gui.py' -v
"""
import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

TMP = tempfile.mkdtemp(prefix='nsgui-')
os.environ['XDG_STATE_HOME'] = os.path.join(TMP, 'state')       # before importing the app: it reads these
os.environ['XDG_CONFIG_HOME'] = os.path.join(TMP, 'config')
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import networkscout_gui as g  # noqa: E402

ns = g.ns
HAVE_DISPLAY = g.HAS_TK and bool(os.environ.get('DISPLAY'))


def drain(m):
    out = []
    while not m.events.empty():
        out.append(m.events.get())
    return out


def texts(events):
    return ' | '.join(e['text'] for e in events)


def free_port():
    s = socket.socket()
    s.bind(('0.0.0.0', 0))
    p = s.getsockname()[1]
    s.close()
    return p


class FakePopen:
    def __init__(self, lines):
        self.stdout = iter(json.dumps(l) + '\n' for l in lines)

    def terminate(self):
        pass


# ======================================================================================
class Helpers(unittest.TestCase):

    def test_friendly_owner(self):
        base = '/user.slice/user-1000.slice/user@1000.service/app.slice/'
        self.assertEqual(g.friendly_owner(base + 'app-flatpak-com.transmissionbt.Transmission-12345.scope'), 'Transmission')
        self.assertEqual(g.friendly_owner(base + 'app-org.kde.kdeconnect.daemon@autostart.service'), 'kdeconnect')
        self.assertEqual(g.friendly_owner('/system.slice/avahi-daemon.service'), 'avahi-daemon')
        self.assertEqual(g.friendly_owner('/system.slice/systemd-resolved.service'), 'systemd-resolved')
        self.assertEqual(g.friendly_owner(''), '')

    def test_socket_snapshot(self):
        listen, conns = g.socket_snapshot()
        self.assertIsInstance(listen, list)
        for s in listen:
            self.assertIn(s['scope'], ('all', 'loopback', 'link-local', 'lan', 'public'))
            self.assertTrue(0 < s['port'] < 65536)
        for c in conns:
            self.assertEqual(len(c), 6)

    def test_notification_text_is_escaped(self):
        self.assertEqual(g.notify_text('<a href="http://x">&</a>\x07 ok'), '&lt;a href="http://x"&gt;&amp;&lt;/a&gt; ok')
        self.assertLessEqual(len(g.notify_text('x' * 1000)), 300)

    def test_fw_allows(self):
        snap = {'on': True, 'target': 'default', 'ports': ['8080/tcp'], 'services': [], 'svc_ports': []}
        self.assertTrue(g.fw_allows(snap, 'tcp', 8080, []))
        self.assertFalse(g.fw_allows(snap, 'udp', 8080, []))
        self.assertTrue(g.fw_allows(snap, 'udp', 51413, ['51413/udp']))
        self.assertTrue(g.fw_allows(dict(snap, target='ACCEPT'), 'tcp', 1, []))
        self.assertTrue(g.fw_allows(dict(snap, on=False), 'tcp', 1, []))          # firewall off: everything reachable

    def test_firewall_snapshot_busctl_matches_fallback(self):
        fast = g.firewall_snapshot()
        if fast['tool'] != 'firewalld' or not fast['on']:
            self.skipTest('firewalld not running')
        real_which = ns.which
        with mock.patch.object(ns, 'which', side_effect=lambda n: None if n == 'busctl' else real_which(n)):
            slow = g.firewall_snapshot()
        for k in ('on', 'zone', 'default', 'target', 'log'):
            self.assertEqual(fast[k], slow[k], k)
        self.assertEqual(sorted(fast['services']), sorted(slow['services']))
        self.assertEqual(sorted(fast['ports']), sorted(slow['ports']))
        self.assertEqual(sorted(fast['svc_ports']), sorted(slow['svc_ports']))


# ======================================================================================
class MonitorEvents(unittest.TestCase):

    def test_journal_alerts(self):
        lines = [
            {'_COMM': 'sudo', 'MESSAGE': 'pam_unix(sudo:auth): authentication failure; logname=user uid=1000'},
            {'_COMM': 'sshd-session', 'MESSAGE': 'Failed password for root from 45.155.205.99 port 4242 ssh2'},
            {'_COMM': 'sshd', 'MESSAGE': 'Accepted publickey for user from 192.168.1.5 port 5000 ssh2'},
            {'_COMM': 'polkitd', 'MESSAGE': 'Operator of unix-session:2 FAILED to authenticate to gain authorization'},
            {'_TRANSPORT': 'kernel', 'MESSAGE': 'filter_IN_home_REJECT: IN=eth0 OUT= SRC=45.155.205.99 DST=192.168.1.20 '
                                                'LEN=60 PROTO=TCP SPT=4444 DPT=22 SYN'},
            {'_TRANSPORT': 'kernel', 'MESSAGE': 'filter_IN_home_REJECT: IN=eth0 OUT= SRC=45.155.205.99 DST=192.168.1.20 '
                                                'LEN=60 PROTO=TCP SPT=4445 DPT=22 SYN'},          # repeat: grouped
            {'_TRANSPORT': 'kernel', 'MESSAGE': list(b'filter_IN_home_REJECT: IN=eth0 SRC=192.168.1.31 DST=192.168.1.20 '
                                                     b'PROTO=UDP SPT=1900 DPT=55555')},            # binary journal field
            {'_TRANSPORT': 'kernel', 'MESSAGE': 'i915 0000:00:02.0: some driver message'},          # ignored
            {'_COMM': 'NetworkManager', 'MESSAGE': "<info>  device (wlp0s20f3): state change: config -> activated "
                                                   "(reason 'none', managed-type: 'full')"},
            {'_COMM': 'NetworkManager', 'MESSAGE': 'device (veth12ab): state change: config -> activated'},  # ignored
            {'_COMM': 'firewalld', 'MESSAGE': 'ERROR: INVALID_ZONE: nonexistent'},
        ]
        m = g.Monitor(online=False)
        real_which = ns.which
        with mock.patch.object(g.subprocess, 'Popen', return_value=FakePopen(lines)), \
                mock.patch.object(ns, 'which', side_effect=lambda n: '/usr/bin/journalctl' if n == 'journalctl'
                                  else real_which(n)):         # also on systems without systemd
            m.follow_journal()
        ev = drain(m)
        t = texts(ev)
        self.assertIn('Wrong sudo password', t)
        self.assertIn('SSH: Failed password for root from 45.155.205.99', t)
        self.assertIn('SSH login: Accepted publickey', t)
        self.assertIn('Failed administrator password', t)
        self.assertIn('Blocked: 45.155.205.99 -> port 22/tcp: from the internet', t)
        self.assertEqual(t.count('45.155.205.99 -> port 22'), 1)                   # second attempt grouped
        self.assertIn('Blocked: 192.168.1.31 -> port 55555/udp: likely a reply to device discovery', t)
        self.assertIn('wlp0s20f3 activated', t)
        self.assertNotIn('veth', t)
        self.assertNotIn('i915', t)
        self.assertIn('firewalld: ERROR', t)
        self.assertTrue(all(e['notify'] for e in ev if 'sudo' in e['text'] or 'SSH' in e['text']))

    def fw(self, **kw):
        snap = {'tool': 'firewalld', 'on': True, 'zone': 'home', 'default': 'home', 'services': ['dhcpv6-client'],
                'ports': [], 'target': 'default', 'log': 'off', 'wide': [], 'svc_ports': ['546/udp']}
        snap.update(kw)
        return snap

    def test_syslog_lines_without_systemd(self):
        """OpenRC/runit systems: the same alerts come from /var/log/auth.log, messages or kern.log."""
        lines = [
            'Oct 12 19:04:30 gentoo sudo[812]: pam_unix(sudo:auth): authentication failure; logname=user uid=1000\n',
            'Oct 12 19:05:01 gentoo sshd[901]: Failed password for invalid user admin from 45.155.205.99 port 4242 ssh2\n',
            '2026-10-12T19:05:02+00:00 arch sshd[902]: Accepted publickey for user from 192.168.1.5 port 5000 ssh2\n',
            'Oct 12 19:06:00 gentoo kernel: [ 1234.5678] filter_IN_public_REJECT: IN=eth0 SRC=45.155.205.99 '
            'DST=192.168.1.9 PROTO=TCP SPT=40000 DPT=3389\n',
            'Oct 12 19:07:00 gentoo cron[1]: (root) CMD (run-parts /etc/cron.hourly)\n',          # ignored
            'not a syslog line at all\n',                                                          # ignored
        ]
        m = g.Monitor(online=False)
        m.parse_log_lines(iter(lines), journal=False)
        t = texts(drain(m))
        self.assertIn('Wrong sudo password', t)
        self.assertIn('SSH: Failed password for invalid user admin', t)
        self.assertIn('SSH login: Accepted publickey', t)
        self.assertIn('Blocked: 45.155.205.99 -> port 3389/tcp: from the internet', t)
        self.assertNotIn('cron', t)

    def test_follow_journal_falls_back_to_log_files(self):
        m = g.Monitor(online=False)
        real_which = ns.which
        with mock.patch.object(ns, 'which', side_effect=lambda n: None if n == 'journalctl' else real_which(n)), \
                mock.patch.object(m, 'follow_logfiles') as fl:
            m.follow_journal()
        fl.assert_called_once()

    def test_without_ss(self):
        real_which = ns.which
        with mock.patch.object(ns, 'which', side_effect=lambda n: None if n == 'ss' else real_which(n)):
            listen, conns = g.socket_snapshot()
        with_ss, _ = g.socket_snapshot()
        exposed = lambda socks: sorted(set((s['proto'], s['port']) for s in socks if s['scope'] != 'loopback'
                                           and not s['ephemeral']))
        self.assertEqual(exposed(listen), exposed(with_ss))
        for c in conns:
            self.assertEqual(len(c), 6)

    def test_ufw_rules_unknown_without_root(self):
        snap = {'on': True, 'target': 'default', 'ports': [], 'services': [], 'rules_known': False}
        self.assertIsNone(g.fw_allows(snap, 'tcp', 51413, []))

    def test_firewall_change_events(self):
        m = g.Monitor(online=False)
        m.prev['fw'] = self.fw(zone='FedoraWorkstation', services=['ssh', 'dhcpv6-client'], ports=['1025-65535/tcp'])
        with mock.patch.object(g, 'firewall_snapshot', return_value=self.fw(services=['dhcpv6-client', 'kdeconnect'],
                                                                         log='unicast')):
            m.t_firewall(False)
        t = texts(drain(m))
        for want in ('profile: FedoraWorkstation -> home', 'now lets in: kdeconnect', 'no longer lets in: ssh',
                     'closed port 1025-65535/tcp', 'blocked attempts: unicast'):
            self.assertIn(want, t)
        with mock.patch.object(g, 'firewall_snapshot', return_value=self.fw(on=False)):
            m.t_firewall(False)
        ev = drain(m)
        self.assertEqual(ev[0]['level'], 'risk')
        self.assertTrue(ev[0]['notify'])
        self.assertIn('Firewall turned OFF', ev[0]['text'])

    def test_live_port_open_and_close(self):
        port = free_port()
        m = g.Monitor(online=False)
        m.t_firewall(True)
        m.t_sockets(True)
        drain(m)
        srv = subprocess.Popen([sys.executable, '-m', 'http.server', str(port), '--bind', '0.0.0.0'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            opened = ''
            for _ in range(20):
                time.sleep(0.5)
                m.t_sockets(False)
                opened = texts(drain(m))
                if 'Port %d/tcp opened' % port in opened:
                    break
            self.assertIn('Port %d/tcp opened' % port, opened)
            self.assertIn('python', opened.lower())
        finally:
            srv.terminate()
            srv.wait()
        time.sleep(0.5)
        m.t_sockets(False)
        self.assertIn('Port %d/tcp closed' % port, texts(drain(m)))

    def test_connection_events(self):
        m = g.Monitor(online=False)
        m.prev['exposed'] = {('tcp', 1716): 'kdeconnect'}
        m.check_connections(True, [])
        rows = [('tcp', '192.168.1.20', 1716, '45.155.205.50', 50000, 'kdeconnect'),     # inbound from the internet
                ('tcp', '192.168.1.20', 41000, '198.51.100.4', 4444, 'curl'),            # unusual outbound port
                ('tcp', '192.168.1.20', 41001, '151.101.1.140', 443, 'firefox')]
        m.check_connections(False, rows)
        ev = drain(m)
        t = texts(ev)
        self.assertIn('Incoming connection: 45.155.205.50 -> port 1716/tcp', t)
        self.assertIn('unusual port 4444', t)
        self.assertIn('firefox -> 151.101.1.140:443', t)
        self.assertTrue(next(e for e in ev if 'Incoming' in e['text'])['notify'])
        conn = next(e for e in ev if 'firefox' in e['text'])
        self.assertEqual(conn['cat'], 'conn')                                     # hidden by default filter
        m.check_connections(False, rows)
        self.assertFalse([e for e in drain(m) if 'firefox' in e['text']])        # same peer: no repeat

    def net(self, m, arp, vpn=None, first=False):
        with mock.patch.object(ns, 'default_routes_v4', return_value=[{'iface': 'eth0', 'gateway': '192.168.1.1', 'metric': 1}]), \
                mock.patch.object(ns, 'default_routes_v6', return_value=[]), \
                mock.patch.object(ns, 'arp_table', return_value=arp), \
                mock.patch.object(ns, 'active_vpn', return_value=vpn), \
                mock.patch.object(ns, 'global_ipv6_addresses', return_value=[]):
            m.t_network(first)
        return drain(m)

    def test_network_events(self):
        gw = {'ip': '192.168.1.1', 'mac': 'aa:aa:aa:aa:aa:aa', 'iface': 'eth0'}
        m = g.Monitor(online=False)
        self.net(m, [gw], first=True)
        t = texts(self.net(m, [gw, {'ip': '192.168.1.77', 'mac': 'bb:bb:bb:bb:bb:bb', 'iface': 'eth0'}]))
        self.assertIn('New device on your network: 192.168.1.77', t)
        ev = self.net(m, [gw], vpn='wg0')
        self.assertIn('VPN connected (wg0)', texts(ev))
        ev = self.net(m, [dict(gw, mac='cc:cc:cc:cc:cc:cc')], vpn='wg0')
        risk = [e for e in ev if e['level'] == 'risk']
        self.assertTrue(risk and 'hardware address changed' in risk[0]['text'] and risk[0]['notify'])
        ev = self.net(m, [dict(gw, mac='cc:cc:cc:cc:cc:cc'), {'ip': '192.168.1.66', 'mac': 'cc:cc:cc:cc:cc:cc', 'iface': 'eth0'}])
        self.assertIn('Possible ARP spoofing', texts(ev))

    def test_devices_task_scans_once_then_on_request(self):
        fake = {'iface': 'eth0', 'gateway': '10.0.0.1', 'scanned': False,
                'devices': [{'ip': '10.0.0.1', 'mac': '00:00:5e:00:53:01', 'name': 'Router', 'kind': 'router'}],
                'names': {'00:00:5e:00:53:42': ('Pixel-8', 'mdns')}}
        m = g.Monitor(online=False)
        with mock.patch.object(ns, 'lan_devices', return_value=fake) as ld:
            m.t_devices(True)                                     # first round: quick list, no scan yet
            self.assertFalse(ld.call_args.kwargs['scan'])
            self.assertEqual(m.get()['devices']['list'][0]['name'], 'Router')
            m.t_devices(False)                                    # then one scan soon after start
            self.assertTrue(ld.call_args.kwargs['scan'])
            m.t_devices(False)                                    # later rounds: passive
            self.assertFalse(ld.call_args.kwargs['scan'])
            m.request_scan()
            m.t_devices(False)
            self.assertTrue(ld.call_args.kwargs['scan'])
        self.assertEqual(m.dev_names['00:00:5e:00:53:42'], ('Pixel-8', 'mdns'))     # names asked once
        self.assertIn('Scanned your network: 1 device', texts(drain(m)))

    def test_named_device_comes_back(self):
        ns.save_device_label('00:00:5e:00:53:31', 'Living room TV')
        try:
            gw = {'ip': '192.168.1.1', 'mac': 'aa:aa:aa:aa:aa:aa', 'iface': 'eth0'}
            m = g.Monitor(online=False)
            self.net(m, [gw], first=True)
            t = texts(self.net(m, [gw, {'ip': '192.168.1.31', 'mac': '00:00:5e:00:53:31', 'iface': 'eth0'}]))
            self.assertIn('Back on your network: Living room TV (192.168.1.31)', t)
        finally:
            ns.save_device_label('00:00:5e:00:53:31', '')

    def test_certificate_and_dns_events(self):
        m = g.Monitor(online=False)
        anchor = {'sha256': 'ab' * 32, 'subject_cn': 'Evil Root CA', 'subject_o': 'Evil', 'path': '/x.crt',
                  'shipped_by_os': False}
        with mock.patch.object(ns, 'local_ca_anchors', return_value=[]):
            m.t_certs(True)
        with mock.patch.object(ns, 'local_ca_anchors', return_value=[anchor]):
            m.t_certs(False)
        ev = drain(m)
        self.assertTrue(ev and ev[0]['level'] == 'risk' and 'NEW trusted root certificate: Evil Root CA' in ev[0]['text'])
        with mock.patch.object(ns, 'local_ca_anchors', return_value=[]):
            m.t_certs(False)
        self.assertIn('Root certificate removed', texts(drain(m)))
        on = {'encrypted': True, 'llmnr': False, 'servers': ['1.1.1.1'], 'resolved': True}
        with mock.patch.object(ns, 'dns_state', return_value=on):
            m.t_dns(True)
        with mock.patch.object(ns, 'dns_state', return_value=dict(on, encrypted=False, llmnr=True, servers=['192.168.1.1'])):
            m.t_dns(False)
        t = texts(drain(m))
        for want in ('DNS encryption OFF', 'LLMNR on', 'DNS servers: 192.168.1.1'):
            self.assertIn(want, t)


# ======================================================================================
@unittest.skipUnless(HAVE_DISPLAY, 'needs a display and tkinter')
class AppWindow(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        os.makedirs(g.STATE_DIR, exist_ok=True)
        recent = time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(time.time() - 60))
        with open(g.EVENT_LOG, 'w') as f:                     # history that should be shown again
            f.write(json.dumps({'time': recent, 'level': 'you', 'category': 'you', 'text': 'Old test action'}) + '\n')
        cls.root = g.tk.Tk(className='nstest')
        cls.app = g.NetworkScoutApp(cls.root, argparse.Namespace(widget=False, offline=True, layout='wide'))
        cls.pump(lambda: cls.app.monitor.get().get('ready'), 25)

    @classmethod
    def tearDownClass(cls):
        cls.app.monitor.stop()
        cls.root.destroy()

    @classmethod
    def pump(cls, cond, seconds):
        end = time.time() + seconds
        while time.time() < end:
            cls.root.update()
            if cond():
                return True
            time.sleep(0.05)
        return False

    def auto_close_dialogs(self, delay=400):
        def close():
            for w in self.root.winfo_children():
                if isinstance(w, g.tk.Toplevel):
                    w.destroy()
        self.root.after(delay, close)

    def test_ready_and_rendered(self):
        self.assertTrue(self.app.monitor.get().get('ready'))
        self.app.render(self.app.monitor.get())
        self.root.update()
        self.assertGreater(len(self.app.cv.find_all()), 80)
        self.assertTrue(self.app.two_col)
        self.assertEqual(self.root.winfo_width(), g.WINDOW_WIDTH)

    def test_history_reloaded(self):
        self.assertIn('Old test action', texts(self.app.events))

    def test_filters_scroll_and_notify(self):
        st = self.app.monitor.get()
        for cat in ('alert', 'net', 'conn', 'you'):
            self.app.toggle_filter(cat)
            self.app.render(st)
            self.app.toggle_filter(cat)
        for i in range(120):
            self.app.you('test event %d' % i)
        self.pump(lambda: False, 1)
        self.app.render(st)
        top, bottom, x1, x2 = self.app.events_area
        ev = mock.Mock(num=5, delta=0, x=(x1 + x2) / 2, y=(top + bottom) / 2)
        self.app.on_wheel(ev)
        self.assertGreater(self.app.scroll, 0)
        self.app.render(st)
        before = self.app.cfg['notify']
        self.app.toggle_notify()
        with open(g.CONFIG_PATH) as f:
            self.assertEqual(json.load(f)['notify'], not before)
        self.app.toggle_notify()

    def test_dialogs(self):
        self.auto_close_dialogs()
        self.assertEqual(self.app.ask('Title', 'Body', ['Yes', 'No', 'Cancel']), 'Cancel')
        self.auto_close_dialogs()
        with mock.patch.object(self.app, 'run_ns') as run_ns:
            self.app.open_port_dialog()
        run_ns.assert_not_called()
        self.auto_close_dialogs()
        self.app.show_finding({'title': 'A finding', 'detail': 'details', 'fix': 'do something'})

    def test_background_action(self):
        self.app.run_ns('t_dns', ['dns'], 'DNS status (test)', privileged=False)
        ok = self.pump(lambda: 'DNS status (test)' in texts(self.app.events), 60)
        self.assertTrue(ok)
        self.assertNotIn('t_dns', self.app.busy)

    def test_missing_pkexec_is_reported(self):
        real_which = ns.which
        with mock.patch.object(ns, 'which', side_effect=lambda n: None if n == 'pkexec' else real_which(n)):
            self.app.run_ns('t_pk', ['firewall', 'on'], 'Firewall on (test)')
            ok = self.pump(lambda: 'pkexec is not installed' in texts(self.app.events), 15)
        self.assertTrue(ok)

    def test_health_card(self):
        self.app.health = {'counts': {'RISK': 1, 'WARN': 2, 'INFO': 3, 'OK': 4},
                           'findings': [{'level': 'RISK', 'title': 'Serious thing', 'detail': '', 'fix': ''},
                                        {'level': 'WARN', 'title': 'Improve thing', 'detail': '', 'fix': ''}],
                           '_mtime': time.time()}
        self.app.health_stale = True
        self.app.render(self.app.monitor.get())
        self.assertEqual(self.app.verdict(self.app.monitor.get())[0], 'AT RISK')
        self.assertIn('outdated', self.app.health_age())

    def test_render_speed(self):
        st = self.app.monitor.get()
        t = time.process_time()
        for _ in range(10):
            self.app.render(st)
            self.root.update_idletasks()
        per = (time.process_time() - t) / 10
        print('\n    render: %.0f ms CPU' % (per * 1000))
        self.assertLess(per, 0.15)

    def test_tall_layout(self):
        root2 = g.tk.Tk(className='nstest2')
        try:
            old = g.WINDOW_WIDTH
            app2 = g.NetworkScoutApp(root2, argparse.Namespace(widget=False, offline=True, layout='tall'))
            self.assertFalse(app2.two_col)
            self.assertEqual(g.WINDOW_WIDTH, g.COL_W)
            app2.monitor.stop()
            g.WINDOW_WIDTH = old
        finally:
            root2.destroy()


# ======================================================================================
class DemoMode(unittest.TestCase):
    """--demo: invented data only; the switches change the invented state and nothing on the computer."""

    def test_demo_switches_change_only_the_invented_state(self):
        m = g.DemoMonitor()
        self.assertIn('51413/tcp', m.get()['fw']['ports'])
        m.apply(['ports', 'block', 'transmission'])
        self.assertEqual(m.get()['fw']['ports'], [])
        m.apply(['ports', 'allow', '8080/tcp', '--for', '1h'])
        self.assertEqual(m.get()['fw']['ports'], ['8080/tcp'])
        m.apply(['firewall', 'off', '--for', '15m'])
        self.assertFalse(m.get()['fw']['on'])
        m.apply(['firewall', 'profile', 'public'])
        self.assertEqual(m.get()['fw']['zone'], 'public')
        m.apply(['dns', 'plain'])
        self.assertFalse(m.get()['dns']['encrypted'])
        m.apply(['run', 'steam', 'start'])
        self.assertTrue(m.get()['running']['steam'])
        self.assertIn('Firewall turned OFF', texts(drain(m)))

    def test_demo_data_uses_documentation_addresses_only(self):
        st = g.demo_state()
        for ip in (st['net']['lan_ip'], st['net']['gw']):
            self.assertTrue(ns.ip_obj(ip).is_private)
        self.assertTrue(st['public']['v4'].startswith('203.0.113.'))             # RFC 5737
        self.assertTrue(st['public']['v6'].startswith('2001:db8:'))              # RFC 3849
        self.assertTrue(st['net']['gw_mac'].startswith('00:00:5e:00:53:'))       # RFC 7042
        for _, _, _, _, text in g.DEMO_EVENTS:
            for word in text.replace('(', ' ').replace(')', ' ').split():
                a = ns.ip_obj(word.rstrip(':'))
                if a and not a.is_private:
                    self.assertTrue(any(word.startswith(p) for p in ('192.0.2.', '198.51.100.', '203.0.113.')), word)

    def test_demo_devices_are_invented(self):
        for d in g.DEMO_DEVICES:
            self.assertTrue(d['ip'].startswith('10.0.0.'), d['ip'])
            self.assertRegex(d['mac'], r'^0[02]:00:5e:00:53:')                     # RFC 7042 documentation MACs
        m = g.DemoMonitor()
        m.name_device('00:00:5e:00:53:55', 'Printer upstairs')
        self.assertIn('Printer upstairs', [d['name'] for d in m.get()['devices']['list']])
        m.request_scan()
        self.assertIn('Scanned your network', texts(drain(m)))

    @unittest.skipUnless(HAVE_DISPLAY, 'needs a display and tkinter')
    def test_demo_app_reads_and_writes_nothing(self):
        # in its own process, so monitors left over from other tests cannot run programs meanwhile
        code = r'''
import argparse, json, os, sys, time
from unittest import mock
sys.path.insert(0, sys.argv[1])
import networkscout_gui as g
calls = []
boom = lambda *a, **k: calls.append(repr(a)[:120])
root = g.tk.Tk(className="nsdemo")
with mock.patch.object(g.subprocess, "run", boom), mock.patch.object(g.subprocess, "Popen", boom), \
        mock.patch.object(g.ns, "run", boom), mock.patch.object(g, "busctl_fw", boom):
    app = g.NetworkScoutApp(root, argparse.Namespace(widget=False, offline=False, layout="wide", demo=True))
    end = time.time() + 10
    while time.time() < end and not app.monitor.get().get("ready"):
        root.update()
        time.sleep(0.05)
    app.run_ns("fw", ["firewall", "on"], "Firewall turned on")
    app.open_terminal(["fix"])
    app.run_check()
    end = time.time() + 8
    while time.time() < end and (app.busy or app.health_busy):
        root.update()
        time.sleep(0.05)
    app.tick()
    app.render(app.monitor.get())
    root.update()
    shown = " ".join(app.cv.itemcget(i, "text") for i in app.cv.find_all() if app.cv.type(i) == "text")
    app.toggle_devices_view()
    app.render(app.monitor.get())
    root.update()
    shown_dev = " ".join(app.cv.itemcget(i, "text") for i in app.cv.find_all() if app.cv.type(i) == "text")
    app.toggle_filter("alert")                           # a filter chip goes back to the events
    back = app.cfg["events_view"]
    app.monitor.stop()
print(json.dumps({"calls": calls, "shown": shown, "shown_dev": shown_dev, "back": back,
                  "events": [e["text"] for e in app.events],
                  "files": [os.path.join(d, f) for d, _, fs in os.walk(os.environ["XDG_STATE_HOME"]) for f in fs] +
                           [os.path.join(d, f) for d, _, fs in os.walk(os.environ["XDG_CONFIG_HOME"]) for f in fs]}))
'''
        home = tempfile.mkdtemp(dir=TMP)
        env = dict(os.environ, XDG_STATE_HOME=os.path.join(home, 's'), XDG_CONFIG_HOME=os.path.join(home, 'c'))
        p = subprocess.run([sys.executable, '-c', code, os.path.dirname(HERE)], stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, encoding='utf-8', env=env, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr[-800:])
        r = json.loads(p.stdout.strip().splitlines()[-1])
        self.assertEqual(r['calls'], [])                     # no programs run, no firewall asked
        self.assertEqual(r['files'], [])                     # no event log, config or lock written
        self.assertIn(g.DEMO_HOST, r['shown'])
        self.assertNotIn(os.uname().nodename, r['shown'])
        self.assertIn('203.0.113.45', r['shown'])
        for want in ('Firewall turned on', 'Demo: would open a terminal with: networkscout fix', 'Health check done'):
            self.assertTrue(any(e.startswith(want) for e in r['events']), want)
        for want in ('Devices', 'Living room TV', '00:00:5e:00:53:31', '10.0.0.55', 'Click a device to give it a name'):
            self.assertIn(want, r['shown_dev'])
        self.assertEqual(r['back'], 'events')


def tearDownModule():
    shutil.rmtree(TMP, ignore_errors=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
