#!/usr/bin/env python3
"""
================================================================================
 networkScout app - live network-security dashboard with switches
 Firewall, ports, apps, DNS and a live event feed, in pySysMon's "Midnight Ink"
 style. Uses networkscout.py (same folder) for every check and change.
 License: MIT (c) 2026 Yogesh
================================================================================
"""

import argparse
import collections
import datetime
import fcntl
import json
import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import networkscout as ns                       # noqa: E402  (core checks, standard library only)

try:
    import tkinter as tk
    from tkinter import font as tkfont
    HAS_TK = True
except ImportError:
    HAS_TK = False

# ------------------------------------------------------------------------------
# CONFIGURATION & COLOR PALETTE (shared with pySysMon / pyQuotes)
# ------------------------------------------------------------------------------
FONT_CANDIDATES = ("FantasqueSansM Nerd Font", "FantasqueSansM Nerd Font Mono", "Fantasque Sans Mono",
                   "JetBrainsMono Nerd Font", "DejaVu Sans Mono", "monospace")
FONT_PX = 14
COL_W = 480                    # width of one column of cards
TWO_COLUMNS_BELOW = 1300       # screens shorter than this get two columns side by side
EVENT_ROWS = 12                # visible rows in the live events list (more in two-column mode)
WINDOW_WIDTH = COL_W           # set at start-up: COL_W or 2 * COL_W
WIDGET_POSITION = "top-left"   # --widget mode: top-left, top-right, bottom-left, bottom-right
OFFSET_X = 24
OFFSET_Y = 24
WINDOW_OPACITY = 0.97

COLOR_BG = "#191926"
COLOR_CARD = "#20202f"
COLOR_CARD_EDGE = "#2b2b40"
COLOR_TRACK = "#2c2c42"
COLOR_FG = "#e8e8f2"
COLOR_LABEL = "#9a9ab8"
COLOR_DIM = "#62627e"
COLOR_PRIMARY = "#7dd3fc"
COLOR_ACCENT = "#c4b5fd"
COLOR_PINK = "#f9a8d4"
COLOR_SUCCESS = "#86efac"
COLOR_WARNING = "#fde68a"
COLOR_DANGER = "#fca5a5"

LEVEL_COLOR = {"risk": COLOR_DANGER, "warn": COLOR_WARNING, "info": COLOR_PRIMARY, "ok": COLOR_SUCCESS,
               "you": COLOR_ACCENT}

# Font Awesome glyphs from the Nerd Font (Basic Multilingual Plane only: Tk 8.6 cannot draw beyond it).
# Written as escapes on purpose: these private-use characters vanish when copied as literal text.
ICONS = {
    "shield": "\uf132", "fire": "\uf06d", "globe": "\uf0ac", "cubes": "\uf1b3", "bolt": "\uf0e7",
    "heart": "\uf21e", "lock": "\uf023", "unlock": "\uf09c", "key": "\uf084", "eye": "\uf06e",
    "warn": "\uf071", "check": "\uf00c", "times": "\uf00d", "info": "\uf05a", "bell": "\uf0f3",
    "clock": "\uf017", "refresh": "\uf021", "wrench": "\uf0ad", "plug": "\uf1e6", "wifi": "\uf1eb",
    "download": "\uf019", "mobile": "\uf10b", "terminal": "\uf120", "print": "\uf02f", "exchange": "\uf0ec",
    "user": "\uf007", "server": "\uf233", "ban": "\uf05e", "plus": "\uf067", "file": "\uf15c",
    "sitemap": "\uf0e8", "secret": "\uf21b", "laptop": "\uf109", "sync": "\uf021", "game": "\uf11b",
    "share": "\uf064", "caret": "\uf0d7",
}
APP_ICON = {"transmission": "download", "qbittorrent": "download", "deluge": "download", "kdeconnect": "mobile",
            "syncthing": "sync", "steam": "game", "localsend": "share", "ssh": "terminal", "samba": "server",
            "mdns": "sitemap", "printing": "print"}
# desktop apps the "Running" switch can start/stop: name -> (flatpak id or None, native commands)
LAUNCH = {
    "transmission": ("com.transmissionbt.Transmission", ["transmission-gtk", "transmission-qt"]),
    "qbittorrent": ("org.qbittorrent.qBittorrent", ["qbittorrent"]),
    "deluge": ("org.deluge_torrent.deluge", ["deluge-gtk", "deluge"]),
    "localsend": ("org.localsend.localsend_app", ["localsend_app", "localsend"]),
    "steam": ("com.valvesoftware.Steam", ["steam"]),
    "syncthing": (None, ["syncthing"]),
}
SHOW_ALWAYS = ("transmission", "kdeconnect", "ssh")
SUSPICIOUS_PORTS = {23, 2323, 4444, 4445, 1337, 31337, 6666, 6667, 6697, 12345, 54321}
ZONE_SHORT = {"drop": "strict: ignore all incoming", "block": "refuse all incoming",
              "public": "caf\u00e9s, airports, unknown networks", "work": "workplace", "home": "home network",
              "internal": "trusted internal network", "trusted": "NO protection", "external": "router with NAT",
              "dmz": "exposed server", "FedoraWorkstation": "Fedora default (ports 1025+ open)",
              "FedoraServer": "server default"}

STATE_DIR = os.path.join(os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state"), "networkscout")
CONFIG_PATH = os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"),
                           "networkscout", "app.json")
EVENT_LOG = os.path.join(STATE_DIR, "events.log")
NS_SCRIPT = os.path.join(HERE, "networkscout.py")
ROOT_PYTHON = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else sys.executable


def mix_color(c1, c2, t):
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join("%02x" % round(x + (y - x) * t) for x, y in zip(a, b))


def notify_text(text):
    """Notification servers read simple HTML markup; event text can come from outside (journal, network)."""
    text = "".join(c for c in text if c >= " ")[:300]
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def now_hm():
    return time.strftime("%H:%M:%S")


# ------------------------------------------------------------------------------
# FAST SYSTEM QUERIES (busctl / ss / nmcli: small C programs, ~10-30 ms each)
# ------------------------------------------------------------------------------
def busctl_fw(method, iface="org.fedoraproject.FirewallD1", sig=None, *args):
    cmd = ["busctl", "--system", "--json=short", "call", "org.fedoraproject.FirewallD1",
           "/org/fedoraproject/FirewallD1", iface, method]
    if sig:
        cmd += [sig] + [str(a) for a in args]
    r = ns.run(cmd, 5)
    if not r or r[0] != 0:
        return None
    try:
        return json.loads(r[1])["data"]
    except (ValueError, KeyError):
        return None


def firewall_snapshot():
    """{'tool','on','zone','default','services','ports','target','log','wide'} using busctl when possible."""
    snap = {"tool": None, "on": None, "zone": None, "default": None, "services": [], "ports": [],
            "target": "default", "log": "off", "wide": []}
    dev = (ns.default_routes_v4() or ns.default_routes_v6() or [{}])[0].get("iface")
    if ns.which("busctl") and ns.which("firewall-cmd"):
        st = ns.run(["busctl", "--system", "--json=short", "get-property", "org.fedoraproject.FirewallD1",
                     "/org/fedoraproject/FirewallD1", "org.fedoraproject.FirewallD1", "state"], 5)
        snap["tool"] = "firewalld"
        if not st or st[0] != 0:
            snap["on"] = False
            return snap
        snap["on"] = '"RUNNING"' in st[1]
        default = busctl_fw("getDefaultZone")
        snap["default"] = default[0] if default else None
        zone = busctl_fw("getZoneOfInterface", "org.fedoraproject.FirewallD1.zone", "s", dev) if dev else None
        snap["zone"] = (zone[0] if zone and zone[0] else None) or snap["default"]
        settings = busctl_fw("getZoneSettings2", "org.fedoraproject.FirewallD1.zone", "s", snap["zone"]) \
            if snap["zone"] else None
        if settings:
            d = settings[0] if isinstance(settings, list) else settings
            snap["services"] = d.get("services", {}).get("data", [])
            snap["ports"] = ["%s/%s" % (p, pr) for p, pr in d.get("ports", {}).get("data", [])]
            snap["target"] = d.get("target", {}).get("data", "default")
        log = busctl_fw("getLogDenied")
        snap["log"] = log[0] if log else "off"
    else:
        fw = ns.firewall_state()
        snap.update(tool=fw["tool"], on=fw["active"], zone=fw.get("zone"), target=fw.get("target") or "default",
                    rules_known=fw["tool"] == "firewalld" or (fw["tool"] == "ufw" and ns.is_root()))
        if fw["tool"] == "firewalld" and fw["active"]:
            info = ns.fwd_zone_info(fw["zone"])
            snap["services"], snap["ports"] = info["services"], info["ports"]
            snap["default"] = ns.stdout_of(["firewall-cmd", "--get-default-zone"], 10).strip()
            snap["log"] = ns.stdout_of(["firewall-cmd", "--get-log-denied"], 10).strip() or "off"
    snap["svc_ports"] = [pp for svc in snap["services"] for pp in service_ports(svc)] \
        if snap["tool"] == "firewalld" else []
    snap["wide"] = [p for p in snap["ports"] if "-" in p.split("/")[0] and
                    int(p.split("/")[0].split("-")[1]) - int(p.split("/")[0].split("-")[0]) >= 1000]
    return snap


_SVC_CACHE = {}


def service_ports(svc):
    """Ports of a firewalld service, via busctl (fast); falls back to firewall-cmd."""
    if svc not in _SVC_CACHE:
        d = busctl_fw("getServiceSettings2", "org.fedoraproject.FirewallD1", "s", svc)
        if d:
            d = d[0] if isinstance(d, list) else d
            _SVC_CACHE[svc] = ["%s/%s" % (p, pr) for p, pr in d.get("ports", {}).get("data", [])]
        else:
            _SVC_CACHE[svc] = list(ns.fwd_service_ports(svc))
    return _SVC_CACHE[svc]


def fw_allows(snap, proto, port, services_ports):
    """True if the firewall zone lets this port in (by service, port rule or range); None if unknown."""
    if not snap.get("on"):
        return snap.get("on") is False or None
    if not snap.get("rules_known", True):
        return None
    if (snap.get("target") or "").upper() == "ACCEPT":
        return True
    return ns.port_specs_cover(snap["ports"] + services_ports, proto, port)


def friendly_owner(cgroup):
    """'app-flatpak-com.transmissionbt.Transmission-1234.scope' -> 'Transmission'."""
    unit = ns.unit_from_cgroup(cgroup)
    if not unit:
        return ""
    unit = re.sub(r"^flatpak-", "", unit).split("@")[0]
    if "." in unit and not unit.startswith("systemd"):
        parts = [x for x in unit.split(".") if x.lower() not in ("daemon", "desktop", "app", "service")]
        unit = parts[-1] if parts else unit
    return unit


def proc_connections():
    """Established TCP connections from /proc (used when `ss` is not installed)."""
    conns = []
    for path in ("/proc/net/tcp", "/proc/net/tcp6"):
        for line in (ns.read(path) or "").splitlines()[1:]:
            f = line.split()
            if len(f) > 3 and f[3] == "01":
                try:
                    lip, lport = ns._hex_addr(f[1])
                    pip, pport = ns._hex_addr(f[2])
                except (ValueError, IndexError):
                    continue
                conns.append(("tcp", lip, lport, pip, pport, ""))
    return conns


def socket_snapshot():
    """One `ss` call (no per-process lookup, ~30 ms): listening sockets and established connections.
    Without `ss` (minimal systems) the same comes from /proc."""
    if not ns.which("ss"):
        try:
            return ns.listening_sockets(), proc_connections()
        except Exception:
            return [], []
    rng = (ns.read("/proc/sys/net/ipv4/ip_local_port_range") or "32768 60999").split()
    lo, hi = int(rng[0]), int(rng[1])
    listen, conns = [], []
    for line in ns.stdout_of(["ss", "-H", "-tuane"], 5).splitlines():
        f = line.split()
        if len(f) < 6:
            continue
        proto, state = f[0], f[1]
        try:
            lip, lport = f[4].rsplit(":", 1)
            pip, pport = f[5].rsplit(":", 1)
            lport = int(lport)
            pport = int(pport) if pport.isdigit() else 0
        except ValueError:
            continue
        lip, pip = lip.split("%")[0].strip("[]"), pip.split("%")[0].strip("[]")
        cg = re.search(r"\bcgroup:(\S+)", line)
        owner = friendly_owner(cg.group(1)) if cg else ""
        if (proto == "tcp" and state == "LISTEN") or (proto == "udp" and state == "UNCONN"):
            a = ns.ip_obj(lip if lip not in ("*", "") else "0.0.0.0")
            if a is None:
                continue
            scope = ("all" if a.is_unspecified else "loopback" if a.is_loopback else
                     "link-local" if a.is_link_local else "lan" if a.is_private else "public")
            listen.append({"proto": proto, "addr": lip, "port": lport, "scope": scope, "process": owner,
                           "unit": owner, "user": "", "pid": None, "ephemeral": proto == "udp" and lo <= lport <= hi})
        elif state == "ESTAB":
            conns.append((proto, lip, lport, pip, pport, owner))
    return listen, conns


def process_names():
    names = set()
    for pid in os.listdir("/proc"):
        if pid.isdigit():
            try:
                with open("/proc/%s/comm" % pid) as f:
                    names.add(f.read().strip())
            except OSError:
                pass
    return names


def wifi_info():
    out = ns.stdout_of(["nmcli", "-t", "-f", "ACTIVE,SSID,SECURITY,DEVICE", "device", "wifi", "list", "--rescan", "no"], 6)
    for line in out.splitlines():
        parts = re.split(r"(?<!\\):", line)
        if parts and parts[0] == "yes" and len(parts) >= 4:
            return {"ssid": parts[1].replace("\\:", ":"), "security": parts[2] or "OPEN", "dev": parts[3]}
    return None


def installed_flatpaks():
    out = ns.stdout_of(["flatpak", "list", "--app", "--columns=application"], 20)
    return set(l.strip() for l in out.splitlines() if l.strip())


# ------------------------------------------------------------------------------
# MONITOR THREAD: polls the system and turns differences into events
# ------------------------------------------------------------------------------
class Monitor(threading.Thread):
    def __init__(self, online=True):
        super().__init__(daemon=True)
        self.online = online
        self.events = queue.Queue()
        self.lock = threading.Lock()
        self.state = {}
        self.stop_flag = threading.Event()
        self.wake = threading.Event()
        self.prev = {}
        self.seen_peers = {}
        self.conn_budget = collections.defaultdict(float)
        self.journal = None

    # -- helpers --------------------------------------------------------------
    def emit(self, level, cat, icon, text, notify=False):
        self.events.put({"t": time.time(), "level": level, "cat": cat, "icon": icon, "text": text,
                         "notify": notify})

    def set(self, **kw):
        with self.lock:
            if any(self.state.get(k) != v for k, v in kw.items()):
                self.state.update(kw)
                self.state["updated"] = time.time()

    def get(self):
        with self.lock:
            return dict(self.state)

    def refresh_now(self):
        self.wake.set()

    # -- tasks ----------------------------------------------------------------
    def t_firewall(self, first):
        snap = firewall_snapshot()
        old = self.prev.get("fw")
        self.prev["fw"] = snap
        self.set(fw=snap)
        if first or not old:
            return
        if old["on"] and snap["on"] is False:
            self.emit("risk", "alert", "fire", "Firewall turned OFF: everything listening is now reachable", True)
        elif old["on"] is False and snap["on"]:
            self.emit("ok", "alert", "fire", "Firewall turned on")
        if snap["on"] and old["on"]:
            if snap["zone"] != old["zone"]:
                self.emit("info", "alert", "fire", "Firewall profile: %s -> %s" % (old["zone"], snap["zone"]))
            for s in sorted(set(snap["services"]) - set(old["services"])):
                self.emit("warn", "alert", "unlock", "Firewall now lets in: %s" % s)
            for s in sorted(set(old["services"]) - set(snap["services"])):
                self.emit("ok", "alert", "lock", "Firewall no longer lets in: %s" % s)
            for p in sorted(set(snap["ports"]) - set(old["ports"])):
                self.emit("warn", "alert", "unlock", "Firewall now lets in port %s" % p)
            for p in sorted(set(old["ports"]) - set(snap["ports"])):
                self.emit("ok", "alert", "lock", "Firewall closed port %s" % p)
            if snap["log"] != old["log"]:
                self.emit("info", "alert", "eye", "Logging of blocked attempts: %s" % snap["log"])

    def t_sockets(self, first):
        light, conns = socket_snapshot()
        keys = sorted(set((s["proto"], s["port"]) for s in light if s["scope"] in ("all", "lan", "public")
                          and not s["ephemeral"]))
        if first or keys != self.prev.get("exposed_keys"):
            try:                                   # exact process names, only when the open ports change
                self.prev["full"] = ns.listening_sockets()
            except Exception:
                self.prev["full"] = light
        self.prev["exposed_keys"] = keys
        socks = self.prev["full"]
        exposed = {}
        for s in socks:
            if s["scope"] in ("all", "lan", "public") and not s["ephemeral"]:
                exposed[(s["proto"], s["port"])] = ns.describe_owner(s)
        old = self.prev.get("exposed")
        self.prev["exposed"] = exposed
        self.set(listeners=socks, exposed=exposed)
        self.check_connections(first, conns)
        if first or old is None:
            return
        fw = self.prev.get("fw") or {}
        if old is None:
            return
        for key in sorted(set(exposed) - set(old)):
            proto, port = key
            reach = fw_allows(fw, proto, port, fw.get("svc_ports", []))
            name = ns.PORTS.get(port, ("", ""))[0]
            self.emit("warn" if reach else "info", "alert", "unlock" if reach else "plug",
                      "Port %d/%s opened by %s%s%s" % (port, proto, exposed[key], " (%s)" % name if name else "",
                                                       ": reachable from your network" if reach else ", blocked by firewall"),
                      bool(reach))
        for key in sorted(set(old) - set(exposed)):
            self.emit("info", "net", "plug", "Port %d/%s closed (%s)" % (key[1], key[0], old[key]))

    def check_connections(self, first, rows):
        exposed_ports = set(p for _, p in (self.prev.get("exposed") or {}))
        inbound, outbound = [], []
        for proto, _lip, lport, pip, pport, owner in rows:
            a = ns.ip_obj(pip)
            if not a or a.is_loopback:
                continue
            if lport in exposed_ports:
                inbound.append((pip, lport, proto, owner))
            else:
                outbound.append((pip, pport, proto, owner))
        self.set(conn_count=len(outbound), inbound_count=len(inbound))
        now = time.time()
        for pip, lport, proto, owner in inbound:
            key = ("in", pip, lport)
            if key not in self.seen_peers and not first:
                self.emit("warn" if not ns.ip_obj(pip).is_private else "info", "alert", "exchange",
                          "Incoming connection: %s -> port %d/%s (%s)" % (pip, lport, proto, owner or "?"),
                          not ns.ip_obj(pip).is_private)
            self.seen_peers[key] = now
        for pip, pport, _proto, owner in outbound:
            net = pip.rsplit(".", 1)[0] if ":" not in pip else ":".join(pip.split(":")[:4])
            key = ("out", owner, net)
            if key in self.seen_peers:
                self.seen_peers[key] = now
                continue
            self.seen_peers[key] = now
            if first:
                continue
            if pport in SUSPICIOUS_PORTS:
                self.emit("warn", "alert", "warn", "%s connected to %s on unusual port %d" % (owner or "a program", pip, pport), True)
            elif now - self.conn_budget[owner] > 2:
                self.conn_budget[owner] = now
                self.emit("info", "conn", "exchange", "%s -> %s:%d" % (owner or "system", pip, pport))
        if len(self.seen_peers) > 5000:
            cutoff = now - 1800
            self.seen_peers = {k: v for k, v in self.seen_peers.items() if v > cutoff}

    def t_network(self, first):
        v4, v6 = ns.default_routes_v4(), ns.default_routes_v6()
        dev = (v4 or v6 or [{}])[0].get("iface")
        gw = v4[0]["gateway"] if v4 else (v6[0]["gateway"] if v6 else None)
        arp = ns.arp_table()
        gw_mac = next((a["mac"] for a in arp if a["ip"] == gw), None)
        vpn = ns.active_vpn()
        lan_ip = None
        for line in ns.stdout_of(["ip", "-4", "-o", "addr", "show", "dev", dev], 3).splitlines() if dev else []:
            m = re.search(r"inet (\S+)/", line)
            if m:
                lan_ip = m.group(1)
        if not lan_ip:
            lan_ip = next(iter(sorted(ns.my_lan_ips())), None)
        devices = {(a["ip"], a["mac"]) for a in arp if a["iface"] == dev}
        old = self.prev.get("net")
        self.prev["net"] = {"dev": dev, "gw": gw, "gw_mac": gw_mac, "vpn": vpn, "devices": devices}
        self.set(net={"dev": dev, "gw": gw, "gw_mac": gw_mac, "vpn": vpn, "lan_ip": lan_ip,
                      "devices": len(devices), "ipv6": bool(ns.global_ipv6_addresses())})
        twins = [a["ip"] for a in arp if gw_mac and a["mac"] == gw_mac and a["ip"] != gw and a["iface"] == dev]
        if twins and (not old or not old.get("twins_reported")):
            self.emit("risk", "alert", "warn", "Possible ARP spoofing: %s also claims to be your router (%s)"
                      % (", ".join(twins), gw_mac), True)
            self.prev["net"]["twins_reported"] = True
        if first or not old:
            return
        if dev != old["dev"] or gw != old["gw"]:
            self.emit("info", "net", "plug", "Network changed: %s via router %s" % (dev or "offline", gw or "-"))
        elif gw_mac and old["gw_mac"] and gw_mac != old["gw_mac"]:
            self.emit("risk", "alert", "warn", "Your router's hardware address changed (%s -> %s): new router, "
                                              "or someone impersonating it" % (old["gw_mac"], gw_mac), True)
        if vpn != old["vpn"]:
            self.emit("ok" if vpn else "warn", "net", "secret", "VPN %s" % ("connected (%s)" % vpn if vpn else "disconnected"))
        if dev == old["dev"]:
            for ip, mac in sorted(devices - old["devices"]):
                if not any(ip == o[0] for o in old["devices"]):
                    self.emit("info", "net", "laptop", "New device on your network: %s (%s)" % (ip, mac))

    def t_wifi(self, first):
        w = wifi_info()
        old = self.prev.get("wifi", "unset")
        self.prev["wifi"] = w
        self.set(wifi=w)
        if not first and old != "unset" and w and (not old or old.get("ssid") != w["ssid"]):
            open_net = w["security"] in ("", "--", "OPEN") or "WEP" in w["security"]
            self.emit("risk" if open_net else "info", "net", "wifi", "Wi-Fi: joined \"%s\" (%s)" % (w["ssid"], w["security"]),
                      open_net)

    def t_dns(self, first):
        try:
            st = ns.dns_state()
        except Exception:
            return
        old = self.prev.get("dns")
        self.prev["dns"] = st
        self.set(dns=st)
        if first or not old:
            return
        if st["encrypted"] != old["encrypted"]:
            self.emit("ok" if st["encrypted"] else "warn", "alert", "key",
                      "DNS encryption %s" % ("on" if st["encrypted"] else "OFF"))
        if st["llmnr"] != old["llmnr"]:
            self.emit("warn" if st["llmnr"] else "ok", "alert", "sitemap", "LLMNR %s" % ("on" if st["llmnr"] else "off"))
        if st["servers"] != old["servers"]:
            self.emit("info", "net", "sitemap", "DNS servers: %s" % (", ".join(st["servers"][:3]) or "none"))

    def t_certs(self, first):
        try:
            anchors = {a["sha256"]: a for a in ns.local_ca_anchors()}
        except Exception:
            return
        old = self.prev.get("certs")
        self.prev["certs"] = anchors
        self.set(certs=[a for a in anchors.values() if not a["shipped_by_os"]])
        if first or old is None:
            return
        for k in set(anchors) - set(old):
            a = anchors[k]
            self.emit("risk", "alert", "key", "NEW trusted root certificate: %s" % (a.get("subject_cn") or a.get("subject_o")
                                                                                    or a["path"]), True)
        for k in set(old) - set(anchors):
            self.emit("ok", "alert", "key", "Root certificate removed: %s" % (old[k].get("subject_cn") or old[k]["path"]))

    def t_apps(self, first):
        names = process_names()
        running = {}
        for key, app in ns.APPS.items():
            rx = re.compile(app["proc"])
            running[key] = any(rx.search(n.lower()) for n in names)
        old = self.prev.get("running")
        self.prev["running"] = running
        self.set(running=running)
        if first or not old:
            return
        for key in running:
            if running[key] != old.get(key) and key in LAUNCH:
                self.emit("info", "you", APP_ICON.get(key, "cubes"), "%s %s" % (
                    ns.APPS[key]["label"], "started" if running[key] else "stopped"))

    def t_installed(self, first):
        fl = installed_flatpaks() if ns.which("flatpak") else set()
        inst = {}
        for key, (fid, cmds) in LAUNCH.items():
            inst[key] = (fid if fid in fl else None) or next((c for c in cmds if ns.which(c)), None)
        self.set(installed=inst)

    def t_public(self, first):
        if not self.online:
            return
        info = {}
        for fam, url in ((4, "https://1.1.1.1/cdn-cgi/trace"), (6, "https://[2606:4700:4700::1111]/cdn-cgi/trace")):
            try:
                status, _, body = ns.http_get(url, timeout=6)
                d = dict(l.split("=", 1) for l in body.decode().splitlines() if "=" in l)
                info["v%d" % fam] = d.get("ip")
                info.setdefault("loc", d.get("loc"))
            except Exception:
                info["v%d" % fam] = None
        old = self.prev.get("public")
        self.prev["public"] = info
        if info.get("v4") and (not old or old.get("v4") != info.get("v4")):
            info["owner"] = ns.ip_owner(info["v4"], True)
        elif old:
            info["owner"] = old.get("owner")
        self.set(public=info)
        if old and info.get("v4") and old.get("v4") and info["v4"] != old["v4"]:
            self.emit("info", "net", "globe", "Public IP changed: %s -> %s" % (old["v4"], info["v4"]))

    # -- journal follower (wrong passwords, SSH logins, blocked attempts) --------
    LOG_FILES = ("/var/log/auth.log", "/var/log/secure", "/var/log/messages", "/var/log/syslog", "/var/log/kern.log")
    SYSLOG_LINE = re.compile(r"^(?:\w{3}\s+\d+\s+[\d:]+|\d{4}-\d\d-\d\dT\S+)\s+\S+\s+"
                             r"([^\s:\[]+)(?:\[\d+\])?:\s*(.*)$")

    def follow_logfiles(self):
        """For systems without the systemd journal (OpenRC, runit, s6...): tail the classic log files."""
        files = [p for p in self.LOG_FILES if os.access(p, os.R_OK)]
        if not files:
            return

        def lines():
            handles = {}
            for p in files:
                try:
                    f = open(p, "r", encoding="utf-8", errors="replace")
                    f.seek(0, 2)
                    handles[p] = (f, os.fstat(f.fileno()).st_ino)
                except OSError:
                    pass
            while not self.stop_flag.is_set():
                got = False
                for p, (f, ino) in list(handles.items()):
                    for line in f.readlines():
                        got = True
                        yield line
                    try:
                        if os.stat(p).st_ino != ino:             # log rotated: start on the new file
                            f.close()
                            nf = open(p, "r", encoding="utf-8", errors="replace")
                            handles[p] = (nf, os.fstat(nf.fileno()).st_ino)
                    except OSError:
                        pass
                if not got:
                    time.sleep(1)

        self.parse_log_lines(lines(), journal=False)

    def follow_journal(self):
        if not ns.which("journalctl"):
            self.follow_logfiles()
            return
        cmd = ["journalctl", "-f", "-n", "0", "-o", "json", "_COMM=sudo", "+", "_COMM=sshd", "+", "_COMM=sshd-session",
               "+", "_COMM=polkitd", "+", "_COMM=firewalld", "+", "_TRANSPORT=kernel", "+", "_COMM=NetworkManager"]
        try:
            self.journal = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                            encoding="utf-8", errors="replace")
        except OSError:
            return
        self.parse_log_lines(self.journal.stdout, journal=True)

    def parse_log_lines(self, source, journal=True):
        """Turn journal (JSON) or syslog-style lines into events."""
        blocked_seen = {}
        for line in source:
            if self.stop_flag.is_set():
                break
            if journal:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                msg = e.get("MESSAGE") or ""
                if isinstance(msg, list):
                    msg = bytes(msg).decode("utf-8", "replace")
                comm = e.get("_COMM", "")
            else:
                m = self.SYSLOG_LINE.match(line.strip())
                if not m:
                    continue
                comm, msg = m.group(1), m.group(2)
                e = {"_TRANSPORT": "kernel"} if comm == "kernel" else {}
            if comm == "sudo" and ("incorrect password" in msg or "authentication failure" in msg):
                self.emit("warn", "alert", "user", "Wrong sudo password (%s)" % (e.get("_UID") and msg.split(":")[0] or "sudo"), True)
            elif comm.startswith("sshd") and ("Failed password" in msg or "Invalid user" in msg):
                self.emit("warn", "alert", "terminal", "SSH: %s" % msg[:90], True)
            elif comm.startswith("sshd") and msg.startswith("Accepted "):
                self.emit("warn", "alert", "terminal", "SSH login: %s" % msg[:90], True)
            elif comm == "polkitd" and "FAILED to authenticate" in msg:
                self.emit("warn", "alert", "user", "Failed administrator password (polkit)")
            elif comm == "firewalld" and ("ERROR" in msg or "WARNING" in msg):
                self.emit("warn", "alert", "fire", "firewalld: %s" % msg[:90])
            elif comm == "NetworkManager" and re.search(r"state change: \w+ -> (activated|disconnected|unavailable)", msg):
                m = re.search(r"device \(([^)]+)\): state change: \w+ -> (\w+)", msg)
                if m and not m.group(1).startswith(("veth", "docker", "virbr", "tap")):
                    self.emit("info", "net", "plug", "%s %s" % (m.group(1), m.group(2)))
            elif e.get("_TRANSPORT") == "kernel" and ("_REJECT" in msg or "_DROP" in msg or "FINAL_REJECT" in msg) \
                    and "SRC=" in msg:
                src = re.search(r"SRC=(\S+)", msg)
                dpt = re.search(r"DPT=(\d+)", msg)
                proto = re.search(r"PROTO=(\w+)", msg)
                sip = src.group(1) if src else "?"
                port = int(dpt.group(1)) if dpt else 0
                eph = port >= 32768
                a = ns.ip_obj(sip)
                key = (sip, "eph" if eph else port)         # random high ports are grouped per sender
                rec = blocked_seen.setdefault(key, [0.0, 0])
                rec[1] += 1
                if time.time() - rec[0] > 60:
                    more = " (+%d more in the last minute)" % (rec[1] - 1) if rec[1] > 1 else ""
                    rec[0], rec[1] = time.time(), 0
                    hint = ""
                    if eph and a and a.is_private:
                        hint = ": likely a reply to device discovery (harmless)"
                    elif a and not a.is_private:
                        hint = ": from the internet"
                    self.emit("info", "alert", "ban", "Blocked: %s -> port %s/%s%s%s" % (
                        sip, port or "?", (proto.group(1).lower() if proto else "?"), hint, more))

    # -- loop -----------------------------------------------------------------
    def run(self):
        threading.Thread(target=self.follow_journal, daemon=True).start()
        tasks = [("firewall", 3, self.t_firewall), ("sockets", 4, self.t_sockets), ("network", 4, self.t_network),
                 ("apps", 4, self.t_apps), ("dns", 10, self.t_dns), ("wifi", 15, self.t_wifi),
                 ("installed", 120, self.t_installed), ("certs", 60, self.t_certs), ("public", 300, self.t_public)]
        last = collections.defaultdict(float)
        first = True
        while not self.stop_flag.is_set():
            forced = self.wake.is_set()
            self.wake.clear()
            now = time.time()
            for name, every, fn in tasks:
                if forced and name in ("public", "installed"):
                    if now - last[name] < 20:
                        continue
                if forced or now - last[name] >= every:
                    try:
                        fn(first)
                    except Exception as e:          # keep monitoring whatever happens
                        self.emit("info", "net", "info", "monitor %s: %s" % (name, str(e)[:60]))
                    last[name] = time.time()
            if first:
                self.set(ready=True)
                self.emit("ok", "you", "shield", "networkScout is watching")
            first = False
            self.wake.wait(1.0)

    def stop(self):
        self.stop_flag.set()
        self.wake.set()
        if self.journal:
            try:
                self.journal.terminate()
                self.journal.wait(timeout=3)
                self.journal.stdout.close()
            except (OSError, subprocess.TimeoutExpired, AttributeError):
                pass


# ------------------------------------------------------------------------------
# DEMO MODE (--demo): an invented computer for screenshots and for trying the switches safely.
# Addresses come from the ranges reserved for documentation (RFC 5737, RFC 3849, RFC 7042).
# ------------------------------------------------------------------------------
DEMO_HOST, DEMO_OS = "my-laptop", "Fedora Linux"


def demo_state():
    exposed = {("tcp", 51413): "transmission-gtk (flatpak-com.transmissionbt.Transmission)",
               ("udp", 51413): "transmission-gtk (flatpak-com.transmissionbt.Transmission)",
               ("tcp", 1716): "kdeconnectd", ("udp", 1716): "kdeconnectd", ("udp", 5353): "avahi-daemon",
               ("tcp", 8000): "python3 (a web server you started)"}
    listeners = [{"addr": "0.0.0.0", "ephemeral": False, "pid": None, "port": port, "process": owner.split()[0],
                  "proto": proto, "scope": "all", "unit": "", "user": "me"} for (proto, port), owner in exposed.items()]
    listeners.append({"addr": "127.0.0.1", "ephemeral": False, "pid": None, "port": 631, "process": "cupsd",
                      "proto": "tcp", "scope": "loopback", "unit": "cups.service", "user": "root"})
    return {
        "fw": {"tool": "firewalld", "on": True, "zone": "home", "default": "home", "target": "default",
               "log": "unicast", "services": ["dhcpv6-client", "mdns", "kdeconnect"], "ports": ["51413/tcp", "51413/udp"],
               "svc_ports": ["546/udp", "5353/udp", "1714-1764/tcp", "1714-1764/udp"], "wide": [], "rules_known": True},
        "dns": {"resolved": True, "encrypted": True, "ours": True, "provider": "Quad9", "current": "9.9.9.9",
                "servers": ["9.9.9.9", "149.112.112.112"], "llmnr": False},
        "net": {"dev": "wlan0", "lan_ip": "10.0.0.23", "gw": "10.0.0.1", "gw_mac": "00:00:5e:00:53:01", "ipv6": True,
                "vpn": None, "devices": 6},
        "wifi": {"dev": "wlan0", "ssid": "Home-WiFi", "security": "WPA2"},
        "public": {"v4": "203.0.113.45", "v6": "2001:db8:4a1:7::23", "owner": "Example ISP (XX)", "loc": "XX"},
        "installed": {"transmission": "com.transmissionbt.Transmission", "steam": "com.valvesoftware.Steam",
                      "qbittorrent": None, "deluge": None, "localsend": None, "syncthing": None},
        "running": {"transmission": True, "kdeconnect": True, "mdns": True, "printing": True, "steam": False,
                    "ssh": False, "samba": False, "syncthing": False, "localsend": False, "qbittorrent": False,
                    "deluge": False},
        "listeners": listeners, "exposed": exposed, "certs": [], "conn_count": 23, "inbound_count": 2,
    }


# (seconds ago, level, category, icon, text)
DEMO_EVENTS = [
    (2700, "ok", "you", "shield", "networkScout is watching"),
    (2400, "you", "you", "check", "Encrypted DNS turned on (checked: names still resolve)"),
    (2280, "ok", "alert", "key", "DNS is now encrypted (Quad9)"),
    (1900, "info", "net", "wifi", "Wi-Fi: joined \"Home-WiFi\" (WPA2)"),
    (1750, "info", "net", "laptop", "New device on your network: 10.0.0.31 (00:00:5e:00:53:31)"),
    (1500, "info", "alert", "ban", "Blocked: 10.0.0.31 -> port 8009/tcp"),
    (1210, "warn", "alert", "terminal", "SSH: Failed password for invalid user admin from 198.51.100.77 port 52144"),
    (1180, "info", "alert", "ban", "Blocked: 198.51.100.77 -> port 22/tcp: from the internet"),
    (900, "you", "you", "check", "Allowed incoming for Transmission (BitTorrent)"),
    (880, "warn", "alert", "unlock", "Firewall now lets in port 51413/tcp"),
    (600, "info", "conn", "exchange", "firefox -> 203.0.113.80:443"),
    (420, "info", "alert", "plug", "Port 8000/tcp opened by python3, blocked by firewall"),
    (300, "info", "alert", "ban", "Blocked: 192.0.2.14 -> port 3389/tcp: from the internet"),
    (120, "info", "net", "plug", "New device on your network: 10.0.0.42 (00:00:5e:00:53:42)"),
    (45, "info", "conn", "exchange", "steam -> 203.0.113.120:27017"),
]

DEMO_HEALTH = {
    "counts": {"RISK": 0, "WARN": 2, "INFO": 12, "OK": 21, "SKIP": 0},
    "findings": [
        {"level": "WARN", "title": "3 Flatpak app updates are waiting",
         "detail": "Apps installed from Flathub get security fixes through these updates.",
         "fix": "flatpak update   (or: networkscout fix)"},
        {"level": "WARN", "title": "SSH allows password logins",
         "detail": "Password logins can be guessed. Keys are much safer.",
         "fix": "Set PasswordAuthentication no in /etc/ssh/sshd_config, or turn SSH off if you do not use it."},
    ],
}


class DemoMonitor(Monitor):
    """--demo: the invented computer above. Nothing on this computer is read or changed; the switches only
    change the invented state."""

    def __init__(self):
        super().__init__(online=False)
        self.state = demo_state()

    def run(self):
        now = time.time()
        for ago, level, cat, icon, text in DEMO_EVENTS:
            self.events.put({"t": now - ago, "level": level, "cat": cat, "icon": icon, "text": text, "notify": False})
        self.set(ready=True)
        self.stop_flag.wait()

    def stop(self):
        self.stop_flag.set()

    def apply(self, args):
        """Change the invented state the way `networkscout <args>` would change a real computer."""
        st = self.get()
        fw, dns, running = dict(st["fw"]), dict(st["dns"]), dict(st["running"])
        a = list(args) + ["", "", ""]
        if a[0] == "firewall" and a[1] in ("on", "off"):
            fw["on"] = a[1] == "on"
            if fw["on"]:
                self.emit("ok", "alert", "fire", "Firewall turned on")
            else:
                self.emit("risk", "alert", "fire", "Firewall turned OFF: everything listening is now reachable")
        elif a[0] == "firewall" and a[1] == "profile":
            self.emit("info", "alert", "fire", "Firewall profile: %s -> %s" % (fw["zone"], a[2]))
            fw["zone"] = a[2]
        elif a[0] == "firewall" and a[1] == "log-blocked":
            fw["log"] = "unicast" if a[2] == "on" else "off"
        elif a[0] == "ports" and a[1] in ("allow", "block", "close-unused"):
            target = a[2]
            specs = ns.APPS[target]["ports"] if target in ns.APPS else ([target] if a[1] != "close-unused" else [])
            if a[1] == "allow":
                fw["ports"] = sorted(set(fw["ports"]) | set(specs))
            else:
                keep = lambda p: not any(ns.port_specs_cover([p], q.split("/")[1], int(q.split("/")[0].split("-")[0]))
                                         for q in specs)
                fw["ports"] = [p for p in fw["ports"] if keep(p)] if specs else []
                if target in ns.APPS:
                    fw["services"] = [sv for sv in fw["services"] if sv not in ns.APPS[target]["services"]]
                    fw["svc_ports"] = [p for p in fw["svc_ports"] if keep(p)]
            for spec in specs[:2]:
                if a[1] == "allow":
                    self.emit("warn", "alert", "unlock", "Firewall now lets in port %s" % spec)
                else:
                    self.emit("ok", "alert", "lock", "Firewall closed port %s" % spec)
        elif a[0] == "dns" and a[1] in ("encrypt", "plain"):
            dns.update(encrypted=a[1] == "encrypt", provider="Quad9" if a[1] == "encrypt" else None,
                       current="9.9.9.9" if a[1] == "encrypt" else "10.0.0.1",
                       servers=["9.9.9.9", "149.112.112.112"] if a[1] == "encrypt" else ["10.0.0.1"])
        elif a[0] == "dns" and a[1] == "llmnr":
            dns["llmnr"] = a[2] == "on"
        elif a[0] == "run":
            running[a[1]] = a[2] == "start"
        self.set(fw=fw, dns=dns, running=running)


# ------------------------------------------------------------------------------
# EWMH WINDOW HINTS for --widget mode (from pySysMon)
# ------------------------------------------------------------------------------
class X11DesktopHints:
    STATES = ("_NET_WM_STATE_BELOW", "_NET_WM_STATE_STICKY", "_NET_WM_STATE_SKIP_TASKBAR",
              "_NET_WM_STATE_SKIP_PAGER", "_KDE_NET_WM_STATE_SKIP_SWITCHER")

    def __init__(self, inner_window_id):
        self.inner_window, self.window, self.xlib, self.display = inner_window_id, None, None, None
        try:
            import ctypes
            import ctypes.util
            xlib = ctypes.cdll.LoadLibrary(ctypes.util.find_library("X11") or "libX11.so.6")
            xlib.XOpenDisplay.restype = ctypes.c_void_p
            xlib.XOpenDisplay.argtypes = [ctypes.c_char_p]
            xlib.XInternAtom.restype = ctypes.c_ulong
            xlib.XInternAtom.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
            xlib.XDefaultRootWindow.restype = ctypes.c_ulong
            xlib.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
            xlib.XChangeProperty.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong,
                                             ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
            xlib.XSendEvent.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int, ctypes.c_long, ctypes.c_void_p]
            xlib.XFlush.argtypes = [ctypes.c_void_p]
            xlib.XFree.argtypes = [ctypes.c_void_p]
            xlib.XQueryTree.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong),
                                        ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_void_p),
                                        ctypes.POINTER(ctypes.c_uint)]
            self._handler = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)(lambda d, e: 0)
            xlib.XSetErrorHandler(self._handler)
            display = xlib.XOpenDisplay(None)
            if display:
                self.ctypes, self.xlib, self.display = ctypes, xlib, display
        except Exception:
            pass

    def _atom(self, name):
        return self.xlib.XInternAtom(self.display, name.encode(), 0)

    def apply(self):
        if not self.display:
            return
        ct = self.ctypes
        root, parent = ct.c_ulong(), ct.c_ulong()
        children, n = ct.c_void_p(), ct.c_uint()
        if not self.xlib.XQueryTree(self.display, self.inner_window, ct.byref(root), ct.byref(parent),
                                    ct.byref(children), ct.byref(n)):
            return
        if children:
            self.xlib.XFree(children)
        self.window = parent.value if parent.value and parent.value != root.value else self.inner_window
        arr = (ct.c_long * 5)(2, 0, 0, 0, 0)
        self.xlib.XChangeProperty(self.display, self.window, self._atom("_MOTIF_WM_HINTS"),
                                  self._atom("_MOTIF_WM_HINTS"), 32, 0, arr, 5)

        class XClientMessageEvent(ct.Structure):
            _fields_ = [("type", ct.c_int), ("serial", ct.c_ulong), ("send_event", ct.c_int),
                        ("display", ct.c_void_p), ("window", ct.c_ulong), ("message_type", ct.c_ulong),
                        ("format", ct.c_int), ("data", ct.c_long * 5)]

        class XEvent(ct.Union):
            _fields_ = [("xclient", XClientMessageEvent), ("pad", ct.c_long * 24)]

        rootw = self.xlib.XDefaultRootWindow(self.display)
        for state in self.STATES:
            ev = XEvent()
            ev.xclient.type, ev.xclient.window = 33, self.window
            ev.xclient.message_type, ev.xclient.format = self._atom("_NET_WM_STATE"), 32
            ev.xclient.data[0], ev.xclient.data[1], ev.xclient.data[3] = 1, self._atom(state), 1
            self.xlib.XSendEvent(self.display, rootw, 0, (1 << 20) | (1 << 19), ct.byref(ev))
        self.xlib.XFlush(self.display)


# ------------------------------------------------------------------------------
# THE APP
# ------------------------------------------------------------------------------
class NetworkScoutApp:
    PAD, INSET, GAP = 14, 14, 10

    def __init__(self, root, args):
        self.root, self.args = root, args
        self.demo = getattr(args, "demo", False)
        self.monitor = DemoMonitor() if self.demo else Monitor(online=not args.offline)
        self.events = collections.deque(maxlen=400)
        self.busy = {}                 # control key -> label while a change runs
        self.scroll = 0
        self.health = None
        self.health_busy = False
        self.health_stale = False
        self.height = 0
        self.dirty = True
        self.pending = False
        self.last_render = 0.0
        self._fit_cache = {}
        self.hover = None
        self.cfg = self.load_config()
        self.ui_calls = queue.Queue()      # functions that worker threads want run on the Tk thread
        self.setup_fonts()
        self.setup_window()
        if not self.demo:
            os.makedirs(STATE_DIR, exist_ok=True)
        last_change = 0.0 if self.demo else self.load_history()
        self.load_health()
        if self.health and last_change > self.health.get("_mtime", 0):
            self.health_stale = True              # settings were changed after the last check
        self.monitor.start()
        self.root.protocol("WM_DELETE_WINDOW", self.quit)
        self.tick()
        if self.cfg.get("auto_check", True) and not args.offline and not self.demo:
            self.root.after(8000, self.maybe_auto_check)

    # -- config -------------------------------------------------------------
    def load_config(self):
        cfg = {"filters": {"alert": True, "net": True, "conn": False, "you": True}, "notify": True,
               "auto_check": True}
        if self.demo:
            return cfg
        try:
            with open(CONFIG_PATH) as f:
                cfg.update(json.load(f))
        except (OSError, ValueError):
            pass
        return cfg

    def save_config(self):
        if self.demo:
            return
        try:
            os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
            with open(CONFIG_PATH, "w") as f:
                json.dump(self.cfg, f, indent=1)
        except OSError:
            pass

    # -- setup ----------------------------------------------------------------
    def setup_fonts(self):
        installed = set(tkfont.families(self.root))
        family = next((f for f in FONT_CANDIDATES if f in installed), "monospace")
        self.nerd = "Nerd" in family
        self.f_logo = tkfont.Font(family=family, size=-int(FONT_PX * 1.6), weight="bold")
        self.f_title = tkfont.Font(family=family, size=-FONT_PX, weight="bold")
        self.f_body = tkfont.Font(family=family, size=-FONT_PX)
        self.f_small = tkfont.Font(family=family, size=-(FONT_PX - 2))
        self.f_icon = tkfont.Font(family=family, size=-(FONT_PX + 1))
        self.lh = self.f_body.metrics("linespace")

    def icon(self, name):
        return ICONS.get(name, "") if self.nerd else ""

    def setup_window(self):
        global WINDOW_WIDTH
        self.two_col = self.args.layout == "wide" or (self.args.layout == "auto" and
                                                       self.root.winfo_screenheight() < TWO_COLUMNS_BELOW)
        WINDOW_WIDTH = COL_W * 2 - self.PAD if self.two_col else COL_W
        self.cx1, self.cx2 = self.PAD, COL_W - self.PAD
        self.event_rows = EVENT_ROWS
        self.root.title("networkScout")
        self.root.configure(bg=COLOR_BG)
        self.root.resizable(False, False)
        try:
            self.root.attributes("-alpha", WINDOW_OPACITY)
        except tk.TclError:
            pass
        self.cv = tk.Canvas(self.root, width=WINDOW_WIDTH, height=600, bg=COLOR_BG, bd=0, highlightthickness=0)
        self.cv.pack(fill=tk.BOTH, expand=True)
        for seq in ("<Button-4>", "<Button-5>", "<MouseWheel>"):
            self.cv.bind(seq, self.on_wheel)
        self.cv.tag_bind("click", "<Enter>", lambda e: self.cv.configure(cursor="hand2"))
        self.cv.tag_bind("click", "<Leave>", lambda e: self.cv.configure(cursor=""))
        self.wm_hints = None
        if self.args.widget:
            self.root.withdraw()
            self.root.update_idletasks()
            self.root.deiconify()
            self.root.update_idletasks()
            self.wm_hints = X11DesktopHints(self.root.winfo_id())
            self.wm_hints.apply()
            self.root.after(500, self.wm_hints.apply)

    def place(self, height):
        height = min(height, self.root.winfo_screenheight() - 60)
        if height == self.height:
            return
        self.height = height
        if self.args.widget:
            sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
            x = OFFSET_X if WIDGET_POSITION.endswith("left") else sw - WINDOW_WIDTH - OFFSET_X
            y = OFFSET_Y if WIDGET_POSITION.startswith("top") else sh - height - OFFSET_Y
            self.root.geometry("%dx%d+%d+%d" % (WINDOW_WIDTH, height, x, y))
        else:
            self.root.geometry("%dx%d" % (WINDOW_WIDTH, height))
        self.cv.configure(height=height)

    # -- main loop -------------------------------------------------------------
    def tick(self):
        while True:
            try:
                fn = self.ui_calls.get_nowait()
            except queue.Empty:
                break
            try:
                fn()
            except Exception as e:
                self.you("UI: %s" % e, "warn", "warn")
        got = False
        while True:
            try:
                ev = self.monitor.events.get_nowait()
            except queue.Empty:
                break
            self.add_event(ev)
            got = got or self.cfg["filters"].get(ev["cat"], True)
        st = self.monitor.get()
        now = time.time()
        if st.get("updated") != getattr(self, "_last_update", None):
            self._last_update = st.get("updated")
            self.pending = True                      # background change: redraw within 2 s
        if got:
            self.dirty = True                        # a visible event: redraw now
        animating = bool(self.busy or self.health_busy)
        due = self.dirty or (self.pending and now - self.last_render >= 2.0) or \
            (animating and now - self.last_render >= 0.5)
        if due and self.root.state() != "iconic":
            self.render(st)
            self.dirty = self.pending = False
            self.last_render = time.time()
        self.root.after(250, self.tick)

    def load_history(self, n=60):
        """Show the most recent events from the log again; returns the time of your last change."""
        last_change = 0.0
        try:
            with open(EVENT_LOG, "rb") as f:
                f.seek(0, 2)
                start = max(0, f.tell() - 40000)
                f.seek(start)
                lines = f.read().decode("utf-8", "replace").splitlines()
            if start:
                lines = lines[1:]                    # the first line may be cut in half
        except OSError:
            return last_change
        icons = {"you": "user", "alert": "warn", "net": "plug", "conn": "exchange"}
        for line in lines[-n:]:
            try:
                e = json.loads(line)
                t = time.mktime(time.strptime(e["time"], "%Y-%m-%dT%H:%M:%S"))
            except (ValueError, KeyError):
                continue
            if e.get("category") == "you" and e.get("level") == "you":
                last_change = max(last_change, t)
            self.events.appendleft({"t": t, "level": e.get("level", "info"), "cat": e.get("category", "net"),
                                    "icon": icons.get(e.get("category"), "info"), "text": e.get("text", ""),
                                    "notify": False})
        return last_change

    def add_event(self, ev):
        self.events.appendleft(ev)
        if self.scroll:
            self.scroll += 1
        if self.demo:
            return
        try:
            if os.path.exists(EVENT_LOG) and os.path.getsize(EVENT_LOG) > 1000000:
                os.replace(EVENT_LOG, EVENT_LOG + ".1")
            with open(EVENT_LOG, "a") as f:
                f.write(json.dumps({"time": datetime.datetime.fromtimestamp(ev["t"]).isoformat(timespec="seconds"),
                                    "level": ev["level"], "category": ev["cat"], "text": ev["text"]}) + "\n")
        except OSError:
            pass
        if ev.get("notify") and self.cfg.get("notify") and ns.which("notify-send"):
            urgency = "critical" if ev["level"] == "risk" else "normal"
            subprocess.Popen(["notify-send", "-a", "networkScout", "-u", urgency, "-i", "security-high",
                              "networkScout", notify_text(ev["text"])], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)

    def you(self, text, level="you", icon="user"):
        self.monitor.events.put({"t": time.time(), "level": level, "cat": "you", "icon": icon, "text": text,
                                 "notify": False})

    # -- actions ------------------------------------------------------------------
    def run_ns(self, key, args, label, privileged=True, done_text=None):
        """Run networkscout.py in the background (asking for the admin password via pkexec when needed)."""
        if key in self.busy:
            return
        self.busy[key] = label
        self.dirty = True
        if self.demo:
            def pretend():
                time.sleep(1.2)
                self.monitor.apply(args)
                self.you(done_text or label, "you", "check")
                self.health_stale = True
                self.busy.pop(key, None)
            threading.Thread(target=pretend, daemon=True).start()
            return

        def worker():
            if privileged:
                pk = ns.which("pkexec")
                if not pk:
                    self.you("Cannot change settings: pkexec is not installed", "warn", "warn")
                    self.busy.pop(key, None)
                    return
                cmd = [pk, ROOT_PYTHON, "-I", ns.trusted_core() or NS_SCRIPT] + args + ["--yes", "--no-color"]
            else:
                cmd = [sys.executable, "-I", NS_SCRIPT] + args + ["--no-color"]
            try:
                p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="utf-8",
                                   errors="replace", timeout=900)
                rc, out = p.returncode, p.stdout
            except (OSError, subprocess.TimeoutExpired) as e:
                rc, out = 1, str(e)
            if rc in (126, 127) and privileged:
                self.you("%s: cancelled (no password given)" % label, "info", "ban")
            elif rc == 0:
                self.you(done_text or label, "you", "check")
                self.health_stale = True
            else:
                last = [l.strip() for l in out.splitlines() if l.strip()][-1:] or ["failed"]
                self.you("%s failed: %s" % (label, last[0][:80]), "warn", "warn")
            self.busy.pop(key, None)
            self.monitor.refresh_now()
        threading.Thread(target=worker, daemon=True).start()

    def toggle_firewall(self, fw):
        if fw.get("on"):
            choice = self.ask("Turn the firewall off?",
                              "Every device on your network (and, over IPv6, possibly the internet) could connect "
                              "to any program that listens.", ["Off for 15 minutes", "Turn off", "Cancel"])
            if choice == "Off for 15 minutes":
                self.run_ns("fw", ["firewall", "off", "--for", "15m"], "Firewall off for 15 minutes")
            elif choice == "Turn off":
                self.run_ns("fw", ["firewall", "off"], "Firewall turned off")
        else:
            self.run_ns("fw", ["firewall", "on"], "Firewall turned on")

    def choose_profile(self, event, fw):
        menu = tk.Menu(self.root, tearoff=0, bg=COLOR_CARD, fg=COLOR_FG, activebackground=COLOR_TRACK,
                       activeforeground=COLOR_PRIMARY, font=self.f_body, bd=0)
        if self.demo:
            zones = ["drop", "block", "public", "work", "home", "internal", "trusted"]
        else:
            zl = busctl_fw("getZones", "org.fedoraproject.FirewallD1.zone")
            zones = zl[0] if zl else ns.stdout_of(["firewall-cmd", "--get-zones"], 10).split()
        zones = [z for z in zones if z not in ns.SYSTEM_ZONES]
        order = ["drop", "block", "public", "work", "home", "internal", "FedoraWorkstation", "trusted"]
        zones = sorted(zones, key=lambda z: (order.index(z) if z in order else 99, z))
        for z in zones:
            label = "%s %-17s %s" % ("\u2022" if z == fw.get("zone") else " ", z, ZONE_SHORT.get(z, ""))
            menu.add_command(label=label, command=lambda z=z: self.set_profile(z))
        menu.add_separator()
        menu.add_command(label="  Use the chosen profile only on this network: hold Shift while choosing",
                         state="disabled")
        self._shift = bool(event.state & 0x1)
        menu.tk_popup(event.x_root, event.y_root)

    def set_profile(self, zone):
        args = ["firewall", "profile", zone] + (["--this-network"] if getattr(self, "_shift", False) else [])
        if zone == "trusted" and self.ask("Use the \"trusted\" profile?", "It accepts every incoming connection.",
                                          ["Use it", "Cancel"]) != "Use it":
            return
        self.run_ns("profile", args, "Firewall profile: %s" % zone)

    def toggle_app_incoming(self, key, allowed, wide):
        app = ns.APPS[key]
        if allowed is None:                        # rules unknown (ufw without root): ask what to do
            choice = self.ask(app["label"], "networkScout cannot read your firewall rules without administrator "
                              "rights. What should happen to incoming connections for this app?",
                              ["Allow", "Block", "Cancel"])
            if choice == "Cancel":
                return
            allowed = choice == "Block"
        if allowed and wide:
            self.close_unused(reason="%s is let in by the wide port range %s. Closing it means removing that "
                                     "range; you will be asked about each app." % (app["label"], ", ".join(wide)))
            return
        if allowed:
            self.run_ns("in_" + key, ["ports", "block", key], "Blocked incoming for %s" % app["label"])
        else:
            self.run_ns("in_" + key, ["ports", "allow", key], "Allowed incoming for %s" % app["label"])

    def allow_for(self, key, target, minutes=60):
        self.run_ns("tmp_" + key, ["ports", "allow", target, "--for", "%dm" % minutes],
                    "Allowed %s for %d minutes" % (target, minutes))

    def toggle_port(self, port, proto, allowed, wide):
        target = "%d/%s" % (port, proto)
        if allowed and wide:
            self.close_unused(reason="Port %s is let in by the wide port range %s." % (target, ", ".join(wide)))
            return
        self.run_ns("port_%s" % target, ["ports", "block" if allowed else "allow", target],
                    "%s incoming on port %s" % ("Blocked" if allowed else "Allowed", target))

    def toggle_running(self, key, running, installed):
        fid, cmds = LAUNCH[key]
        label = ns.APPS[key]["label"]
        if self.demo:
            self.monitor.apply(["run", key, "stop" if running else "start"])
            self.you("%s %s" % (label, "quit" if running else "started"), "you", "times" if running else "check")
            return
        self.busy["run_" + key] = "..."

        def worker():
            if running:
                rx = ns.APPS[key]["proc"].lstrip("^").strip("()").split("|")[0]
                subprocess.call(["pkill", "-TERM", "-u", str(os.getuid()), rx])
                for _ in range(20):
                    time.sleep(0.5)
                    if not any(re.search(ns.APPS[key]["proc"], n.lower()) for n in process_names()):
                        break
                else:
                    if fid:
                        subprocess.call(["flatpak", "kill", fid], stderr=subprocess.DEVNULL)
                self.you("%s quit" % label, "you", "times")
            else:
                cmd = ["flatpak", "run", installed] if installed and "." in installed else [installed]
                subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
                time.sleep(3)
                self.you("%s started" % label, "you", "check")
            self.busy.pop("run_" + key, None)
            self.monitor.refresh_now()
        threading.Thread(target=worker, daemon=True).start()

    def toggle_dns(self, st):
        if st.get("encrypted"):
            if self.ask("Turn encrypted DNS off?", "Your lookups go back to your network's DNS servers, unencrypted.",
                        ["Turn off", "Cancel"]) == "Turn off":
                self.run_ns("dns", ["dns", "plain"], "Encrypted DNS turned off")
        else:
            self.run_ns("dns", ["dns", "encrypt"], "Encrypted DNS turned on",
                        done_text="Encrypted DNS turned on (checked: names still resolve)")

    def toggle_llmnr(self, st):
        on = st.get("llmnr")
        self.run_ns("llmnr", ["dns", "llmnr", "off" if on else "on"], "LLMNR turned %s" % ("off" if on else "on"))

    def toggle_log(self, fw):
        on = fw.get("log", "off") != "off"
        self.run_ns("log", ["firewall", "log-blocked", "off" if on else "on"],
                    "Logging of blocked attempts %s" % ("off" if on else "on"))

    def close_unused(self, reason=""):
        if "close" in self.busy:
            return
        self.busy["close"] = "planning"

        def worker():
            if self.demo:
                out = "  Close port 8000/tcp (python3: nothing outside needs it)? [Y/n] yes (recommended)\n"
            else:
                out = subprocess.run([sys.executable, "-I", NS_SCRIPT, "ports", "close-unused", "--dry-run", "--yes",
                                      "--no-color"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="utf-8",
                                     errors="replace").stdout
            self.busy.pop("close", None)
            self.ui_calls.put(lambda: self._close_unused_dialog(reason, out))
        threading.Thread(target=worker, daemon=True).start()

    def _close_unused_dialog(self, reason, output):
        plan = [l for l in output.splitlines() if "(recommended)" in l or "lets in" in l]
        text = (reason + "\n\n" if reason else "") + "Recommended changes:\n" + "\n".join(
            "  " + re.sub(r"\s*\[[Yy]/[Nn]\]\s*", " -> ", l.strip()).replace(" (recommended)", "") for l in plan) + \
            "\n\nTo choose differently app by app, use \"Fix in terminal\"."
        choice = self.ask("Close ports nothing needs?", text, ["Apply", "Fix in terminal", "Cancel"], wide=True)
        if choice == "Apply":
            self.run_ns("close", ["ports", "close-unused"], "Closed unused ports")
        elif choice == "Fix in terminal":
            self.open_terminal(["ports", "close-unused"])

    def open_port_dialog(self):
        d = self.dialog("Open a port")
        port_var, proto_var = tk.StringVar(value=""), tk.StringVar(value="tcp")
        dur_var, src_var = tk.StringVar(value="1h"), tk.StringVar(value="anyone")
        lan = None
        st = self.monitor.get()
        lip = (st.get("net") or {}).get("lan_ip")
        if lip:
            lan = ".".join(lip.split(".")[:3]) + ".0/24"
        rows = [("Port (or range)", tk.Entry(d, textvariable=port_var, width=14, bg=COLOR_TRACK, fg=COLOR_FG,
                                              insertbackground=COLOR_FG, relief="flat", font=self.f_body))]
        for label, widget in rows:
            tk.Label(d, text=label, bg=COLOR_BG, fg=COLOR_LABEL, font=self.f_small).pack(anchor="w", padx=16)
            widget.pack(anchor="w", padx=16, pady=(0, 8))
        for title, var, opts in (("Protocol", proto_var, [("TCP", "tcp"), ("UDP", "udp")]),
                                 ("For how long", dur_var, [("15 min", "15m"), ("1 hour", "1h"), ("8 hours", "8h"),
                                                            ("Always", "")]),
                                 ("Who may connect", src_var, [("Anyone", "anyone")] +
                                  ([("My network (%s)" % lan, lan)] if lan else []))):
            tk.Label(d, text=title, bg=COLOR_BG, fg=COLOR_LABEL, font=self.f_small).pack(anchor="w", padx=16)
            fr = tk.Frame(d, bg=COLOR_BG)
            fr.pack(anchor="w", padx=12, pady=(0, 8))
            for text, val in opts:
                tk.Radiobutton(fr, text=text, value=val, variable=var, bg=COLOR_BG, fg=COLOR_FG, selectcolor=COLOR_TRACK,
                               activebackground=COLOR_BG, activeforeground=COLOR_PRIMARY, font=self.f_body,
                               highlightthickness=0).pack(side="left", padx=4)
        result = {}

        def ok():
            result["go"] = True
            d.destroy()
        self.buttons(d, [("Open", ok), ("Cancel", d.destroy)])
        d.wait_window()
        if not result.get("go"):
            return
        port = port_var.get().strip()
        if not re.match(r"^\d{1,5}(-\d{1,5})?$", port):
            self.you("Not a valid port: %r" % port, "warn", "warn")
            return
        target = "%s/%s" % (port, proto_var.get())
        args = ["ports", "allow", target]
        if dur_var.get():
            args += ["--for", dur_var.get()]
        if src_var.get() != "anyone":
            args += ["--from", src_var.get()]
        self.run_ns("open_" + target, args, "Opened port %s%s" % (target, " for %s" % dur_var.get() if dur_var.get() else ""))

    def find_terminal(self):
        for term, flag in (("konsole", "-e"), ("gnome-terminal", "--"), ("kgx", "-e"), ("ptyxis", "--"),
                           ("xfce4-terminal", "-x"), ("alacritty", "-e"), ("kitty", ""), ("foot", ""),
                           ("wezterm", "start --"), ("x-terminal-emulator", "-e"), ("xterm", "-e")):
            if ns.which(term):
                return [term] + (flag.split() if flag else [])
        return None

    def open_terminal(self, args):
        if self.demo:
            self.you("Demo: would open a terminal with: networkscout %s" % " ".join(args), "you", "terminal")
            return
        term = self.find_terminal()
        if not term:
            self.you("No terminal app found. Run: networkscout %s" % " ".join(args), "warn", "warn")
            return
        cmd = term + [ROOT_PYTHON if os.path.exists(ROOT_PYTHON) else sys.executable, ns.trusted_core() or NS_SCRIPT] + args
        if args and args[0] == "fix":
            cmd.append("--pause")
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        self.you("Opened a terminal: networkscout %s" % " ".join(args), "you", "terminal")

    # -- health check ----------------------------------------------------------------
    def health_paths(self):
        return os.path.join(STATE_DIR, "last-check.json"), os.path.join(STATE_DIR, "last-check.md")

    def load_health(self):
        if self.demo:
            self.health = dict(DEMO_HEALTH, _mtime=time.time() - 25 * 60)
            return
        jp, _ = self.health_paths()
        try:
            with open(jp) as f:
                self.health = json.load(f)
            self.health["_mtime"] = os.path.getmtime(jp)
        except (OSError, ValueError):
            self.health = None

    def maybe_auto_check(self):
        if not self.health or self.health_stale or time.time() - self.health.get("_mtime", 0) > 6 * 3600:
            self.run_check()
        self.root.after(3600 * 1000, self.maybe_auto_check)

    def run_check(self):
        if self.health_busy:
            return
        self.health_busy = True
        self.health_stale = False
        self.dirty = True
        jp, mp = self.health_paths()

        def worker():
            cmd = [sys.executable, "-I", NS_SCRIPT, "--no-color", "--json", jp, "--report", mp]
            if self.args.offline:
                cmd.append("--offline")
            if self.demo:
                time.sleep(3)
            else:
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=900)
            self.load_health()
            c = (self.health or {}).get("counts", {})
            self.you("Health check done: %d serious, %d to improve" % (c.get("RISK", 0), c.get("WARN", 0)),
                     "risk" if c.get("RISK") else ("warn" if c.get("WARN") else "ok"), "heart")
            self.health_busy = False
            self.dirty = True
        threading.Thread(target=worker, daemon=True).start()

    def open_report(self):
        if self.demo:
            self.you("Demo: would open the report of the last check", "you", "file")
            return
        _, mp = self.health_paths()
        if os.path.exists(mp) and ns.which("xdg-open"):
            subprocess.Popen(["xdg-open", mp], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def show_finding(self, f):
        text = (f.get("detail") or "") + ("\n\nWhat to do:\n" + f["fix"] if f.get("fix") else "")
        self.ask(f["title"], text, ["Close"], wide=True)

    # -- dialogs ---------------------------------------------------------------------
    def dialog(self, title):
        d = tk.Toplevel(self.root, bg=COLOR_BG)
        d.title(title)
        d.transient(self.root)
        d.resizable(False, False)
        tk.Label(d, text=title, bg=COLOR_BG, fg=COLOR_FG, font=self.f_title).pack(anchor="w", padx=16, pady=(14, 8))
        return d

    def buttons(self, d, items):
        fr = tk.Frame(d, bg=COLOR_BG)
        fr.pack(fill="x", padx=12, pady=(6, 14))
        for i, (text, cmd) in enumerate(items):
            primary = i == 0
            tk.Button(fr, text=text, command=cmd, bg=COLOR_PRIMARY if primary else COLOR_TRACK,
                      fg=COLOR_BG if primary else COLOR_FG, activebackground=COLOR_ACCENT, relief="flat", bd=0,
                      font=self.f_body, padx=12, pady=4, highlightthickness=0).pack(side="left", padx=4)

    def ask(self, title, text, options, wide=False):
        d = self.dialog(title)
        msg = tk.Message(d, text=text, bg=COLOR_BG, fg=COLOR_LABEL, font=self.f_small, width=560 if wide else 380)
        msg.pack(anchor="w", padx=16)
        result = {"v": options[-1]}

        def pick(v):
            result["v"] = v
            d.destroy()
        self.buttons(d, [(o, lambda o=o: pick(o)) for o in options])
        d.update_idletasks()
        x = self.root.winfo_rootx() + 30
        y = self.root.winfo_rooty() + 60
        d.geometry("+%d+%d" % (x, y))
        try:
            d.grab_set()
        except tk.TclError:
            pass
        d.wait_window()
        return result["v"]

    # -- input ---------------------------------------------------------------------------
    def on_wheel(self, e):
        top, bottom, x1, x2 = getattr(self, "events_area", (0, 0, 0, 0))
        if not (top <= e.y <= bottom and x1 - 20 <= e.x <= x2 + 20):
            return
        delta = -1 if (getattr(e, "num", 0) == 4 or getattr(e, "delta", 0) > 0) else 1
        shown = len(self.filtered_events())
        self.scroll = max(0, min(self.scroll + delta * 2, max(0, shown - self.event_rows)))
        self.dirty = True

    def click(self, tag, fn):
        self.cv.tag_bind(tag, "<Button-1>", fn)

    def filtered_events(self):
        f = self.cfg["filters"]
        return [e for e in self.events if f.get(e["cat"], True)]

    # -- drawing primitives -----------------------------------------------------------------
    def text(self, x, y, s, font, color, anchor="nw", tags=()):
        return self.cv.create_text(x, y, text=s, font=font, fill=color, anchor=anchor, tags=tags)

    def fit(self, s, font, max_w):
        """Shorten s with an ellipsis to fit max_w pixels (cached: measuring text is the slow part)."""
        key = (s, str(font), int(max_w))
        hit = self._fit_cache.get(key)
        if hit is not None:
            return hit
        if font.measure(s) <= max_w:
            res = s
        else:
            lo, hi = 0, len(s)
            while lo < hi:                           # longest prefix that fits, by binary search
                mid = (lo + hi + 1) // 2
                if font.measure(s[:mid] + "\u2026") <= max_w:
                    lo = mid
                else:
                    hi = mid - 1
            res = s[:lo] + "\u2026"
        if len(self._fit_cache) > 3000:
            self._fit_cache.clear()
        self._fit_cache[key] = res
        return res

    def rrect(self, x1, y1, x2, y2, r, **kw):
        r = max(0, min(r, (x2 - x1) / 2, (y2 - y1) / 2))
        pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
               x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
        return self.cv.create_polygon(pts, smooth=True, splinesteps=10, **kw)

    def switch(self, x, y, on, tag, fn, busy=False, color=COLOR_SUCCESS, enabled=True):
        """A toggle switch whose right edge is at x. on: True / False / None (unknown)."""
        w, h = 38, 20
        x1, y1 = x - w, y
        if busy:
            fill, knob_x = mix_color(COLOR_TRACK, COLOR_WARNING, 0.35 + 0.25 * (int(time.time() * 2) % 2)), x1 + w / 2
        elif on:
            fill, knob_x = color, x - h / 2
        else:
            fill, knob_x = COLOR_TRACK, x1 + h / 2
        if not enabled or on is None:
            fill = mix_color(fill, COLOR_CARD, 0.6)
        tags = (tag, "click") if enabled and not busy else (tag,)
        self.rrect(x1, y1, x, y1 + h, h / 2, fill=fill, outline=mix_color(COLOR_CARD_EDGE, fill, 0.5), tags=tags)
        self.cv.create_oval(knob_x - 7, y1 + 3, knob_x + 7, y1 + h - 3,
                            fill=COLOR_BG if on and not busy else COLOR_LABEL, outline="", tags=tags)
        if enabled and not busy:
            self.click(tag, lambda e: fn())

    def button(self, x, y, label, tag, fn, color=COLOR_PRIMARY, anchor="ne", small=True, pass_event=False):
        font = self.f_small if small else self.f_body
        w = font.measure(label) + 16
        h = font.metrics("linespace") + 6
        x1 = x - w if anchor == "ne" else x
        self.rrect(x1, y, x1 + w, y + h, 7, fill=mix_color(COLOR_CARD, color, 0.18),
                   outline=mix_color(COLOR_CARD, color, 0.5), tags=(tag, "click"))
        self.text(x1 + w / 2, y + h / 2, label, font, color, "center", tags=(tag, "click"))
        self.click(tag, (lambda e: fn(e)) if pass_event else (lambda e: fn()))
        return x1, w

    def card(self, y, title, icon, color, body, right=None, right_color=None):
        x1, x2 = self.cx1, self.cx2
        left, right_x = x1 + self.INSET, x2 - self.INSET
        top = y
        y += 10
        tx = left
        if self.icon(icon):
            self.text(tx, y, self.icon(icon), self.f_title, color)
            tx += 22
        self.text(tx, y, title, self.f_title, color)
        if right:
            self.text(right_x, y + 1, right, self.f_small, right_color or COLOR_LABEL, "ne")
        y = body(y + self.f_title.metrics("linespace") + 8, left, right_x)
        y += 10
        bg = self.rrect(x1, top, x2, y, 12, fill=COLOR_CARD, outline=COLOR_CARD_EDGE)
        notch = self.rrect(x1, top + 11, x1 + 3, top + 11 + self.f_title.metrics("linespace"), 1.5, fill=color, outline="")
        self.cv.tag_lower(notch)
        self.cv.tag_lower(bg)
        return y + self.GAP

    def row(self, y, left, right, icon, label, sub=None, icon_color=COLOR_LABEL, label_color=COLOR_FG, sub_color=COLOR_DIM,
            label_tag=None):
        if self.icon(icon):
            self.text(left, y, self.icon(icon), self.f_icon, icon_color)
        tx = left + (24 if self.icon(icon) else 0)
        self.text(tx, y, label, self.f_body, label_color, tags=(label_tag, "click") if label_tag else ())
        if sub:
            self.text(tx, y + self.lh, self.fit(sub, self.f_small, right - tx - 150), self.f_small, sub_color,
                      tags=(label_tag, "click") if label_tag else ())
            return y + self.lh * 2 + 6
        return y + self.lh + 8

    # -- rendering -------------------------------------------------------------------------------
    def verdict(self, st):
        h = self.health or {}
        c = h.get("counts", {})
        fw = st.get("fw") or {}
        if fw.get("on") is False or c.get("RISK"):
            return "AT RISK", COLOR_DANGER
        if (fw.get("wide") or c.get("WARN")):
            return "NEEDS ATTENTION", COLOR_WARNING
        if not h:
            return "WATCHING", COLOR_PRIMARY
        return "PROTECTED", COLOR_SUCCESS

    def render(self, st):
        cv = self.cv
        cv.delete("all")
        W = WINDOW_WIDTH
        y = self.PAD
        # header
        label, color = self.verdict(st)
        if self.icon("shield"):
            self.text(self.PAD + 2, y, self.icon("shield"), self.f_logo, color)
        self.text(self.PAD + (34 if self.icon("shield") else 2), y, "networkScout", self.f_logo, COLOR_FG)
        pw = self.f_small.measure(label) + 18
        self.rrect(W - self.PAD - pw, y + 4, W - self.PAD, y + 4 + self.lh + 4, 9,
                   fill=mix_color(COLOR_BG, color, 0.22), outline=color)
        self.text(W - self.PAD - pw / 2, y + 6 + self.lh / 2, label, self.f_small, color, "center")
        y += self.f_logo.metrics("linespace") + 2
        net = st.get("net") or {}
        host, osname = (DEMO_HOST, DEMO_OS) if self.demo else (os.uname().nodename, ns.os_release().get("NAME", "Linux"))
        sub = "%s \u2022 %s \u2022 %s %s" % (host, osname, net.get("dev") or "offline", net.get("lan_ip") or "")
        self.text(self.PAD + 2, y, self.fit(sub, self.f_small, W - 2 * self.PAD), self.f_small, COLOR_DIM)
        y += self.lh + 10
        if not st.get("ready"):
            self.text(W / 2, y + 30, "Looking around\u2026", self.f_body, COLOR_LABEL, "n")
            self.place(int(y + 90))
            return
        top = y
        self.cx1, self.cx2 = self.PAD, COL_W - self.PAD
        y = self.card(y, "PROTECTION", "shield", COLOR_PRIMARY, lambda yy, l, r: self.body_protection(st, yy, l, r))
        y = self.card(y, "APPS & PORTS", "cubes", COLOR_ACCENT, lambda yy, l, r: self.body_apps(st, yy, l, r),
                      right="RUN    INCOMING", right_color=COLOR_DIM)
        y = self.card(y, "NETWORK", "globe", COLOR_PINK, lambda yy, l, r: self.body_network(st, yy, l, r))
        if self.two_col:
            left_bottom = y
            self.cx1, self.cx2 = COL_W - self.PAD + self.GAP, WINDOW_WIDTH - self.PAD
            y = top
        y = self.card(y, "HEALTH CHECK", "heart", COLOR_SUCCESS, lambda yy, l, r: self.body_health(st, yy, l, r),
                      right=self.health_age(), right_color=COLOR_DIM)
        if self.two_col:     # let the event list fill the right column down to the left column's bottom
            fixed = self.f_title.metrics("linespace") + 8 + 20 + self.lh + 12 + self.lh + 2 + 10 + self.GAP
            self.event_rows = max(EVENT_ROWS, int((left_bottom - y - fixed) // (self.lh + 3)))
        y = self.card(y, "LIVE EVENTS", "bolt", COLOR_WARNING, lambda yy, l, r: self.body_events(st, yy, l, r),
                      right="%d" % len(self.filtered_events()), right_color=COLOR_DIM)
        if self.two_col:
            y = max(y, left_bottom)
        foot = ("demo: invented data, nothing on this computer is read or changed" if self.demo else
                "changes ask for your password \u2022 log: %s" % EVENT_LOG.replace(os.path.expanduser("~"), "~"))
        self.text(W / 2, y - 2, foot, self.f_small, COLOR_DIM, "n")
        self.place(int(y + self.lh + 6))

    def health_age(self):
        if self.health_busy:
            return "checking\u2026"
        if not self.health:
            return "not run yet"
        if self.health_stale:
            return "outdated: you changed settings"
        age = time.time() - self.health.get("_mtime", time.time())
        return "%s ago" % ns.human_age(age) if age > 120 else "just now"

    def body_protection(self, st, y, left, right):
        fw = st.get("fw") or {}
        dns = st.get("dns") or {}
        # firewall
        on = fw.get("on")
        sub = ("profile: %s \u25be" % (fw.get("zone") or "?")) if on else ("OFF" if on is False else "not found")
        y0 = y
        self.row(y, left, right, "fire", "Firewall", sub, icon_color=COLOR_SUCCESS if on else COLOR_DANGER,
                 sub_color=COLOR_PRIMARY if on else COLOR_DANGER, label_tag="profile" if on else None)
        if on:
            self.cv.tag_bind("profile", "<Button-1>", lambda e: self.choose_profile(e, fw))
        self.switch(right, y0 + 6, on, "sw_fw", lambda: self.toggle_firewall(fw), busy="fw" in self.busy or "profile" in self.busy,
                    enabled=fw.get("tool") in ("firewalld", "ufw"))
        y += self.lh * 2 + 6
        if fw.get("wide"):
            self.text(left + 24, y, self.fit("%s %s let almost everything in" % (self.icon("warn"), ", ".join(fw["wide"])),
                                             self.f_small, right - left - 150), self.f_small, COLOR_WARNING)
            self.button(right, y - 3, "Close unused", "btn_close", lambda: self.close_unused(), COLOR_WARNING)
            y += self.lh + 10
        if fw.get("tool") == "firewalld":
            y0 = y
            log_on = fw.get("log", "off") != "off"
            y = self.row(y, left, right, "eye", "Log blocked attempts", "shows them below in Live events" if log_on
                         else "off: blocked attempts are not recorded", icon_color=COLOR_PRIMARY if log_on else COLOR_LABEL)
            self.switch(right, y0 + 6, log_on, "sw_log", lambda: self.toggle_log(fw), busy="log" in self.busy,
                        enabled=bool(on))
        # DNS
        if dns.get("resolved"):
            y0 = y
            enc = dns.get("encrypted")
            sub = ("via %s" % dns.get("provider")) if enc and dns.get("provider") else (
                "on" if enc else "plain text via %s" % (dns.get("current") or ", ".join(dns.get("servers", [])[:1]) or "?"))
            y = self.row(y, left, right, "key", "Encrypted DNS", sub, icon_color=COLOR_SUCCESS if enc else COLOR_WARNING)
            self.switch(right, y0 + 6, enc, "sw_dns", lambda: self.toggle_dns(dns), busy="dns" in self.busy)
            y0 = y
            ll = dns.get("llmnr")
            y = self.row(y, left, right, "sitemap", "LLMNR name guessing", "on: devices nearby can answer lookups" if ll
                         else "off (safer)", icon_color=COLOR_WARNING if ll else COLOR_SUCCESS)
            self.switch(right, y0 + 6, ll, "sw_llmnr", lambda: self.toggle_llmnr(dns), busy="llmnr" in self.busy,
                        color=COLOR_WARNING)
        certs = st.get("certs") or []
        if certs:
            self.text(left, y, self.fit("%s %d extra root certificate%s trusted: %s" % (
                self.icon("warn"), len(certs), "s" if len(certs) > 1 else "",
                certs[0].get("subject_cn") or certs[0].get("subject_o") or ""), self.f_small, right - left - 70),
                self.f_small, COLOR_WARNING)
            self.button(right, y - 3, "Fix\u2026", "btn_certfix", lambda: self.open_terminal(["fix", "--only", "certs"]),
                        COLOR_WARNING)
            y += self.lh + 10
        return y - 8

    def body_apps(self, st, y, left, right):
        fw = st.get("fw") or {}
        running = st.get("running") or {}
        installed = st.get("installed") or {}
        listeners = st.get("listeners") or []
        exposed = st.get("exposed") or {}
        is_fwd = fw.get("tool") == "firewalld" and fw.get("on")
        svc_ports = fw.get("svc_ports", []) if is_fwd else []
        covered = set()
        shown = 0
        for key, app in ns.APPS.items():
            listening = [s for s in listeners if re.search(app["proc"], (s["process"] or s["unit"]).lower())
                         and s["scope"] != "loopback" and not s["ephemeral"]]
            inst = installed.get(key)
            in_zone = any(sv in fw.get("services", []) for sv in app["services"])
            if key in LAUNCH:
                if not (running.get(key) or listening or inst):
                    continue
            elif not (listening or in_zone or key in SHOW_ALWAYS):
                continue
            ports = list(app["ports"]) + ["%d/%s" % (s["port"], s["proto"]) for s in listening]
            for s in listening:
                covered.add((s["proto"], s["port"]))
            allowed = None
            via_wide = []
            if fw.get("on"):
                res = [fw_allows(fw, p.split("/")[1], int(p.split("/")[0].split("-")[0]), svc_ports) for p in ports]
                allowed = True if True in res else (None if None in res else False)
                via_wide = [w for w in fw.get("wide", []) if any(
                    ns.port_specs_cover([w], p.split("/")[1], int(p.split("/")[0].split("-")[0])) for p in ports)]
            elif fw.get("on") is False:
                allowed = True
            state = "running" if running.get(key) else ("installed" if inst else ("not installed" if key in LAUNCH else "not running"))
            if listening:
                state += " \u2022 listening on %s" % ", ".join(sorted(set("%d/%s" % (s["port"], s["proto"]) for s in listening))[:3])
            if via_wide and allowed:
                state += " \u2022 let in by %s" % via_wide[0]
            y0 = y
            y = self.row(y, left, right, APP_ICON.get(key, "cubes"), app["label"], state,
                         icon_color=COLOR_SUCCESS if running.get(key) else COLOR_LABEL)
            # incoming switch
            self.switch(right, y0 + 6, allowed, "sw_in_" + key,
                        lambda k=key, a=allowed, w=via_wide: self.toggle_app_incoming(k, a, w),
                        busy=("in_" + key) in self.busy or "close" in self.busy, color=COLOR_WARNING,
                        enabled=fw.get("tool") in ("firewalld", "ufw") and bool(fw.get("on")))
            # temporary allow
            if fw.get("on") and not allowed:
                self.button(right - 48, y0 + 5, self.icon("clock") + " 1h" if self.nerd else "1h", "tmp_" + key,
                            lambda k=key: self.allow_for(k, k))
            # running switch (desktop apps only)
            if key in LAUNCH and (inst or running.get(key)):
                self.switch(right - 100, y0 + 6, bool(running.get(key)), "sw_run_" + key,
                            lambda k=key, r=running.get(key), i=inst: self.toggle_running(k, r, i),
                            busy=("run_" + key) in self.busy, color=COLOR_PRIMARY)
            shown += 1
        # other ports open to the network
        others = [(proto, port, owner) for (proto, port), owner in sorted(exposed.items(), key=lambda kv: kv[0][1])
                  if (proto, port) not in covered and ns.PORTS.get(port, ("", ns.INFO))[1] != ns.OK
                  and port not in (5353, 5355)]
        for proto, port, owner in others[:6]:
            allowed = fw_allows(fw, proto, port, svc_ports) if fw.get("on") else (True if fw.get("on") is False else None)
            wide = [w for w in fw.get("wide", []) if ns.port_specs_cover([w], proto, port)]
            name = ns.PORTS.get(port, ("unknown service", ""))[0]
            y0 = y
            y = self.row(y, left, right, "plug", "Port %d/%s" % (port, proto), "%s \u2022 %s" % (owner, name),
                         icon_color=COLOR_WARNING if allowed else COLOR_LABEL)
            self.switch(right, y0 + 6, allowed, "sw_port_%d_%s" % (port, proto),
                        lambda p=port, pr=proto, a=allowed, w=wide: self.toggle_port(p, pr, a, w),
                        busy=("port_%d/%s" % (port, proto)) in self.busy, color=COLOR_WARNING,
                        enabled=bool(fw.get("on")))
            if fw.get("on") and not allowed:
                self.button(right - 48, y0 + 5, self.icon("clock") + " 1h" if self.nerd else "1h",
                            "tmpp_%d_%s" % (port, proto), lambda p=port, pr=proto: self.allow_for("p%d" % p, "%d/%s" % (p, pr)))
        busy_open = [k for k in self.busy if k.startswith("open_") or k.startswith("tmp")]
        x1, _ = self.button(left, y, (self.icon("plus") + " " if self.nerd else "+ ") + "Open a port\u2026", "btn_open",
                            lambda: self.open_port_dialog(), COLOR_PRIMARY, anchor="nw")
        if busy_open:
            self.text(left + 140, y + 2, "working\u2026", self.f_small, COLOR_WARNING)
        if fw.get("tool") == "firewalld":
            self.button(right, y, "Profiles: " + (fw.get("zone") or "?") + " \u25be", "btn_prof",
                        lambda e: self.choose_profile(e, fw), COLOR_LABEL, pass_event=True)
        return y + self.lh + 6

    def body_network(self, st, y, left, right):
        net = st.get("net") or {}
        pub = st.get("public") or {}
        dns = st.get("dns") or {}
        wifi = st.get("wifi")
        lines = []
        if wifi and wifi.get("dev") == net.get("dev"):
            sec = wifi["security"]
            lines.append(("wifi", "Wi-Fi \"%s\"" % wifi["ssid"], sec, COLOR_DANGER if sec in ("OPEN", "--") or "WEP" in sec else COLOR_FG))
        elif net.get("dev"):
            lines.append(("plug", "Cable (%s)" % net["dev"], net.get("lan_ip") or "", COLOR_FG))
        else:
            lines.append(("plug", "Offline", "", COLOR_DANGER))
        if net.get("gw"):
            lines.append(("server", "Router %s" % net["gw"], net.get("gw_mac") or "", COLOR_FG))
        lines.append(("secret", "VPN", net.get("vpn") or "not in use", COLOR_FG if net.get("vpn") else COLOR_LABEL))
        if pub.get("v4") or pub.get("v6"):
            owner = (pub.get("owner") or "").split(" (")[0]
            lines.append(("globe", "Public IP %s" % (pub.get("v4") or ""), self.fit(owner, self.f_small, 200), COLOR_FG))
            if pub.get("v6"):
                lines.append(("globe", "IPv6", pub["v6"], COLOR_FG))
        lines.append(("sitemap", "DNS %s" % ("encrypted" if dns.get("encrypted") else "unencrypted"),
                      dns.get("current") or ", ".join(dns.get("servers", [])[:2]),
                      COLOR_SUCCESS if dns.get("encrypted") else COLOR_WARNING))
        lines.append(("exchange", "%d connections out, %d in" % (st.get("conn_count", 0), st.get("inbound_count", 0)),
                      "%d devices seen on your network" % net.get("devices", 0), COLOR_FG))
        for icon, a, b, col in lines:
            if self.icon(icon):
                self.text(left, y, self.icon(icon), self.f_icon, COLOR_LABEL)
            tx = left + (24 if self.icon(icon) else 0)
            a = self.fit(a, self.f_body, right - tx - 120)
            self.text(tx, y, a, self.f_body, col)
            room = right - (tx + self.f_body.measure(a)) - 16
            if b and room > 40:
                self.text(right, y + 1, self.fit(b, self.f_small, room), self.f_small, COLOR_LABEL, "ne")
            y += self.lh + 4
        return y - 4

    def body_health(self, st, y, left, right):
        h = self.health
        if h:
            c = h.get("counts", {})
            x = left
            for key, label, col in (("RISK", "serious", COLOR_DANGER), ("WARN", "to improve", COLOR_WARNING),
                                    ("INFO", "info", COLOR_PRIMARY), ("OK", "fine", COLOR_SUCCESS)):
                t = self.text(x, y, str(c.get(key, 0)), self.f_title, col)
                x = self.cv.bbox(t)[2] + 4
                t = self.text(x, y + 1, label, self.f_small, COLOR_LABEL)
                x = self.cv.bbox(t)[2] + 14
            y += self.lh + 8
            todo = [f for f in h.get("findings", []) if f["level"] in ("RISK", "WARN")]
            todo.sort(key=lambda f: 0 if f["level"] == "RISK" else 1)
            for i, f in enumerate(todo[:5]):
                col = COLOR_DANGER if f["level"] == "RISK" else COLOR_WARNING
                tag = "finding_%d" % i
                self.text(left, y, "\u2022", self.f_body, col)
                self.text(left + 14, y, self.fit(f["title"], self.f_small, right - left - 14), self.f_small, COLOR_FG,
                          tags=(tag, "click"))
                self.click(tag, lambda e, f=f: self.show_finding(f))
                y += self.lh + 2
            if len(todo) > 5:
                self.text(left + 14, y, "+ %d more in the report" % (len(todo) - 5), self.f_small, COLOR_DIM)
                y += self.lh + 2
            y += 6
        else:
            self.text(left, y, "Run a full check of updates, encryption, DNS, certificates and ports.",
                      self.f_small, COLOR_LABEL)
            y += self.lh + 8
        x = left
        for label, tag, fn, col in (("Check again" if self.health_stale else "Check now", "btn_check",
                                     self.run_check, COLOR_WARNING if self.health_stale else COLOR_SUCCESS),
                                    ("Fix\u2026", "btn_fix", lambda: self.open_terminal(["fix"]), COLOR_WARNING),
                                    ("Report", "btn_report", self.open_report, COLOR_LABEL)):
            if tag == "btn_check" and self.health_busy:
                label = "Checking" + "." * (1 + int(time.time() * 2) % 3)
            x1, w = self.button(x, y, label, tag, fn, col, anchor="nw")
            x = x1 + w + 8
        return y + self.lh + 6

    def body_events(self, st, y, left, right):
        x = left
        f = self.cfg["filters"]
        for cat, label in (("alert", "Alerts"), ("net", "Network"), ("conn", "Connections"), ("you", "You")):
            col = COLOR_WARNING if f.get(cat) else COLOR_DIM
            x1, w = self.button(x, y, label, "chip_" + cat, lambda c=cat: self.toggle_filter(c), col, anchor="nw")
            x = x1 + w + 6
        bell_col = COLOR_PRIMARY if self.cfg.get("notify") else COLOR_DIM
        self.button(right, y, (self.icon("bell") + " " if self.nerd else "") + ("alerts on" if self.cfg.get("notify") else "alerts off"),
                    "chip_bell", self.toggle_notify, bell_col)
        y += self.lh + 12
        evs = self.filtered_events()
        top = y
        if not evs:
            self.text(left, y, "Nothing yet. Events appear here as they happen.", self.f_small, COLOR_DIM)
            y += self.lh + 4
        for e in evs[self.scroll:self.scroll + self.event_rows]:
            col = LEVEL_COLOR.get(e["level"], COLOR_LABEL)
            self.text(left, y, time.strftime("%H:%M:%S", time.localtime(e["t"])), self.f_small, COLOR_DIM)
            ix = left + self.f_small.measure("00:00:00 ") + 2
            if self.icon(e["icon"]):
                self.text(ix, y - 1, self.icon(e["icon"]), self.f_small, col)
                ix += 18
            self.text(ix, y, self.fit(e["text"], self.f_small, right - ix), self.f_small,
                      COLOR_FG if e["level"] in ("risk", "warn") else COLOR_LABEL)
            y += self.lh + 3
        if len(evs) > self.event_rows:
            self.text(right, y, "scroll for more (%d-%d of %d)" % (self.scroll + 1, min(len(evs), self.scroll + self.event_rows),
                                                                   len(evs)), self.f_small, COLOR_DIM, "ne")
            y += self.lh + 2
        self.events_area = (top - 30, y, left, right)
        return y

    def toggle_filter(self, cat):
        self.cfg["filters"][cat] = not self.cfg["filters"].get(cat, True)
        self.scroll = 0
        self.save_config()
        self.dirty = True

    def toggle_notify(self):
        self.cfg["notify"] = not self.cfg.get("notify", True)
        self.save_config()
        self.dirty = True

    def quit(self):
        self.monitor.stop()
        self.root.destroy()


def single_instance():
    os.makedirs(STATE_DIR, exist_ok=True)
    fh = open(os.path.join(STATE_DIR, "app.lock"), "w")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return None
    return fh


def main():
    ap = argparse.ArgumentParser(description="networkScout app: live network-security dashboard with switches.")
    ap.add_argument("--widget", action="store_true", help="sit on the desktop below other windows (like pySysMon)")
    ap.add_argument("--offline", action="store_true", help="no internet lookups (public IP, online checks)")
    ap.add_argument("--layout", choices=["auto", "wide", "tall"], default="auto",
                    help="two columns (wide), one column (tall), or pick by screen height (auto)")
    ap.add_argument("--demo", action="store_true",
                    help="show an invented computer (for screenshots or trying the switches); reads and changes nothing")
    args = ap.parse_args()
    if not HAS_TK:
        print("This Python has no tkinter. Use the terminal version instead:  networkscout  (see --help),\n"
              "or run ./install.sh, which sets up a Python with tkinter.")
        return 1
    lock = None if args.demo else single_instance()
    if lock is None and not args.demo:
        print("networkScout is already running.")
        return 0
    root = tk.Tk(className="networkScout")
    app = NetworkScoutApp(root, args)
    signal.signal(signal.SIGTERM, lambda *a: root.after(0, app.quit))
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
