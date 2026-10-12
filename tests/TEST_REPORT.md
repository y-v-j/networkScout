# networkScout test report

**Date:** 2026-10-12 · **Version tested:** the code in this folder on that date

## Summary

| What | Result |
|---|---|
| Unit and scenario tests (core 79, command line 13, app 27) | **119 / 119 pass** on the desktop host and in all 7 distribution containers, as a normal user and as root (skips listed below) |
| Accuracy against the system's own tools | **18 / 18 match** |
| Installer (install, launchers, fallback Python, autostart, uninstall) | **13 / 13** on Debian, Arch, openSUSE and Alpine |
| Full check and every command, 8 systems | **0 tracebacks** |
| Python versions | 3.6, 3.11, 3.12, 3.13, 3.14 |
| Steady CPU of the app | about 1.7 % |
| Security review | 4 findings, all fixed and covered by tests |

## Systems

| System | Package manager / init | Python | Check and commands | core | cli | app |
|---|---|---|---|---|---|---|
| Bazzite 44 (Fedora Atomic) desktop | rpm-ostree / systemd | 3.14 | pass, plus real changes | 79 ✓ | 13 ✓ | 27 ✓ |
| Debian 12 | apt / none | 3.11 | pass | 79 ✓ | 13 ✓ | 27 ✓ |
| Ubuntu 24.04 | apt / none | 3.12 | pass | 79 ✓ | 13 ✓ | 27 ✓ |
| Fedora 44 (non-atomic) | dnf / none | 3.14 | pass | 79 ✓ | 13 ✓ | 27 ✓ |
| Arch Linux | pacman / none | 3.14 | pass | 79 ✓ | 13 ✓ | 27 ✓ |
| Gentoo | portage / OpenRC tools | 3.14 | pass | 79 ✓ | 13 ✓ | no Tk |
| Alpine 3.24 | apk, musl, BusyBox, no `ss` | 3.14 | pass | 79 ✓ | 13 ✓ | 27 ✓ |
| openSUSE Tumbleweed | zypper / none | 3.13 | pass | 79 ✓ | 13 ✓ | 27 ✓ |
| python:3.6-slim | apt / none | 3.6 | pass | 79 ✓ | – | – |

Containers ran the app tests under Xvfb. The app was also shown on a real desktop from inside the Debian and Fedora containers (`tests/distro_containers.sh app`).

**Expected skips:**

- **command line:** the firewall and port dry-runs need a running firewall, which the containers do not have; the administrator-rights test is skipped when running as root.
- **app:** comparing the D-Bus and `firewall-cmd` firewall readings needs firewalld.
- **Python 3.6:** online lookups were turned off (`NETWORKSCOUT_TEST_OFFLINE=1`).

**Expected exit codes in containers:**

- The check exits with 1 ("things to improve") or 2 ("serious"; the Debian 12 image has a pending security update, which was correctly reported).
- `ports allow` and `firewall profile` exit with 1 and explain that no firewall is installed.

## What the tests cover

- **Detectors with simulated attacks:**
  - ARP spoofing and a changed router address;
  - DNS hijacking, interception and tampering; a DNS leak around a VPN; missing DNSSEC validation;
  - a rogue root certificate; HTTPS interception; a captive portal; plain-HTTP tampering;
  - a wrong clock; open Wi-Fi; an exposed database; a world-writable Docker socket; `ld.so.preload`; unsigned kernel modules;
  - UPnP port forwards; stalled updaters; Gentoo tree age.
- **Commands:**
  - every command, read-only or with `--dry-run`;
  - the backups and `undo.sh` of real changes (in a temporary folder).
- **App:**
  - live events from simulated journal and syslog lines: failed sudo and SSH, blocked attempts grouped per source, polkit;
  - system states: firewall turned off, router impersonation, new certificates;
  - a real port opened and closed during the test;
  - window layouts, filters, dialogs, background actions and drawing speed;
  - `--demo` mode runs no programs and writes no files (checked in a separate process).
- **Portability:**
  - missing `ss`, `ip`, `journalctl` (log files instead), `busctl`, firewalld or ufw;
  - ufw rules unreadable without root;
  - the Python chosen at install time being removed.

## Bugs found by testing and fixed

| Bug | Fix |
|---|---|
| `human_age(90)` said "1 minutes" | Correct plurals |
| The event history dropped its first line when the log was short | Only skip a possibly cut line after seeking |
| A closed pipe (`networkscout \| head`) printed a traceback | Handled in `main()` |
| `XDG_STATE_HOME` was ignored when running as root | Only `sudo`/`pkexec` runs use the invoking user's folder |
| DNS server names kept the `#SNI` suffix | Stripped |
| The journal reader process was not reaped on quit | Waited for and closed |
| The app used 8–9 % CPU | Owners from the cgroup instead of scanning `/proc/*/fd`, redraws throttled, text fitting cached: about 1.7 % |
| Tests assumed systemd's `journalctl`, a non-root user and Fedora's CA bundle path | Tests made independent of those (found by the Debian, root and openSUSE runs) |
| `tests/distro_containers.sh app` left the app running after Ctrl+C | The app's process is ended when the script ends |

## Security review

| # | Finding | Fix |
|---|---|---|
| S1 | Undo scripts written by root-run changes were stored in a folder the user could edit, so a later `sudo …/undo.sh` could run tampered code | Root-run changes store backups in `/var/lib/networkscout/backups` (0700) |
| S2 | The app's switches ran the copy of the core in the user's home folder as root | `sudo ./install.sh --system-core` installs a root-owned copy; privileged actions use it when its file and folders are owned by root and not writable by others |
| S3 | A UPnP answer could make networkScout fetch a description from any host | The description must come from the device that answered, on the local network, over plain HTTP |
| S4 | Notification text was passed to the desktop as markup | Escaped, control characters removed, length capped |

## Reproduce

```bash
python3 -m unittest discover -s tests -p 'test_core.py'
python3 -m unittest discover -s tests -p 'test_cli.py'
<python with tkinter> -m unittest discover -s tests -p 'test_gui.py'
python3 tests/accuracy_check.py
tests/distro_containers.sh create && tests/distro_containers.sh test
```
