#!/usr/bin/env bash
# ==============================================================================
# networkScout - installer
#
# Installs entirely in user space (no root, works on immutable/atomic systems):
#   ~/.local/share/networkscout/            networkscout.py (checks) + networkscout_gui.py (app)
#   ~/.local/bin/networkscout               terminal command (check, fix, ports, firewall, dns)
#   ~/.local/bin/networkscout-app           the desktop app
#   ~/.local/share/applications/networkscout.desktop
#   ~/.local/share/icons/hicolor/scalable/apps/networkscout.svg
#   ~/.config/autostart/networkscout.desktop  (only with --startup widget|window)
#
# Optional, needs sudo:  sudo ./install.sh --system-core
#   /usr/local/lib/networkscout/networkscout.py  root-owned copy used for every administrator action
#   /usr/local/bin/networkscout                  so "sudo networkscout ..." works too
#
# Usage: ./install.sh [--startup none|widget|window] [--python PATH] [--no-start] [--uninstall] [--help]
#        sudo ./install.sh --system-core | --remove-system-core
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="${HOME}/.local/share/networkscout"
BIN_DIR="${HOME}/.local/bin"
DESKTOP_FILE="${HOME}/.local/share/applications/networkscout.desktop"
ICON_FILE="${HOME}/.local/share/icons/hicolor/scalable/apps/networkscout.svg"
AUTOSTART_FILE="${HOME}/.config/autostart/networkscout.desktop"
# Shared with pySysMon / pyQuotes: one conda env with an Xft-enabled Tk serves all three
CONDA_ENV_NAME="${NETWORKSCOUT_CONDA_ENV:-conky-env}"
SYSTEM_DIR="/usr/local/lib/networkscout"
SYSTEM_BIN="/usr/local/bin/networkscout"

STARTUP="none"
PYTHON=""
START_NOW=1
UNINSTALL=0
SYSTEM_CORE=""

BOLD="\033[1m"; CYAN="\033[36m"; GREEN="\033[32m"; YELLOW="\033[33m"; RED="\033[31m"; RESET="\033[0m"
step() { echo -e "${BOLD}${CYAN}==>${RESET} ${BOLD}$*${RESET}"; }
ok()   { echo -e "    ${GREEN}✓${RESET} $*"; }
warn() { echo -e "    ${YELLOW}!${RESET} $*"; }
die()  { echo -e "${RED}✗ $*${RESET}" >&2; exit 1; }

usage() {
  cat <<EOF
networkScout installer

Options:
  --startup MODE   Start the app at login: none (default), widget (on the desktop,
                   below other windows, like pySysMon) or window (a normal window)
  --python PATH    Python with tkinter to use for the app (auto-detected otherwise)
  --no-start       Do not open the app after installing
  --uninstall      Remove networkScout (keeps your reports, event log and backups)
  -h, --help       Show this help

Optional, with sudo (recommended for the safest setup):
  --system-core         Install a root-owned copy of the core that every administrator action uses,
                        so programs running as you cannot change what later runs as root
  --remove-system-core  Remove that copy again

Environment:
  NETWORKSCOUT_CONDA_ENV  conda env for the app (default: conky-env, shared with pySysMon)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --startup)   STARTUP="${2:-}"; shift 2 ;;
    --python)    PYTHON="${2:-}"; shift 2 ;;
    --no-start)  START_NOW=0; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    --system-core) SYSTEM_CORE="system-core"; shift ;;
    --remove-system-core) SYSTEM_CORE="remove-system-core"; shift ;;
    -h|--help)   usage; exit 0 ;;
    *) usage; die "Unknown option: $1" ;;
  esac
done
case "$STARTUP" in none|widget|window) ;; *) die "--startup must be none, widget or window" ;; esac

if [[ -n "$SYSTEM_CORE" ]]; then
  [[ "$(id -u)" -eq 0 ]] || die "This part needs administrator rights:  sudo ./install.sh --${SYSTEM_CORE}"
  if [[ "$SYSTEM_CORE" == "remove-system-core" ]]; then
    step "Removing the root-owned core"
    rm -rf "$SYSTEM_DIR"
    rm -f "$SYSTEM_BIN"
    ok "Removed ${SYSTEM_DIR} and ${SYSTEM_BIN}; administrator actions use the copy in your home folder again"
    exit 0
  fi
  step "Installing the root-owned core to ${SYSTEM_DIR}"
  ROOT_PY="/usr/bin/python3"; [[ -x "$ROOT_PY" ]] || ROOT_PY="$(command -v python3)"
  install -d -o root -g root -m 755 "$SYSTEM_DIR"
  install -o root -g root -m 644 "${SCRIPT_DIR}/networkscout.py" "${SYSTEM_DIR}/networkscout.py"
  printf '#!/bin/sh\n# networkScout (root-owned copy, installed by install.sh --system-core)\nexec "%s" -I "%s/networkscout.py" "$@"\n' \
    "$ROOT_PY" "$SYSTEM_DIR" > "$SYSTEM_BIN"
  chown root:root "$SYSTEM_BIN"
  chmod 755 "$SYSTEM_BIN"
  ok "Every administrator action (fix, ports, firewall, dns and the app's switches) now runs this copy"
  ok "\"sudo networkscout ...\" works too"
  warn "After updating networkScout, run this again so both copies match"
  exit 0
fi

stop_running() {
  # Only the copy installed here; "[.]" keeps pkill from matching its own command line
  pkill -f "${APP_DIR}/networkscout_gui[.]py" 2>/dev/null && sleep 1 || true
}

if [[ $UNINSTALL -eq 1 ]]; then
  step "Removing networkScout"
  stop_running
  rm -rf "$APP_DIR"
  rm -f "${BIN_DIR}/networkscout" "${BIN_DIR}/networkscout-app" "$DESKTOP_FILE" "$ICON_FILE" "$AUTOSTART_FILE"
  command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q "$(dirname "$DESKTOP_FILE")" || true
  ok "Removed the app, commands, menu entry and startup entry"
  echo "    Kept: ~/.local/state/networkscout (event log, baseline, undo backups), ~/.config/networkscout,"
  echo "    ~/networkscout-reports and the conda env '${CONDA_ENV_NAME}'. Changes you made with"
  echo "    'networkscout fix/ports/firewall/dns' stay in place; undo scripts are in ~/.local/state/networkscout/backups."
  exit 0
fi

# ------------------------------------------------------------------------------
# 1. Python for the terminal command (any Python 3.6+, standard library only)
# ------------------------------------------------------------------------------
step "[1/4] Python for the terminal command"
CLI_PY=""
for c in /usr/bin/python3 python3 /usr/libexec/platform-python python; do
  p="$(command -v "$c" 2>/dev/null || true)"
  if [[ -n "$p" ]] && "$p" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 6) else 1)' 2>/dev/null; then
    CLI_PY="$p"; break
  fi
done
[[ -n "$CLI_PY" ]] || die "Python 3.6 or newer is needed (it is preinstalled on almost every Linux system)."
ok "Using ${CLI_PY} ($("$CLI_PY" -c 'import platform; print(platform.python_version())'))"

# ------------------------------------------------------------------------------
# 2. Python with tkinter (+ Xft for smooth fonts) for the app
# ------------------------------------------------------------------------------
step "[2/4] Python for the app (tkinter)"
has_tkinter() { "$1" -c "import tkinter" >/dev/null 2>&1; }
has_xft_tk() {
  local tkmod
  tkmod="$("$1" -c 'import _tkinter; print(_tkinter.__file__)' 2>/dev/null)" || return 1
  ldd "$tkmod" 2>/dev/null | grep -qi "libXft"
}
find_conda() {
  local c
  for c in "$(command -v conda 2>/dev/null || true)" "$(command -v mamba 2>/dev/null || true)" \
           "$HOME/miniforge3/bin/conda" "$HOME/miniconda3/bin/conda" "$HOME/anaconda3/bin/conda"; do
    [[ -n "$c" && -x "$c" ]] && { echo "$c"; return 0; }
  done
  return 1
}

APP_PY=""
if [[ -n "$PYTHON" ]]; then
  [[ -x "$PYTHON" ]] || PYTHON="$(command -v "$PYTHON" || true)"
  [[ -n "$PYTHON" ]] || die "--python interpreter not found"
  has_tkinter "$PYTHON" || die "${PYTHON} has no tkinter module"
  APP_PY="$PYTHON"
elif CONDA="$(find_conda)"; then
  CONDA_BASE="$("$CONDA" info --base 2>/dev/null | tail -n 1)"
  [[ -d "$CONDA_BASE" ]] || die "Could not determine the conda base directory"
  ENV_PY="${CONDA_BASE}/envs/${CONDA_ENV_NAME}/bin/python"
  if [[ -x "$ENV_PY" ]] && has_xft_tk "$ENV_PY"; then
    ok "Reusing conda env '${CONDA_ENV_NAME}'"
  elif [[ -x "$ENV_PY" ]]; then
    echo "    Adding an Xft-enabled Tk to conda env '${CONDA_ENV_NAME}'..."
    "$CONDA" install -y -q -n "$CONDA_ENV_NAME" -c conda-forge --override-channels "tk=*=xft_*" >/dev/null
    ok "Updated conda env '${CONDA_ENV_NAME}'"
  else
    echo "    Creating conda env '${CONDA_ENV_NAME}' (Python 3.12 with an Xft-enabled Tk)..."
    "$CONDA" create -y -q -n "$CONDA_ENV_NAME" -c conda-forge --override-channels "python=3.12" "tk=8.6.*=xft_*" >/dev/null
    ok "Created conda env '${CONDA_ENV_NAME}'"
  fi
  APP_PY="$ENV_PY"
else
  for c in python3 /usr/bin/python3; do
    p="$(command -v "$c" 2>/dev/null || true)"
    [[ -n "$p" ]] && has_tkinter "$p" && { APP_PY="$p"; break; }
  done
fi
if [[ -z "$APP_PY" ]]; then
  warn "No Python with tkinter found: the app is skipped, the terminal command works."
  warn "For the app, install Miniforge (https://conda-forge.org/download/) and run this script again,"
  warn "or install your distribution's python3-tk / python3-tkinter package."
elif has_xft_tk "$APP_PY"; then
  ok "Tk has Xft support (smooth, antialiased fonts): ${APP_PY}"
else
  ok "Using ${APP_PY}"
  warn "This Tk lacks Xft support: text will look blocky. Install Miniforge/conda and re-run for smooth fonts."
fi

# ------------------------------------------------------------------------------
# 3. Files, commands, menu entry
# ------------------------------------------------------------------------------
step "[3/4] Installing to ${APP_DIR}"
stop_running
mkdir -p "$APP_DIR" "$BIN_DIR" "$(dirname "$DESKTOP_FILE")" "$(dirname "$ICON_FILE")"
install -m 644 "${SCRIPT_DIR}/networkscout.py" "${APP_DIR}/networkscout.py"
install -m 644 "${SCRIPT_DIR}/networkscout_gui.py" "${APP_DIR}/networkscout_gui.py"
install -m 644 "${SCRIPT_DIR}/assets/networkscout.svg" "$ICON_FILE"

cat > "${BIN_DIR}/networkscout" <<EOF
#!/bin/sh
# networkScout terminal command (generated by install.sh). -I: ignore PYTHONPATH and user site-packages.
# If the Python chosen at install time disappears (system update), any Python 3.6+ will do.
PY="${CLI_PY}"
if ! [ -x "\$PY" ]; then
  for c in python3 /usr/bin/python3 /usr/libexec/platform-python python; do
    if command -v "\$c" >/dev/null 2>&1 && "\$c" -c 'import sys; sys.exit(sys.version_info < (3, 6))' 2>/dev/null; then
      PY="\$c"; break
    fi
  done
fi
exec "\$PY" -I "${APP_DIR}/networkscout.py" "\$@"
EOF
chmod 755 "${BIN_DIR}/networkscout"
ok "Command: networkscout   (check; fix; ports; firewall; dns)"

if [[ -n "$APP_PY" ]]; then
  cat > "${BIN_DIR}/networkscout-app" <<EOF
#!/bin/sh
# networkScout desktop app (generated by install.sh). If the Python chosen at install time is gone or
# lost tkinter (e.g. a conda env was removed, or a system update), fall back to any Python with tkinter.
PY="${APP_PY}"
if ! [ -x "\$PY" ] || ! "\$PY" -c 'import tkinter' >/dev/null 2>&1; then
  PY=""
  for c in python3 /usr/bin/python3 python; do
    if command -v "\$c" >/dev/null 2>&1 && "\$c" -c 'import tkinter' >/dev/null 2>&1; then PY="\$c"; break; fi
  done
fi
if [ -z "\$PY" ]; then
  msg="No Python with tkinter was found (was its conda env removed?). Run install.sh again; the 'networkscout' terminal command still works."
  command -v notify-send >/dev/null 2>&1 && notify-send -a networkScout networkScout "\$msg"
  echo "networkScout: \$msg" >&2
  exit 1
fi
exec "\$PY" "${APP_DIR}/networkscout_gui.py" "\$@"
EOF
  chmod 755 "${BIN_DIR}/networkscout-app"
  # "~", not "\$HOME": the autostart generator escapes "\$", so sh would never expand it
  sed -e 's|^Exec=.*|Exec=sh -c "exec ~/.local/bin/networkscout-app"|' "${SCRIPT_DIR}/networkscout.desktop" > "$DESKTOP_FILE"
  chmod 644 "$DESKTOP_FILE"
  command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q "$(dirname "$DESKTOP_FILE")" || true
  ok "App: networkscout-app, and \"networkScout\" in your applications menu"
fi
case ":${PATH}:" in
  *":${BIN_DIR}:"*) ;;
  *) warn "${BIN_DIR} is not in your PATH: add  export PATH=\"\$HOME/.local/bin:\$PATH\"  to ~/.bashrc" ;;
esac

# ------------------------------------------------------------------------------
# 4. Start at login
# ------------------------------------------------------------------------------
step "[4/4] Start at login: ${STARTUP}"
if [[ "$STARTUP" == "none" || -z "$APP_PY" ]]; then
  rm -f "$AUTOSTART_FILE"
  ok "Not started at login (enable later with: ./install.sh --startup widget)"
else
  mkdir -p "$(dirname "$AUTOSTART_FILE")"
  flag=""; [[ "$STARTUP" == "widget" ]] && flag=" --widget"
  sed -e "s|^Exec=.*|Exec=sh -c \"exec ~/.local/bin/networkscout-app${flag}\"|" \
      -e 's|^Name=.*|Name=networkScout (at login)|' "${SCRIPT_DIR}/networkscout.desktop" > "$AUTOSTART_FILE"
  printf 'X-KDE-autostart-after=panel\nX-GNOME-Autostart-enabled=true\n' >> "$AUTOSTART_FILE"
  ok "Starts at login as a ${STARTUP}: ${AUTOSTART_FILE}"
fi

if [[ $START_NOW -eq 1 && -n "$APP_PY" && -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]]; then
  flag=""; [[ "$STARTUP" == "widget" ]] && flag="--widget"
  setsid nohup "${BIN_DIR}/networkscout-app" $flag >/dev/null 2>&1 < /dev/null &
  ok "networkScout is running"
fi

echo
echo -e "${BOLD}Done.${RESET} Try:  networkscout          (full check)"
echo    "                 networkscout fix      (fix what it finds; asks first; can be undone)"
echo    "                 networkscout-app      (the app)"
