#!/usr/bin/env bash
# Long-lived containers of several Linux distributions for testing and trying networkScout.
# The project folder is mounted read-only at /app; nothing on your computer is changed.
# The containers are kept until you remove them yourself (`remove`); after a reboot, `start` brings them back.
#
# Usage: tests/distro_containers.sh <command> [distro ...]
#   create            make the containers and install Python, Tk, Xvfb and fonts (existing ones are kept)
#   test              run the checks, the commands and all test suites in each one; full logs in $OUT
#   shell DISTRO      open a shell inside (the project is at /app; `networkscout` is on the PATH)
#   run DISTRO CMD..  run one command inside, e.g.  run arch networkscout --offline
#   app DISTRO [ARGS] show the desktop app from inside the container on your screen, e.g.  app debian --demo
#   start | stop      start or stop the containers
#   list              show the containers and whether they are running
#   remove            delete the containers (asks first)
# Distros: debian ubuntu fedora arch gentoo alpine opensuse   (default: all of them)
# Needs podman (or docker: ENGINE=docker). Each container is limited to 2 GB of memory.
set -uo pipefail
cd "$(dirname "$0")/.."
PROJECT="$PWD"
ENGINE="${ENGINE:-podman}"
OUT="${OUT:-${XDG_STATE_HOME:-$HOME/.local/state}/networkscout/distro-tests}"
ALL="debian ubuntu fedora arch gentoo alpine opensuse"

declare -A IMAGE SETUP GUI
IMAGE[debian]=docker.io/library/debian:12
SETUP[debian]='apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get -qq install -y python3 python3-tk xvfb xauth fonts-dejavu-core iproute2 >/dev/null'
IMAGE[ubuntu]=docker.io/library/ubuntu:24.04
SETUP[ubuntu]=${SETUP[debian]}
IMAGE[fedora]=registry.fedoraproject.org/fedora:44
SETUP[fedora]='dnf -q -y install python3 python3-tkinter xorg-x11-server-Xvfb xauth dejavu-sans-fonts dejavu-sans-mono-fonts iproute shadow-utils >/dev/null'
IMAGE[arch]=docker.io/library/archlinux:latest
SETUP[arch]='pacman -Syu --noconfirm --needed python tk xorg-server-xvfb xorg-xauth ttf-dejavu iproute2 >/dev/null 2>&1'
IMAGE[gentoo]=docker.io/gentoo/stage3:latest
SETUP[gentoo]='true'                       # Python is already there; Tk would mean rebuilding Python from source
IMAGE[alpine]=docker.io/library/alpine:latest
SETUP[alpine]='apk add -q python3 python3-tkinter xvfb-run xauth font-dejavu shadow'   # no systemd, musl libc, no ss
IMAGE[opensuse]=registry.opensuse.org/opensuse/tumbleweed:latest
SETUP[opensuse]='zypper -nq refresh && zypper -nq install python3 python3-tk xvfb-run xauth dejavu-fonts iproute2 shadow >/dev/null'
for d in $ALL; do GUI[$d]=1; done
GUI[gentoo]=0

die() { echo "error: $*" >&2; exit 1; }
name() { echo "ns-$1"; }
exists() { $ENGINE container exists "$(name "$1")" 2>/dev/null; }
running() { [ "$($ENGINE inspect -f '{{.State.Running}}' "$(name "$1")" 2>/dev/null)" = true ]; }
check_distro() { [ -n "${IMAGE[$1]:-}" ] || die "unknown distro '$1' (choose from: $ALL)"; }
ensure_up() {
  check_distro "$1"
  exists "$1" || die "$(name "$1") does not exist yet: run  $0 create $1"
  running "$1" || $ENGINE start "$(name "$1")" >/dev/null
}

create() {
  local d=$1 n x11=()
  n=$(name "$d")
  if exists "$d"; then echo "$n: already there (kept)"; return 0; fi
  echo "$n: creating from ${IMAGE[$d]}"
  # your display's socket folder, read-only and under another name, so Xvfb inside can still use /tmp/.X11-unix
  [ -d /tmp/.X11-unix ] && x11=(-v /tmp/.X11-unix:/tmp/.X11-host:ro)
  # a shell that sleeps until it is stopped (`sleep infinity` is not available everywhere, e.g. busybox)
  $ENGINE run -d --name "$n" --hostname "$n" --label networkscout.distro="$d" --memory 2g \
    --security-opt label=disable -v "$PROJECT":/app:ro "${x11[@]}" "${IMAGE[$d]}" \
    sh -c 'trap "exit 0" TERM INT; while :; do sleep 3600 & wait $!; done' >/dev/null || return 1
  echo "$n: installing packages (this can take a few minutes)"
  $ENGINE exec "$n" sh -c "${SETUP[$d]}" || { echo "$n: package setup FAILED (the container is kept; try again with: $0 create $d after removing it)"; return 1; }
  $ENGINE exec "$n" sh -c '
    for c in networkscout:networkscout.py networkscout-app:networkscout_gui.py; do
      printf "#!/bin/sh\nexec python3 /app/%s \"\$@\"\n" "${c#*:}" > "/usr/local/bin/${c%%:*}"
      chmod 755 "/usr/local/bin/${c%%:*}"
    done
    id tester >/dev/null 2>&1 || useradd -m tester 2>/dev/null || adduser -D tester'
  echo "$n: ready ($($ENGINE exec "$n" sh -c '. /etc/os-release; echo "$PRETTY_NAME"'), $($ENGINE exec "$n" python3 --version))"
}

TESTS='
cd /app
T=/tmp/ns-$(id -u); rm -rf "$T"; mkdir -p "$T"
echo "### $(. /etc/os-release; echo "$PRETTY_NAME") | $(python3 --version) | user $(id -un)"
python3 -B networkscout.py --offline --no-baseline --json $T/off.json >$T/off.txt 2>&1; echo "offline check exit=$?"
python3 -B networkscout.py --no-baseline --json $T/on.json >$T/on.txt 2>&1; echo "online check exit=$?"
python3 -B -c "import json; d=json.load(open(\"$T/on.json\")); print(\"online counts\", d[\"counts\"])"
echo "tracebacks in checks: $(cat $T/off.txt $T/on.txt | grep -c Traceback)"
for c in "ports" "firewall" "dns" "fix --dry-run --yes" "ports allow 8080 --dry-run" "firewall profile home --dry-run"; do
  python3 -B networkscout.py $c --no-color >$T/cmd.txt 2>&1; rc=$?
  echo "cmd [$c] exit=$rc traceback=$(grep -c Traceback $T/cmd.txt)"
done
for suite in core cli gui; do
  if [ $suite = gui ]; then
    [ "$GUI" = 1 ] || { echo "suite gui: skipped (no Tk in this container)"; continue; }
    run="xvfb-run -a python3"
  else
    run="python3"
  fi
  $run -B -m unittest discover -s tests -p "test_$suite.py" >$T/$suite.txt 2>&1
  echo "suite $suite: $(grep -E "^Ran " $T/$suite.txt) -> $(grep -E "^(OK|FAILED)" $T/$suite.txt)"
  grep -E "^(ERROR|FAIL):" $T/$suite.txt | sed "s/^/    /"
  cat $T/$suite.txt >> $T/suites.log
done
'

run_tests() {
  local d=$1 n log
  n=$(name "$d")
  ensure_up "$d"
  log="$OUT/$d.log"
  : > "$log"
  for user in tester root; do
    $ENGINE exec --user "$user" -e GUI="${GUI[$d]}" -e NETWORKSCOUT_TEST_OFFLINE="${NETWORKSCOUT_TEST_OFFLINE:-}" "$n" \
      sh -c "$TESTS"' echo "--- full test output"; cat "$T/suites.log"' >> "$log" 2>&1
  done
  echo "=== $n"
  grep -E '^###|exit=|counts|tracebacks|^suite|^    (ERROR|FAIL)' "$log"
}

app() {
  local d=$1; shift
  ensure_up "$d"
  [ "${GUI[$d]}" = 1 ] || die "$d has no Tk; try another distro"
  [ -n "${DISPLAY:-}" ] && [ -d /tmp/.X11-unix ] || die "needs an X11 or XWayland display (DISPLAY is not set)"
  # link your display's socket into place and hand over a copy of its cookie (valid for any host name)
  local num=${DISPLAY#*:}; num=${num%%.*}
  $ENGINE exec "$(name "$d")" sh -c "mkdir -p /tmp/.X11-unix && chmod 1777 /tmp/.X11-unix &&
    ln -sf /tmp/.X11-host/X$num /tmp/.X11-unix/X$num" || die "this container was made without access to your display; remove and create it again"
  if command -v xauth >/dev/null 2>&1; then
    xauth nlist "$DISPLAY" 2>/dev/null | sed -e 's/^..../ffff/' |
      $ENGINE exec -i "$(name "$d")" xauth -f /tmp/.ns-xauth nmerge - 2>/dev/null
  fi
  # podman exec does not pass Ctrl+C on: remember the app's process and end it when this script ends
  trap '$ENGINE exec "$(name "$d")" sh -c "kill \$(cat /tmp/.ns-app.pid) 2>/dev/null; rm -f /tmp/.ns-app.pid"' EXIT
  trap 'exit 130' INT TERM HUP
  $ENGINE exec -e DISPLAY="$DISPLAY" -e XAUTHORITY=/tmp/.ns-xauth "$(name "$d")" \
    sh -c 'echo $$ > /tmp/.ns-app.pid; exec python3 /app/networkscout_gui.py "$@"' sh "$@"
}

cmd="${1:-}"; shift || true
case "$cmd" in
  create)
    for d in ${*:-$ALL}; do check_distro "$d"; create "$d"; done ;;
  test)
    mkdir -p "$OUT"
    for d in ${*:-$ALL}; do run_tests "$d"; done
    echo "(full logs: $OUT/<distro>.log)" ;;
  shell)
    [ $# -ge 1 ] || die "which distro? e.g.  $0 shell debian"
    ensure_up "$1"
    $ENGINE exec -it -w /app "$(name "$1")" sh -c 'command -v bash >/dev/null && exec bash || exec sh' ;;
  run)
    [ $# -ge 2 ] || die "e.g.  $0 run arch networkscout --offline"
    d=$1; shift; ensure_up "$d"
    $ENGINE exec -it -w /app "$(name "$d")" "$@" ;;
  app)
    [ $# -ge 1 ] || die "which distro? e.g.  $0 app debian --demo"
    app "$@" ;;
  start)
    for d in ${*:-$ALL}; do check_distro "$d"; exists "$d" && $ENGINE start "$(name "$d")" >/dev/null && echo "$(name "$d"): running"; done ;;
  stop)
    for d in ${*:-$ALL}; do check_distro "$d"; exists "$d" && $ENGINE stop -t 5 "$(name "$d")" >/dev/null && echo "$(name "$d"): stopped"; done ;;
  list)
    $ENGINE ps -a --filter label=networkscout.distro --format '{{.Names}}\t{{.Status}}\t{{.Image}}' ;;
  remove)
    targets=""; for d in ${*:-$ALL}; do check_distro "$d"; exists "$d" && targets="$targets $(name "$d")"; done
    [ -n "$targets" ] || { echo "nothing to remove"; exit 0; }
    read -r -p "Delete$targets? [y/N] " a
    [ "$a" = y ] || [ "$a" = Y ] || { echo "kept"; exit 0; }
    $ENGINE rm -f $targets ;;
  *)
    sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
    [ -z "$cmd" ] || [ "$cmd" = help ] || [ "$cmd" = -h ] || [ "$cmd" = --help ] || exit 2 ;;
esac
