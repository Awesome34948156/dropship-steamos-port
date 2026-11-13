#!/bin/bash
# Find out why the installed service never applies anything, when running the
# same helper by hand works.
#
#   sudo scripts/diagnose-service.sh
#
# scripts/watcher-test.sh proves the watcher works unsandboxed, so when the
# installed service misbehaves the difference is systemd's hardening. This
# bisects that: run the same binary
# under the same unit properties, and then under progressively fewer of them,
# until it starts working. That names the directive responsible instead of
# guessing at it.
#
# Nothing here changes the install, and it never reads or writes your real
# service.json: the probe gets a config of its own. The service is stopped while
# the probe runs (two watchers cannot both hold the lock) and started again at
# the end.
set -u
export PATH=/usr/bin:/usr/sbin:/bin:/sbin

# Derived from this script's own location so it works from any checkout.
REPO=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
# shellcheck source=scripts/lib/deck-fixture.sh
. "$REPO/scripts/lib/deck-fixture.sh"

UNIT=dropship-steamos.service
HELPER=/var/lib/dropship-steamos/dropship-steamos-helper
# Not /tmp: the probe units run with PrivateTmp=yes, so they see a private /tmp
# and could never read a file the host wrote there. The desktop user's home is
# visible to them under ProtectHome=read-only, and CAP_DAC_READ_SEARCH covers
# the 0700 traversal. This is deliberately not the real config path.
DIAG_CONFIG=$DESKTOP_HOME/dropship-diag-service.json

[ "$(id -u)" -eq 0 ] || { echo "run this with sudo"; exit 1; }

# Root-run scratch: mktemp keeps the hand-run log out of a fixed, predictable
# /tmp name.
DIAG_DIR=$(mktemp -d)
HAND_LOG=$DIAG_DIR/hand.log
CONFIG_TMP=

cleanup() {
    stop_game >/dev/null 2>&1
    systemctl stop ds-diag.service 2>/dev/null
    systemctl reset-failed ds-diag.service 2>/dev/null
    nft delete table inet dropship_steamos 2>/dev/null
    rm -f "$DIAG_CONFIG"
    if [ -n "$CONFIG_TMP" ]; then rm -f "$CONFIG_TMP"; fi
    rm -rf "$DIAG_DIR"
    systemctl start "$UNIT" 2>/dev/null
}
trap cleanup EXIT

echo "############ 1. what the service actually said ############"
echo "--- journal, last 60 lines ---"
journalctl -u "$UNIT" --no-pager -n 60 2>&1
echo
echo "--- published state ---"
cat /run/dropship-steamos/state.json 2>&1
echo
echo "--- resolved hardening ---"
systemctl show "$UNIT" -p CapabilityBoundingSet -p AmbientCapabilities \
    -p ProtectSystem -p ProtectHome -p ProtectControlGroups -p RestrictAddressFamilies \
    -p NoNewPrivileges -p PrivateTmp -p ProtectProc -p ProcSubset 2>&1

echo
echo "############ 2. setting up ############"
systemctl stop "$UNIT"
stop_game >/dev/null 2>&1
nft delete table inet dropship_steamos 2>/dev/null
# Staged in a root-only file and copied into place, rather than a root shell
# redirect into a path under the desktop user's home.
CONFIG_TMP=$(mktemp)
cat > "$CONFIG_TMP" <<JSON
{ "version": 1, "enabled": true, "revision": 900002,
  "ipv4": ["$V4"], "ipv6": ["$V6"] }
JSON
install -o root -g root -m 0644 "$CONFIG_TMP" "$DIAG_CONFIG"
rm -f "$CONFIG_TMP"
CONFIG_TMP=
echo "config written to $DIAG_CONFIG"
start_game && echo "fake game is running" || echo "COULD NOT START THE FAKE GAME"

echo
echo "############ 2b. can a sandboxed root process read /proc and run nft? ############"
# The two ways this can fail silently are "cannot see the game" and "cannot run
# nft", and the watcher reports both as nothing happening. Ask each question
# directly, under the same capability set the unit uses.
systemctl reset-failed ds-probe.service 2>/dev/null
systemd-run --unit=ds-probe --collect \
    -p "CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_READ_SEARCH" \
    -p "AmbientCapabilities=CAP_NET_ADMIN CAP_DAC_READ_SEARCH" \
    -p NoNewPrivileges=yes \
    -p ProtectSystem=strict \
    -p ProtectHome=read-only \
    -p ProtectControlGroups=yes \
    -p "RestrictAddressFamilies=AF_NETLINK AF_UNIX" \
    -p Environment=PATH=/usr/bin:/usr/sbin:/bin:/sbin \
    /bin/sh -c '
        echo "uid=$(id -u), capabilities=$(grep CapEff /proc/self/status)"
        echo "--- reading the fake game cmdline, which is what detection needs ---"
        found=0
        for p in $(pgrep -f "Overwatch.exe" 2>/dev/null); do
            found=1
            printf "  pid %s: " "$p"
            cat "/proc/$p/cmdline" 2>&1 | tr "\0" " " || echo "  UNREADABLE"
            echo
            printf "  cgroup: "
            cat "/proc/$p/cgroup" 2>&1 || echo "  UNREADABLE"
        done
        [ "$found" = 1 ] || echo "  pgrep found no Overwatch.exe process at all"
        echo "--- running nft (what apply needs) ---"
        nft list tables
        echo "  nft exit=$?"
    ' >/dev/null 2>&1
sleep 3
journalctl -u ds-probe.service --no-pager -n 30 2>&1 | sed 's/^/    /'
systemctl reset-failed ds-probe.service 2>/dev/null

echo
echo "############ 3. the same binary, by hand (baseline) ############"
nft delete table inet dropship_steamos 2>/dev/null
"$HELPER" watch --config "$DIAG_CONFIG" > "$HAND_LOG" 2>&1 &
HAND=$!
if wait_applied 20; then
    echo "  RESULT: applied — the binary and the inputs are fine"
else
    echo "  RESULT: did NOT apply even by hand. The problem is not the sandbox."
fi
kill "$HAND" 2>/dev/null
wait "$HAND" 2>/dev/null
echo "  --- its log ---"
sed 's/^/    /' "$HAND_LOG"
nft delete table inet dropship_steamos 2>/dev/null

# systemd applies every property the unit sets, for a like-for-like comparison.
# Both capabilities and the runtime directory are here because they are in the
# unit: a bisection that omits one asks a different question.
common_props=(
    -p "CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_READ_SEARCH"
    -p "AmbientCapabilities=CAP_NET_ADMIN CAP_DAC_READ_SEARCH"
    -p NoNewPrivileges=yes
    -p PrivateTmp=yes
    -p ProtectSystem=strict
    -p ProtectHome=read-only
    -p ProtectKernelTunables=yes
    -p ProtectKernelModules=yes
    -p ProtectControlGroups=yes
    -p ProtectClock=yes
    -p RestrictNamespaces=yes
    -p "RestrictAddressFamilies=AF_NETLINK AF_UNIX"
    -p LockPersonality=yes
    -p RuntimeDirectory=dropship-steamos
    -p RuntimeDirectoryMode=0755
    -p Environment=PATH=/usr/bin:/usr/sbin:/bin:/sbin
)

run_sandboxed() {
    desc=$1
    shift
    systemctl stop ds-diag.service 2>/dev/null
    systemctl reset-failed ds-diag.service 2>/dev/null
    nft delete table inet dropship_steamos 2>/dev/null
    systemd-run --unit=ds-diag --collect "$@" \
        "$HELPER" watch --config "$DIAG_CONFIG" >/dev/null 2>&1
    sleep 1
    if wait_applied 20; then
        echo "  RESULT: applied ($desc)"
        RESULT=applied
    else
        echo "  RESULT: did NOT apply ($desc)"
        RESULT=blocked
    fi
    echo "  --- ds-diag journal ---"
    journalctl -u ds-diag.service --no-pager -n 25 2>&1 | sed 's/^/    /'
    systemctl stop ds-diag.service 2>/dev/null
    systemctl reset-failed ds-diag.service 2>/dev/null
}

echo
echo "############ 4. with the full unit hardening ############"
run_sandboxed "full hardening" "${common_props[@]}"
full=$RESULT

if [ "$full" = blocked ]; then
    echo
    echo "############ 5. bisecting: capabilities only ############"
    run_sandboxed "both capabilities, no filesystem protection" \
        -p "CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_READ_SEARCH" \
        -p "AmbientCapabilities=CAP_NET_ADMIN CAP_DAC_READ_SEARCH" \
        -p Environment=PATH=/usr/bin:/usr/sbin:/bin:/sbin
    caps_only=$RESULT

    if [ "$caps_only" = applied ]; then
        echo
        echo "  => the capability set is fine; a filesystem/protection directive is the cause."
        echo
        echo "############ 6. bisecting: protection, no capability limit ############"
        run_sandboxed "protection directives, capabilities untouched" \
            -p PrivateTmp=yes -p ProtectSystem=strict -p ProtectHome=read-only \
            -p ProtectKernelTunables=yes -p ProtectKernelModules=yes \
            -p ProtectControlGroups=yes -p ProtectClock=yes -p RestrictNamespaces=yes \
            -p LockPersonality=yes -p Environment=PATH=/usr/bin:/usr/sbin:/bin:/sbin
        echo
        echo "  => if this applied, CapabilityBoundingSet/AmbientCapabilities is the culprit."
        echo "     if this also failed, narrow it to ProtectSystem=strict vs the rest."
    else
        echo
        echo "  => the capability set is the cause, with no filesystem directive involved."
    fi
fi

echo
echo "############ done ############"
echo "The service has been restarted. Your real service.json was never touched."
