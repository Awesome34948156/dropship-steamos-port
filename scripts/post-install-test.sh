#!/bin/bash
# Check the *installed* service, as opposed to the hand-run watcher that
# scripts/watcher-test.sh covers.
#
#   sudo scripts/post-install-test.sh
#
# Run it after packaging/install.sh. It answers the one thing that cannot be
# tested by running the helper by hand: whether the watcher still works once
# systemd has applied the unit's hardening. Every failure of that kind is
# silent — the service stays active and simply never applies anything.
#
# That is not hypothetical. The first version of the unit bounded capabilities
# to CAP_NET_ADMIN alone, which left the helper unable to traverse the 0700
# /home/deck, and so unable to read its own config at all. The journal said
# "Permission denied" and the service looked idle rather than broken. See the
# capability comment in packaging/dropship-steamos.service. Anything added to
# that hardening block should be run past this script before it ships.
#
# It also checks ExecStopPost, which is the promise that stopping the service
# cannot leave drop rules behind with nothing left running to remove them.
#
# Your region selection is backed up and restored; the service is left running.
set -u
export PATH=/usr/bin:/usr/sbin:/bin:/sbin

UNIT=dropship-steamos.service
LIB=/var/lib/dropship-steamos
HELPER=$LIB/dropship-steamos-helper
CONFIG=/home/deck/.config/dropship-steamos/service.json
BACKUP=$CONFIG.before-post-install-test
SCOPE=app-steam-app2357570-99999
SCOPE_DIR=/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice
V4=192.0.2.0/24
V6=2001:db8::/32

pass=0
fail=0
ok()   { echo "  PASS  $*"; pass=$((pass + 1)); }
bad()  { echo "  FAIL  $*"; fail=$((fail + 1)); }
step() { echo; echo "== $* =="; }

[ "$(id -u)" -eq 0 ] || { echo "run this with sudo"; exit 1; }

table_present() { nft list table inet dropship_steamos >/dev/null 2>&1; }
as_deck() { runuser -u deck -- env XDG_RUNTIME_DIR=/run/user/1000 "$@"; }
now_ms() { date +%s%3N; }

start_game() {
    as_deck systemctl --user stop "$SCOPE.scope" 2>/dev/null
    as_deck systemctl --user reset-failed "$SCOPE.scope" 2>/dev/null
    as_deck systemd-run --user --scope --unit="$SCOPE" --collect \
        bash -c 'exec -a Overwatch.exe sleep 300' >/dev/null 2>&1 &
    for _ in $(seq 1 30); do
        pgrep -f 'Overwatch\.exe' >/dev/null && return 0
        sleep 0.2
    done
    return 1
}

stop_game() {
    pkill -f 'Overwatch\.exe' 2>/dev/null
    as_deck systemctl --user stop "$SCOPE.scope" 2>/dev/null
    for _ in $(seq 1 30); do pgrep -f 'Overwatch\.exe' >/dev/null || return 0; sleep 0.2; done
    return 1
}

cleanup() {
    stop_game >/dev/null 2>&1
    if [ -f "$BACKUP" ]; then mv -f "$BACKUP" "$CONFIG"; fi
    systemctl start "$UNIT" 2>/dev/null
}
trap cleanup EXIT

echo "Dropship post-install check"

# ------------------------------------------------------------------- layout
step "what the installer put where"
[ -f "/etc/systemd/system/$UNIT" ] && ok "the unit is installed" || bad "no unit at /etc/systemd/system/$UNIT"
[ -x "$HELPER" ] && ok "the helper is installed and executable" || bad "no executable helper at $HELPER"

helper_owner=$(stat -c '%U:%G %a' "$HELPER" 2>/dev/null)
if [ "$helper_owner" = "root:root 755" ]; then
    ok "the helper is root-owned 755 ($helper_owner) — the desktop user cannot replace it"
else
    bad "the helper is $helper_owner; expected root:root 755"
fi

# Root-owned in a root-owned directory is the property that makes running it
# without a prompt safe, so the directory matters as much as the file.
lib_owner=$(stat -c '%U:%G %a' "$LIB" 2>/dev/null)
[ "$lib_owner" = "root:root 755" ] && ok "its directory is root-owned 755" \
    || bad "its directory is $lib_owner; expected root:root 755"

gui=/home/deck/.local/lib/dropship-steamos/dropship-steamos
desktop=/home/deck/.local/share/applications/dropship-steamos.desktop
icon=/home/deck/.local/lib/dropship-steamos/game-icon-overwatch.svg
[ -x "$gui" ] && ok "the GUI is installed" || bad "no GUI at $gui"
[ -f "$icon" ] && ok "the launcher icon is installed" || bad "no icon at $icon"
if [ -f "$desktop" ]; then
    desktop_owner=$(stat -c '%U:%G' "$desktop")
    # Written as the desktop user on purpose: a root-owned file in the home
    # directory is a mess that outlives the uninstall.
    [ "$desktop_owner" = "deck:deck" ] && ok "the launcher entry is owned by deck, not root" \
        || bad "the launcher entry is $desktop_owner; expected deck:deck"
    grep -q '^Icon=.*game-icon-overwatch.svg' "$desktop" \
        && ok "the launcher entry points at an icon that exists" \
        || bad "the launcher entry's Icon= does not point at the installed icon"
else
    bad "no launcher entry at $desktop"
fi

# ------------------------------------------------------------------ running
step "the service is actually running"
systemctl is-active --quiet "$UNIT" && ok "it is active" || bad "it is not active"
systemctl is-enabled --quiet "$UNIT" && ok "it is enabled for boot" || bad "it is not enabled"

# The GUI asks systemd this same question, unprivileged, to decide whether to
# show the toggle or the manual buttons.
as_deck systemctl is-active --quiet "$UNIT" && ok "deck can query it without root (the GUI depends on this)" \
    || bad "deck cannot query the unit's state"

# ------------------------------------------------- the capability question
step "nft works under the unit's hardening — the thing only systemd can answer"
[ -f "$CONFIG" ] && cp -a "$CONFIG" "$BACKUP"
mkdir -p "$(dirname "$CONFIG")"
cat > "$CONFIG" <<JSON
{ "version": 1, "enabled": true, "revision": 900001,
  "ipv4": ["$V4"], "ipv6": ["$V6"] }
JSON
chmod 0644 "$CONFIG"

nft delete table inet dropship_steamos 2>/dev/null
systemctl restart "$UNIT"
sleep 2
systemctl is-active --quiet "$UNIT" || bad "the service did not survive a restart"

start_game || bad "could not start the fake game"
applied_ms=""
started=$(now_ms)
for _ in $(seq 1 150); do
    if table_present; then applied_ms=$(( $(now_ms) - started )); break; fi
    sleep 0.2
done

if [ -n "$applied_ms" ]; then
    ok "the service applied rules after ${applied_ms}ms (nft works inside the sandbox)"
else
    bad "the service never applied anything — nft is most likely blocked"
    echo "        CapabilityBoundingSet=CAP_NET_ADMIN or ProtectSystem=strict is the suspect."
    echo "        journalctl -u $UNIT -n 40"
fi

if [ -n "$applied_ms" ]; then
    nft list table inet dropship_steamos 2>/dev/null | grep -qF "$SCOPE" \
        && ok "the rules are scoped to the live game cgroup" \
        || bad "the rules are not scoped to $SCOPE"
    nft list table inet dropship_steamos 2>/dev/null | grep -F 'daddr' | grep -vqF 'socket cgroupv2' \
        && bad "there is a rule with no cgroup scope" || ok "every rule is cgroup-scoped"
    journalctl -u "$UNIT" --no-pager -n 20 2>/dev/null | grep -q 'applied' \
        && ok "the transition reached the journal" || bad "nothing about it in the journal"
fi

# The GUI cannot read nft — that needs CAP_NET_ADMIN — so the published state
# is its only way to know what is applied.
step "the service publishes state the GUI can read"
if [ -f /run/dropship-steamos/state.json ]; then
    ok "/run/dropship-steamos/state.json exists"
    as_deck cat /run/dropship-steamos/state.json >/dev/null 2>&1 \
        && ok "deck can read it" || bad "deck cannot read it; the GUI would show nothing"
    as_deck cat /run/dropship-steamos/state.json 2>/dev/null | grep -q "$SCOPE" \
        && ok "it names the cgroup the rules are bound to" \
        || bad "it does not mention $SCOPE"
else
    bad "no published state at /run/dropship-steamos/state.json"
fi

# -------------------------------------------------- stopping leaves nothing
step "stopping the service removes the rules (ExecStopPost)"
systemctl stop "$UNIT"
sleep 2
table_present && bad "the rules survived the service stopping — they would leak forever" \
    || ok "no rules left behind"

# ------------------------------------------------------ restoring the world
step "putting things back"
systemctl start "$UNIT"
sleep 1
systemctl is-active --quiet "$UNIT" && ok "the service is running again" || bad "the service did not come back"
stop_game >/dev/null 2>&1
if [ -f "$BACKUP" ]; then
    mv -f "$BACKUP" "$CONFIG"
    ok "your region selection is restored"
else
    rm -f "$CONFIG"
    ok "no selection to restore; the test config was removed"
fi

step "summary"
echo "$pass passed, $fail failed"
exit "$([ "$fail" -eq 0 ] && echo 0 || echo 1)"
