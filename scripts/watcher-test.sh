#!/bin/bash
# Drive the watcher by hand and check its whole cycle, with systemd out of the
# picture.
#
#   sudo scripts/watcher-test.sh
#
# Needs root: nft wants CAP_NET_ADMIN and the runtime directory lives in /run.
#
# This deliberately fakes the game rather than asking you to play it. A process
# whose argv[0] is "Overwatch.exe" is started inside a transient user scope
# named exactly the way Steam names one, so the watcher's discovery path — the
# part that cannot be exercised off the device — runs against an identical
# /proc/<pid>/cgroup and /proc/<pid>/cmdline.
#
# Nothing here touches your real config: the watcher is pointed at a temporary
# one, because --config is a parameter for exactly this reason.
#
# Deck-specific: it assumes the desktop user is `deck`. It also tests the
# watcher in isolation, which means it passes even when the *unit* is broken —
# scripts/post-install-test.sh is the stronger test, because it goes through the
# installed service and so catches sandbox mistakes this one cannot see. Running
# both is the point; this one is the faster loop while changing watcher logic.
set -u
export PATH=/usr/bin:/usr/sbin:/bin:/sbin

# Derived from this script's own location so it works from any checkout, the way
# packaging/install.sh does it.
REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
HELPER=$REPO/target/release/dropship-steamos-helper
CONFIG=/tmp/dropship-watcher-service.json
LOG=/tmp/dropship-watcher.log
SCOPE=app-steam-app2357570-99999
SCOPE_DIR=/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice
V4=192.0.2.0/24
V6=2001:db8::/32

pass=0
fail=0
ok()   { echo "  PASS  $*"; pass=$((pass + 1)); }
bad()  { echo "  FAIL  $*"; fail=$((fail + 1)); }
step() { echo; echo "== $* =="; }
check() { if [ "$1" = "$2" ]; then ok "$3"; else bad "$3 (wanted $2, got $1)"; fi; }

[ "$(id -u)" -eq 0 ] || { echo "run this with sudo"; exit 1; }
[ -x "$HELPER" ] || { echo "no helper at $HELPER"; exit 1; }

now_ms() { date +%s%3N; }

table_present() { nft list table inet dropship_steamos >/dev/null 2>&1; }

# How many rules in the live table are scoped to a given path.
rules_scoped_to() {
    nft list table inet dropship_steamos 2>/dev/null \
        | grep -F 'socket cgroupv2' | grep -cF "$1"
}

# `grep -c` already prints 0 when it matches nothing, so the `|| true` is there
# to swallow its exit status — appending `|| echo 0` would yield "0\n0" and
# every numeric comparison downstream would fail.
log_count() {
    [ -f "$LOG" ] || { echo 0; return; }
    grep -c "$1" "$LOG" 2>/dev/null || true
}

as_deck() { runuser -u deck -- env XDG_RUNTIME_DIR=/run/user/1000 "$@"; }

start_game() {
    # A run that aborted leaves a transient unit behind, and systemd-run then
    # refuses the name. Cheap insurance against having to know that.
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
    for _ in $(seq 1 30); do
        pgrep -f 'Overwatch\.exe' >/dev/null || return 0
        sleep 0.2
    done
    return 1
}

# Waits up to $1 seconds for the table to reach the wanted state.
wait_table() {
    local want=$1 limit=$2
    for _ in $(seq 1 "$((limit * 5))"); do
        if [ "$(table_present && echo yes || echo no)" = "$want" ]; then return 0; fi
        sleep 0.2
    done
    return 1
}

cleanup() {
    pkill -f 'Overwatch\.exe' 2>/dev/null
    as_deck systemctl --user stop "$SCOPE.scope" 2>/dev/null
    [ -n "${WATCHER:-}" ] && kill "$WATCHER" 2>/dev/null
    sleep 0.3
    nft delete table inet dropship_steamos 2>/dev/null
    rm -f "$CONFIG"
}
trap cleanup EXIT

echo "Dropship Phase 4: the watcher by hand"
echo "helper: $HELPER"

# ---------------------------------------------------------------- preparation
step "preparing a clean slate"
cleanup >/dev/null 2>&1
sleep 0.5
cat > "$CONFIG" <<JSON
{ "version": 1, "enabled": true, "revision": 1,
  "ipv4": ["$V4"], "ipv6": ["$V6"] }
JSON
chmod 0644 "$CONFIG"
table_present && bad "a dropship table was already present" || ok "no dropship table to start with"

# ------------------------------------------------------------------- baseline
step "the watcher runs with no game present"
"$HELPER" watch --config "$CONFIG" > "$LOG" 2>&1 &
WATCHER=$!
sleep 3
kill -0 "$WATCHER" 2>/dev/null && ok "the watcher is alive" || bad "the watcher exited"
table_present && bad "it applied blocks with no game running" || ok "it applied nothing with no game running"
grep -q 'watching for Overwatch' "$LOG" && ok "it logged a startup line" || bad "no startup line in the log"

# -------------------------------------------------------- 1. apply on launch
step "1. the game launches -> blocks applied"
start_game || bad "could not start the fake game"
started=$(now_ms)
if wait_table yes 15; then
    ok "the table appeared after $(( $(now_ms) - started ))ms"
else
    bad "the table never appeared"
fi
check "$(rules_scoped_to "$SCOPE")" 2 "both rules are scoped to $SCOPE"
nft list table inet dropship_steamos 2>/dev/null | grep -qF "$V4" \
    && ok "the v4 set carries $V4" || bad "the v4 set is missing $V4"
nft list table inet dropship_steamos 2>/dev/null | grep -qF "$V6" \
    && ok "the v6 set carries $V6" || bad "the v6 set is missing $V6"
check "$(log_count 'applied')" 1 "it applied exactly once"
nft list table inet dropship_steamos 2>/dev/null | grep -F 'daddr' \
    | grep -vqF 'socket cgroupv2' \
    && bad "there is a rule with no cgroup scope" || ok "every rule is cgroup-scoped"

# ------------------------------------------------------------ 2. steady state
step "2. nothing changes while the game just runs"
sleep 6
check "$(log_count 'applied')" 1 "no re-apply over 6s (no churn)"
check "$(log_count 'removed')" 0 "no removal over 6s"

# ------------------------------------------------------ 3. remove on exit
step "3. the game quits -> blocks removed after the grace period"
stopped=$(now_ms)
stop_game || bad "the fake game did not stop"
if wait_table no 25; then
    elapsed=$(( $(now_ms) - stopped ))
    ok "the table went away after ${elapsed}ms"
    # ABSENT_GRACE is 10s and the poll is 2s, so anything under ~8s would mean
    # the grace period is not being honoured.
    if [ "$elapsed" -ge 8000 ]; then
        ok "it waited out the grace period"
    else
        bad "it removed the blocks in ${elapsed}ms, faster than the 10s grace"
    fi
else
    bad "the table was still there 25s after the game quit"
fi

# --------------------------------------------- 4. recreate at the same path
step "4. the cgroup is recreated at the same path (a Steam restart)"
start_game || bad "could not restart the fake game"
wait_table yes 15 || bad "the table did not come back for round two"
inode_before=$(stat -c %i "$SCOPE_DIR/$SCOPE.scope" 2>/dev/null)
removes_before=$(log_count 'removed')
applies_before=$(log_count 'applied')
ok "round two is up (inode $inode_before)"

# Down and straight back up, well inside the 10s grace — this is the shape of a
# Steam restart, and the only thing that can tell it apart from "still running"
# is the cgroup object's identity.
stop_game >/dev/null 2>&1
start_game >/dev/null 2>&1
sleep 2
inode_after=$(stat -c %i "$SCOPE_DIR/$SCOPE.scope" 2>/dev/null)
if [ -n "$inode_after" ] && [ "$inode_before" != "$inode_after" ]; then
    ok "the cgroup was recreated: inode $inode_before -> $inode_after"
else
    bad "the cgroup was not recreated (inode $inode_before -> ${inode_after:-none})"
fi
check "$(log_count 'removed')" "$removes_before" "the grace period held, so nothing was torn down"
# The decisive check: nft binds a rule to the cgroup *object* that existed when
# it was created, so a rule left over from the old inode matches nothing. The
# apply line names the inode, so finding the new one there is proof the rules
# were rebuilt against the cgroup that is actually running.
for _ in $(seq 1 60); do
    grep -q "cgroup $inode_after" "$LOG" && break
    sleep 0.2
done
if grep -q "cgroup $inode_after" "$LOG"; then
    ok "it re-applied, and the log names the live cgroup object (inode $inode_after)"
else
    bad "it never re-applied to inode $inode_after — the rules would be silently dead"
    echo "        applies logged so far: $(log_count 'applied'), was $applies_before before the recreate"
fi

# -------------------------------------------------------- 5. the toggle off
step "5. switched off -> removed at once, no grace period"
cat > "$CONFIG" <<JSON
{ "version": 1, "enabled": false, "revision": 2,
  "ipv4": ["$V4"], "ipv6": ["$V6"] }
JSON
switched=$(now_ms)
if wait_table no 10; then
    elapsed=$(( $(now_ms) - switched ))
    ok "the table went away after ${elapsed}ms"
    if [ "$elapsed" -lt 5000 ]; then
        ok "it did not wait out any grace period"
    else
        bad "it took ${elapsed}ms, which looks like a grace period on the off path"
    fi
else
    bad "the table survived being switched off"
fi

step "6. and it stays off while the game is still running"
sleep 6
table_present && bad "the blocks came back with the toggle off" \
    || ok "no blocks came back"

# ------------------------------------------------------------------- wrapping
step "summary"
echo "$pass passed, $fail failed"
echo
echo "The watcher's own log, in full:"
sed 's/^/    /' "$LOG"
echo
if [ "$fail" -eq 0 ]; then
    echo "All good. Next: sudo $REPO/packaging/install.sh"
else
    echo "Something above failed; the log is at $LOG"
fi
exit "$([ "$fail" -eq 0 ] && echo 0 || echo 1)"
