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
REPO=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
# shellcheck source=scripts/lib/deck-fixture.sh
. "$REPO/scripts/lib/deck-fixture.sh"

HELPER=$REPO/target/release/dropship-steamos-helper
UNIT=dropship-steamos.service

[ "$(id -u)" -eq 0 ] || { echo "run this with sudo"; exit 1; }
[ -x "$HELPER" ] || { echo "no helper at $HELPER"; exit 1; }

# Root-run test files, in a directory only root can predict: a fixed /tmp name
# can be pre-created as a symlink by anyone. The config is temporary anyway, but
# the watcher runs as root and writes the log.
TEST_DIR=$(mktemp -d)
CONFIG=$TEST_DIR/service.json
LOG=$TEST_DIR/watcher.log

# The installed service is the other owner of the nft table and the watcher
# lock. Left running, it would remove the table this test just applied and the
# hand-run watcher would fail to take the lock — the worst of both. Stop it for
# the duration, and put it back the way it was on exit.
service_was_active=0
if systemctl is-active --quiet "$UNIT" 2>/dev/null; then
    service_was_active=1
fi

now_ms() { date +%s%3N; }

check() { if [ "$1" = "$2" ]; then ok "$3"; else bad "$3 (wanted $2, got $1)"; fi; }

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

# Waits up to $2 seconds for a literal string to appear in the live table.
wait_for_element() { # <text> <seconds>
    local needle=$1 limit=$2
    for _ in $(seq 1 "$((limit * 5))"); do
        nft list table inet dropship_steamos 2>/dev/null | grep -qF "$needle" && return 0
        sleep 0.2
    done
    return 1
}

# Replaces the config atomically: the on-disk file is either the old document or
# the new one, never a half-written prefix. A plain redirect can be caught
# mid-write, and the watcher correctly treats an unreadable config as "do
# nothing", which would make a timing test meaningless.
write_config() {
    local tmp="$CONFIG.tmp.$$"
    cat > "$tmp"
    chmod 0644 "$tmp"
    mv -f "$tmp" "$CONFIG"
}

cleanup() {
    stop_game >/dev/null 2>&1
    [ -n "${WATCHER:-}" ] && kill "$WATCHER" 2>/dev/null
    sleep 0.3
    # Only if the service is not running: while it is, the table is the
    # service's live state, not this test's leftovers. The refusal path below
    # covers the usual way that happens.
    if ! systemctl is-active --quiet "$UNIT" 2>/dev/null; then
        nft delete table inet dropship_steamos 2>/dev/null
    fi
    rm -rf "$TEST_DIR"
    if [ "$service_was_active" -eq 1 ]; then
        systemctl start "$UNIT" 2>/dev/null
    fi
}
trap cleanup EXIT

echo "Dropship Phase 4: the watcher by hand"
echo "helper: $HELPER"

step "the installed service must not run this test with us"
if [ "$service_was_active" -eq 1 ]; then
    if systemctl stop "$UNIT" 2>/dev/null; then
        ok "stopped $UNIT; it cannot remove the table or hold the lock during the test"
    else
        bad "could not stop $UNIT"
        echo "Refusing to continue: it would fight this test for the table." >&2
        # Nothing was changed, so there is nothing to undo — and the cleanup
        # trap would kill the fake-game pattern and delete the table of a
        # service that is still running.
        trap - EXIT
        rmdir "$TEST_DIR" 2>/dev/null
        exit 1
    fi
else
    ok "$UNIT is not active, so nothing else is watching"
fi

# ---------------------------------------------------------------- preparation
step "preparing a clean slate"
# Not the cleanup function: that restarts the installed service, which is the
# one thing this preparation must not do.
stop_game >/dev/null 2>&1
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
if wait_for_table yes 15; then
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

# ---------------------------------------- 2b. a changed selection while running
step "2b. a changed selection is re-applied while the game runs"
# The watcher compares the plan it applied with the config on every poll. Before
# that comparison existed, changing regions while rules were up did nothing at
# all until the game restarted — silently. ACTIVE_INTERVAL is 2s.
V4_ALT=198.51.100.0/24
changed=$(now_ms)
write_config <<JSON
{ "version": 1, "enabled": true, "revision": 2,
  "ipv4": ["$V4_ALT"], "ipv6": ["$V6"] }
JSON
if wait_for_element "$V4_ALT" 5; then
    elapsed=$(( $(now_ms) - changed ))
    ok "the new v4 range reached nft after ${elapsed}ms"
    # One 2s poll plus the nft apply, with slack for scheduling on a handheld.
    if [ "$elapsed" -le 4000 ]; then
        ok "it updated within one poll (~2s)"
    else
        bad "it took ${elapsed}ms, longer than the 2s poll should allow"
    fi
else
    bad "the new v4 range never reached nft — a changed selection is ignored"
fi
nft list table inet dropship_steamos 2>/dev/null | grep -qF "$V4" \
    && bad "the old v4 range $V4 is still present" \
    || ok "the old v4 range $V4 was replaced"
nft list table inet dropship_steamos 2>/dev/null | grep -qF "$V6" \
    && ok "the unchanged v6 range survived the re-apply" \
    || bad "the v6 range disappeared when only v4 changed"

# ------------------------------------------------------ 3. remove on exit
step "3. the game quits -> blocks removed after the grace period"
stopped=$(now_ms)
stop_game || bad "the fake game did not stop"
if wait_for_table no 25; then
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
wait_for_table yes 15 || bad "the table did not come back for round two"
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
write_config <<JSON
{ "version": 1, "enabled": false, "revision": 3,
  "ipv4": ["$V4"], "ipv6": ["$V6"] }
JSON
switched=$(now_ms)
if wait_for_table no 10; then
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

# ------------------------------- 7. off with an empty selection
step "7. switched off with an empty selection -> removed"
# The off position has to win over "nothing selected". If the empty-selection
# guard ran first, this combination would leave live rules installed with
# nothing left to remove them — the user cleared the regions and switched the
# feature off, and the blocks would survive both.
write_config <<JSON
{ "version": 1, "enabled": true, "revision": 4,
  "ipv4": ["$V4"], "ipv6": ["$V6"] }
JSON
if wait_for_table yes 15; then
    ok "the table came back for the empty-selection test"
else
    bad "the table did not come back; cannot test off with an empty selection"
fi
switched=$(now_ms)
write_config <<JSON
{ "version": 1, "enabled": false, "revision": 5,
  "ipv4": [], "ipv6": [] }
JSON
if wait_for_table no 10; then
    elapsed=$(( $(now_ms) - switched ))
    ok "the table went away after ${elapsed}ms"
    if [ "$elapsed" -lt 5000 ]; then
        ok "the empty selection did not delay the removal"
    else
        bad "it took ${elapsed}ms; the off path should not wait"
    fi
else
    bad "enabled:false with an empty selection left the rules installed"
fi

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
if [ "$service_was_active" -eq 1 ]; then
    echo "$UNIT was stopped for this test and is started again on exit."
fi
exit "$([ "$fail" -eq 0 ] && echo 0 || echo 1)"
