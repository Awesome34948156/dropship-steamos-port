#!/usr/bin/env bash
#
# Dropship for SteamOS — on-device cgroup spike
#
# Verifies the assumptions the cgroup-scoped firewall design rests on. Nothing
# outside a throwaway `inet dropship_spike` table is touched, and that table is
# deleted on exit. The real `dropship_steamos` table is never modified.
#
# Usage:
#   ./spike-cgroup.sh              # safe: counter rules only
#   ./spike-cgroup.sh --drop       # adds a real drop rule for the game cgroup
#
# Run in Desktop Mode (Konsole), with Overwatch installed via Steam.

set -uo pipefail

TABLE=dropship_spike
GAME_PATTERN="overwatch.exe"
DO_DROP=0

for arg in "$@"; do
  case "$arg" in
    --drop) DO_DROP=1 ;;
    -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------- presentation

if [ -t 1 ]; then
  BOLD=$'\033[1m'; RED=$'\033[31m'; GREEN=$'\033[32m'
  YELLOW=$'\033[33m'; DIM=$'\033[2m'; OFF=$'\033[0m'
else
  BOLD=""; RED=""; GREEN=""; YELLOW=""; DIM=""; OFF=""
fi

step()  { printf '\n%s==> %s%s\n' "$BOLD" "$1" "$OFF"; }
ok()    { printf '  %s✓%s %s\n' "$GREEN" "$OFF" "$1"; }
warn()  { printf '  %s!%s %s\n' "$YELLOW" "$OFF" "$1"; }
fail()  { printf '  %s✗%s %s\n' "$RED" "$OFF" "$1"; }
info()  { printf '  %s%s%s\n' "$DIM" "$1" "$OFF"; }

pause() {
  if [ -t 0 ]; then
    printf '\n%s%s%s\n' "$BOLD" "$1" "$OFF"
    read -r -p "    press Enter when ready… " _ || true
  else
    printf '\n%s%s%s\n' "$BOLD" "$1" "$OFF"
    info "(non-interactive; continuing)"
  fi
}

cleanup() {
  step "Cleaning up"
  as_root nft delete table inet "$TABLE" 2>/dev/null \
    && ok "removed test table inet $TABLE" \
    || info "test table was already absent"
}
trap cleanup EXIT

as_root() {
  if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi
}

# --------------------------------------------------------------- pure helpers

# /proc/<pid>/cgroup -> cgroup v2 path with the leading slash removed, or empty.
# Picks the unified `0::` entry and drops the "(deleted)" marker a zombie
# process carries after its cgroup is removed.
cgroup_path_of() {
  sed -n 's/^0:://p' "/proc/$1/cgroup" 2>/dev/null \
    | head -n 1 \
    | sed 's/[[:space:]]*$//; s/ (deleted)$//; s|^/||'
}

# Number of slash-separated components. nftables counts cgroup ancestors
# one-based, so this equals the `level` that matches this exact cgroup.
level_of() {
  printf '%s' "$1" | awk -F/ '{ n=0; for (i=1;i<=NF;i++) if ($i!="") n++; print n }'
}

# First N non-empty components of a path, i.e. the ancestor at level N.
# Empty components are skipped without consuming the budget, so a leading or
# doubled slash cannot shift the result.
ancestor_of() {
  printf '%s' "$1" | awk -v n="$2" -F/ '{
    out=""; seen=0
    for (i=1;i<=NF;i++) {
      if ($i=="") continue
      seen++
      if (seen>n) break
      out = out (out=="" ? "" : "/") $i
    }
    print out
  }'
}

game_pid() {
  ps -eo pid=,args= 2>/dev/null \
    | awk -v pat="$GAME_PATTERN" 'tolower($0) ~ pat { print $1; exit }'
}

# Sum of `packets` across rules carrying the given comment.
counter_for() {
  as_root nft list table inet "$TABLE" 2>/dev/null \
    | grep "\"$1\"" \
    | grep -o 'packets [0-9]*' \
    | awk '{ s += $2 } END { print s+0 }'
}

# ------------------------------------------------------------------ 1. probe

step "1. Environment probe"
info "$(uname -srm)"

if ! command -v nft >/dev/null 2>&1; then
  fail "no 'nft' on PATH — nftables is not installed."
  warn "SteamOS has a read-only root filesystem, so a pacman install is wiped"
  warn "by OS updates. This is open question #1 and blocks everything else."
  exit 1
fi
ok "nft found: $(command -v nft)"
info "$(nft --version 2>&1)"

NFT_VERSION=$(nft --version 2>/dev/null | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' | head -n1)
if [ -n "$NFT_VERSION" ]; then
  if [ "$(printf '%s\n0.9.9\n' "$NFT_VERSION" | sort -V | head -n1)" = "0.9.9" ]; then
    ok "nftables $NFT_VERSION supports cgroup v2 matching (needs >= 0.9.9)"
  else
    fail "nftables $NFT_VERSION is older than 0.9.9 — cgroup v2 matching unavailable"
  fi
fi

if mount | grep -q 'type cgroup2'; then
  ok "cgroup v2 (unified) hierarchy is mounted"
else
  fail "no cgroup2 mount — matching will not work"
fi

KERNEL=$(uname -r)
info "kernel $KERNEL (cgroup v2 matching needs >= 5.13)"

CONFIG=""
[ -r /proc/config.gz ] && CONFIG=/proc/config.gz
[ -r "/boot/config-$KERNEL" ] && CONFIG="/boot/config-$KERNEL"
if [ -n "$CONFIG" ]; then
  for opt in CONFIG_NFT_SOCKET CONFIG_SOCK_CGROUP_DATA CONFIG_CGROUPS; do
    if zgrep -q "^$opt=y" "$CONFIG" 2>/dev/null || grep -q "^$opt=y" "$CONFIG" 2>/dev/null; then
      ok "$opt=y"
    else
      warn "$opt not confirmed in $CONFIG"
    fi
  done
else
  warn "no kernel config available to inspect (CONFIG_NFT_SOCKET unverified)"
fi

# -------------------------------------------------------- 2. locate the game

step "2. Locate Overwatch and read its cgroup"

PID=$(game_pid)
if [ -z "$PID" ]; then
  fail "no process matching '$GAME_PATTERN' is running."
  warn "Launch Overwatch from Steam first, then re-run this script."
  exit 1
fi
ok "Overwatch is running as PID $PID"

GAME_CGROUP=$(cgroup_path_of "$PID")
if [ -z "$GAME_CGROUP" ]; then
  fail "could not read a cgroup v2 path from /proc/$PID/cgroup"
  exit 1
fi
GAME_LEVEL=$(level_of "$GAME_CGROUP")
ok "cgroup: $GAME_CGROUP"
ok "depth:  $GAME_LEVEL components"

info "child processes of the game sit in these cgroups:"
ps --ppid "$PID" -o pid= 2>/dev/null | while read -r child; do
  child_path=$(cgroup_path_of "$child")
  [ -n "$child_path" ] && [ "$child_path" != "$GAME_CGROUP" ] \
    && info "    $child_path"
done

# ------------------------------------------------------ 3. control counter

step "3. Control: prove the mechanism works on this kernel"

SELF_CGROUP=$(cgroup_path_of $$)
SELF_LEVEL=$(level_of "$SELF_CGROUP")
ok "this shell's cgroup: $SELF_CGROUP (level $SELF_LEVEL)"

as_root nft delete table inet "$TABLE" 2>/dev/null
as_root nft add table inet "$TABLE" || exit 1
as_root nft add chain inet "$TABLE" output \
  '{ type filter hook output priority filter; policy accept; }' || exit 1
as_root nft add rule inet "$TABLE" output \
  socket cgroupv2 level "$SELF_LEVEL" "$SELF_CGROUP" counter comment "control" || exit 1

# Generate a little outbound traffic from this shell.
(curl -s -o /dev/null --max-time 5 https://example.com 2>/dev/null || true)

CONTROL=$(counter_for control)
if [ "$CONTROL" -gt 0 ]; then
  ok "control rule counted $CONTROL packets — cgroup v2 matching works here"
else
  fail "control rule counted 0 packets — cgroup matching is not working on this kernel"
  warn "the results below cannot be trusted; investigate this first"
fi

# ------------------------------------------- 4. one counter per ancestor level

step "4. Install a counter at every ancestor level"

info "a socket matches its own cgroup AND every ancestor, so the deepest"
info "level that increments reveals where Proton's sockets actually live."

for level in $(seq 1 "$GAME_LEVEL"); do
  path=$(ancestor_of "$GAME_CGROUP" "$level")
  [ -z "$path" ] && continue
  if as_root nft add rule inet "$TABLE" output \
      socket cgroupv2 level "$level" "$path" counter comment "lvl-$level" 2>/dev/null; then
    info "level $level -> $path"
  else
    fail "level $level -> $path (nft rejected this ancestor)"
  fi
done

pause "Now play or sit in an Overwatch match for ~30 seconds, then come back."

step "5. Results"
BEST=0
for level in $(seq 1 "$GAME_LEVEL"); do
  packets=$(counter_for "lvl-$level")
  path=$(ancestor_of "$GAME_CGROUP" "$level")
  if [ "$packets" -gt 0 ]; then
    ok "level $level: $packets packets   $path"
    BEST=$level
  else
    info "level $level: 0 packets       $path"
  fi
done

printf '\n'
if [ "$BEST" -eq 0 ]; then
  fail "No ancestor level matched the game's traffic."
  warn "Sockets are not inheriting this process's cgroup, or the game was idle."
  warn "Re-run while a match is actually in progress before concluding anything."
elif [ "$BEST" -eq "$GAME_LEVEL" ]; then
  ok "Sockets live in the game's own cgroup (level $BEST)."
  info "The design works as implemented: discover the PID's cgroup and match it."
else
  warn "Sockets live at level $BEST, ABOVE the game's own cgroup (level $GAME_LEVEL)."
  warn "Matching the game's exact path would miss them; match this ancestor instead:"
  warn "    socket cgroupv2 level $BEST \"$(ancestor_of "$GAME_CGROUP" "$BEST")\""
  info "This is the finding that changes the implementation."
fi

# --------------------------------------------------------- 6. relaunch test

pause "Step 6: fully QUIT Overwatch (back to the Steam UI), relaunch it, and re-enter a match."

NEW_PID=$(game_pid)
if [ -z "$NEW_PID" ]; then
  warn "Overwatch is not running — skipping the relaunch test"
else
  NEW_CGROUP=$(cgroup_path_of "$NEW_PID")
  info "new PID $NEW_PID, cgroup: $NEW_CGROUP"
  if [ "$NEW_CGROUP" = "$GAME_CGROUP" ]; then
    info "cgroup path is unchanged across the relaunch"
  else
    warn "cgroup path CHANGED across the relaunch"
  fi

  if [ "$BEST" -gt 0 ]; then
    before=$(counter_for "lvl-$BEST")
    pause "Play for ~30 seconds in this new session, then return."
    after=$(counter_for "lvl-$BEST")
    if [ "$after" -gt "$before" ]; then
      ok "the level-$BEST rule still counted packets after relaunch (+$((after - before)))"
      info "rules survive relaunches — the re-apply prompt may be unnecessary"
    else
      fail "the level-$BEST rule counted nothing new after relaunch"
      warn "re-applying on every game launch IS required, as assumed"
    fi
  fi
fi

# ------------------------------------------------------------ 7. optional drop

if [ "$DO_DROP" -eq 1 ] && [ "$BEST" -gt 0 ]; then
  step "7. Drop test (--drop)"
  DROP_PATH=$(ancestor_of "$GAME_CGROUP" "$BEST")
  as_root nft add rule inet "$TABLE" output \
    socket cgroupv2 level "$BEST" "$DROP_PATH" drop comment "drop-test" \
    && ok "installed drop rule for level $BEST"
  pause "Check in-game connectivity, and that a browser still reaches these regions."
  info "Remove it at any time with: sudo nft delete table inet $TABLE"
fi

step "Done"
info "The test table is removed on exit. Please paste this output back."
