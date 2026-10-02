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
# Run this over SSH from another machine while Overwatch runs in *Game Mode*:
# switching the Deck to Desktop Mode closes the running game, and steps 2-7 all
# need the game alive. The TTY comes from your SSH client, not from Konsole.

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

# nft re-parses the path string itself, so it needs *nft-level* quotes. Sent
# unquoted, `user@1000.service` lexes as `user`, `@`, then a bare number, and
# nft fails with "syntax error, unexpected number". Any path containing `@`
# (i.e. every real Steam cgroup) must be quoted.
add_scoped_counter() { # <level> <path> <comment>
  as_root nft add rule inet "$TABLE" output \
    socket cgroupv2 level "$1" "\"$2\"" counter comment "\"$3\""
}

# One packets value per ancestor level, space separated.
read_levels() {
  local level
  for level in $(seq 1 "$GAME_LEVEL"); do counter_for "lvl-$level"; done | tr '\n' ' '
}

# Per-level deltas between two read_levels snapshots.
level_deltas() { # <before> <after>
  printf '%s\n%s\n' "$1" "$2" | awk '{
    if (NR==1) { n = split($0, a, " ") }
    else {
      split($0, b, " ")
      for (i=1;i<=n;i++) printf "%s%s", (i>1?" ":""), b[i]-a[i]
      print ""
    }
  }'
}

delta_at() { # <deltas> <level>
  printf '%s' "$1" | awk -v n="$2" '{ print $n+0 }'
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
    # =m counts: nft_socket ships as a module and autoloads on first use, so
    # only checking =y reports a false alarm on every stock Valve kernel.
    val=$(zgrep -m1 "^$opt=" "$CONFIG" 2>/dev/null || grep -m1 "^$opt=" "$CONFIG" 2>/dev/null)
    case "$val" in
      *"=y") ok "$opt=y" ;;
      *"=m") ok "$opt=m (module; autoloads when a socket rule is added)" ;;
      "")    warn "$opt absent from $CONFIG" ;;
      *)     warn "$opt disabled ($val)" ;;
    esac
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
add_scoped_counter "$SELF_LEVEL" "$SELF_CGROUP" "control" || exit 1

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
info "level that moves reveals where Proton's sockets actually live."
info "caveat: levels at or above user@1000.service also carry Steam's own and"
info "this SSH session's traffic, so only the game's own level is unambiguous."

for level in $(seq 1 "$GAME_LEVEL"); do
  path=$(ancestor_of "$GAME_CGROUP" "$level")
  [ -z "$path" ] && continue
  if err=$(add_scoped_counter "$level" "$path" "lvl-$level" 2>&1); then
    info "level $level -> $path"
  else
    fail "level $level -> $path"
    info "    nft said: $err"
  fi
done

# ------------------------------------------------------ 5. game-running window

step "5. Game running: per-level deltas"

BEFORE=$(read_levels)
pause "Get into an Overwatch match (or the practice range) for ~30 seconds, then come back."
AFTER=$(read_levels)
RUNNING=$(level_deltas "$BEFORE" "$AFTER")

for level in $(seq 1 "$GAME_LEVEL"); do
  info "level $level: +$(delta_at "$RUNNING" "$level") packets   $(ancestor_of "$GAME_CGROUP" "$level")"
done

GAME_DELTA=$(delta_at "$RUNNING" "$GAME_LEVEL")
printf '\n'
if [ "$GAME_DELTA" -gt 0 ]; then
  ok "the game's OWN cgroup (level $GAME_LEVEL) moved: +$GAME_DELTA packets."
  info "Sockets inherit the game's cgroup, so matching its exact path is correct —"
  info "which is what the app already does."
else
  fail "the game's own cgroup (level $GAME_LEVEL) did not move."
  warn "Either the game was idle, or its sockets live at a higher level."
  warn "Step 6 separates the two: a level carrying other traffic keeps counting"
  warn "after the game closes, while the game's own level cannot."
fi

# ------------------------------------------------------ 6. game-closed control

pause "Step 6: fully QUIT Overwatch back to the Steam UI, then press Enter."

CLOSED_BEFORE=$(read_levels)
info "measuring 20s with the game closed…"
sleep 20
CLOSED_AFTER=$(read_levels)
CLOSED=$(level_deltas "$CLOSED_BEFORE" "$CLOSED_AFTER")

printf '\n'
for level in $(seq 1 "$GAME_LEVEL"); do
  info "level $level: +$(delta_at "$CLOSED" "$level") packets with the game closed"
done
printf '\n'

if [ "$(delta_at "$CLOSED" "$GAME_LEVEL")" -eq 0 ]; then
  ok "the game's own level stayed flat with the game closed — it is game-specific."
else
  warn "the game's own level still moved with the game closed. Its path embeds the"
  warn "launcher PID, so nothing should match it — treat those numbers as suspect."
fi

# A level that moved while the game was closed is carrying someone else's
# traffic (Steam, gamescope, this SSH session), so it cannot be attributed.
BEST=0
if [ "$GAME_DELTA" -gt 0 ]; then
  BEST=$GAME_LEVEL
else
  for level in $(seq 1 "$GAME_LEVEL"); do
    [ "$(delta_at "$CLOSED" "$level")" -eq 0 ] || continue
    [ "$(delta_at "$RUNNING" "$level")" -gt 0 ] || continue
    BEST=$level
  done
  if [ "$BEST" -gt 0 ]; then
    ok "level $BEST moved only while the game was running: $(ancestor_of "$GAME_CGROUP" "$BEST")"
    warn "matching the game's own level would miss those — match this ancestor instead."
  else
    fail "no level can be attributed to the game. Re-run during an active match."
  fi
fi

# ------------------------------------------------------------ 7. relaunch test

pause "Step 7: relaunch Overwatch, get back into a match, then press Enter."

NEW_PID=$(game_pid)
if [ -z "$NEW_PID" ]; then
  warn "Overwatch is not running — skipping the relaunch test"
elif [ "$NEW_PID" = "$PID" ]; then
  fail "the PID is still $PID — the game was not actually relaunched."
  warn "skipping the relaunch test rather than reporting a false result."
elif [ "$BEST" -eq 0 ]; then
  warn "no attributable level to test — skipping the relaunch test"
else
  NEW_CGROUP=$(cgroup_path_of "$NEW_PID")
  info "old PID $PID -> $GAME_CGROUP"
  info "new PID $NEW_PID -> $NEW_CGROUP"

  before=$(counter_for "lvl-$BEST")
  pause "Play for ~30 seconds in this new session, then return."
  after=$(counter_for "lvl-$BEST")
  delta=$((after - before))

  if [ "$BEST" -eq "$GAME_LEVEL" ]; then
    # The rule still pins the *old* launcher's scope, which the new instance
    # cannot be in, so counting nothing is the expected and informative result.
    if [ "$delta" -eq 0 ]; then
      ok "the old level-$BEST rule counted nothing after relaunch, as expected."
      warn "the cgroup path is per-launch, so blocks MUST be re-applied after"
      warn "every game launch. The re-apply prompt is load-bearing."
    else
      warn "the old rule counted +$delta — unexpected; the path may not be per-launch."
    fi
  elif [ "$delta" -gt 0 ]; then
    ok "the level-$BEST ancestor rule kept counting (+$delta) after relaunch"
    info "an ancestor scope survives relaunches; an exact-scope match would not"
  else
    warn "the level-$BEST rule counted nothing new after relaunch"
  fi
fi

# ------------------------------------------------------------ 7. optional drop

if [ "$DO_DROP" -eq 1 ] && [ "$BEST" -gt 0 ]; then
  step "8. Drop test (--drop)"
  DROP_PATH=$(ancestor_of "$GAME_CGROUP" "$BEST")
  as_root nft add rule inet "$TABLE" output \
    socket cgroupv2 level "$BEST" "$DROP_PATH" drop comment "drop-test" \
    && ok "installed drop rule for level $BEST"
  pause "Check in-game connectivity, and that a browser still reaches these regions."
  info "Remove it at any time with: sudo nft delete table inet $TABLE"
fi

step "Done"
info "The test table is removed on exit. Please paste this output back."
