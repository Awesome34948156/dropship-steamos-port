# shellcheck shell=bash
# Shared on-device fixture for the Steam Deck service scripts.
#
# Sourced, never executed: each script derives REPO from its own location and
# sources this file, so the checks work from any checkout. It carries only the
# parts that were identical across scripts — the fake game's name and scope, the
# desktop user, the nft/table probes, the cgroup probe and the PASS/FAIL
# reporting — so a change in what "the game looks like" cannot drift between
# them.
#
# The callers run as root on the Deck; each one checks that itself, because the
# message belongs where the user typed the command.

# These are read by the sourcing scripts, which shellcheck cannot see.
# shellcheck disable=SC2034
DESKTOP_USER=${DROPSHIP_DESKTOP_USER:-deck}
DESKTOP_GROUP=${DROPSHIP_DESKTOP_GROUP:-deck}
DESKTOP_HOME=${DROPSHIP_DESKTOP_HOME:-/home/deck}
DESKTOP_UID=$(id -u "$DESKTOP_USER" 2>/dev/null || printf '1000')
SCOPE=app-steam-app2357570-99999
V4=192.0.2.0/24
V6=2001:db8::/32
SCOPE_DIR=/sys/fs/cgroup/user.slice/user-$DESKTOP_UID.slice/user@$DESKTOP_UID.service/app.slice

as_root() {
    if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi
}

# Runs a command as the desktop user, inside their session bus/runtime
# directory. The fake game has to be started this way: a transient --user scope
# is what gives it the cgroup shape Steam's own launch creates.
as_deck() {
    runuser -u "$DESKTOP_USER" -- env "XDG_RUNTIME_DIR=/run/user/$DESKTOP_UID" "$@"
}

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

table_present() { nft list table inet dropship_steamos >/dev/null 2>&1; }

table_state() { if table_present; then echo yes; else echo no; fi; }

# Waits up to $2 seconds for the table to reach $1 ("yes" or "no").
wait_for_table() { # <yes|no> <seconds>
    local want=$1 limit=$2
    for _ in $(seq 1 "$((limit * 5))"); do
        [ "$(table_state)" = "$want" ] && return 0
        sleep 0.2
    done
    return 1
}

# Waits up to $1 seconds for the table to appear.
wait_applied() { wait_for_table yes "$1"; }

# HTTP status seen by a curl running *inside* the given cgroup, or empty if the
# process could not be moved there at all.
#
# The probe moves itself into the cgroup and only then execs curl. Doing it the
# other way round — background a curl and write its PID into cgroup.procs —
# races the fork: the shell spawns curl immediately, so curl may open its socket
# in the parent's cgroup and the rule would miss it. nft matches the cgroup the
# socket was created in, so the move has to land before the first connect.
probe_in_cgroup() { # <cgroup path> <ip>
    local probe status
    probe=$(mktemp) || return 1
    cat > "$probe" <<'EOS'
#!/bin/sh
echo $$ > "/sys/fs/cgroup/$1/cgroup.procs" || exit 3
exec curl -s -o /dev/null -m 5 -w '%{http_code}' "http://$2"
EOS
    as_root sh "$probe" "$1" "$2" 2>/dev/null
    status=$?
    rm -f "$probe"
    return "$status"
}

# PASS/FAIL reporting shared by the service scripts. `pass`/`fail` are counters
# read by the summary at the end of each caller.
pass=0
fail=0
ok()   { echo "  PASS  $*"; pass=$((pass + 1)); }
bad()  { echo "  FAIL  $*"; fail=$((fail + 1)); }
step() { echo; echo "== $* =="; }
