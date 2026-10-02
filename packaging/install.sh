#!/bin/sh
# Install the Dropship watcher service, so blocks are applied when Overwatch
# starts and removed when it exits, with no password prompt.
#
#   sudo packaging/install.sh
#   sudo packaging/install.sh --uninstall
#
# Safe to run again: it is how you repair an install after a SteamOS update.
#
# Why a service rather than a passwordless polkit rule: the privileged side
# decides what rules to build, so nothing the user writes is ever executed as
# root. The helper is installed root-owned in a root-owned directory, which is
# what makes running it without a prompt safe.
#
# Where things go, and why:
#   /var/lib/dropship-steamos/  the helper. Root-owned, so the desktop user
#                               cannot replace what root will execute.
#   /etc/systemd/system/        the unit. `/etc` is an overlay on SteamOS and
#                               this path is already on the base keep-list, so
#                               it survives an atomic update with no extra work.
#   ~/.local/lib/…              the GUI. Unprivileged, so it stays user-owned.
set -eu

UNIT=dropship-steamos.service
LIB_DIR=/var/lib/dropship-steamos
UNIT_DIR=/etc/systemd/system
SERVICE_USER_HOME_CONFIG=.config/dropship-steamos/service.json

say() { printf '%s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run this with sudo: sudo $0 $*"

REPO=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
HELPER_SRC=${DROPSHIP_HELPER:-$REPO/target/release/dropship-steamos-helper}
GUI_SRC=${DROPSHIP_GUI:-$REPO/target/release/dropship-steamos}
ICON_SRC=$REPO/assets/icons/game-icon-overwatch.svg

# The desktop user owns the GUI and the config; root only owns the helper.
detect_desktop_user() {
    if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != root ]; then
        printf '%s' "$SUDO_USER"
        return
    fi
    found=$(loginctl list-users --no-legend 2>/dev/null | awk '$2 != "root" {print $2; exit}') || found=
    if [ -z "$found" ]; then
        found=$(getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 {print $1; exit}') || found=
    fi
    printf '%s' "$found"
}

DESKTOP_USER=$(detect_desktop_user)
[ -n "$DESKTOP_USER" ] || die "could not work out which user's desktop this is; set SUDO_USER"
DESKTOP_HOME=$(getent passwd "$DESKTOP_USER" | cut -d: -f6)
[ -n "$DESKTOP_HOME" ] && [ -d "$DESKTOP_HOME" ] || die "no home directory for $DESKTOP_USER"
DESKTOP_GROUP=$(id -gn "$DESKTOP_USER")
CONFIG_PATH=$DESKTOP_HOME/$SERVICE_USER_HOME_CONFIG

# Fail loudly and specifically, rather than falling back to the manual path and
# leaving the user wondering why they are still being prompted.
probe_writable() {
    probe=$UNIT_DIR/.dropship-write-probe
    if ! : > "$probe" 2>/dev/null; then
        die "cannot write to $UNIT_DIR even as root.
SteamOS keeps /etc on an overlay whose upper layer lives in /var, so this is
usually writable. If it is not, the service cannot be installed at all — tell
whoever maintains Dropship rather than reaching for 'steamos-readonly disable',
which turns off dm-verity for the whole system."
    fi
    rm -f "$probe"
}

install_service() {
    [ -x "$HELPER_SRC" ] || die "helper not found at $HELPER_SRC; build it with 'cargo build --release' or set DROPSHIP_HELPER"
    probe_writable

    say "Installing the privileged helper into $LIB_DIR"
    install -d -o root -g root -m 0755 "$LIB_DIR"
    install -o root -g root -m 0755 "$HELPER_SRC" "$LIB_DIR/dropship-steamos-helper"

    say "Installing $UNIT"
    sed "s|@CONFIG@|$CONFIG_PATH|g" "$REPO/packaging/$UNIT" > "$UNIT_DIR/$UNIT"
    chown root:root "$UNIT_DIR/$UNIT"
    chmod 0644 "$UNIT_DIR/$UNIT"

    systemctl daemon-reload
    systemctl enable "$UNIT"
    # restart, not 'enable --now': on a re-run this is an upgrade, and the
    # running process still has the previous binary mapped.
    systemctl restart "$UNIT"
}

install_launcher() {
    if [ ! -x "$GUI_SRC" ]; then
        say "Skipping the launcher entry: no GUI binary at $GUI_SRC"
        return
    fi

    gui_dir=$DESKTOP_HOME/.local/lib/dropship-steamos
    apps_dir=$DESKTOP_HOME/.local/share/applications
    say "Installing the app for $DESKTOP_USER into $gui_dir"
    install -d -o "$DESKTOP_USER" -g "$DESKTOP_GROUP" -m 0755 "$gui_dir"
    install -o "$DESKTOP_USER" -g "$DESKTOP_GROUP" -m 0755 "$GUI_SRC" \
        "$gui_dir/dropship-steamos"
    [ -f "$ICON_SRC" ] && install -o "$DESKTOP_USER" -g "$DESKTOP_GROUP" -m 0644 \
        "$ICON_SRC" "$gui_dir/game-icon-overwatch.svg"

    # Written as the desktop user, not as root: a root-owned file inside the
    # home directory is a small mess that outlives the uninstall.
    install -d -o "$DESKTOP_USER" -g "$DESKTOP_GROUP" -m 0755 "$apps_dir"
    sed -e "s|@HELPER@|$LIB_DIR/dropship-steamos-helper|g" \
        -e "s|@GUI@|$gui_dir/dropship-steamos|g" \
        -e "s|@ICON@|$gui_dir/game-icon-overwatch.svg|g" \
        "$REPO/packaging/dropship-steamos.desktop" \
        > "$apps_dir/dropship-steamos.desktop"
    chown "$DESKTOP_USER:$DESKTOP_GROUP" "$apps_dir/dropship-steamos.desktop"
    chmod 0644 "$apps_dir/dropship-steamos.desktop"
}

report() {
    say ""
    if systemctl is-active --quiet "$UNIT"; then
        say "The watcher is running. Blocks will be applied while Overwatch runs."
    else
        say "WARNING: $UNIT is not running. See: journalctl -u $UNIT -n 40"
    fi
    say ""
    say "Next:"
    say "  1. Open 'Dropship for SteamOS' from the application launcher."
    say "  2. Select regions, then switch on 'Block while Overwatch runs'."
    say "  3. Launch Overwatch. Within a few seconds:"
    say "       sudo nft list table inet dropship_steamos"
    say ""
    say "Logs:   journalctl -u $UNIT -f"
    say "Remove: sudo $0 --uninstall"
}

uninstall_service() {
    say "Stopping and removing $UNIT"
    systemctl stop "$UNIT" 2>/dev/null || true
    systemctl disable "$UNIT" 2>/dev/null || true
    rm -f "$UNIT_DIR/$UNIT"
    systemctl daemon-reload
    rm -rf "$LIB_DIR"
    # The published state and lock live in tmpfs; systemd removes the runtime
    # directory, but clear it too in case the service never started.
    rm -rf /run/dropship-steamos
}

uninstall_launcher() {
    say "Removing the launcher entry and app for $DESKTOP_USER"
    rm -f "$DESKTOP_HOME/.local/share/applications/dropship-steamos.desktop"
    rm -rf "$DESKTOP_HOME/.local/lib/dropship-steamos"
}

case "${1:-}" in
    --uninstall)
        uninstall_service
        uninstall_launcher
        say ""
        say "Removed. Your region selection in $CONFIG_PATH was left alone."
        say "Any rules still installed can be cleared with: sudo nft delete table inet dropship_steamos"
        ;;
    "")
        install_service
        install_launcher
        report
        ;;
    *)
        die "unknown option '$1'; use no argument to install, or --uninstall"
        ;;
esac
