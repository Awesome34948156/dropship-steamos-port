#!/bin/sh
# Launch Dropship from a terminal inside the Deck's desktop session.
#
# Run this from Konsole on the Deck itself, not over SSH. The window needs
# WAYLAND_DISPLAY from the session, and the manual Apply path needs the session
# bus so KDE's polkit agent can answer the prompt. Over SSH both are absent, and
# Apply would fail even if the window somehow appeared.
#
# The installed launcher entry (see packaging/) is the normal way to start the
# app. This exists for when you want to watch stderr.
#
# Release binaries by default, which is what packaging/install.sh installs.
# Override either path to run a debug build instead.
set -eu
cd "$(dirname "$0")" || exit 1

HELPER=${DROPSHIP_STEAMOS_HELPER:-$PWD/target/release/dropship-steamos-helper}
GUI=${DROPSHIP_STEAMOS_GUI:-$PWD/target/release/dropship-steamos}

DROPSHIP_STEAMOS_HELPER="$HELPER" exec "$GUI"
