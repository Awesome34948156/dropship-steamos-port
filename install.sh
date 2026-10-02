#!/bin/sh
# Entry point for the release tarball. Run it with sudo.
#
#   sudo ./install.sh
#   sudo ./install.sh --uninstall
#
# If you have a git checkout, you do not want this file — use
# `sudo packaging/install.sh`, which finds the binaries where `cargo build
# --release` leaves them. This one is for the tarball, which has no build tree.
#
# Why it exists: packaging/install.sh locates the binaries relative to its own
# parent directory, so from a checkout it expects target/release/. A tarball has
# the binaries sitting at the top level instead. Rather than teach the installer
# about a second layout — and risk the copy that has actually been verified on a
# Deck — this names the binaries explicitly through the environment variables the
# installer already supports, then gets out of the way. Both entry points end in
# the same installer, unchanged.
set -eu

# Checked here as well as in packaging/install.sh, and not for redundancy: that
# script's message names its own path, so a user who typed `sudo ./install.sh`
# would be told to run `sudo .../packaging/install.sh` — a command they never
# typed and have no reason to trust. The check belongs wherever the user is.
[ "$(id -u)" -eq 0 ] || {
    echo "error: run this with sudo: sudo $0 $*" >&2
    exit 1
}

# Absolute, and computed without cd'ing, so it works from any working
# directory: running it from ~/Downloads gives the same result as cd'ing into
# the extracted directory first.
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)

helper=$here/dropship-steamos-helper
gui=$here/dropship-steamos

# Also checked by the installer's own preflight. Kept here because this is the
# one place that knows the user is looking at a tarball, and so can name the
# checkout command as the alternative. The installer can only say "these files
# are missing"; this can say "you probably wanted the other entry point".
[ -x "$helper" ] || {
    echo "error: no helper binary beside this script ($helper)" >&2
    echo "       from a checkout, run: sudo packaging/install.sh" >&2
    exit 1
}
[ -x "$gui" ] || {
    echo "error: no app binary beside this script ($gui)" >&2
    echo "       from a checkout, run: sudo packaging/install.sh" >&2
    exit 1
}

export DROPSHIP_STEAMOS_HELPER="$helper"
export DROPSHIP_STEAMOS_GUI="$gui"

exec "$here/packaging/install.sh" "$@"
