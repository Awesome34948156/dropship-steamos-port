# Installing Dropship for SteamOS

For putting a released build on a Steam Deck. If you have a git checkout and a Rust
toolchain, the [README](README.md#automatic-blocking) covers that path instead.

## What you need

- **An x86_64 Steam Deck.** The archive is built for x86_64, so it is right for every Steam
  Deck and wrong for anything else.
- **Overwatch 2 installed through Steam.** The app finds the game and its Proton prefix
  itself; it cannot block for a game that is not there.
- **Desktop Mode.** Game Mode has no terminal, and the download-and-install steps below need
  one.

## 1. Download

Take both files from the [release page](https://github.com/Awesome34948156/dropship-steamos-port/releases):

- `dropship-steamos-<version>-linux-x86_64.tar.gz`
- `SHA256SUMS`

Both are needed. The checksum in the next step reads one file to verify the other, so
downloading only the archive leaves you unable to check it. In Desktop Mode they land in
`~/Downloads`.

## 2. Install

Open Konsole and run:

```sh
cd ~/Downloads
tar -xzf dropship-steamos-<version>-linux-x86_64.tar.gz
cd dropship-steamos-<version>
sha256sum -c SHA256SUMS
sudo ./install.sh
```

The checksum should print `OK`. The installer then asks for your password — that is expected
and not a sign anything is wrong. It installs a small privileged helper and a systemd service
so that blocking happens with no password prompt from then on; the app itself stays
user-owned. Leave the binaries where they are until the install finishes, because the
installer looks for them next to itself.

## 3. Use it

Open **Dropship for SteamOS** from the application launcher. Pick your regions, then switch
on **Block while Overwatch runs**. From then on the rules go up within a few seconds of
launching Overwatch and come down again when you quit.

There is a manual path too: **Apply blocks** applies them by hand while the game is running,
and **Disable all Dropship blocks** clears them. It needs no service and is the fallback if
automatic blocking does not work for you.

## 4. Check you got the build you think you did

The version is shown at the top right of the window, next to the heading. That is the point
of it being there: this app arrives as a downloaded artifact rather than a build you just
made, and "did the install take?" is otherwise a question with no answer in the window.

To confirm the rules exist at all:

```sh
sudo nft list table inet dropship_steamos
```

## Upgrading

Run the same commands from step 2 against the newer archive. The installer is idempotent, so
it both installs and upgrades; there is no separate upgrade step, and your region selection
is left alone.

## Uninstalling

```sh
cd ~/Downloads/dropship-steamos-<version>
sudo ./install.sh --uninstall
```

That removes the service and the launcher entry. Your region selection in
`~/.config/dropship-steamos/` is left alone; delete it yourself if you want it gone.

## If something did not work

- **Rules do not appear on launch.** The automatic path has only ever been driven against a
  stand-in process shaped like Steam's game scope, not against a real Overwatch launch. If
  the rules have not appeared within about ten seconds, that is the known gap rather than
  something you did wrong — use **Apply blocks** in the app meanwhile.
- **The window will not start, with a `GLIBC_2.xx not found` error.** The build image is
  deliberately older than the Deck's own glibc. That error means the binary is newer than the
  system, which should not happen on a Deck; report it rather than working around it.
- **The watcher is not running.** `journalctl -u dropship-steamos -n 40` shows why, and
  re-running the install is the repair path.
- **Game Mode.** The installer adds the app to Desktop Mode's application menu. Adding it to
  Game Mode means creating a non-Steam shortcut to it, the same as for any other `.desktop`
  application; that path has not been tested.

## Requirements

Kernel ≥ 5.13 and nftables ≥ 0.9.9 for cgroup v2 matching, which is what scopes the blocks to
Overwatch's process tree instead of the whole device. Both are satisfied on SteamOS. The
binaries are dynamically linked against glibc, so they are not portable to musl
distributions.
