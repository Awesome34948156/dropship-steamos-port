# Dropship for SteamOS

An in-progress, native SteamOS server selector for Overwatch 2. It uses the public Dropship server catalogue and creates a dedicated `nftables` table named `dropship_steamos`.

## Current milestone

- Native Rust/egui desktop UI.
- Fetches and validates the current server catalogue.
- Saves region choices at `~/.config/dropship-steamos/settings.json`.
- Locates standard Steam installations (including SD-card libraries) and the configurable Proton prefix.
- Discovers the running Overwatch process and reads its cgroup v2 path from `/proc/<pid>/cgroup`.
- Generates separate IPv4/IPv6 nftables sets, scoped with `socket cgroupv2`, and can apply or remove only its own table through a privileged helper.
- An optional systemd service applies the blocks when Overwatch starts and removes them when it exits, with no password prompt.

## Automatic blocking

Install once. From then on you choose regions in advance, and the rules appear when you launch the game and disappear when you quit — no password prompt on either end.

```sh
sudo packaging/install.sh
```

That installs a small watcher service and a launcher entry. Open **Dropship for SteamOS** from the application launcher, pick your regions, and switch on **Block while Overwatch runs**. The installer is idempotent, so running it again is the repair path.

**Why this is safe without a password prompt.** The privileged side decides what to build. The GUI writes only *which networks* to block, into `~/.config/dropship-steamos/service.json`; the service never reads a cgroup from that file, deriving it instead from the live game process. The helper is installed root-owned in a root-owned directory, so the desktop user cannot replace what root will execute. That combination is what a passwordless-polkit design would not have given you.

Two consequences worth knowing:

- **Blocked ranges are as fresh as the last time you opened the app.** The service deliberately never touches the network, so it cannot refresh the catalogue on its own. Everything it needs is resolved by the GUI and written to that file.
- **Clearing every region does not remove the rules.** Only switching the toggle off does. An empty selection leaves the last known blocks in place, because the alternative — tearing live rules down over what might be an unreadable file — fails in the direction that loses your blocks mid-match.

To remove the service and the launcher entry:

```sh
sudo packaging/install.sh --uninstall
```

## Scoping

Blocks are scoped to Overwatch's process tree with an nftables cgroup v2 match, so other applications on the device are never affected:

```
socket cgroupv2 level 5 "user.slice/…/app.slice/app-steam-2357570.scope" ip daddr @blocked_ipv4 drop
```

The cgroup path is discovered from the live game process rather than hardcoded, and the `level` is derived from the depth of that path.

A plan without a cgroup cannot be constructed at all: `RulePlan` requires one, so there is no code path — and no fallback — that can install a device-wide rule.

In Desktop Mode the game shares Steam's own cgroup, so the scope covers the Steam client too. Only traffic *to the blocked ranges* is dropped, and Steam talks to Valve rather than to Blizzard's game servers, so the overlap is close to nothing in practice. Automatic blocking narrows this further by removing the rules whenever the game is not running.

**Requirements:** kernel ≥ 5.13 and nftables ≥ 0.9.9 for cgroup v2 matching.

## Manual mode

Without the service installed, the app applies blocks by hand instead: **Apply blocks** requires Overwatch to be running, because the cgroup only exists while the game does, and the rules stay until you remove them. **Disable all Dropship blocks** clears them.

One subtlety the app handles for you: restarting Steam rebuilds the game's cgroup at an *identical path*, and nftables resolves a cgroup when the rule is added rather than tracking the path. The app records the cgroup's inode alongside its path, so it can tell that a rule no longer matches anything and prompt you to re-apply.

Because rules are scoped to a cgroup that is destroyed when the game exits, a rule left in place after the game closes is inert rather than harmful.

## Surviving SteamOS updates

`/etc/systemd/system/*.service` and `/etc/systemd/system/*.wants/**` are on SteamOS's base atomic-update keep-list, so the unit and its enablement symlink come through an OS update without extra work — no keep-list drop-in is needed.

`/var` is the weaker link. SteamOS pairs `var-A`/`var-B` with the two rootfs slots and copies the active one across on update (`holo-sync-var`), which is a known failure point upstream. If the helper disappears, re-run `sudo packaging/install.sh`; it is idempotent for exactly this reason.

## Development

```sh
cargo run --bin dropship-steamos
```

The privileged helper must be discoverable as `dropship-steamos-helper`, or supplied through `DROPSHIP_STEAMOS_HELPER`. During local development:

```sh
DROPSHIP_STEAMOS_HELPER="$PWD/target/debug/dropship-steamos-helper" cargo run --bin dropship-steamos
```

The helper is the only privileged entry point and accepts exactly three verbs: `apply` and `disable`, which the manual UI reaches over `pkexec`, and `watch --config <absolute path>`, which the service runs. It only ever creates or removes the `inet dropship_steamos` nftables table, and `apply`/`disable` refuse to run while the watcher holds its lock.

The installed launcher entry is the normal way to start the app on the Deck. To watch stderr instead, `./run.sh` launches the same binaries from the terminal — but it has to be a terminal **inside the desktop session**, not an SSH shell. The window needs `WAYLAND_DISPLAY`, and the manual Apply path needs the session bus so KDE's polkit agent can answer the prompt; over SSH both are absent.

To exercise the watcher by hand before involving systemd:

```sh
sudo ./target/debug/dropship-steamos-helper watch --config "$HOME/.config/dropship-steamos/service.json"
```

## License

GPL-3.0-only. This project is a SteamOS-oriented reimplementation inspired by [stowmyy/dropship](https://github.com/stowmyy/dropship), whose catalogue URL is used during this initial milestone.
