# Dropship for SteamOS

An in-progress, native SteamOS server selector for Overwatch 2. It uses the public Dropship server catalogue and creates a dedicated `nftables` table named `dropship_steamos`.

## Current milestone

- Native Rust/egui desktop UI.
- Fetches and validates the current server catalogue.
- Saves region choices at `~/.config/dropship-steamos/settings.json`.
- Locates standard Steam installations (including SD-card libraries) and the configurable Proton prefix.
- Discovers the running Overwatch process and reads its cgroup v2 path from `/proc/<pid>/cgroup`.
- Generates separate IPv4/IPv6 nftables sets, scoped with `socket cgroupv2`, and can apply or remove only its own table through a privileged helper.

## Scoping

Blocks are scoped to Overwatch's process tree with an nftables cgroup v2 match, so other applications on the device are never affected:

```
socket cgroupv2 level 5 "user.slice/…/app.slice/app-steam-2357570.scope" ip daddr @blocked_ipv4 drop
```

The cgroup path is discovered from the live game process rather than hardcoded, and the `level` is derived from the depth of that path.

A plan without a cgroup cannot be constructed at all: `RulePlan` requires one, so there is no code path — and no fallback — that can install a device-wide rule.

**Requirements:** kernel ≥ 5.13 and nftables ≥ 0.9.9 for cgroup v2 matching.

**Overwatch must be running** to apply or re-apply blocks, because the cgroup only exists while the game does. After quitting and relaunching the game, apply again — the app shows a prompt when it notices the process tree has changed.

Because rules are scoped to a cgroup that is destroyed when the game exits, a rule left in place after the game closes is inert rather than harmful. Use **Disable all Dropship blocks** to remove the table entirely.

## Development

```sh
cargo run --bin dropship-steamos
```

The privileged helper must be discoverable as `dropship-steamos-helper`, or supplied through `DROPSHIP_STEAMOS_HELPER`. During local development:

```sh
DROPSHIP_STEAMOS_HELPER="$PWD/target/debug/dropship-steamos-helper" cargo run --bin dropship-steamos
```

Applying and disabling rules deliberately prompts through `pkexec`; the normal UI never runs as root. The helper only accepts `apply` and `disable`, and only creates/removes the `inet dropship_steamos` nftables table.

## License

GPL-3.0-only. This project is a SteamOS-oriented reimplementation inspired by [stowmyy/dropship](https://github.com/stowmyy/dropship), whose catalogue URL is used during this initial milestone.
