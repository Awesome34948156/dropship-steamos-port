# Dropship for SteamOS

An in-progress, native SteamOS server selector for Overwatch 2. It uses the public Dropship server catalogue and creates a dedicated `nftables` table named `dropship_steamos`.

## Current milestone

- Native Rust/egui desktop UI.
- Fetches and validates the current server catalogue.
- Saves region choices at `~/.config/dropship-steamos/settings.json`.
- Locates standard Steam installations and the configurable Proton prefix.
- Detects a running Overwatch Proton/Wine process before enabling rule changes.
- Generates separate IPv4/IPv6 nftables sets and can apply or remove only its own table through a privileged helper.

The current firewall rule is **global**: selected destination networks are blocked for the entire SteamOS device. The next milestone scopes this to Overwatch's Proton/Wine cgroup. Do not use the current MVP while other applications need to reach selected regions.

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
