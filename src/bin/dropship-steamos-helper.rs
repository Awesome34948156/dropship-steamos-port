//! The one privileged entry point.
//!
//! Everything that needs root goes through here: the GUI reaches it over
//! `pkexec` for a one-off apply, and systemd runs it as `watch` for the
//! automatic mode. Keeping it to a single binary is deliberate — it is the
//! whole attack surface of the privileged side, and it stays small enough to
//! read in one sitting.

use std::{io::Read, path::PathBuf};

use anyhow::{Context, Result, bail};
use dropship_steamos::{firewall, service};

/// The most bytes of plan the helper will read from stdin.
///
/// `pkexec` hands us whatever the unprivileged caller wrote, so the read has to
/// be bounded before any parsing happens. Four times the largest service config,
/// and already far past [`firewall::MAX_NETWORKS`], so a plan this big is never
/// a real one.
const MAX_PLAN_BYTES: u64 = 4 * 1024 * 1024;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let action = args
        .next()
        .context("usage: dropship-steamos-helper <apply|disable|watch --config PATH>")?;

    match action.as_str() {
        "apply" => {
            // Take the lock first: if the service is running it owns the table,
            // and a second writer would only be overwritten on the next tick
            // anyway. Failing loudly here is better than a flap.
            let _lock = service::Lock::acquire()?;

            let plan = read_plan(std::io::stdin())?;
            firewall::apply(&plan).map(|_| ())
        }

        // Deliberately *not* locked. This is the safe direction — it only ever
        // removes rules — and it has to work at exactly the moment the service
        // is being stopped, which is when the lock is most likely to be busy.
        "disable" => firewall::disable(),

        // Takes the lock itself, for the lifetime of the process.
        "watch" => service::run(&config_path(args)?),

        _ => bail!("usage: dropship-steamos-helper <apply|disable|watch --config PATH>"),
    }
}

/// Reads and deserialises a firewall plan from `reader`.
///
/// The cap is applied while reading rather than by trusting a length the caller
/// supplied, so a stream that never ends cannot grow this process without
/// bound. One byte past the cap is read deliberately: that is what distinguishes
/// "exactly at the limit" from "there was more".
fn read_plan(reader: impl Read) -> Result<firewall::RulePlan> {
    let mut input = String::new();
    let mut limited = reader.take(MAX_PLAN_BYTES + 1);
    limited
        .read_to_string(&mut input)
        .context("could not read firewall plan from stdin")?;
    if input.len() as u64 > MAX_PLAN_BYTES {
        bail!("firewall plan is larger than the {MAX_PLAN_BYTES} bytes allowed");
    }
    serde_json::from_str(&input).context("invalid firewall plan")
}

/// Reads the path after `--config`.
///
/// Requires an absolute path because this runs as root, where a relative path
/// resolves somewhere else entirely — and where `$HOME` is `/root`. An
/// installer bug that passed a relative path should fail at startup rather than
/// silently watch a file nobody writes.
fn config_path(mut args: impl Iterator<Item = String>) -> Result<PathBuf> {
    let flag = args.next().context("watch needs --config PATH")?;
    if flag != "--config" {
        bail!("expected --config, got {flag:?}");
    }
    let path = PathBuf::from(args.next().context("--config needs a path")?);
    if !path.is_absolute() {
        bail!("--config must be an absolute path, got {}", path.display());
    }
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> std::vec::IntoIter<String> {
        values
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn an_absolute_config_path_is_accepted() {
        let path = config_path(args(&["--config", "/home/deck/.config/service.json"])).unwrap();
        assert_eq!(path, PathBuf::from("/home/deck/.config/service.json"));
    }

    #[test]
    fn a_relative_config_path_is_refused() {
        // As root this would resolve against /root, not the user's home.
        assert!(config_path(args(&["--config", "service.json"])).is_err());
    }

    #[test]
    fn a_missing_or_malformed_flag_is_refused() {
        assert!(config_path(args(&[])).is_err());
        assert!(config_path(args(&["--config"])).is_err());
        assert!(config_path(args(&["service.json"])).is_err());
        assert!(config_path(args(&["--path", "/etc/x"])).is_err());
    }

    #[test]
    fn a_valid_plan_is_read_from_the_stream() {
        let input = r#"{
            "cgroup": {"path": "user.slice/app.slice/app-steam-1.scope", "level": 3},
            "ipv4": ["192.0.2.0/24"],
            "ipv6": ["2001:db8::/32"]
        }"#;

        let plan = read_plan(std::io::Cursor::new(input.as_bytes())).unwrap();
        assert_eq!(plan.cgroup.path, "user.slice/app.slice/app-steam-1.scope");
        assert_eq!(plan.ipv4.len(), 1);
        assert_eq!(plan.ipv6.len(), 1);
    }

    #[test]
    fn malformed_json_is_refused() {
        assert!(read_plan(std::io::Cursor::new(b"{not json".as_slice())).is_err());
        // Valid JSON, but not a plan: the cgroup is mandatory.
        assert!(read_plan(std::io::Cursor::new(b"{}".as_slice())).is_err());
    }

    #[test]
    fn an_oversized_plan_is_refused_before_parsing() {
        let oversized = vec![b' '; MAX_PLAN_BYTES as usize + 1];
        let error = read_plan(std::io::Cursor::new(oversized)).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("larger than"), "{message}");
    }
}
