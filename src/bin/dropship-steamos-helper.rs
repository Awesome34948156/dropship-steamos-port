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

            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input)?;
            let plan: firewall::RulePlan =
                serde_json::from_str(&input).context("invalid firewall plan")?;
            firewall::apply(&plan)
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
}
