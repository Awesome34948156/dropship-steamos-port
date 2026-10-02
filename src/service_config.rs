//! The contract between the unprivileged GUI and the privileged watcher.
//!
//! This file is written by the GUI, as the desktop user, and read by a root
//! daemon that acts on it every few seconds forever. That makes it the one
//! piece of untrusted input in the privileged path, and the reason this module
//! is stricter than `settings.rs` needs to be.
//!
//! It is kept separate from `settings.json` on purpose. `settings.json` is GUI
//! state — catalogue tokens, app id, an acknowledgement checkbox. This is a
//! trust boundary. Root parses five fields here and never sees a catalogue
//! token or a network URL, which is what makes the privileged parser something
//! you can audit by reading one screen.
//!
//! The design decision that matters most: **there is no cgroup field.** The
//! watcher derives the cgroup from the live process instead, so nothing written
//! here can aim the blocks at a scope of the writer's choosing. That is
//! enforced by construction rather than by a check that could be removed.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// The only schema version this build understands.
///
/// A file claiming any other version is refused rather than guessed at: a newer
/// GUI may mean something different by a field, and acting on a half-understood
/// file is how a root daemon blocks the wrong thing.
pub const VERSION: u32 = 1;

/// The most CIDRs the watcher will act on.
///
/// Not a resource limit — nft handles far more — but a bound on what a
/// user-writable file can ask a root process to hand the kernel. Without it,
/// `deck` could point the daemon at an arbitrarily large set on every boot.
pub const MAX_NETWORKS: usize = 4096;

/// The largest file worth reading. Comfortably above a full [`MAX_NETWORKS`]
/// selection, so it only ever rejects something that was never a real config.
const MAX_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceConfig {
    pub version: u32,
    /// Whether blocks should be applied while the game runs. This is the
    /// toggle's state, and the off position is how the user disables.
    #[serde(default)]
    pub enabled: bool,
    /// Bumped on every write. Carried for diagnostics only — no logic reads
    /// it, because `ScopedCgroup` already answers "is this still current?".
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub ipv4: Vec<IpNet>,
    #[serde(default)]
    pub ipv6: Vec<IpNet>,
}

impl ServiceConfig {
    /// Builds a config from a selection, splitting the families for storage.
    pub fn new(enabled: bool, revision: u64, networks: Vec<IpNet>) -> Self {
        let (ipv4, ipv6) = networks
            .into_iter()
            .partition(|network| network.addr().is_ipv4());
        Self {
            version: VERSION,
            enabled,
            revision,
            ipv4,
            ipv6,
        }
    }

    /// Every network, both families, as the watcher wants them.
    pub fn networks(&self) -> Vec<IpNet> {
        let mut networks = self.ipv4.clone();
        networks.extend(self.ipv6.iter().copied());
        networks
    }

    fn validate(&self) -> Result<()> {
        if self.version != VERSION {
            bail!(
                "service config is version {} but this build understands version {VERSION}",
                self.version
            );
        }

        let total = self.ipv4.len() + self.ipv6.len();
        if total > MAX_NETWORKS {
            bail!("service config lists {total} networks, more than the {MAX_NETWORKS} allowed");
        }

        // The families are stored apart, so a v6 address in the v4 list is a
        // sign the file was hand-edited or written by something that is not us.
        // nft would reject the resulting set anyway; failing here says why.
        for network in &self.ipv4 {
            if !network.addr().is_ipv4() {
                bail!("ipv4 list contains a non-IPv4 network: {network}");
            }
        }
        for network in &self.ipv6 {
            if !network.addr().is_ipv6() {
                bail!("ipv6 list contains a non-IPv6 network: {network}");
            }
        }

        Ok(())
    }
}

/// Parses config bytes, without touching the filesystem.
///
/// Split out from [`load`] so the hostile-input tests need no files, and so the
/// privileged parser has exactly one entry point to audit. Note that CIDRs
/// arrive as [`IpNet`] rather than `String`: the type does the injection
/// defence, because a value that fails to parse as an address never becomes a
/// value at all, and so can never reach the nft script.
pub fn parse(bytes: &[u8]) -> Result<ServiceConfig> {
    let config: ServiceConfig =
        serde_json::from_slice(bytes).context("service config is not valid JSON")?;
    config.validate()?;
    Ok(config)
}

pub fn path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("dropship-steamos")
        .join("service.json"))
}

/// Reads and validates a config file.
///
/// Every error here is meant to be survivable: the caller treats a failure as
/// "no instruction", which leaves any live rules exactly as they are. A config
/// that cannot be read must never be read as "disable".
pub fn load_from(path: &Path) -> Result<ServiceConfig> {
    let metadata =
        fs::metadata(path).with_context(|| format!("could not stat {}", path.display()))?;
    if metadata.len() > MAX_BYTES {
        bail!(
            "{} is {} bytes, larger than any real service config",
            path.display(),
            metadata.len()
        );
    }
    let bytes = fs::read(path).with_context(|| format!("could not read {}", path.display()))?;
    parse(&bytes)
}

pub fn load() -> Result<ServiceConfig> {
    load_from(&path()?)
}

/// Writes a config atomically, via a temporary file and a rename.
///
/// The rename is not decoration. The watcher may read this file at any moment,
/// and a half-written file would be a torn read — which the watcher treats as
/// "no instruction", so the worst case is a poll that does nothing rather than
/// a wrong decision. This makes even that transient case not happen.
pub fn save_to(path: &Path, config: &ServiceConfig) -> Result<()> {
    config.validate()?;
    let parent = path.parent().context("service config path has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(config)?)?;
    fs::rename(temporary, path)?;
    Ok(())
}

pub fn save(config: &ServiceConfig) -> Result<()> {
    save_to(&path()?, config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn networks() -> Vec<IpNet> {
        vec![
            "192.0.2.0/24".parse().unwrap(),
            "2001:db8::/32".parse().unwrap(),
        ]
    }

    fn sample() -> ServiceConfig {
        ServiceConfig::new(true, 3, networks())
    }

    #[test]
    fn around_trip_preserves_the_selection() {
        let config = sample();
        let bytes = serde_json::to_vec(&config).unwrap();
        let parsed = parse(&bytes).unwrap();

        assert!(parsed.enabled);
        assert_eq!(parsed.revision, 3);
        assert_eq!(parsed.ipv4.len(), 1);
        assert_eq!(parsed.ipv6.len(), 1);
        assert_eq!(parsed.networks().len(), 2);
    }

    #[test]
    fn the_families_are_split_on_the_way_in() {
        let config = sample();
        assert_eq!(config.ipv4, vec!["192.0.2.0/24".parse::<IpNet>().unwrap()]);
        assert_eq!(config.ipv6, vec!["2001:db8::/32".parse::<IpNet>().unwrap()]);
    }

    #[test]
    fn a_future_version_is_refused_rather_than_guessed_at() {
        // Acting on a file whose meaning may have changed is how a root daemon
        // blocks the wrong thing. Refusing leaves existing rules untouched.
        let mut config = sample();
        config.version = VERSION + 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn an_oversized_selection_is_refused() {
        let too_many = vec!["192.0.2.0/24".parse().unwrap(); MAX_NETWORKS + 1];
        let config = ServiceConfig::new(true, 1, too_many);
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_selection_at_the_limit_is_accepted() {
        let at_limit = vec!["192.0.2.0/24".parse().unwrap(); MAX_NETWORKS];
        assert!(ServiceConfig::new(true, 1, at_limit).validate().is_ok());
    }

    #[test]
    fn a_network_in_the_wrong_family_list_is_refused() {
        let mut config = sample();
        config.ipv6.push("192.0.2.0/24".parse().unwrap());
        assert!(config.validate().is_err());

        let mut config = sample();
        config.ipv4.push("2001:db8::/32".parse().unwrap());
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_malformed_network_is_refused() {
        // The typed field is the injection defence: this never becomes a value,
        // so it can never reach the nft script.
        for hostile in [
            r#"{"version":1,"ipv4":["192.0.2.0/24 } ; drop"],"ipv6":[]}"#,
            r#"{"version":1,"ipv4":["not-an-address"],"ipv6":[]}"#,
            r#"{"version":1,"ipv4":["192.0.2.0/33"],"ipv6":[]}"#,
        ] {
            assert!(parse(hostile.as_bytes()).is_err(), "accepted {hostile}");
        }
    }

    #[test]
    fn an_empty_file_is_refused() {
        // A truncated or never-written file must not read as "nothing selected
        // and disabled", which the watcher would act on.
        assert!(parse(b"").is_err());
        assert!(parse(b"   ").is_err());
    }

    #[test]
    fn torn_json_is_refused() {
        assert!(parse(br#"{"version":1,"enabled":true,"ipv4":["192.0"#).is_err());
    }

    #[test]
    fn an_unknown_field_is_refused() {
        // Strictness at a trust boundary. A config carrying something we do not
        // understand, at a version we claim to understand, is not a config we
        // should act on.
        let bytes = br#"{"version":1,"enabled":true,"cgroup":"user.slice","ipv4":[],"ipv6":[]}"#;
        assert!(parse(bytes).is_err());
    }

    #[test]
    fn the_optional_fields_default_rather_than_failing() {
        let parsed = parse(br#"{"version":1}"#).unwrap();
        assert!(!parsed.enabled);
        assert_eq!(parsed.revision, 0);
        assert!(parsed.networks().is_empty());
    }

    #[test]
    fn a_config_with_no_networks_parses_but_selects_nothing() {
        // Not an error — the GUI legitimately writes this when the user clears
        // the selection. The watcher's empty-set rule is what makes it inert.
        let parsed = parse(br#"{"version":1,"enabled":true,"ipv4":[],"ipv6":[]}"#).unwrap();
        assert!(parsed.enabled);
        assert!(parsed.networks().is_empty());
    }

    #[test]
    fn saving_and_loading_round_trips_through_a_real_file() {
        let directory = std::env::temp_dir().join(format!(
            "dropship-config-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("service.json");

        save_to(&path, &sample()).unwrap();
        let loaded = load_from(&path).unwrap();
        assert!(loaded.enabled);
        assert_eq!(loaded.networks(), sample().networks());

        // The temporary file must not be left behind.
        assert!(!directory.join("service.json.tmp").exists());

        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn a_missing_file_is_an_error_not_an_empty_config() {
        let missing = std::env::temp_dir().join("dropship-config-does-not-exist.json");
        assert!(load_from(&missing).is_err());
    }
}
