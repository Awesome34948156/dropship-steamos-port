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
    io::Read,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::fsutil;

pub use crate::firewall::MAX_NETWORKS;

/// The only schema version this build understands.
///
/// A file claiming any other version is refused rather than guessed at: a newer
/// GUI may mean something different by a field, and acting on a half-understood
/// file is how a root daemon blocks the wrong thing.
pub const VERSION: u32 = 1;

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
        let (ipv4, ipv6) = crate::firewall::split_families(networks);
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
        crate::firewall::validate_families(&self.ipv4, &self.ipv6)
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
    Ok(fsutil::config_dir()?.join("service.json"))
}

/// Reads and validates a config file.
///
/// Every error here is meant to be survivable: the caller treats a failure as
/// "no instruction", which leaves any live rules exactly as they are. A config
/// that cannot be read must never be read as "disable".
///
/// The file is opened once and inspected through that same handle. A
/// stat-then-read pair would let the desktop user swap a regular file for a
/// symlink or a FIFO between the two calls, and this runs as root. `O_NOFOLLOW`
/// refuses a symlink at the final component, `O_NONBLOCK` stops a FIFO from
/// blocking the open forever, and the `is_file` check rejects every other kind
/// of file before a single byte is read.
pub fn load_from(path: &Path) -> Result<ServiceConfig> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .with_context(|| format!("could not stat {}", path.display()))?;

    let metadata = file
        .metadata()
        .with_context(|| format!("could not stat {}", path.display()))?;
    if !metadata.is_file() {
        bail!("{} is not a regular file", path.display());
    }

    let mut bytes = Vec::with_capacity(metadata.len().min(MAX_BYTES) as usize);
    let mut limited = file.take(MAX_BYTES + 1);
    limited
        .read_to_end(&mut bytes)
        .with_context(|| format!("could not read {}", path.display()))?;
    if bytes.len() as u64 > MAX_BYTES {
        bail!(
            "{} is larger than the {MAX_BYTES} bytes any real service config uses",
            path.display()
        );
    }
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
    fsutil::write_json_atomic(path, config)
}

pub fn save(config: &ServiceConfig) -> Result<()> {
    save_to(&path()?, config)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh directory under the system temp dir, unique per test.
    fn temp_directory(label: &str) -> PathBuf {
        let unique = format!(
            "dropship-config-test-{}-{}-{label}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let directory = std::env::temp_dir().join(unique);
        fs::create_dir_all(&directory).unwrap();
        directory
    }

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
        let directory = temp_directory("round-trip");
        let path = directory.join("service.json");

        save_to(&path, &sample()).unwrap();
        let loaded = load_from(&path).unwrap();
        assert!(loaded.enabled);
        assert_eq!(loaded.networks(), sample().networks());

        // No temporary file may be left behind.
        let leftovers: Vec<_> = fs::read_dir(&directory)
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temporary file was left behind");

        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn a_regular_config_file_loads() {
        let directory = temp_directory("regular");
        let path = directory.join("service.json");
        fs::write(&path, serde_json::to_vec(&sample()).unwrap()).unwrap();

        let loaded = load_from(&path).unwrap();
        assert!(loaded.enabled);
        assert_eq!(loaded.networks(), sample().networks());

        fs::remove_dir_all(&directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_to_a_valid_config_is_refused() {
        // Root must not be redirected through a link the desktop user controls,
        // even when the link points at a perfectly good config today.
        let directory = temp_directory("symlink");
        let target = directory.join("real.json");
        save_to(&target, &sample()).unwrap();
        let link = directory.join("link.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert!(load_from(&link).is_err());

        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn a_directory_is_refused() {
        // Opening a directory succeeds on both Linux and macOS; only the
        // `is_file` check keeps it from being read.
        let directory = temp_directory("directory");
        let nested = directory.join("service.json");
        fs::create_dir(&nested).unwrap();

        assert!(load_from(&nested).is_err());

        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn an_oversized_regular_file_is_refused() {
        let directory = temp_directory("oversized");
        let path = directory.join("service.json");
        // Whitespace: large enough to trip the cap, but the size check must be
        // what rejects it rather than the JSON parser.
        fs::write(&path, vec![b' '; MAX_BYTES as usize + 1]).unwrap();

        assert!(load_from(&path).is_err());

        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn a_missing_file_is_an_error_not_an_empty_config() {
        let missing = std::env::temp_dir().join("dropship-config-does-not-exist.json");
        assert!(load_from(&missing).is_err());
    }
}
