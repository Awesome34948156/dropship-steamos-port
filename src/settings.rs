use std::{collections::BTreeSet, fs, path::PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::fsutil;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Settings {
    #[serde(default = "default_steam_app_id")]
    pub steam_app_id: u32,
    #[serde(default)]
    pub blocked_server_tokens: BTreeSet<String>,
    #[serde(default)]
    pub acknowledged_cgroup: bool,
}

impl Default for Settings {
    fn default() -> Self {
        // `#[derive(Default)]` would ignore the serde attribute above and set
        // the app id to 0, which is what a fresh install used to show.
        Self {
            steam_app_id: default_steam_app_id(),
            blocked_server_tokens: BTreeSet::new(),
            acknowledged_cgroup: false,
        }
    }
}

fn default_steam_app_id() -> u32 {
    2_357_570 // Overwatch 2 on Steam; configurable in the UI.
}

pub fn path() -> Result<PathBuf> {
    Ok(fsutil::config_dir()?.join("settings.json"))
}

/// Parses settings bytes, repairing an app id that older builds persisted as 0.
///
/// Split out from [`load`] so the defaulting rules are testable without a file.
pub fn parse(bytes: &[u8]) -> Result<Settings> {
    let mut settings: Settings =
        serde_json::from_slice(bytes).context("settings file is invalid")?;
    // Zero is what the version with a derived `Default` wrote. One is what the
    // UI's `1..=u32::MAX` drag range clamped that zero to the first time the
    // field was touched. Neither is a usable app id here, so both mean "never
    // set" and repair themselves on load.
    if settings.steam_app_id <= 1 {
        settings.steam_app_id = default_steam_app_id();
    }
    Ok(settings)
}

pub fn load() -> Result<Settings> {
    let path = path()?;
    if !path.exists() {
        return Ok(Settings::default());
    }
    let bytes = fs::read(&path).with_context(|| format!("could not read {}", path.display()))?;
    parse(&bytes)
}

pub fn save(settings: &Settings) -> Result<()> {
    fsutil::write_json_atomic(&path()?, settings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_app_id_is_overwatch() {
        // `#[derive(Default)]` used to make this 0 on a fresh install.
        assert_eq!(Settings::default().steam_app_id, 2_357_570);
    }

    #[test]
    fn an_empty_document_uses_the_serde_default() {
        assert_eq!(parse(b"{}").unwrap().steam_app_id, 2_357_570);
    }

    #[test]
    fn a_persisted_zero_is_repaired() {
        // Older builds wrote this after the derived Default leaked out.
        assert_eq!(
            parse(br#"{"steam_app_id":0}"#).unwrap().steam_app_id,
            2_357_570
        );
    }

    #[test]
    fn a_persisted_one_is_repaired() {
        // The old UI's `1..=u32::MAX` range clamped that zero to one the first
        // time the field was edited; it is the same "never set" state.
        assert_eq!(
            parse(br#"{"steam_app_id":1}"#).unwrap().steam_app_id,
            2_357_570
        );
    }

    #[test]
    fn a_real_app_id_survives() {
        assert_eq!(parse(br#"{"steam_app_id":123}"#).unwrap().steam_app_id, 123);
    }

    #[test]
    fn the_selection_and_acknowledgement_round_trip() {
        let settings =
            parse(br#"{"blocked_server_tokens":["tpe1","gsg1"],"acknowledged_cgroup":true}"#)
                .unwrap();
        assert!(settings.acknowledged_cgroup);
        assert!(settings.blocked_server_tokens.contains("tpe1"));
        assert_eq!(settings.steam_app_id, 2_357_570);
    }
}
