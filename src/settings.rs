use std::{collections::BTreeSet, fs, path::PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Settings {
    #[serde(default = "default_steam_app_id")]
    pub steam_app_id: u32,
    #[serde(default)]
    pub blocked_server_tokens: BTreeSet<String>,
    #[serde(default)]
    pub acknowledged_cgroup: bool,
}

fn default_steam_app_id() -> u32 {
    2_357_570 // Overwatch 2 on Steam; configurable in the UI.
}

pub fn path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("dropship-steamos")
        .join("settings.json"))
}

pub fn load() -> Result<Settings> {
    let path = path()?;
    if !path.exists() {
        return Ok(Settings::default());
    }
    let bytes = fs::read(&path).with_context(|| format!("could not read {}", path.display()))?;
    serde_json::from_slice(&bytes).context("settings file is invalid")
}

pub fn save(settings: &Settings) -> Result<()> {
    let path = path()?;
    let parent = path.parent().context("settings path has no parent")?;
    fs::create_dir_all(parent)?;
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(settings)?)?;
    fs::rename(temporary, path)?;
    Ok(())
}
