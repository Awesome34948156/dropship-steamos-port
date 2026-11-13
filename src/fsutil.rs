//! Small filesystem helpers shared by the modules that persist JSON.
//!
//! The GUI writes `settings.json` and `service.json`; the privileged watcher
//! writes `state.json`. All three are read by another thread or process at any
//! moment, so they go to a temporary file and are renamed into place: a reader
//! sees either the old file or the new one, never a half-written one.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::Serialize;

/// `~/.config/dropship-steamos`, the directory the GUI owns.
pub fn config_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set")?;
    Ok(PathBuf::from(home).join(".config").join("dropship-steamos"))
}

/// Writes `value` as pretty JSON, atomically.
///
/// The temporary name carries the process id so two GUI instances writing the
/// same file cannot rename each other's half-written copy. The parent directory
/// is created on demand.
pub fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path.parent().context("JSON path has no parent")?;
    fs::create_dir_all(parent).with_context(|| format!("could not create {}", parent.display()))?;
    let temporary = temporary_path(path);
    fs::write(&temporary, serde_json::to_vec_pretty(value)?)
        .with_context(|| format!("could not write {}", temporary.display()))?;
    fs::rename(&temporary, path)
        .with_context(|| format!("could not publish {}", path.display()))?;
    Ok(())
}

fn temporary_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state");
    path.with_file_name(format!("{name}.{}.tmp", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct Sample {
        value: u32,
    }

    fn temp_directory(label: &str) -> PathBuf {
        let unique = format!(
            "dropship-fsutil-test-{}-{}-{label}",
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

    #[test]
    fn writes_json_and_leaves_no_temporary_file() {
        let directory = temp_directory("write");
        let path = directory.join("settings.json");

        write_json_atomic(&path, &Sample { value: 7 }).unwrap();

        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains("\"value\": 7"), "{text}");
        let leftovers: Vec<_> = fs::read_dir(&directory)
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temporary file was left behind");

        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn creates_the_parent_directory_on_demand() {
        let directory = temp_directory("parent");
        let path = directory.join("nested").join("state.json");

        write_json_atomic(&path, &Sample { value: 9 }).unwrap();
        assert!(path.is_file());

        fs::remove_dir_all(&directory).unwrap();
    }
}
