use std::{path::PathBuf, process::Command};

use crate::firewall::CgroupMatch;

#[derive(Clone, Debug, Default)]
pub struct SteamInstall {
    pub root: PathBuf,
    pub proton_prefix: Option<PathBuf>,
    pub installed: bool,
    pub game_pid: Option<u32>,
    /// The cgroup Overwatch is currently running in, discovered from the live
    /// process. Only present while the game runs, and not stable across
    /// launches, so it is re-read rather than stored.
    pub cgroup: Option<CgroupMatch>,
}

impl SteamInstall {
    pub fn game_running(&self) -> bool {
        self.game_pid.is_some()
    }
}

pub fn discover(app_id: u32) -> SteamInstall {
    let game_pid = overwatch_pid();
    let cgroup = game_pid.and_then(cgroup_for_pid);

    let root = steam_roots()
        .into_iter()
        .find(|root| root.join("steamapps").is_dir());

    let Some(root) = root else {
        return SteamInstall {
            game_pid,
            cgroup,
            ..Default::default()
        };
    };

    let manifest = root.join(format!("steamapps/appmanifest_{app_id}.acf"));
    let prefix = root.join(format!("steamapps/compatdata/{app_id}/pfx"));
    SteamInstall {
        root,
        proton_prefix: prefix.is_dir().then_some(prefix),
        installed: manifest.is_file(),
        game_pid,
        cgroup,
    }
}

fn steam_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        roots.push(home.join(".local/share/Steam"));
        roots.push(home.join(".steam/steam"));
        // Flatpak Steam keeps its own copy of the library tree.
        roots.push(home.join(".var/app/com.valvesoftware.Steam/.local/share/Steam"));
    }

    // SteamOS mounts external libraries (SD cards) under /run/media/<device>.
    if let Ok(entries) = std::fs::read_dir("/run/media") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                roots.push(path);
            }
        }
    }

    roots
}

/// Extracts the PID of the running game from `ps -eo pid=,args=` output.
pub fn overwatch_pid_from_ps(output: &str) -> Option<u32> {
    output.lines().find_map(|line| {
        let lowered = line.to_ascii_lowercase();
        if !(lowered.contains("overwatch.exe") || lowered.contains("_retail_/overwatch")) {
            return None;
        }
        line.split_whitespace().next()?.parse().ok()
    })
}

pub fn overwatch_pid() -> Option<u32> {
    let output = Command::new("ps")
        .args(["-eo", "pid=,args="])
        .output()
        .ok()?;
    overwatch_pid_from_ps(&String::from_utf8_lossy(&output.stdout))
}

/// Picks the cgroup v2 path out of `/proc/<pid>/cgroup` contents.
///
/// The unified hierarchy is always the `0::` entry; any other lines describe
/// legacy v1 hierarchies and are ignored.
pub fn parse_cgroup_v2(contents: &str) -> Option<String> {
    contents
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(|path| {
            let path = path.trim();
            path.strip_suffix(" (deleted)").unwrap_or(path).to_owned()
        })
        .filter(|path| !path.is_empty())
}

#[cfg(target_os = "linux")]
pub fn cgroup_for_pid(pid: u32) -> Option<CgroupMatch> {
    let contents = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    let path = parse_cgroup_v2(&contents)?;
    CgroupMatch::from_path(&path).ok()
}

#[cfg(not(target_os = "linux"))]
pub fn cgroup_for_pid(_pid: u32) -> Option<CgroupMatch> {
    None
}

pub fn steam_library_hint(install: &SteamInstall) -> String {
    if install.root.as_os_str().is_empty() {
        return "Steam was not found in the current user's standard locations.".to_owned();
    }
    if !install.installed {
        return format!(
            "Steam found at {}, but this app ID is not installed.",
            install.root.display()
        );
    }
    if let Some(prefix) = &install.proton_prefix {
        return format!("Overwatch Proton prefix: {}", prefix.display());
    }
    "Overwatch is installed, but its Proton prefix has not been created yet. Launch it once from Steam.".to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CGROUP_FILE: &str =
        "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-steam-2357570.scope\n";

    #[test]
    fn parses_the_unified_hierarchy_entry() {
        assert_eq!(
            parse_cgroup_v2(CGROUP_FILE).unwrap(),
            "/user.slice/user-1000.slice/user@1000.service/app.slice/app-steam-2357570.scope"
        );
    }

    #[test]
    fn parsed_path_feeds_straight_into_a_cgroup_match() {
        let path = parse_cgroup_v2(CGROUP_FILE).unwrap();
        let matched = CgroupMatch::from_path(&path).unwrap();
        assert_eq!(matched.level, 5);
        assert!(!matched.path.starts_with('/'));
    }

    #[test]
    fn ignores_legacy_v1_hierarchies() {
        let mixed = "12:pids:/user.slice\n5:cpu:/user.slice\n0::/user.slice/app.slice/game.scope\n";
        assert_eq!(
            parse_cgroup_v2(mixed).unwrap(),
            "/user.slice/app.slice/game.scope"
        );
    }

    #[test]
    fn strips_the_deleted_marker() {
        let zombie = "0::/user.slice/app.slice/game.scope (deleted)\n";
        assert_eq!(
            parse_cgroup_v2(zombie).unwrap(),
            "/user.slice/app.slice/game.scope"
        );
    }

    #[test]
    fn missing_unified_entry_is_none() {
        assert!(parse_cgroup_v2("12:pids:/user.slice\n").is_none());
        assert!(parse_cgroup_v2("").is_none());
        assert!(parse_cgroup_v2("0::\n").is_none());
    }

    #[test]
    fn finds_the_game_pid() {
        let ps =
            "    1 /sbin/init\n 4242 /home/deck/.steam/steamapps/common/Overwatch/Overwatch.exe\n";
        assert_eq!(overwatch_pid_from_ps(ps), Some(4242));
    }

    #[test]
    fn finds_a_retail_prefix_wine_process() {
        let ps = " 99 wine64-preloader _retail_/Overwatch.exe\n";
        assert_eq!(overwatch_pid_from_ps(ps), Some(99));
    }

    #[test]
    fn no_game_means_no_pid() {
        let ps = "    1 /sbin/init\n  200 /usr/bin/firefox\n";
        assert_eq!(overwatch_pid_from_ps(ps), None);
        assert_eq!(overwatch_pid_from_ps(""), None);
    }

    #[test]
    fn unparseable_pid_field_is_ignored() {
        let ps = "notapid Overwatch.exe\n";
        assert_eq!(overwatch_pid_from_ps(ps), None);
    }
}
