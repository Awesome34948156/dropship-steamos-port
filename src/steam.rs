use std::path::PathBuf;
#[cfg(not(target_os = "linux"))]
use std::process::Command;

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

/// The whole picture, filesystem included.
///
/// The expensive half of the pair with [`game_state`]: it stats the Steam
/// libraries, which include the removable ones under `/run/media`. Call it when
/// the answer could have changed — startup, a different app id, or a user
/// asking — not on a timer.
pub fn discover(app_id: u32) -> SteamInstall {
    let (game_pid, cgroup) = game_state();

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

/// Whether a command line describes the game.
///
/// Split out so the `ps` path and the `/proc` path below share one definition
/// rather than drifting apart.
pub fn looks_like_overwatch(command_line: &str) -> bool {
    let lowered = command_line.to_ascii_lowercase();
    lowered.contains("overwatch.exe") || lowered.contains("_retail_/overwatch")
}

/// Extracts the PID of the running game from `ps -eo pid=,args=` output.
pub fn overwatch_pid_from_ps(output: &str) -> Option<u32> {
    output.lines().find_map(|line| {
        if !looks_like_overwatch(line) {
            return None;
        }
        line.split_whitespace().next()?.parse().ok()
    })
}

/// Whether a cgroup is one the game could plausibly be running in.
///
/// The game is found by looking for a process whose command line *looks* like
/// Overwatch, which any process can imitate. This is the guard that keeps an
/// imitator — or, far more likely, a stale or unrelated process — from choosing
/// which cgroup the blocks get scoped to.
///
/// It is a **safety** control, not a security boundary. The threat it addresses
/// is a wrong scope, not an escalation: the config that reaches the privileged
/// watcher still cannot name a cgroup, and `deck` is the user the device
/// already belongs to.
///
/// Deliberately does not name `app-steam@autostart.service`. That is the KDE
/// *Desktop Mode autostart* unit; Game Mode runs a different session and will
/// have a different path. Matching the shape rather than the exact name is what
/// lets both modes work without a mode switch.
///
/// Measured on the Deck 2026-10-02: this also accepts
/// `app.slice/steamos-manager.service`, a SteamOS user service that merely has
/// "steam" in its name. That is a false positive, but an unreachable one — a
/// cgroup is only ever selected for a process whose command line already looks
/// like the game, and nothing in `steamos-manager` does, nor could `deck` put
/// one there without root. It is left loose deliberately: tightening to
/// `app-steam*` would also have to be right about Game Mode, whose cgroup has
/// still not been measured, and being wrong there means blocking silently never
/// happens at all. Loose-and-unreachable beats tight-and-maybe-broken until
/// that path is known.
pub fn is_game_cgroup(cgroup: &CgroupMatch) -> bool {
    let mut in_app_slice = false;
    let mut names_steam = false;
    for segment in cgroup.path.split('/') {
        if segment == "app.slice" {
            in_app_slice = true;
        }
        if segment.to_ascii_lowercase().contains("steam") {
            names_steam = true;
        }
    }
    in_app_slice && names_steam
}

/// Every PID whose command line looks like the game, lowest first.
///
/// Reads `/proc` directly rather than shelling out to `ps`: this runs on a
/// timer in a root daemon, and a process spawn every tick is not free on a
/// battery-powered handheld.
#[cfg(target_os = "linux")]
pub fn overwatch_pids() -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut pids: Vec<u32> = entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .collect();
    pids.sort_unstable();

    pids.into_iter()
        .filter(|pid| {
            // cmdline is NUL-separated; join so the shared predicate sees
            // something shaped like a `ps` line. A process that exited between
            // the readdir and here simply drops out.
            std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|raw| {
                looks_like_overwatch(&String::from_utf8_lossy(&raw).replace('\0', " "))
            })
        })
        .collect()
}

#[cfg(not(target_os = "linux"))]
pub fn overwatch_pids() -> Vec<u32> {
    Vec::new()
}

/// The cgroup the game is running in, chosen from every candidate rather than
/// the first one found.
///
/// `overwatch_pid_from_ps` returns the *lowest* matching PID, and PIDs are
/// handed out in ascending order — so a stale or long-lived process that merely
/// resembles the game outranks the real one, which always has a high, recently
/// allocated PID. Resolving every candidate and keeping the first with a
/// plausible cgroup is what makes the live game win that race.
#[cfg(target_os = "linux")]
pub fn running_game_cgroup() -> Option<CgroupMatch> {
    overwatch_pids()
        .into_iter()
        .filter_map(cgroup_for_pid)
        .find(is_game_cgroup)
}

#[cfg(not(target_os = "linux"))]
pub fn running_game_cgroup() -> Option<CgroupMatch> {
    None
}

/// The lowest PID whose command line looks like the game.
///
/// On Linux this is a `/proc` scan rather than a `ps` fork. The caller polls it
/// on a timer, and forking the whole process table every tick is the kind of
/// work that stops an event loop from answering — which is exactly what shows up
/// as "not responding" while the machine is trying to shut down.
///
/// [`overwatch_pids`] sorts ascending, so the first entry is the lowest PID,
/// which is what the `ps` path returned too.
#[cfg(target_os = "linux")]
pub fn overwatch_pid() -> Option<u32> {
    overwatch_pids().first().copied()
}

/// See the Linux version above. The fork stays as the development fallback for
/// platforms without `/proc`.
#[cfg(not(target_os = "linux"))]
pub fn overwatch_pid() -> Option<u32> {
    let output = Command::new("ps")
        .args(["-eo", "pid=,args="])
        .output()
        .ok()?;
    overwatch_pid_from_ps(&String::from_utf8_lossy(&output.stdout))
}

/// The live half of the picture: whether the game is running, and where.
///
/// Deliberately touches nothing but `/proc`, because this is the part that is
/// polled on a timer. [`discover`] is the expensive half — it stats real
/// filesystems, including the removable libraries under `/run/media` — and a
/// `stat` on a mount that is being torn down is uninterruptible, which would
/// wedge the calling thread through a shutdown rather than merely slow it.
pub fn game_state() -> (Option<u32>, Option<CgroupMatch>) {
    let game_pid = overwatch_pid();
    let cgroup = game_pid.and_then(cgroup_for_pid);
    (game_pid, cgroup)
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

    /// Measured on the Deck, Desktop Mode.
    const DESKTOP_CGROUP: &str =
        "/user.slice/user-1000.slice/user@1000.service/app.slice/app-steam@autostart.service";

    #[test]
    fn the_measured_desktop_mode_cgroup_is_accepted() {
        let cgroup = CgroupMatch::from_path(DESKTOP_CGROUP).unwrap();
        assert!(is_game_cgroup(&cgroup));
    }

    #[test]
    fn game_mode_is_accepted_without_naming_the_desktop_unit() {
        // Game Mode has not been measured yet, but it runs a different session
        // and so a different unit name. Matching on shape rather than on the
        // Desktop Mode name is what keeps that from being a mode switch.
        let cgroup = CgroupMatch::from_path(
            "/user.slice/user-1000.slice/user@1000.service/app.slice/app-steam-app2357570-4242.scope",
        )
        .unwrap();
        assert!(is_game_cgroup(&cgroup));
    }

    #[test]
    fn a_renamed_process_outside_a_steam_scope_is_rejected() {
        // The spoof this exists to stop: `exec -a Overwatch.exe sleep 9999`
        // runs in the user's own session scope, not under app.slice.
        let cgroup =
            CgroupMatch::from_path("/user.slice/user-1000.slice/user@1000.service/session.slice")
                .unwrap();
        assert!(!is_game_cgroup(&cgroup));
    }

    #[test]
    fn a_steam_scope_outside_app_slice_is_rejected() {
        let cgroup =
            CgroupMatch::from_path("/user.slice/user-1000.slice/user@1000.service/steam.scope")
                .unwrap();
        assert!(!is_game_cgroup(&cgroup));
    }

    #[test]
    fn an_app_slice_scope_without_steam_is_rejected() {
        let cgroup = CgroupMatch::from_path(
            "/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox@1.service",
        )
        .unwrap();
        assert!(!is_game_cgroup(&cgroup));
    }

    #[test]
    fn the_shared_command_line_predicate_is_case_insensitive() {
        assert!(looks_like_overwatch("Overwatch.EXE"));
        assert!(looks_like_overwatch("wine64 _retail_/Overwatch.exe"));
        assert!(!looks_like_overwatch("/usr/bin/firefox"));
        // The OldGame folder is not the game.
        assert!(!looks_like_overwatch("_retail_/OldGame.exe"));
    }
}
