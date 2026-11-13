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

/// Where an app lives, as far as the filesystem can tell.
#[derive(Clone, Debug, PartialEq, Eq)]
struct LibraryPick {
    root: PathBuf,
    proton_prefix: Option<PathBuf>,
    installed: bool,
}

/// The filesystem half of the picture: where Steam and the app live.
///
/// The expensive half of the pair with [`game_state`]: it stats the Steam
/// libraries, which include the removable ones under `/run/media`. Call it when
/// the answer could have changed — startup, a different app id, or a user
/// asking — not on a timer. The live fields of the returned [`SteamInstall`]
/// are left empty; [`game_state`] is the half that reads `/proc`.
pub fn discover(app_id: u32) -> SteamInstall {
    let Some(picked) = pick_root(&steam_roots(), app_id) else {
        return SteamInstall::default();
    };
    SteamInstall {
        root: picked.root,
        proton_prefix: picked.proton_prefix,
        installed: picked.installed,
        ..Default::default()
    }
}

/// Picks the Steam root that holds `app_id`.
///
/// Every candidate root is searched for the app's manifest rather than taking
/// the first root that merely has a `steamapps` directory: on a Deck the home
/// library almost always exists, so that rule reports an app installed on an SD
/// card as missing and misses its Proton prefix too. The prefix is then looked
/// for under the root that owns the manifest.
///
/// When no root has the manifest, the first root with a `steamapps` directory
/// is returned with `installed: false`, so the hint can still say where Steam
/// was found. `None` means no root looks like a Steam library at all.
fn pick_root(roots: &[PathBuf], app_id: u32) -> Option<LibraryPick> {
    let pick = |root: &PathBuf, installed: bool| {
        let prefix = root.join(format!("steamapps/compatdata/{app_id}/pfx"));
        LibraryPick {
            root: root.clone(),
            proton_prefix: prefix.is_dir().then_some(prefix),
            installed,
        }
    };

    if let Some(root) = roots.iter().find(|root| {
        root.join(format!("steamapps/appmanifest_{app_id}.acf"))
            .is_file()
    }) {
        return Some(pick(root, true));
    }

    roots
        .iter()
        .find(|root| root.join("steamapps").is_dir())
        .map(|root| pick(root, false))
}

/// Every place a Steam library may live, home and removable.
fn steam_roots() -> Vec<PathBuf> {
    let mut bases = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        bases.push(home.join(".local/share/Steam"));
        bases.push(home.join(".steam/steam"));
        // Flatpak Steam keeps its own copy of the library tree.
        bases.push(home.join(".var/app/com.valvesoftware.Steam/.local/share/Steam"));
    }

    // SteamOS mounts external libraries (SD cards) under /run/media/<device>.
    if let Ok(entries) = std::fs::read_dir("/run/media") {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                bases.push(path);
            }
        }
    }

    with_library_children(bases)
}

/// Adds the standard external-library layout beside each base root.
///
/// An external library normally sits in a `SteamLibrary` directory next to the
/// mount point, while some layouts keep `steamapps` at the mount root itself.
/// Both shapes are listed, base first, so the first-root fallback in
/// [`pick_root`] keeps naming the same root the old rule did.
fn with_library_children(bases: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut roots = Vec::with_capacity(bases.len() * 2);
    for base in bases {
        roots.push(base.clone());
        roots.push(base.join("SteamLibrary"));
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

/// One process whose command line looked like the game, with the facts needed
/// to tell the game itself from the launchers that started it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GameCandidate {
    pub pid: u32,
    /// The process that started this one, from `/proc/<pid>/stat`.
    pub parent: Option<u32>,
    pub cgroup: CgroupMatch,
}

/// Picks the candidate whose cgroup the game's traffic actually runs in.
///
/// Steam does not necessarily launch the game into the cgroup it launches it
/// *from*. Measured on SteamOS 3.9.5 (2026-11-12): `steam-runtime-launch-client`
/// and `steam-runtime-supervisor` sit in the Steam client's own unit,
/// `app-steam@autostart.service`, and both carry the game's path in their
/// command line. The game itself runs in a sibling scope,
/// `app-steam-app2357570-<pid>.scope`. A rule scoped to the former is scoped to
/// a sibling of the latter, not an ancestor, so it matches nothing the game
/// sends — and blocking silently does nothing.
///
/// The launchers are ancestors of the game, so the deepest candidate in the
/// process tree is the game (or a child of it). Ranking by depth rather than by
/// PID keeps this right whatever order Steam allocates PIDs in, and it still
/// picks the Steam client's unit in the older layout where the game ran
/// directly under it. Depth is counted within the candidate set: the walk stops
/// at the first ancestor that is not itself a candidate, which is all the
/// ranking needs.
pub fn select_game_candidate(candidates: &[GameCandidate]) -> Option<GameCandidate> {
    candidates
        .iter()
        .filter(|candidate| is_game_cgroup(&candidate.cgroup))
        .max_by_key(|candidate| (depth_within(candidates, candidate.pid), candidate.pid))
        .cloned()
}

fn depth_within(candidates: &[GameCandidate], pid: u32) -> usize {
    let mut depth = 0;
    let mut current = pid;
    // Bounded by the number of candidates: a cycle or a racing read must not
    // turn into an unbounded walk.
    for _ in 0..candidates.len() {
        let Some(parent) = candidates
            .iter()
            .find(|candidate| candidate.pid == current)
            .and_then(|candidate| candidate.parent)
        else {
            break;
        };
        if parent == current {
            break;
        }
        current = parent;
        depth += 1;
    }
    depth
}

/// Every matching process that has a readable cgroup.
#[cfg(target_os = "linux")]
fn game_candidates(pids: &[u32]) -> Vec<GameCandidate> {
    pids.iter()
        .filter_map(|&pid| {
            Some(GameCandidate {
                pid,
                parent: parent_pid(pid),
                cgroup: cgroup_for_pid(pid)?,
            })
        })
        .collect()
}

/// The live game among an already-scanned set of PIDs.
#[cfg(target_os = "linux")]
fn live_game_from(pids: &[u32]) -> Option<(u32, CgroupMatch)> {
    select_game_candidate(&game_candidates(pids)).map(|candidate| (candidate.pid, candidate.cgroup))
}

/// The live game: a PID and the cgroup its traffic actually runs in.
#[cfg(target_os = "linux")]
fn live_game() -> Option<(u32, CgroupMatch)> {
    live_game_from(&overwatch_pids())
}

#[cfg(not(target_os = "linux"))]
fn live_game() -> Option<(u32, CgroupMatch)> {
    None
}

/// The cgroup the game is running in.
///
/// Chosen by [`select_game_candidate`], not by taking the first plausible
/// candidate: Steam's launch wrappers carry the game's path in their command
/// line and are not in the game's cgroup.
pub fn running_game_cgroup() -> Option<CgroupMatch> {
    live_game().map(|(_, cgroup)| cgroup)
}

/// Reads a process's parent from `/proc/<pid>/stat`.
#[cfg(target_os = "linux")]
fn parent_pid(pid: u32) -> Option<u32> {
    parent_from_stat(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

/// Extracts the ppid field from `/proc/<pid>/stat`.
///
/// The comm field is parenthesised and may itself contain spaces and `)`, and
/// the kernel does not escape it; the last `)` is the only safe split point.
/// The fields after it are state, ppid, … in order, so ppid is the second one.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parent_from_stat(stat: &str) -> Option<u32> {
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
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
///
/// Kept public for tests and development tooling. [`game_state`] takes the
/// first entry of the scan it already made, so the timed path reads `/proc`
/// once rather than twice.
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
#[cfg(target_os = "linux")]
pub fn game_state() -> (Option<u32>, Option<CgroupMatch>) {
    // One `/proc` scan feeds both the candidate selection and the PID-only
    // fallback. Scanning again for the fallback doubled the work on a timer.
    let pids = overwatch_pids();
    // The same selection the watcher uses, so the window's "process tree" line
    // and the manual Apply button name the cgroup the rules are actually
    // scoped to, not a launcher's.
    match live_game_from(&pids) {
        Some((pid, cgroup)) => (Some(pid), Some(cgroup)),
        // Still report the PID so the window can say the game is running even
        // when its cgroup could not be read.
        None => (pids.first().copied(), None),
    }
}

/// See the Linux version above. Without `/proc` only the PID is known.
#[cfg(not(target_os = "linux"))]
pub fn game_state() -> (Option<u32>, Option<CgroupMatch>) {
    (overwatch_pid(), None)
}

/// Picks the raw cgroup v2 path out of `/proc/<pid>/cgroup` contents.
///
/// The unified hierarchy is always the `0::` entry; any other lines describe
/// legacy v1 hierarchies and are ignored. The value is returned as the kernel
/// wrote it, with its leading slash and any trailing `" (deleted)"` marker
/// intact: normalising it is [`CgroupMatch::from_path`]'s job, so there is
/// exactly one place that knows how.
pub fn parse_cgroup_v2(contents: &str) -> Option<String> {
    contents
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
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
    use std::path::Path;

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
    fn the_deleted_marker_is_left_for_the_cgroup_match_to_strip() {
        let zombie = "0::/user.slice/app.slice/game.scope (deleted)\n";
        let raw = parse_cgroup_v2(zombie).unwrap();
        assert_eq!(raw, "/user.slice/app.slice/game.scope (deleted)");
        // Normalisation has a single owner; this proves the raw value still
        // feeds it correctly.
        let matched = CgroupMatch::from_path(&raw).unwrap();
        assert_eq!(matched.path, "user.slice/app.slice/game.scope");
    }

    #[test]
    fn missing_unified_entry_is_none() {
        assert!(parse_cgroup_v2("12:pids:/user.slice\n").is_none());
        assert!(parse_cgroup_v2("").is_none());
        assert!(parse_cgroup_v2("0::\n").is_none());
    }

    /// A throwaway directory removed when the test finishes.
    struct TempTree {
        path: PathBuf,
    }

    impl TempTree {
        fn new(label: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "dropship-steam-{label}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        /// A library root under this tree, with an empty `steamapps`.
        fn root(&self, name: &str) -> PathBuf {
            let root = self.path.join(name);
            std::fs::create_dir_all(root.join("steamapps")).unwrap();
            root
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    const APP_ID: u32 = 2357570;

    fn install_app(root: &Path, app_id: u32) {
        std::fs::write(root.join(format!("steamapps/appmanifest_{app_id}.acf")), "").unwrap();
        std::fs::create_dir_all(root.join(format!("steamapps/compatdata/{app_id}/pfx"))).unwrap();
    }

    fn prefix_under(root: &Path, app_id: u32) -> Option<PathBuf> {
        Some(root.join(format!("steamapps/compatdata/{app_id}/pfx")))
    }

    #[test]
    fn an_app_in_the_home_library_is_found() {
        let tree = TempTree::new("home");
        let home = tree.root("home/Steam");
        let card = tree.root("card/SteamLibrary");
        install_app(&home, APP_ID);

        let picked = pick_root(&[home.clone(), card], APP_ID).unwrap();
        assert_eq!(picked.root, home);
        assert!(picked.installed);
        assert_eq!(picked.proton_prefix, prefix_under(&home, APP_ID));
    }

    #[test]
    fn an_app_that_only_lives_on_the_sd_card_is_found() {
        // The home library exists and has its own `steamapps`; the old
        // first-root rule stopped there and reported the app as missing.
        let tree = TempTree::new("card");
        let home = tree.root("home/Steam");
        let card = tree.root("card/SteamLibrary");
        install_app(&card, APP_ID);

        let picked = pick_root(&[home, card.clone()], APP_ID).unwrap();
        assert_eq!(picked.root, card);
        assert!(picked.installed);
        assert_eq!(picked.proton_prefix, prefix_under(&card, APP_ID));
    }

    #[test]
    fn an_app_in_a_steam_library_child_is_found() {
        // An external mount can hold the library directly or in the standard
        // `SteamLibrary` directory beside it; this app lives in the child.
        let tree = TempTree::new("child");
        let home = tree.root("home/Steam");
        let mount = tree.root("card");
        let library = tree.root("card/SteamLibrary");
        install_app(&library, APP_ID);

        let picked = pick_root(&[home, mount, library.clone()], APP_ID).unwrap();
        assert_eq!(picked.root, library);
        assert!(picked.installed);
        assert_eq!(picked.proton_prefix, prefix_under(&library, APP_ID));
    }

    #[test]
    fn a_missing_app_falls_back_to_the_first_steam_root() {
        let tree = TempTree::new("missing");
        let home = tree.root("home/Steam");
        let card = tree.root("card/SteamLibrary");

        let picked = pick_root(&[home.clone(), card], APP_ID).unwrap();
        assert_eq!(picked.root, home);
        assert!(!picked.installed);
        assert_eq!(picked.proton_prefix, None);

        assert!(pick_root(&[], APP_ID).is_none());
    }

    #[test]
    fn each_base_root_also_offers_its_steam_library_child() {
        // On a Deck the SD card mounts at /run/media/<device> and its library
        // usually sits in the standard `SteamLibrary` directory beneath it.
        let mount = PathBuf::from("/run/media/deck/CARD");
        assert_eq!(
            with_library_children(vec![mount.clone()]),
            vec![mount.clone(), mount.join("SteamLibrary")]
        );
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

    /// Measured on SteamOS 3.9.5, 2026-11-12, while Overwatch was running.
    const STEAM_SERVICE: &str =
        "/user.slice/user-1000.slice/user@1000.service/app.slice/app-steam@autostart.service";
    const GAME_SCOPE: &str =
        "/user.slice/user-1000.slice/user@1000.service/app.slice/app-steam-app2357570-32396.scope";

    fn candidate(pid: u32, parent: Option<u32>, path: &str) -> GameCandidate {
        GameCandidate {
            pid,
            parent,
            cgroup: CgroupMatch::from_path(path).unwrap(),
        }
    }

    #[test]
    fn steam_launch_wrappers_do_not_hide_the_game_scope() {
        // The measured failure: the first two carry Overwatch's path in their
        // command line but live in the Steam client's unit. The old lowest-PID
        // rule picked 32392 and scoped every rule to a sibling of the game.
        let candidates = [
            candidate(32392, Some(2911), STEAM_SERVICE),
            candidate(32395, Some(2816), STEAM_SERVICE),
            candidate(32396, Some(32395), GAME_SCOPE),
            candidate(32397, Some(32396), GAME_SCOPE),
            candidate(32466, Some(32397), GAME_SCOPE),
            candidate(32490, Some(32466), GAME_SCOPE),
            candidate(32496, Some(32490), GAME_SCOPE),
            candidate(32604, Some(32466), GAME_SCOPE),
        ];
        let picked = select_game_candidate(&candidates).unwrap();
        assert_eq!(picked.cgroup.path, GAME_SCOPE.trim_start_matches('/'));
        assert_ne!(picked.cgroup.path, STEAM_SERVICE.trim_start_matches('/'));
    }

    #[test]
    fn the_older_layout_still_scopes_to_the_steam_client() {
        // Before Steam started giving each launch a scope, the game ran under
        // the client's unit. Depth must not lose that case.
        let candidates = [
            candidate(100, Some(1), STEAM_SERVICE),
            candidate(101, Some(100), STEAM_SERVICE),
        ];
        assert_eq!(
            select_game_candidate(&candidates).unwrap().cgroup.path,
            STEAM_SERVICE.trim_start_matches('/')
        );
    }

    #[test]
    fn a_candidate_outside_a_steam_app_scope_is_ignored() {
        let candidates = [
            candidate(
                4000,
                Some(1),
                "/user.slice/user-1000.slice/user@1000.service/session.slice",
            ),
            candidate(4001, Some(4000), GAME_SCOPE),
        ];
        assert_eq!(select_game_candidate(&candidates).unwrap().pid, 4001);
    }

    #[test]
    fn no_plausible_cgroup_means_no_scope() {
        let candidates = [candidate(
            4000,
            None,
            "/user.slice/user-1000.slice/user@1000.service/session.slice",
        )];
        assert!(select_game_candidate(&candidates).is_none());
        assert!(select_game_candidate(&[]).is_none());
    }

    #[test]
    fn the_deeper_chain_wins() {
        // A stale launch and the live one in another scope: the live game's
        // chain is the deeper of the two, so it wins regardless of PID order.
        let stale = "/user.slice/user-1000.slice/user@1000.service/app.slice/app-steam-app2357570-1000.scope";
        let candidates = [
            candidate(1000, Some(1), stale),
            candidate(2000, Some(1), GAME_SCOPE),
            candidate(2001, Some(2000), GAME_SCOPE),
        ];
        assert_eq!(select_game_candidate(&candidates).unwrap().pid, 2001);
    }

    #[test]
    fn the_parent_field_survives_a_hostile_comm() {
        // comm is not escaped and may contain spaces and ')'. The last ')' is
        // the split point; ppid is the second field after it.
        assert_eq!(
            parent_from_stat("123 (a) tricky ) name) S 4242 123 123 0 -1"),
            Some(4242)
        );
        assert_eq!(
            parent_from_stat("123 (Overwatch.exe) S 1 123 123 0"),
            Some(1)
        );
        assert_eq!(parent_from_stat("not a stat line"), None);
        assert_eq!(parent_from_stat(""), None);
    }
}
