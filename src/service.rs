//! The I/O half of the auto-apply service.
//!
//! [`crate::watcher`] decides; this gathers the facts and carries the decision
//! out. The split keeps the decision table testable anywhere and leaves the
//! part that needs a real device — `/proc`, `nft`, `/run` — small enough to
//! read in one go.
//!
//! Runs as root, from systemd, forever. Two consequences shape everything here:
//! it must not leak rules when it stops, and it must not be quiet when it
//! fails. Every state change prints one line to stdout, which systemd routes to
//! the journal.

use std::{
    fs::{self, File, OpenOptions},
    path::Path,
    thread::sleep,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::{
    firewall::{self, ScopedCgroup},
    service_config, steam,
    watcher::{Decision, Observation, Watcher},
};

/// How often to look while something could be about to change: the game is
/// running, or our rules are up and could need taking down.
const ACTIVE_INTERVAL: Duration = Duration::from_secs(2);

/// How often to look when nothing is happening at all.
///
/// The only thing being waited for is a game launch, and a match takes far
/// longer than this to load, so the poll can be lazy. This matters on a
/// handheld: it is the difference between waking the CPU every two seconds
/// forever and doing so every ten.
const IDLE_INTERVAL: Duration = Duration::from_secs(10);

/// How often to confirm the table is still there even when settled.
///
/// Reading `/proc` is cheap; asking nft is a fork, so it is kept off the poll
/// path. But the cgroup comparison only catches the game's process tree being
/// replaced — it cannot see another tool running `nft flush ruleset` while the
/// cgroup stays put. This is the backstop for that, and for inode recycling.
const HEARTBEAT: Duration = Duration::from_secs(60);

/// Where the lock and the published state live.
///
/// `/run` is tmpfs: volatile, cleared at boot, which matches the lifetime of
/// the rules themselves, since nftables state does not survive a reboot either.
pub const RUNTIME_DIR: &str = "/run/dropship-steamos";

/// The unit name, shared by the service it installs and the GUI that asks
/// systemd about it.
pub const UNIT: &str = "dropship-steamos.service";

/// What the service tells the GUI about itself.
///
/// The GUI cannot read the nft table — that needs CAP_NET_ADMIN — so without
/// this it could only guess what is applied, which is exactly the failure mode
/// `ScopedCgroup` exists to prevent.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublishedState {
    /// The scope the installed rules are bound to, or `None` if none are.
    pub applied: Option<ScopedCgroup>,
    /// The config revision those rules were built from, for diagnostics.
    pub revision: u64,
    /// The last thing the watcher did: `apply`, `disable`, or `starting`.
    pub last_decision: String,
    pub since_unix_secs: u64,
}

/// Whether the watcher service is running.
///
/// Asks systemd rather than looking for the unit file. A unit that is present
/// but dead is the one state the GUI must not mistake for "something else is
/// handling this" — it would stop applying and leave nothing applying.
pub fn is_active() -> bool {
    std::process::Command::new("systemctl")
        .args(["is-active", UNIT])
        .output()
        .is_ok_and(|output| {
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "active"
        })
}

/// Reads what the service last published, if it has.
///
/// An error here means "cannot tell", which the GUI shows as such rather than
/// as "nothing is applied" — conflating the two would report a reassuring state
/// the GUI has no evidence for.
pub fn read_state() -> Result<PublishedState> {
    let path = Path::new(RUNTIME_DIR).join("state.json");
    let bytes = fs::read(&path).with_context(|| format!("could not read {}", path.display()))?;
    serde_json::from_slice(&bytes).context("service state is not valid JSON")
}

/// Held for the lifetime of the process, so a second watcher cannot start.
///
/// Belt and braces against the GUI's own guards: a stale GUI, or a developer
/// running the helper by hand, must not race the daemon for the same table.
pub struct Lock {
    _file: File,
}

impl Lock {
    pub fn acquire() -> Result<Self> {
        Self::acquire_in(Path::new(RUNTIME_DIR))
    }

    /// The directory is a parameter so tests can use a temporary one; the real
    /// path needs root and only exists on Linux.
    fn acquire_in(directory: &Path) -> Result<Self> {
        fs::create_dir_all(directory)
            .with_context(|| format!("could not create {}", directory.display()))?;
        let path = directory.join("lock");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .with_context(|| format!("could not open {}", path.display()))?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(_) => bail!("another Dropship watcher already holds {}", path.display()),
        }
    }
}

/// Runs the watcher until the process is killed.
pub fn run(config_path: &Path) -> Result<()> {
    let _lock = Lock::acquire()?;

    let mut watcher = Watcher::new();
    // Assume the table is absent until told otherwise. Guessing "present" would
    // make the first poll skip an apply that is actually needed.
    let mut table_present = firewall::table_present().unwrap_or(false);
    let mut last_heartbeat = Instant::now();
    let mut since = epoch_secs();

    // Both of these exist to keep the journal readable. The loop runs every few
    // seconds forever, so anything printed unconditionally becomes noise, and
    // noise is how a real failure goes unnoticed.
    let mut last_line: Option<String> = None;
    let mut last_config_error: Option<String> = None;

    println!("watching for Overwatch; config {}", config_path.display());
    publish_state(None, 0, "starting", since)?;

    loop {
        let (enabled, networks, revision) = match service_config::load_from(config_path) {
            Ok(config) => {
                if last_config_error.take().is_some() {
                    println!("service config is readable again");
                }
                (config.enabled, config.networks(), config.revision)
            }
            Err(error) => {
                // A config that cannot be read is "no instruction", never
                // "disable". It is most likely mid-write, or left empty by a
                // failed catalogue fetch, and taking live rules down over that
                // would punch a hole exactly when the user is playing. The
                // empty selection below is what makes the watcher inert.
                let message = format!("{error:#}");
                if last_config_error.as_deref() != Some(message.as_str()) {
                    println!("ignoring service config: {message}");
                    last_config_error = Some(message);
                }
                (false, Vec::new(), 0)
            }
        };

        // The cgroup is discovered, never read from the config — that is the
        // property that stops a user-writable file from aiming the blocks.
        let game = steam::running_game_cgroup().map(|cgroup| ScopedCgroup::of(&cgroup));
        let observation = Observation {
            game,
            enabled,
            networks,
            table_present,
        };

        let decision = watcher.step(&observation, Instant::now());

        match &decision {
            Decision::Apply(plan) => match firewall::apply(plan) {
                Ok(()) => {
                    watcher.applied(ScopedCgroup::of(&plan.cgroup));
                    table_present = true;
                    since = epoch_secs();
                    note(
                        &mut last_line,
                        format!(
                            "applied {} blocks scoped to {}",
                            plan.ipv4.len() + plan.ipv6.len(),
                            plan.cgroup.path
                        ),
                    );
                    publish_state(watcher.current().cloned(), revision, "apply", since)?;
                }
                Err(error) => note(&mut last_line, format!("could not apply blocks: {error:#}")),
            },
            Decision::Disable => match firewall::disable() {
                Ok(()) => {
                    watcher.removed();
                    table_present = false;
                    since = epoch_secs();
                    note(&mut last_line, "removed blocks".to_owned());
                    publish_state(None, revision, "disable", since)?;
                }
                Err(error) => note(
                    &mut last_line,
                    format!("could not remove blocks: {error:#}"),
                ),
            },
            Decision::Idle => {}
        }

        if last_heartbeat.elapsed() >= HEARTBEAT {
            if let Ok(present) = firewall::table_present() {
                table_present = present;
            }
            last_heartbeat = Instant::now();
        }

        let interval = if observation.game.is_some() || watcher.is_tracking() {
            ACTIVE_INTERVAL
        } else {
            IDLE_INTERVAL
        };
        sleep(interval);
    }
}

/// Writes the state file the GUI reads.
///
/// Written with a rename so a reader never sees a partial file. Left
/// world-readable on purpose: the point is for the unprivileged GUI to read it.
fn publish_state(
    applied: Option<ScopedCgroup>,
    revision: u64,
    last_decision: &str,
    since_unix_secs: u64,
) -> Result<()> {
    let state = PublishedState {
        applied,
        revision,
        last_decision: last_decision.to_owned(),
        since_unix_secs,
    };
    let directory = Path::new(RUNTIME_DIR);
    fs::create_dir_all(directory)?;
    let path = directory.join("state.json");
    let temporary = directory.join("state.json.tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(&state)?)
        .with_context(|| format!("could not write {}", temporary.display()))?;
    fs::rename(&temporary, &path)
        .with_context(|| format!("could not publish {}", path.display()))?;
    Ok(())
}

/// Prints `line` unless it is the same as last time.
fn note(last: &mut Option<String>, line: String) {
    if last.as_deref() != Some(line.as_str()) {
        println!("{line}");
        *last = Some(line);
    }
}

fn epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::CgroupMatch;

    #[test]
    fn a_second_lock_cannot_be_taken() {
        // The guard against two watchers racing for one table.
        let directory = std::env::temp_dir().join(format!(
            "dropship-lock-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let first = Lock::acquire_in(&directory).expect("first lock should succeed");
        assert!(
            Lock::acquire_in(&directory).is_err(),
            "second lock should have failed"
        );
        drop(first);
        // Releasing must let the next one in, or a crashed service would wedge
        // the feature until reboot.
        assert!(
            Lock::acquire_in(&directory).is_ok(),
            "lock should be reacquirable"
        );

        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn the_published_state_round_trips_through_json() {
        let scoped = ScopedCgroup {
            cgroup: CgroupMatch::from_path(
                "user.slice/user-1000.slice/user@1000.service/app.slice/app-steam@autostart.service",
            )
            .unwrap(),
            inode: Some(31_422),
        };
        let state = PublishedState {
            applied: Some(scoped.clone()),
            revision: 12,
            last_decision: "apply".to_owned(),
            since_unix_secs: 1_790_000_000,
        };

        let json = serde_json::to_value(&state).unwrap();
        assert_eq!(json["applied"]["inode"], 31_422);
        assert_eq!(json["revision"], 12);
        assert_eq!(json["last_decision"], "apply");

        // The GUI parses this back, so the field must survive the trip.
        let back: ScopedCgroup = serde_json::from_value(json["applied"].clone()).unwrap();
        assert!(back.still_matches(&scoped));
    }

    #[test]
    fn an_empty_state_serialises_as_null_rather_than_vanishing() {
        // The GUI distinguishes "nothing applied" from "cannot tell", and a
        // missing key would collapse those two.
        let state = PublishedState {
            applied: None,
            revision: 0,
            last_decision: "disable".to_owned(),
            since_unix_secs: 0,
        };
        let json = serde_json::to_value(&state).unwrap();
        assert!(json["applied"].is_null());
        assert!(json.get("applied").is_some());
    }
}
