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
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    path::Path,
    thread::sleep,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::{
    firewall::{self, ScopedCgroup},
    fsutil, service_config, steam,
    watcher::{ConfigFacts, Decision, Observation, Watcher},
};

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
    /// Whether `inet dropship_steamos` exists right now.
    ///
    /// `applied == None` alone cannot distinguish "nothing is installed" from
    /// "a table is installed but this watcher has not identified its scope".
    /// The GUI needs both facts to report the truth.
    #[serde(default)]
    pub table_present: bool,
    /// The config revision those rules were built from, for diagnostics.
    pub revision: u64,
    /// The last thing the watcher did: `apply`, `disable`, or `starting`.
    pub last_decision: String,
    pub since_unix_secs: u64,
}

/// Whether the watcher service is running, when that question has an answer.
///
/// Asks systemd rather than looking for the unit file. A unit that is present
/// but dead is the one state the GUI must not mistake for "something else is
/// handling this" — it would stop applying and leave nothing applying.
///
/// The answer is tri-state on purpose. `activating`, `deactivating` and
/// `reloading` are real systemd states that a restart passes through, and a
/// D-Bus round-trip can fail for reasons that say nothing about the unit.
/// Reporting either as "not running" would hand the GUI the manual path for
/// long enough to run its unlocked Disable, deleting the table a restarting
/// watcher is about to claim. `None` means "cannot tell"; the caller keeps
/// what it last knew.
pub fn is_active() -> Option<bool> {
    // `systemctl is-active` exits non-zero for everything but `active`, so the
    // exit status cannot separate "inactive" from "could not ask". Only the
    // word on stdout can, and only a failure to spawn means there is no word
    // at all.
    match std::process::Command::new("systemctl")
        .args(["is-active", UNIT])
        .output()
    {
        Ok(output) => parse_is_active(&String::from_utf8_lossy(&output.stdout)),
        // No systemctl at all means there is no unit that could be active —
        // a development machine or a container. The manual path is the only
        // one that exists there, so offer it.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(false),
        // systemctl exists but could not be run: cannot tell, keep the last
        // known answer rather than flipping to the manual path.
        Err(_) => None,
    }
}

/// Maps `systemctl is-active` output to a tri-state answer.
///
/// Only settled states count: `active` is running, `inactive` and `failed`
/// are stopped. The transitional states and anything unrecognised — including
/// empty output — are `None`, because acting on them would mistake a restart
/// for a removal.
fn parse_is_active(stdout: &str) -> Option<bool> {
    match stdout.trim() {
        "active" => Some(true),
        "inactive" | "failed" => Some(false),
        _ => None,
    }
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

/// A successful rule change, before the shared bookkeeping is committed.
enum Settled {
    Applied(ScopedCgroup, BTreeSet<IpNet>, String),
    Removed,
}

/// Runs the watcher until the process is killed.
pub fn run(config_path: &Path) -> Result<()> {
    let _lock = Lock::acquire()?;

    let mut watcher = Watcher::new();
    // Assume the table is absent until told otherwise. Guessing "present" would
    // make the first poll skip an apply that is actually needed.
    let mut table_present = firewall::table_present().unwrap_or(false);
    // A table already in place was not applied by this process, so its scope is
    // unknown. Recording it lets the normal decision table reconcile it: it is
    // adopted if the game is running, and removed after the grace period if not.
    watcher.note_table_present(table_present);
    let mut last_heartbeat = Instant::now();
    let mut since = epoch_secs();

    // These two exist to keep the journal readable. The loop runs every few
    // seconds forever, so a *failure* that persists must not print forever —
    // noise is how a real failure goes unnoticed. State transitions are the
    // opposite: they are rare, each one matters, and deduping them was hiding
    // both churn and the re-apply that follows a Steam restart, whose log line
    // is identical because the cgroup path is identical. Hence two mechanisms:
    // `note` for failures, `report` for transitions.
    let mut last_error: Option<String> = None;
    let mut last_config_error: Option<String> = None;

    println!("watching for Overwatch; config {}", config_path.display());
    publish(&mut last_error, None, table_present, 0, "starting", since);

    loop {
        let (config, revision) = match service_config::load_from(config_path) {
            Ok(config) => {
                if last_config_error.take().is_some() {
                    println!("service config is readable again");
                }
                let facts = ConfigFacts {
                    enabled: config.enabled,
                    networks: config.networks(),
                };
                (Some(facts), config.revision)
            }
            Err(error) => {
                // A config that cannot be read is "no instruction", never
                // "disable". It is most likely mid-write, or left empty by a
                // failed catalogue fetch, and taking live rules down over that
                // would punch a hole exactly when the user is playing. Passing
                // `None` below is what makes the watcher inert for this poll.
                let message = format!("{error:#}");
                if last_config_error.as_deref() != Some(message.as_str()) {
                    println!("ignoring service config: {message}");
                    last_config_error = Some(message);
                }
                (None, 0)
            }
        };

        // The cgroup is discovered, never read from the config — that is the
        // property that stops a user-writable file from aiming the blocks.
        let game = steam::running_game_cgroup().map(|cgroup| ScopedCgroup::of(&cgroup));
        let observation = Observation {
            game,
            config,
            table_present,
        };

        let decision = watcher.step(&observation, Instant::now());

        // Do the I/O first, then commit the result through one path. The two
        // transitions used to repeat the bookkeeping, and one of them had the
        // report before the state update while the other had it after.
        let outcome: Result<Option<Settled>, String> = match &decision {
            Decision::Apply(plan) => firewall::apply(plan)
                .map(|scoped| {
                    // Record the plan that was actually installed, not a fresh
                    // read of the config: that is what the next poll compares
                    // against to notice a changed selection.
                    let networks = plan.ipv4.iter().chain(&plan.ipv6).copied().collect();
                    let line = format!(
                        "applied {} blocks scoped to {} (cgroup {})",
                        plan.ipv4.len() + plan.ipv6.len(),
                        plan.cgroup.path,
                        describe_inode(scoped.inode),
                    );
                    Some(Settled::Applied(scoped, networks, line))
                })
                .map_err(|error| format!("could not apply blocks: {error:#}")),
            Decision::Disable => firewall::disable()
                .map(|()| Some(Settled::Removed))
                .map_err(|error| format!("could not remove blocks: {error:#}")),
            Decision::Idle => Ok(None),
        };

        match outcome {
            Ok(Some(settled)) => {
                let (applied, installed, last_decision, line) = match settled {
                    Settled::Applied(scoped, networks, line) => {
                        watcher.applied(scoped, networks);
                        (watcher.current().cloned(), true, "apply", line)
                    }
                    Settled::Removed => {
                        watcher.removed();
                        (None, false, "disable", "removed blocks".to_owned())
                    }
                };
                table_present = installed;
                since = epoch_secs();
                report(&mut last_error, line);
                publish(
                    &mut last_error,
                    applied,
                    table_present,
                    revision,
                    last_decision,
                    since,
                );
            }
            Ok(None) => {}
            Err(message) => note(&mut last_error, message),
        }

        if last_heartbeat.elapsed() >= HEARTBEAT {
            match firewall::table_present() {
                Ok(present) => {
                    table_present = present;
                    // A table appearing or disappearing outside our own apply
                    // or disable changes what the GUI should be told. Only a
                    // fresh query is allowed to seed `Unknown`.
                    if watcher.note_table_present(present) {
                        since = epoch_secs();
                        publish(
                            &mut last_error,
                            watcher.current().cloned(),
                            table_present,
                            revision,
                            "observed",
                            since,
                        );
                    }
                }
                Err(error) => note(
                    &mut last_error,
                    format!("could not check the Dropship table: {error:#}"),
                ),
            }
            last_heartbeat = Instant::now();
        }

        sleep(watcher.next_poll(observation.config.is_some(), observation.game.is_some()));
    }
}

/// Publishes the state, reporting a failure rather than dying over it.
///
/// The state file is a diagnostic for the GUI; the firewall works without it.
/// Treating a full `/run` as fatal would make the daemon exit, `ExecStopPost`
/// remove the rules, systemd restart it, and repeat — flapping blocks over a
/// write that does not affect them.
fn publish(
    last_error: &mut Option<String>,
    applied: Option<ScopedCgroup>,
    table_present: bool,
    revision: u64,
    last_decision: &str,
    since_unix_secs: u64,
) {
    if let Err(error) = publish_state(
        applied,
        table_present,
        revision,
        last_decision,
        since_unix_secs,
    ) {
        note(
            last_error,
            format!("could not publish service state: {error:#}"),
        );
    }
}

/// Writes the state file the GUI reads.
///
/// Written atomically, so a reader never sees a partial file. Left
/// world-readable on purpose: the point is for the unprivileged GUI to read it.
fn publish_state(
    applied: Option<ScopedCgroup>,
    table_present: bool,
    revision: u64,
    last_decision: &str,
    since_unix_secs: u64,
) -> Result<()> {
    let state = PublishedState {
        applied,
        table_present,
        revision,
        last_decision: last_decision.to_owned(),
        since_unix_secs,
    };
    let path = Path::new(RUNTIME_DIR).join("state.json");
    fsutil::write_json_atomic(&path, &state)
}

/// Prints a state transition, unconditionally.
///
/// Never suppressed, because the two things suppression was hiding are exactly
/// the things worth seeing: a watcher that re-applies every tick, and the
/// re-apply after a Steam restart — whose path is unchanged by design, so its
/// line is only distinguishable by the cgroup identity carried alongside it.
/// Clearing the failure memory here means a failure that recurs after a
/// successful transition is reported again rather than swallowed.
fn report(last_error: &mut Option<String>, line: String) {
    println!("{line}");
    *last_error = None;
}

/// Prints a failure `line` unless it is the same as last time.
///
/// Failures are the ones that can repeat every couple of seconds forever, so
/// this is where deduping belongs.
fn note(last: &mut Option<String>, line: String) {
    if last.as_deref() != Some(line.as_str()) {
        println!("{line}");
        *last = Some(line);
    }
}

/// Renders a cgroup inode for the log, where `None` has to read as "could not
/// tell" rather than as a number.
fn describe_inode(inode: Option<u64>) -> String {
    inode.map_or_else(|| "unknown".to_owned(), |inode| inode.to_string())
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
    fn a_settled_systemd_state_becomes_an_answer() {
        assert_eq!(parse_is_active("active\n"), Some(true));
        assert_eq!(parse_is_active("inactive\n"), Some(false));
        assert_eq!(parse_is_active("failed\n"), Some(false));
    }

    #[test]
    fn a_transitional_systemd_state_is_unknown() {
        // A `systemctl restart` passes through these. Reading one as "not
        // running" would flip the GUI into the manual path, whose Disable can
        // delete the table the restarted watcher is about to re-create.
        for state in ["activating\n", "deactivating\n", "reloading\n"] {
            assert_eq!(parse_is_active(state), None, "parsed {state:?}");
        }
    }

    #[test]
    fn an_unrecognised_answer_is_unknown() {
        // `unknown` is what systemd prints for a unit it cannot identify; the
        // empty case is a systemctl that gave no answer at all. Anything else
        // unrecognised is treated the same way rather than guessed at.
        for output in ["unknown\n", "", "   ", "Active\n", "active extra\n"] {
            assert_eq!(parse_is_active(output), None, "parsed {output:?}");
        }
    }

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
    fn an_unreadable_inode_reads_as_unknown_rather_than_a_number() {
        // This goes into the log line that is the only evidence a Steam-restart
        // re-apply happened. Rendering a missing inode as 0 would make two
        // different cgroups look like the same one.
        assert_eq!(describe_inode(Some(31_422)), "31422");
        assert_eq!(describe_inode(None), "unknown");
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
            table_present: true,
            revision: 12,
            last_decision: "apply".to_owned(),
            since_unix_secs: 1_790_000_000,
        };

        let json = serde_json::to_value(&state).unwrap();
        assert_eq!(json["applied"]["inode"], 31_422);
        assert_eq!(json["table_present"], true);
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
            table_present: false,
            revision: 0,
            last_decision: "disable".to_owned(),
            since_unix_secs: 0,
        };
        let json = serde_json::to_value(&state).unwrap();
        assert!(json["applied"].is_null());
        assert!(json.get("applied").is_some());
        assert_eq!(json["table_present"], false);
    }

    #[test]
    fn a_legacy_state_without_table_present_still_parses() {
        // The field arrived after the first releases. A state file left behind
        // in /run across an upgrade must still parse, as "no table".
        let state: PublishedState = serde_json::from_str(
            r#"{"applied":null,"revision":3,"last_decision":"disable","since_unix_secs":7}"#,
        )
        .unwrap();
        assert!(state.applied.is_none());
        assert!(!state.table_present);
    }
}
