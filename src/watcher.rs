//! The decision half of the auto-apply service.
//!
//! Everything here is pure: no I/O, no clock, no nft. `step` takes the facts of
//! one poll and returns what to do about them, which is what makes the whole
//! decision table testable on any OS — the same reason `firewall.rs` and
//! `steam.rs` keep their parsing separate from their command running.
//!
//! The caller (see `service.rs`) gathers an [`Observation`], acts on the
//! [`Decision`], and reports the outcome back with [`Watcher::applied`] or
//! [`Watcher::removed`]. Note what is *not* here: a way to say "that failed".
//! State is only ever updated on success, so a failed apply simply leaves
//! `applied` unchanged and the next tick asks for it again. Retry is the
//! default rather than something that has to be remembered.

use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

use ipnet::IpNet;

use crate::firewall::{RulePlan, ScopedCgroup};

/// How long the game must stay gone before the blocks come down.
///
/// Without a grace period a crash-and-restart — or the moment between a
/// launcher exiting and the game it spawned being reaped — would tear the rules
/// down and rebuild them for nothing. Ten seconds is far longer than any such
/// gap and far shorter than anyone would notice blocks lingering after a quit.
pub const ABSENT_GRACE: Duration = Duration::from_secs(10);

/// How often to poll while something could change: the game is running, or
/// rules — or a table of unknown scope — may need reconciling.
pub const ACTIVE_POLL: Duration = Duration::from_secs(2);

/// How often to poll when nothing is happening at all.
///
/// The only thing being waited for is a game launch, and a match takes far
/// longer than this to load, so the poll can be lazy. This matters on a
/// handheld: it is the difference between waking the CPU every two seconds
/// forever and doing so every ten.
pub const IDLE_POLL: Duration = Duration::from_secs(10);

/// What a readable `service.json` asked for.
#[derive(Clone, Debug)]
pub struct ConfigFacts {
    /// Whether blocks should be applied while the game runs.
    pub enabled: bool,
    /// The selected networks, already parsed into typed values.
    pub networks: Vec<IpNet>,
}

/// One poll's worth of facts, gathered by the caller.
#[derive(Clone, Debug)]
pub struct Observation {
    /// The game's live cgroup and identity, or `None` when it is not running.
    pub game: Option<ScopedCgroup>,
    /// The instruction from `service.json`, or `None` when it could not be read
    /// or validated.
    ///
    /// This must stay distinct from "a readable file that is disabled": the
    /// unreadable case is a torn read and must not tear live rules down, while
    /// the readable-and-disabled case is the user asking for exactly that.
    pub config: Option<ConfigFacts>,
    /// Whether `inet dropship_steamos` currently exists.
    pub table_present: bool,
}

/// What the caller should do about an [`Observation`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Run `firewall::apply` with this plan, then call [`Watcher::applied`].
    Apply(RulePlan),
    /// Run `firewall::disable`, then call [`Watcher::removed`].
    Disable,
    /// Do nothing.
    Idle,
}

/// What this process believes is installed.
///
/// A single `Option<ScopedCgroup>` used to mean both "this process has not
/// applied anything" and "no rules of ours are up". A table left behind by a
/// previous watcher — or by a manual `pkexec` apply — is neither, and could
/// never be reconciled. The three states are separate here.
#[derive(Clone, Debug)]
enum Installed {
    /// No rules of ours are believed to be up.
    None,
    /// The table exists, but this process did not apply it. The scope and the
    /// plan are unknown until the next apply replaces them wholesale.
    Unknown,
    /// This process applied these rules, scoped to `scope`.
    Known {
        scope: ScopedCgroup,
        networks: BTreeSet<IpNet>,
    },
}

impl Installed {
    fn is_some(&self) -> bool {
        !matches!(self, Self::None)
    }
}

pub struct Watcher {
    installed: Installed,
    /// When the game was first seen absent, for the grace period.
    absent_since: Option<Instant>,
}

impl Default for Watcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Watcher {
    pub fn new() -> Self {
        Self {
            installed: Installed::None,
            absent_since: None,
        }
    }

    /// Records the result of a successful apply or removal.
    pub fn record(&mut self, installed: Option<(ScopedCgroup, BTreeSet<IpNet>)>) {
        self.installed = match installed {
            Some((scope, networks)) => Installed::Known { scope, networks },
            None => Installed::None,
        };
        self.absent_since = None;
    }

    /// The caller successfully applied `networks`, scoped to `scope`.
    pub fn applied(&mut self, scope: ScopedCgroup, networks: BTreeSet<IpNet>) {
        self.record(Some((scope, networks)));
    }

    /// The caller successfully removed the rules.
    pub fn removed(&mut self) {
        self.record(None);
    }

    /// The interval the caller should wait before polling again.
    ///
    /// With no readable instruction there is nothing to react to quickly: what
    /// is installed must stay until the config says otherwise. Otherwise a
    /// running game, or any table that may need reconciling, keeps the loop
    /// quick; a quiet device can afford to be lazy.
    pub fn next_poll(&self, config_read: bool, game_running: bool) -> Duration {
        if config_read && (game_running || self.is_tracking()) {
            ACTIVE_POLL
        } else {
            IDLE_POLL
        }
    }

    /// Records a fresh `nft list tables` observation.
    ///
    /// Only call this with a value the caller has just read: a cached
    /// `table_present` may still say true after a successful removal, and
    /// seeding `Unknown` from it would resurrect rules that are gone.
    ///
    /// Returns whether the installed state changed, so the caller can publish
    /// it. It never overrides `Known`: the table disappearing or reappearing
    /// under live rules is the decision table's business, not this method's.
    pub fn note_table_present(&mut self, present: bool) -> bool {
        match (&self.installed, present) {
            (Installed::None, true) => {
                self.installed = Installed::Unknown;
                true
            }
            (Installed::Unknown, false) => {
                self.installed = Installed::None;
                true
            }
            _ => false,
        }
    }

    /// Whether anything may be installed.
    ///
    /// The poll interval keys off this: with rules up — or a table whose scope
    /// this process has not identified — something can change at any moment and
    /// the loop should be quick. With nothing installed, it is only waiting for
    /// a game launch and can afford to be slow.
    pub fn is_tracking(&self) -> bool {
        self.installed.is_some()
    }

    /// The scope the installed rules are bound to, when known.
    ///
    /// Published to the GUI, which cannot read the nft table itself — that
    /// needs CAP_NET_ADMIN — and so has no other way to know what is applied.
    pub fn current(&self) -> Option<&ScopedCgroup> {
        match &self.installed {
            Installed::Known { scope, .. } => Some(scope),
            _ => None,
        }
    }

    /// What to do about `obs`, as of `now`.
    ///
    /// `now` is a parameter rather than a call to `Instant::now` so the grace
    /// period can be tested without sleeping.
    pub fn step(&mut self, obs: &Observation, now: Instant) -> Decision {
        // A config that could not be read is "no instruction", never "disable".
        // It is most likely mid-write, and acting on it would punch a hole in
        // live rules exactly when the user is playing. Leave everything alone.
        let Some(config) = &obs.config else {
            return Decision::Idle;
        };

        // Switched off. Take them down at once — this is the exit the user
        // asked for, and there is nothing to debounce against. This has to come
        // before the empty-selection guard: a disabled config whose selection
        // is empty is still an explicit instruction to remove the rules. Only
        // the unreadable case above is allowed to be inert.
        if !config.enabled {
            return if self.installed.is_some() {
                Decision::Disable
            } else {
                Decision::Idle
            };
        }

        // Enabled with nothing selected. Keep the last known rules: applying an
        // empty set is meaningless, and removing them over what might be a
        // failed catalogue fetch would lose blocks mid-match. The README names
        // this behavior, and the watcher still follows it.
        if config.networks.is_empty() {
            return Decision::Idle;
        }

        if let Some(live) = &obs.game {
            self.absent_since = None;

            // Settled only when the table, the scope *and* the plan all still
            // match. The plan comparison is what makes a change of selected
            // regions reach nft; `still_matches` catches Steam replacing the
            // game's cgroup at an unchanged path; `table_present` catches
            // anything else having removed the table while both stayed put.
            let settled = match &self.installed {
                Installed::Known { scope, networks } => {
                    obs.table_present
                        && scope.still_matches(live)
                        && *networks == config.networks.iter().copied().collect::<BTreeSet<_>>()
                }
                _ => false,
            };
            if settled {
                return Decision::Idle;
            }

            // Nothing is applied yet, the table's scope is unknown, the scope
            // or plan has gone stale, or the table was removed behind our back.
            // All are fixed by applying again, which replaces the table
            // wholesale and so is idempotent.
            return Decision::Apply(RulePlan::from_networks(
                config.networks.clone(),
                live.cgroup.clone(),
            ));
        }

        // The game is not running.
        if !self.installed.is_some() {
            self.absent_since = None;
            return Decision::Idle;
        }

        // Nothing is actually installed, so there is no grace period worth
        // waiting out — the rules are already gone and `disable` is a no-op
        // that settles the bookkeeping.
        if !obs.table_present {
            return Decision::Disable;
        }

        let first_absent = *self.absent_since.get_or_insert(now);
        if now.saturating_duration_since(first_absent) >= ABSENT_GRACE {
            Decision::Disable
        } else {
            Decision::Idle
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firewall::CgroupMatch;

    /// The measured Desktop Mode path (see `firewall::ScopedCgroup`).
    const DESKTOP: &str =
        "user.slice/user-1000.slice/user@1000.service/app.slice/app-steam@autostart.service";
    /// What Game Mode looks like: same shape, different unit name. Used to check
    /// nothing here is hardcoded to the Desktop Mode name.
    const GAME_MODE: &str =
        "user.slice/user-1000.slice/user@1000.service/app.slice/app-steam-app2357570-4242.scope";

    fn scoped(path: &str, inode: u64) -> ScopedCgroup {
        ScopedCgroup {
            cgroup: CgroupMatch::from_path(path).unwrap(),
            inode: Some(inode),
        }
    }

    fn nets(items: &[&str]) -> BTreeSet<IpNet> {
        items.iter().map(|item| item.parse().unwrap()).collect()
    }

    fn running(path: &str, inode: u64) -> Observation {
        Observation {
            game: Some(scoped(path, inode)),
            config: Some(ConfigFacts {
                enabled: true,
                networks: vec!["192.0.2.0/24".parse().unwrap()],
            }),
            table_present: true,
        }
    }

    /// Records a successful apply of the default test selection.
    fn mark_applied(watcher: &mut Watcher, path: &str, inode: u64) {
        watcher.applied(scoped(path, inode), nets(&["192.0.2.0/24"]));
    }

    fn absent() -> Observation {
        Observation {
            game: None,
            ..running(DESKTOP, 7)
        }
    }

    fn plan_of(decision: &Decision) -> &RulePlan {
        match decision {
            Decision::Apply(plan) => plan,
            other => panic!("expected Apply, got {other:?}"),
        }
    }

    #[test]
    fn the_game_appearing_asks_for_a_first_apply() {
        let mut watcher = Watcher::new();
        let decision = watcher.step(&running(DESKTOP, 7), Instant::now());

        let plan = plan_of(&decision);
        assert_eq!(plan.cgroup.path, DESKTOP);
        assert_eq!(plan.ipv4.len(), 1);
    }

    #[test]
    fn a_settled_scope_is_left_alone() {
        // The property that keeps this from churning: applying is only asked
        // for once, not every poll.
        let mut watcher = Watcher::new();
        let now = Instant::now();
        mark_applied(&mut watcher, DESKTOP, 7);

        assert_eq!(watcher.step(&running(DESKTOP, 7), now), Decision::Idle);
        assert_eq!(watcher.step(&running(DESKTOP, 7), now), Decision::Idle);
    }

    #[test]
    fn a_recreated_cgroup_is_re_applied() {
        // The measured hazard: Steam restarts and rebuilds the same path as a
        // new cgroup object, so every rule silently stops matching. Same path,
        // different inode — this is the case a path comparison cannot see.
        let mut watcher = Watcher::new();
        mark_applied(&mut watcher, DESKTOP, 31_366);

        let decision = watcher.step(&running(DESKTOP, 31_422), Instant::now());
        assert_eq!(plan_of(&decision).cgroup.path, DESKTOP);
    }

    #[test]
    fn a_table_removed_behind_our_back_is_re_applied() {
        // The cgroup is untouched, so `still_matches` is happy — but the rules
        // are gone. Nothing else in the design catches this.
        let mut watcher = Watcher::new();
        mark_applied(&mut watcher, DESKTOP, 7);

        let mut obs = running(DESKTOP, 7);
        obs.table_present = false;
        assert!(matches!(
            watcher.step(&obs, Instant::now()),
            Decision::Apply(_)
        ));
    }

    #[test]
    fn game_mode_works_without_naming_the_desktop_unit() {
        let mut watcher = Watcher::new();
        let decision = watcher.step(&running(GAME_MODE, 5), Instant::now());
        assert_eq!(plan_of(&decision).cgroup.path, GAME_MODE);
    }

    #[test]
    fn a_switch_off_removes_immediately() {
        // No grace period on this path: the user asked, and the rules are
        // already live.
        let mut watcher = Watcher::new();
        mark_applied(&mut watcher, DESKTOP, 7);

        let mut obs = absent();
        obs.config.as_mut().unwrap().enabled = false;
        assert_eq!(watcher.step(&obs, Instant::now()), Decision::Disable);
    }

    #[test]
    fn switching_off_with_nothing_applied_is_idle() {
        let mut watcher = Watcher::new();
        let mut obs = absent();
        obs.config.as_mut().unwrap().enabled = false;
        assert_eq!(watcher.step(&obs, Instant::now()), Decision::Idle);
    }

    #[test]
    fn a_quit_waits_out_the_grace_period() {
        let mut watcher = Watcher::new();
        let start = Instant::now();
        mark_applied(&mut watcher, DESKTOP, 7);

        assert_eq!(watcher.step(&absent(), start), Decision::Idle);
        assert_eq!(
            watcher.step(&absent(), start + ABSENT_GRACE / 2),
            Decision::Idle
        );
        assert_eq!(
            watcher.step(&absent(), start + ABSENT_GRACE),
            Decision::Disable
        );
    }

    #[test]
    fn a_restart_within_the_grace_period_keeps_the_rules() {
        // A crash and relaunch should not tear the rules down and rebuild them.
        let mut watcher = Watcher::new();
        let start = Instant::now();
        mark_applied(&mut watcher, DESKTOP, 7);

        assert_eq!(watcher.step(&absent(), start), Decision::Idle);
        assert_eq!(
            watcher.step(&running(DESKTOP, 7), start + ABSENT_GRACE / 2),
            Decision::Idle
        );
        // ...and the timer was reset, so a later absence gets a full grace.
        assert_eq!(
            watcher.step(&absent(), start + ABSENT_GRACE),
            Decision::Idle
        );
    }

    #[test]
    fn a_grace_period_restarts_after_the_game_comes_back() {
        let mut watcher = Watcher::new();
        let start = Instant::now();
        mark_applied(&mut watcher, DESKTOP, 7);

        watcher.step(&absent(), start);
        watcher.step(&running(DESKTOP, 7), start + Duration::from_secs(5));
        assert_eq!(
            watcher.step(&absent(), start + ABSENT_GRACE),
            Decision::Idle,
            "the absence clock should have restarted when the game reappeared"
        );
        assert_eq!(
            watcher.step(&absent(), start + ABSENT_GRACE * 2),
            Decision::Disable
        );
    }

    #[test]
    fn an_absent_game_that_was_never_applied_is_idle() {
        let mut watcher = Watcher::new();
        assert_eq!(watcher.step(&absent(), Instant::now()), Decision::Idle);
    }

    #[test]
    fn a_gone_table_skips_the_grace_period() {
        // Quit, and something else already removed the table. Waiting ten
        // seconds to disable nothing helps no one.
        let mut watcher = Watcher::new();
        mark_applied(&mut watcher, DESKTOP, 7);

        let mut obs = absent();
        obs.table_present = false;
        assert_eq!(watcher.step(&obs, Instant::now()), Decision::Disable);
    }

    #[test]
    fn an_empty_selection_never_applies() {
        let mut watcher = Watcher::new();
        let mut obs = running(DESKTOP, 7);
        obs.config.as_mut().unwrap().networks.clear();
        assert_eq!(watcher.step(&obs, Instant::now()), Decision::Idle);
    }

    #[test]
    fn an_empty_selection_with_blocking_on_keeps_live_rules() {
        // Documented behavior: clearing every region while blocking stays on
        // leaves the last known rules up. The toggle, not an empty selection,
        // is the way to remove them.
        let mut watcher = Watcher::new();
        mark_applied(&mut watcher, DESKTOP, 7);

        let mut obs = absent();
        obs.config.as_mut().unwrap().networks.clear();
        assert_eq!(watcher.step(&obs, Instant::now()), Decision::Idle);
    }

    #[test]
    fn a_failed_apply_is_retried_rather_than_assumed() {
        // State only moves on success, so a failure needs no special handling:
        // the next poll sees the same facts and asks again.
        let mut watcher = Watcher::new();
        let now = Instant::now();

        assert!(matches!(
            watcher.step(&running(DESKTOP, 7), now),
            Decision::Apply(_)
        ));
        // The caller's apply failed, so it never called `applied`.
        assert!(matches!(
            watcher.step(&running(DESKTOP, 7), now),
            Decision::Apply(_)
        ));
    }

    #[test]
    fn a_failed_removal_is_retried_rather_than_assumed() {
        let mut watcher = Watcher::new();
        let start = Instant::now();
        mark_applied(&mut watcher, DESKTOP, 7);

        // The grace period starts on the first *observation* of absence — the
        // watcher cannot know when the game actually quit, only when it first
        // noticed — so this poll starts the clock rather than expiring it.
        assert_eq!(watcher.step(&absent(), start), Decision::Idle);
        assert_eq!(
            watcher.step(&absent(), start + ABSENT_GRACE),
            Decision::Disable
        );
        // The caller's disable failed, so it never called `removed`.
        assert_eq!(
            watcher.step(&absent(), start + ABSENT_GRACE * 2),
            Decision::Disable
        );
    }

    #[test]
    fn a_successful_removal_settles_back_to_idle() {
        let mut watcher = Watcher::new();
        let start = Instant::now();
        mark_applied(&mut watcher, DESKTOP, 7);

        assert_eq!(watcher.step(&absent(), start), Decision::Idle);
        assert_eq!(
            watcher.step(&absent(), start + ABSENT_GRACE),
            Decision::Disable
        );
        watcher.removed();
        assert_eq!(
            watcher.step(&absent(), start + ABSENT_GRACE * 2),
            Decision::Idle
        );
    }

    #[test]
    fn switching_off_with_an_empty_selection_still_removes() {
        // The off switch is an explicit instruction even when the selection is
        // empty. The torn-read guard must not shadow it.
        let mut watcher = Watcher::new();
        mark_applied(&mut watcher, DESKTOP, 7);

        let mut obs = absent();
        obs.config = Some(ConfigFacts {
            enabled: false,
            networks: Vec::new(),
        });
        assert_eq!(watcher.step(&obs, Instant::now()), Decision::Disable);
    }

    #[test]
    fn an_unreadable_config_never_removes_live_rules() {
        // A torn read must not punch a hole, no matter how long it lasts.
        let mut watcher = Watcher::new();
        mark_applied(&mut watcher, DESKTOP, 7);

        let mut obs = absent();
        obs.config = None;
        let start = Instant::now();
        assert_eq!(watcher.step(&obs, start), Decision::Idle);
        assert_eq!(watcher.step(&obs, start + ABSENT_GRACE * 2), Decision::Idle);
    }

    #[test]
    fn an_unreadable_config_leaves_an_untracked_table_alone() {
        let mut watcher = Watcher::new();
        assert!(watcher.note_table_present(true));

        let mut obs = absent();
        obs.config = None;
        assert_eq!(watcher.step(&obs, Instant::now()), Decision::Idle);
        assert!(watcher.is_tracking());
    }

    #[test]
    fn an_unreadable_config_never_applies() {
        let mut watcher = Watcher::new();
        let mut obs = running(DESKTOP, 7);
        obs.config = None;
        assert_eq!(watcher.step(&obs, Instant::now()), Decision::Idle);
    }

    #[test]
    fn a_changed_network_set_is_re_applied() {
        // The failure this state model fixes: same cgroup, same table, a
        // different selection. The old settled check returned Idle forever.
        let mut watcher = Watcher::new();
        mark_applied(&mut watcher, DESKTOP, 7);

        let mut obs = running(DESKTOP, 7);
        obs.config.as_mut().unwrap().networks = vec!["198.51.100.0/24".parse().unwrap()];
        let decision = watcher.step(&obs, Instant::now());
        assert_eq!(
            plan_of(&decision).ipv4,
            vec!["198.51.100.0/24".parse().unwrap()]
        );
    }

    #[test]
    fn a_shrunk_network_set_is_re_applied() {
        let mut watcher = Watcher::new();
        watcher.applied(
            scoped(DESKTOP, 7),
            nets(&["192.0.2.0/24", "198.51.100.0/24"]),
        );

        let obs = running(DESKTOP, 7);
        assert!(matches!(
            watcher.step(&obs, Instant::now()),
            Decision::Apply(_)
        ));
    }

    #[test]
    fn a_reordered_network_set_is_left_alone() {
        // The comparison is by set, so the order the config happens to list
        // ranges in must not cause a re-apply every poll.
        let mut watcher = Watcher::new();
        watcher.applied(
            scoped(DESKTOP, 7),
            nets(&["198.51.100.0/24", "192.0.2.0/24"]),
        );

        let mut obs = running(DESKTOP, 7);
        obs.config.as_mut().unwrap().networks = vec![
            "192.0.2.0/24".parse().unwrap(),
            "198.51.100.0/24".parse().unwrap(),
        ];
        assert_eq!(watcher.step(&obs, Instant::now()), Decision::Idle);
    }

    #[test]
    fn duplicate_cidrs_are_not_a_change() {
        let mut watcher = Watcher::new();
        mark_applied(&mut watcher, DESKTOP, 7);

        let mut obs = running(DESKTOP, 7);
        obs.config.as_mut().unwrap().networks = vec![
            "192.0.2.0/24".parse().unwrap(),
            "192.0.2.0/24".parse().unwrap(),
        ];
        assert_eq!(watcher.step(&obs, Instant::now()), Decision::Idle);
    }

    #[test]
    fn an_untracked_table_is_removed_after_the_grace_period() {
        let mut watcher = Watcher::new();
        assert!(watcher.note_table_present(true));
        let start = Instant::now();

        assert_eq!(watcher.step(&absent(), start), Decision::Idle);
        assert_eq!(
            watcher.step(&absent(), start + ABSENT_GRACE),
            Decision::Disable
        );
    }

    #[test]
    fn an_untracked_table_is_adopted_when_the_game_appears() {
        let mut watcher = Watcher::new();
        assert!(watcher.note_table_present(true));

        let decision = watcher.step(&running(DESKTOP, 7), Instant::now());
        assert_eq!(plan_of(&decision).cgroup.path, DESKTOP);
    }

    #[test]
    fn note_table_present_does_not_override_known_state() {
        let mut watcher = Watcher::new();
        mark_applied(&mut watcher, DESKTOP, 7);

        assert!(!watcher.note_table_present(true));
        assert_eq!(watcher.current().unwrap().cgroup.path, DESKTOP);
        assert!(!watcher.note_table_present(false));
        assert!(watcher.current().is_some());
    }

    #[test]
    fn the_poll_is_active_while_the_game_runs() {
        let watcher = Watcher::new();
        assert_eq!(watcher.next_poll(true, true), ACTIVE_POLL);
    }

    #[test]
    fn the_poll_is_idle_when_nothing_is_running_or_installed() {
        let watcher = Watcher::new();
        assert_eq!(watcher.next_poll(true, false), IDLE_POLL);
    }

    #[test]
    fn an_untracked_table_keeps_the_poll_active() {
        let mut watcher = Watcher::new();
        watcher.note_table_present(true);
        assert_eq!(watcher.next_poll(true, false), ACTIVE_POLL);
    }

    #[test]
    fn an_unreadable_config_uses_the_idle_interval() {
        let mut watcher = Watcher::new();
        watcher.note_table_present(true);
        assert_eq!(watcher.next_poll(false, true), IDLE_POLL);
    }

    #[test]
    fn an_untracked_table_keeps_the_watcher_active() {
        let mut watcher = Watcher::new();
        assert!(!watcher.is_tracking());

        assert!(watcher.note_table_present(true));
        assert!(watcher.is_tracking());

        // A fresh observation that the table is gone settles it back to idle.
        assert!(watcher.note_table_present(false));
        assert!(!watcher.is_tracking());
    }
}
