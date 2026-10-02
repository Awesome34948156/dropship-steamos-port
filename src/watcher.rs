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

use std::time::{Duration, Instant};

use ipnet::IpNet;

use crate::firewall::{RulePlan, ScopedCgroup};

/// How long the game must stay gone before the blocks come down.
///
/// Without a grace period a crash-and-restart — or the moment between a
/// launcher exiting and the game it spawned being reaped — would tear the rules
/// down and rebuild them for nothing. Ten seconds is far longer than any such
/// gap and far shorter than anyone would notice blocks lingering after a quit.
pub const ABSENT_GRACE: Duration = Duration::from_secs(10);

/// One poll's worth of facts, gathered by the caller.
#[derive(Clone, Debug)]
pub struct Observation {
    /// The game's live cgroup and identity, or `None` when it is not running.
    pub game: Option<ScopedCgroup>,
    /// `service.json`'s enabled flag.
    pub enabled: bool,
    /// `service.json`'s networks, already parsed into typed values.
    pub networks: Vec<IpNet>,
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

pub struct Watcher {
    /// The cgroup the currently installed rules were scoped to, as reported by
    /// the caller. `None` means no rules of ours are up.
    applied: Option<ScopedCgroup>,
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
            applied: None,
            absent_since: None,
        }
    }

    /// The caller successfully applied a plan scoped to `scoped`.
    pub fn applied(&mut self, scoped: ScopedCgroup) {
        self.applied = Some(scoped);
        self.absent_since = None;
    }

    /// The caller successfully removed the rules.
    pub fn removed(&mut self) {
        self.applied = None;
        self.absent_since = None;
    }

    /// Whether rules of ours are believed to be installed.
    ///
    /// The poll interval keys off this: with rules up, or the game running,
    /// something can change at any moment and the loop should be quick. With
    /// neither, it is only waiting for a game launch and can afford to be slow.
    pub fn is_tracking(&self) -> bool {
        self.applied.is_some()
    }

    /// The scope the installed rules are bound to, if any.
    ///
    /// Published to the GUI, which cannot read the nft table itself — that
    /// needs CAP_NET_ADMIN — and so has no other way to know what is applied.
    pub fn current(&self) -> Option<&ScopedCgroup> {
        self.applied.as_ref()
    }

    /// What to do about `obs`, as of `now`.
    ///
    /// `now` is a parameter rather than a call to `Instant::now` so the grace
    /// period can be tested without sleeping.
    pub fn step(&mut self, obs: &Observation, now: Instant) -> Decision {
        // Nothing selected, or the config could not be read. Act on neither:
        // applying an empty set is meaningless, and *removing* blocks because a
        // file was momentarily empty would punch a hole in live rules over what
        // is most likely a torn read or a failed catalogue fetch. Leaving the
        // rules up is the recoverable direction.
        if obs.networks.is_empty() {
            return Decision::Idle;
        }

        // Switched off. Take them down at once — this is the exit the user
        // asked for, and there is nothing to debounce against.
        if !obs.enabled {
            return if self.applied.is_some() {
                Decision::Disable
            } else {
                Decision::Idle
            };
        }

        if let Some(live) = &obs.game {
            self.absent_since = None;

            // Already scoped to this exact cgroup *and* the table still exists:
            // nothing to do. Both halves matter. `still_matches` catches the
            // game's process tree being replaced, which happens at an unchanged
            // path every time Steam restarts; `table_present` catches anything
            // else having removed the table while the cgroup stayed put.
            let scoped_correctly = self
                .applied
                .as_ref()
                .is_some_and(|applied| applied.still_matches(live));
            if scoped_correctly && obs.table_present {
                return Decision::Idle;
            }

            // Either nothing is applied yet, or the scope has gone stale, or
            // the table was removed behind our back. All three are fixed by
            // applying again, which replaces the table wholesale and so is
            // idempotent.
            return Decision::Apply(RulePlan::from_networks(
                obs.networks.clone(),
                live.cgroup.clone(),
            ));
        }

        // The game is not running.
        if self.applied.is_none() {
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

    fn running(path: &str, inode: u64) -> Observation {
        Observation {
            game: Some(scoped(path, inode)),
            enabled: true,
            networks: vec!["192.0.2.0/24".parse().unwrap()],
            table_present: true,
        }
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
        watcher.applied(scoped(DESKTOP, 7));

        assert_eq!(watcher.step(&running(DESKTOP, 7), now), Decision::Idle);
        assert_eq!(watcher.step(&running(DESKTOP, 7), now), Decision::Idle);
    }

    #[test]
    fn a_recreated_cgroup_is_re_applied() {
        // The measured hazard: Steam restarts and rebuilds the same path as a
        // new cgroup object, so every rule silently stops matching. Same path,
        // different inode — this is the case a path comparison cannot see.
        let mut watcher = Watcher::new();
        watcher.applied(scoped(DESKTOP, 31_366));

        let decision = watcher.step(&running(DESKTOP, 31_422), Instant::now());
        assert_eq!(plan_of(&decision).cgroup.path, DESKTOP);
    }

    #[test]
    fn a_table_removed_behind_our_back_is_re_applied() {
        // The cgroup is untouched, so `still_matches` is happy — but the rules
        // are gone. Nothing else in the design catches this.
        let mut watcher = Watcher::new();
        watcher.applied(scoped(DESKTOP, 7));

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
        watcher.applied(scoped(DESKTOP, 7));

        let mut obs = absent();
        obs.enabled = false;
        assert_eq!(watcher.step(&obs, Instant::now()), Decision::Disable);
    }

    #[test]
    fn switching_off_with_nothing_applied_is_idle() {
        let mut watcher = Watcher::new();
        let mut obs = absent();
        obs.enabled = false;
        assert_eq!(watcher.step(&obs, Instant::now()), Decision::Idle);
    }

    #[test]
    fn a_quit_waits_out_the_grace_period() {
        let mut watcher = Watcher::new();
        let start = Instant::now();
        watcher.applied(scoped(DESKTOP, 7));

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
        watcher.applied(scoped(DESKTOP, 7));

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
        watcher.applied(scoped(DESKTOP, 7));

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
        watcher.applied(scoped(DESKTOP, 7));

        let mut obs = absent();
        obs.table_present = false;
        assert_eq!(watcher.step(&obs, Instant::now()), Decision::Disable);
    }

    #[test]
    fn an_empty_selection_never_applies() {
        let mut watcher = Watcher::new();
        let mut obs = running(DESKTOP, 7);
        obs.networks.clear();
        assert_eq!(watcher.step(&obs, Instant::now()), Decision::Idle);
    }

    #[test]
    fn an_empty_selection_never_removes_live_rules() {
        // The torn-read guard. If the GUI is mid-write, or a catalogue fetch
        // failed and left the file blank, the rules already up must stay up.
        // Disabling here would silently punch a hole.
        let mut watcher = Watcher::new();
        watcher.applied(scoped(DESKTOP, 7));

        let mut obs = absent();
        obs.networks.clear();
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
        watcher.applied(scoped(DESKTOP, 7));

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
        watcher.applied(scoped(DESKTOP, 7));

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
}
