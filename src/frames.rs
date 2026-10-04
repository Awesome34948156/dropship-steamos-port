//! Leaving when the window stops being drawn.
//!
//! Why this exists. A Wayland compositor does not have to keep answering a
//! window it is not showing, and KWin does not: when a window is occluded — the
//! everyday version of that on a Deck is a game going fullscreen over this
//! window — KWin holds the buffers it has taken, and a frame that was in flight
//! when that happened waits for a release that never comes. The wait is inside
//! the graphics driver's own present call, so no code of ours runs again: the
//! event loop stops servicing events, which means the window answers nothing,
//! including the ping the desktop sends before it asks windows to close. That is
//! the "Dropship for SteamOS is not responding" dialog on the way out of a
//! session, minutes after the game that caused it has gone.
//!
//! Nothing this app can set prevents it. Swap interval 0 does not: with every
//! buffer held there is nothing to swap into. Not drawing while hidden does not
//! either: the app cannot know it is hidden — neither winit nor the compositor
//! reports occlusion — and the frame that strands it is already in flight when
//! the window disappears. What can be done is to notice, which is all this
//! module does.
//!
//! The UI thread stamps the start of every frame; the thread started here reads
//! that stamp. A window that has gone quiet for far longer than a frame can
//! honestly take cannot draw and will not recover, so it leaves the process the
//! same way the session's own `SIGTERM` does: at once, without teardown, so
//! there is nothing left for the desktop to wait on. The app is launched again
//! afterwards; until then a window that cannot draw is of no use to anyone.
//!
//! How long "far longer" is matters as much as the leaving does, and the first
//! answer was wrong. Twenty seconds left the app alive through the window in
//! which the desktop gives up on it: on a Deck on 2026-10-04 the app stranded a
//! frame at 23:41:53 and the shutdown began at 23:42:13, so the app left at the
//! very moment it was being asked about, and the dialog appeared anyway. The
//! desktop's patience is a few seconds, which means the app has to be gone
//! within a few seconds of a stall that, in the recorded cases, began while the
//! user was still deciding to power off. [`STALL`] is now short enough to beat
//! that, and the polls that already ask for a frame every two seconds are what
//! keep it from being so short that an idle window looks stuck.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use eframe::egui;

/// How long the window may go without starting a frame before it is called
/// stuck.
///
/// A frame here takes single-digit milliseconds, and the polls ask for a fresh
/// one every two seconds even when nothing has changed, so five seconds is
/// several missed requests — far past anything honest a frame could be doing,
/// and short enough that the process is gone seconds after a stall rather than
/// minutes. See the module documentation for why that second half is the part
/// that has to hold.
const STALL: Duration = Duration::from_secs(5);

/// How long an idle window is left alone before a frame is asked for.
///
/// This is what makes [`STALL`] mean something: without it, a window with
/// nothing to draw would look exactly like a stuck one, and the watchdog would
/// have to guess. In practice the polls already ask for a frame every two or
/// five seconds, so this only fires once whatever was poking the window has
/// stopped.
const NUDGE: Duration = Duration::from_secs(2);

/// How long a window that has never drawn anything gets.
///
/// The first frame is the expensive one: the graphics context is created, the
/// shaders are compiled, and on a cold start that is seconds rather than
/// milliseconds. Only a window that has proved it can draw is held to
/// [`STALL`].
const FIRST_FRAME: Duration = Duration::from_secs(20);

/// How often the stamp is read.
const TICK: Duration = Duration::from_secs(1);

/// What to do about a window that last started a frame `idle` ago.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// A frame is in flight, or one has just finished. Say nothing.
    Busy,
    /// Idle, and perhaps legitimately so. Ask for a frame.
    Nudge,
    /// Nothing has been drawn for longer than a frame can honestly take.
    Leave,
}

fn verdict(idle: Duration, ever_drew: bool) -> Verdict {
    let stuck_at = if ever_drew { STALL } else { FIRST_FRAME };
    if idle >= stuck_at {
        Verdict::Leave
    } else if idle >= NUDGE {
        Verdict::Nudge
    } else {
        Verdict::Busy
    }
}

/// When the last frame started, on a clock the UI thread and the watchdog
/// share.
struct Stamp {
    origin: Instant,
    /// Milliseconds since `origin`. Zero until the first frame.
    millis: AtomicU64,
    /// Whether any frame has started at all. A window that has never drawn is
    /// held to [`FIRST_FRAME`] rather than [`STALL`], because its first frame
    /// is allowed to be slow in a way that later ones are not.
    drew: AtomicBool,
}

impl Stamp {
    /// How long ago the last frame started.
    fn idle(&self) -> Duration {
        let stamp = Duration::from_millis(self.millis.load(Ordering::Relaxed));
        self.origin.elapsed().saturating_sub(stamp)
    }

    fn ever_drew(&self) -> bool {
        self.drew.load(Ordering::Relaxed)
    }
}

/// Watches the UI thread's frame stamp from a thread of its own.
///
/// Started by [`DropshipApp::new`](crate::app::DropshipApp::new), stamped by its
/// `update`, and dropped with the app, which stops the thread.
pub struct FrameWatchdog {
    stamp: Arc<Stamp>,
    stopped: Arc<AtomicBool>,
}

impl FrameWatchdog {
    /// Starts watching the window `ctx` draws.
    pub fn start(ctx: egui::Context) -> Self {
        let stamp = Arc::new(Stamp {
            origin: Instant::now(),
            millis: AtomicU64::new(0),
            drew: AtomicBool::new(false),
        });
        let stopped = Arc::new(AtomicBool::new(false));
        let (watched, watching) = (Arc::clone(&stamp), Arc::clone(&stopped));
        thread::spawn(move || {
            while !watching.load(Ordering::Relaxed) {
                thread::sleep(TICK);
                match verdict(watched.idle(), watched.ever_drew()) {
                    Verdict::Busy => {}
                    Verdict::Nudge => ctx.request_repaint(),
                    Verdict::Leave => {
                        eprintln!(
                            "The window has not been drawn for {}s, which means the display \
                             has stopped answering it; leaving rather than hanging.",
                            watched.idle().as_secs()
                        );
                        leave();
                    }
                }
            }
        });
        Self { stamp, stopped }
    }

    /// Records that a frame has started. Called by the UI thread, first thing in
    /// every `update`, so the clock measures the frame that is starting rather
    /// than the one before it.
    pub fn frame_started(&self) {
        let since_origin = self.stamp.origin.elapsed().as_millis() as u64;
        self.stamp.millis.store(since_origin, Ordering::Relaxed);
        self.stamp.drew.store(true, Ordering::Relaxed);
    }
}

impl Drop for FrameWatchdog {
    fn drop(&mut self) {
        // The app is on its way out. The thread would die with the process
        // anyway; this is so that it does not outlive the window it watches.
        self.stopped.store(true, Ordering::Relaxed);
    }
}

/// Leaves at once, the way a session that is ending does.
///
/// `SIGTERM` to this thread rather than `_exit` directly, so that leaving has
/// one definition in this program: `main` already installed a handler that
/// exits without running teardown, and linking this library into something
/// without one still gets the default action, which ends the process rather
/// than hanging. The `_exit` behind it only runs if the signal was blocked.
#[cfg(unix)]
fn leave() -> ! {
    unsafe {
        libc::raise(libc::SIGTERM);
        libc::_exit(0)
    }
}

#[cfg(not(unix))]
fn leave() -> ! {
    std::process::exit(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_in_flight_is_left_alone() {
        assert_eq!(verdict(Duration::ZERO, true), Verdict::Busy);
        assert_eq!(verdict(Duration::from_millis(120), true), Verdict::Busy);
    }

    #[test]
    fn an_idle_window_is_only_asked_for_a_frame() {
        assert_eq!(verdict(NUDGE, true), Verdict::Nudge);
        assert_eq!(verdict(STALL - TICK, true), Verdict::Nudge);
    }

    #[test]
    fn a_window_that_stopped_drawing_is_left() {
        assert_eq!(verdict(STALL, true), Verdict::Leave);
        assert_eq!(verdict(STALL * 10, true), Verdict::Leave);
    }

    #[test]
    fn a_window_that_has_never_drawn_is_given_longer() {
        // A cold start spends seconds in the graphics context and the shader
        // compiler before there is any frame to stamp. That is slow, not stuck,
        // and it must not be an exit — but a window that never draws at all
        // still is one.
        assert_eq!(verdict(STALL, false), Verdict::Nudge);
        assert_eq!(verdict(FIRST_FRAME - TICK, false), Verdict::Nudge);
        assert_eq!(verdict(FIRST_FRAME, false), Verdict::Leave);
    }

    #[test]
    fn the_nudge_comes_before_the_stall() {
        // Otherwise a window with nothing to draw would be indistinguishable
        // from one that is stuck, and would be left for being idle.
        assert!(NUDGE < STALL);
    }

    #[test]
    fn the_stall_is_short_enough_to_beat_a_shutdown() {
        // The whole point of the number. The app stranded a frame twenty
        // seconds before a shutdown and left at the moment it was asked about;
        // the desktop's patience is a few seconds, so this has to be too.
        assert!(
            STALL <= Duration::from_secs(5),
            "a longer stall is one the desktop can outwait"
        );
    }

    #[test]
    fn a_stamp_that_was_never_beaten_reads_as_the_whole_clock() {
        let stamp = Stamp {
            origin: Instant::now() - Duration::from_secs(3),
            millis: AtomicU64::new(0),
            drew: AtomicBool::new(false),
        };
        assert!(stamp.idle() >= Duration::from_secs(3));
        assert!(!stamp.ever_drew());
    }

    #[test]
    fn a_fresh_stamp_reads_as_no_time_at_all() {
        let stamp = Stamp {
            origin: Instant::now(),
            millis: AtomicU64::new(0),
            drew: AtomicBool::new(false),
        };
        stamp
            .millis
            .store(stamp.origin.elapsed().as_millis() as u64, Ordering::Relaxed);
        stamp.drew.store(true, Ordering::Relaxed);
        assert!(stamp.idle() < TICK);
        assert!(stamp.ever_drew());
    }

    // `FrameWatchdog::start` is deliberately not exercised here, and should not
    // be: it spawns a thread that would end the test process part-way through
    // the run once the clock above ran out.
}
