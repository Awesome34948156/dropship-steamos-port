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
/// one every two seconds even when nothing has changed. Twenty seconds is three
/// orders of magnitude past anything honest, and still short enough that the
/// process is gone long before a session that is shutting down would give up on
/// the window and ask the user about it.
const STALL: Duration = Duration::from_secs(20);

/// How long an idle window is left alone before a frame is asked for.
///
/// This is what makes [`STALL`] mean something: without it, a window with
/// nothing to draw would look exactly like a stuck one, and the watchdog would
/// have to guess. In practice the polls already ask for a frame every two or
/// five seconds, so this only fires once whatever was poking the window has
/// stopped.
const NUDGE: Duration = Duration::from_secs(5);

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

fn verdict(idle: Duration) -> Verdict {
    if idle >= STALL {
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
}

impl Stamp {
    /// How long ago the last frame started.
    fn idle(&self) -> Duration {
        let stamp = Duration::from_millis(self.millis.load(Ordering::Relaxed));
        self.origin.elapsed().saturating_sub(stamp)
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
        });
        let stopped = Arc::new(AtomicBool::new(false));
        let (watched, watching) = (Arc::clone(&stamp), Arc::clone(&stopped));
        thread::spawn(move || {
            while !watching.load(Ordering::Relaxed) {
                thread::sleep(TICK);
                match verdict(watched.idle()) {
                    Verdict::Busy => {}
                    Verdict::Nudge => ctx.request_repaint(),
                    Verdict::Leave => {
                        eprintln!(
                            "The window has not been drawn for {}s, which means the display \
                             has stopped answering it; leaving rather than hanging.",
                            STALL.as_secs()
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
        assert_eq!(verdict(Duration::ZERO), Verdict::Busy);
        assert_eq!(verdict(Duration::from_millis(120)), Verdict::Busy);
    }

    #[test]
    fn an_idle_window_is_only_asked_for_a_frame() {
        assert_eq!(verdict(NUDGE), Verdict::Nudge);
        assert_eq!(verdict(STALL - TICK), Verdict::Nudge);
    }

    #[test]
    fn a_window_that_stopped_drawing_is_left() {
        assert_eq!(verdict(STALL), Verdict::Leave);
        assert_eq!(verdict(STALL * 10), Verdict::Leave);
    }

    #[test]
    fn the_nudge_comes_before_the_stall() {
        // Otherwise a window with nothing to draw would be indistinguishable
        // from one that is stuck, and would be left for being idle.
        assert!(NUDGE < STALL);
    }

    #[test]
    fn a_stamp_that_was_never_beaten_reads_as_the_whole_clock() {
        let stamp = Stamp {
            origin: Instant::now() - Duration::from_secs(3),
            millis: AtomicU64::new(0),
        };
        assert!(stamp.idle() >= Duration::from_secs(3));
    }

    #[test]
    fn a_fresh_stamp_reads_as_no_time_at_all() {
        let stamp = Stamp {
            origin: Instant::now(),
            millis: AtomicU64::new(0),
        };
        stamp
            .millis
            .store(stamp.origin.elapsed().as_millis() as u64, Ordering::Relaxed);
        assert!(stamp.idle() < TICK);
    }

    // `FrameWatchdog::start` is deliberately not exercised here, and should not
    // be: it spawns a thread that would end the test process part-way through
    // the run once the clock above ran out.
}
