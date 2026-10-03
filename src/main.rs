use dropship_steamos::app::DropshipApp;

/// Leave at once when the session asks us to.
///
/// Closing the window is the polite path, and the event loop handles it. But a
/// session ending is not always polite: logind tears one down with `SIGTERM`. A
/// process that happens to be inside a slow syscall at that moment would sit
/// there until the desktop gives up and offers to force-kill it — which is the
/// "Not Responding" dialog on shutdown.
///
/// `_exit` rather than `exit`, because a signal handler may not run atexit
/// handlers or allocator code: `_exit` is async-signal-safe and `exit` is not.
#[cfg(unix)]
fn exit_when_the_session_ends() {
    unsafe {
        // Via a pointer, because an item-to-integer cast is not what a function
        // pointer is: `sighandler_t` is an address the kernel will call.
        let handler = handler as *const () as libc::sighandler_t;
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
    }
}

#[cfg(unix)]
extern "C" fn handler(_signal: libc::c_int) {
    // No cleanup that could block: the whole point is to be gone immediately.
    unsafe { libc::_exit(0) }
}

#[cfg(not(unix))]
fn exit_when_the_session_ends() {}

fn main() -> eframe::Result<()> {
    exit_when_the_session_ends();

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default().with_inner_size([760.0, 680.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Dropship for SteamOS",
        options,
        Box::new(|cc| Ok(Box::new(DropshipApp::new(cc)))),
    )
}
