use std::{
    collections::BTreeSet,
    io::Write,
    process::{Command, Stdio},
    sync::mpsc::{self, Receiver},
    time::Duration,
};

use eframe::egui;
use ipnet::IpNet;

use crate::{
    catalogue::{self, Catalogue},
    firewall::{CgroupMatch, RulePlan, ScopedCgroup},
    frames::FrameWatchdog,
    service,
    service_config::{self, ServiceConfig},
    settings::{self, Settings},
    steam,
};

/// How often the running-game check is repeated so a newly launched Overwatch
/// is noticed without the user clicking anything.
///
/// The check itself reads only `/proc`. It runs on a thread anyway, because the
/// rule this window lives by is that its event loop never waits for anything —
/// see [`spawn_game_prober`].
const STEAM_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// How often to ask systemd about the service, and re-read what it published.
///
/// Slower than the game poll because neither answer changes quickly, and asking
/// systemd means forking `systemctl`. Off the UI thread for the same reason, and
/// with more at stake: a D-Bus round-trip is slow whenever systemd is busy, and
/// the busiest it ever gets is while the machine is shutting down.
const SERVICE_POLL_INTERVAL: Duration = Duration::from_secs(5);

pub struct DropshipApp {
    /// Cloned into every worker so it can wake the window when it has something
    /// to say.
    ///
    /// This is what lets the polls move onto threads: the window sleeps between
    /// results rather than ticking on a timer and doing the work itself.
    ctx: egui::Context,
    settings: Settings,
    /// The contract written for the privileged watcher. Held so the toggle's
    /// state and the revision survive between writes.
    service: ServiceConfig,
    /// Whether the watcher service is running. When it is, it owns the nft
    /// table and this window must not touch it.
    ///
    /// `None` until the first answer arrives, so the window does not briefly
    /// claim automatic blocking is not installed on a Deck that has it.
    service_active: Option<bool>,
    /// What the service last published, for showing real status.
    service_state: Option<service::PublishedState>,
    catalogue: Option<Catalogue>,
    catalogue_rx: Option<Receiver<Result<Catalogue, String>>>,
    /// The networks the catalogue currently resolves the selection to.
    ///
    /// Cached rather than recomputed per frame: it is read by the status line,
    /// the stale-rules check and the manual plan, and only changes when the
    /// catalogue arrives or a box is ticked. The `Err` is the message shown
    /// while there is no catalogue — "not loaded yet" is not "nothing
    /// selected", and the two must not look alike.
    resolved: Result<Vec<IpNet>, String>,
    /// Where Steam lives — the filesystem half of [`steam::SteamInstall`].
    ///
    /// Refreshed on demand rather than on a timer: finding it stats the Steam
    /// libraries, including the removable ones under `/run/media`, and a `stat`
    /// against a mount that is being torn down does not come back.
    steam: steam::SteamInstall,
    /// The live half, fed by the game prober.
    game_rx: Receiver<(Option<u32>, Option<CgroupMatch>)>,
    /// The identity of the live cgroup, read once per prober message.
    ///
    /// The stale-rules check runs on every frame, and deriving this there would
    /// `stat` the cgroup sixty times a second. Reading it once per observation
    /// still catches a cgroup recreated at an unchanged path, which is what a
    /// Steam restart does.
    live_scoped: Option<ScopedCgroup>,
    /// A Steam-library scan that was asked for and has not answered yet, with
    /// the app id it was started for.
    ///
    /// The id travels with the receiver so a scan started before an app-id
    /// change cannot write its answer over the new id's, and so a scan for an
    /// old id can be replaced instead of waited on.
    ///
    /// Doubles as the reason the hint reads "looking" rather than "not found":
    /// an empty root means "no answer yet", not "no Steam".
    install_rx: Option<(u32, Receiver<steam::SteamInstall>)>,
    service_rx: Receiver<(Option<bool>, Option<service::PublishedState>)>,
    /// A privileged helper run that was asked for and has not finished.
    ///
    /// Its presence is also what disables the manual buttons: a second `pkexec`
    /// would race the first for the same table.
    helper_rx: Option<Receiver<HelperOutcome>>,
    status: String,
    show_rule_preview: bool,
    /// The rules the manual path currently has installed, with the selection
    /// they were built from, so a relaunch of the game, a restart of Steam —
    /// which rebuilds the game's cgroup at an unchanged path — or a change of
    /// selected regions can be detected and the user told to re-apply.
    ///
    /// Only meaningful in the manual path. Once the service is running it knows
    /// this itself and publishes it.
    last_applied: Option<AppliedManual>,
    /// Leaves the process if this window ever stops being drawn, which is the
    /// one way its event loop can stop answering the desktop. See
    /// [`crate::frames`].
    watchdog: FrameWatchdog,
}

/// What a finished privileged run reports back.
struct HelperOutcome {
    /// `"apply"` or `"disable"`, echoed so the window knows which state to move
    /// to without keeping a second copy of what it asked for.
    action: &'static str,
    /// The rules the helper left installed, read once it had finished.
    applied: Option<AppliedManual>,
    result: Result<(), String>,
}

/// The manual apply that is currently installed: its scope and the selection
/// it was built from.
///
/// The selection matters because the cgroup staying put does not mean the
/// user's choice did. Without it, ticking a new region after Apply would leave
/// the old rules in place with no hint that they are stale.
#[derive(Clone, Debug)]
struct AppliedManual {
    scope: ScopedCgroup,
    networks: BTreeSet<IpNet>,
}

impl DropshipApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let settings = settings::load().unwrap_or_else(|error| {
            eprintln!("Could not load settings: {error:#}");
            Settings::default()
        });
        // A missing or unreadable contract is not an error: it just means
        // nothing has been configured for the service yet.
        let service = service_config::load().unwrap_or_else(|error| {
            eprintln!("Starting from an empty service config: {error:#}");
            ServiceConfig::new(false, 0, Vec::new())
        });

        let ctx = cc.egui_ctx.clone();
        let mut app = Self {
            game_rx: spawn_game_prober(ctx.clone()),
            service_rx: spawn_service_prober(ctx.clone()),
            ctx,
            settings,
            service,
            service_active: None,
            service_state: None,
            catalogue: None,
            catalogue_rx: None,
            resolved: Err("The catalogue is not loaded yet".to_owned()),
            steam: steam::SteamInstall::default(),
            live_scoped: None,
            install_rx: None,
            helper_rx: None,
            status: "Loading the current server catalogue…".to_owned(),
            show_rule_preview: false,
            last_applied: None,
            watchdog: FrameWatchdog::start(cc.egui_ctx.clone()),
        };
        // Neither of these is awaited. The window paints straight away and the
        // answers fill in as they land, which is the whole point of the threads.
        app.refresh_catalogue();
        app.refresh_install();
        app
    }

    fn refresh_catalogue(&mut self) {
        if self.catalogue_rx.is_some() {
            return;
        }
        let rx = spawn_oneshot(self.ctx.clone(), move || {
            catalogue::fetch().map_err(|error| error.to_string())
        });
        self.catalogue_rx = Some(rx);
        self.status = "Refreshing the server catalogue…".to_owned();
    }

    /// Starts a scan for where Steam lives unless one for this app id is
    /// already running.
    ///
    /// A scan left over from a previous app id is replaced rather than waited
    /// on: its answer would describe a different app, and the window would
    /// report the wrong "installed" hint. Dropping the old receiver makes its
    /// thread's send fail, which is how that thread learns to exit.
    fn refresh_install(&mut self) {
        let app_id = self.settings.steam_app_id;
        if let Some((running, _)) = &self.install_rx
            && *running == app_id
        {
            return;
        }
        let rx = spawn_oneshot(self.ctx.clone(), move || steam::discover(app_id));
        self.install_rx = Some((app_id, rx));
    }

    fn poll_catalogue(&mut self) {
        let Some(rx) = &self.catalogue_rx else {
            return;
        };
        match rx.try_recv() {
            Ok(Ok(catalogue)) => {
                self.catalogue = Some(catalogue);
                self.status = "Server catalogue is current. Select regions to block.".to_owned();
                self.catalogue_rx = None;
                // A rotated catalogue can change what a token resolves to, so
                // the contract is rewritten here and not only when the user
                // ticks a box. The cache is refreshed first because the
                // contract must be built from the new answer.
                self.refresh_resolved();
                self.sync_service_config();
            }
            Ok(Err(error)) => {
                // Deliberately no write. A failed fetch leaves the last good
                // contract in place rather than blanking it, which would stop
                // blocking silently.
                self.status = format!("Could not refresh catalogue: {error}");
                self.catalogue_rx = None;
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                self.status = "Catalogue request stopped unexpectedly.".to_owned();
                self.catalogue_rx = None;
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
    }

    /// Applies whatever the game prober has sent since the last frame.
    ///
    /// Drained rather than taken once, so a frame that was slow to come round
    /// shows the newest answer instead of working through a backlog.
    fn poll_game(&mut self) {
        while let Ok((game_pid, cgroup)) = self.game_rx.try_recv() {
            // Read the cgroup's identity once per observation, here, rather
            // than in the per-frame stale check: this is a `stat`, and the
            // prober speaks every couple of seconds while the window paints
            // far more often. Doing it on each message is also what notices a
            // cgroup recreated at an unchanged path — the inode is the signal,
            // and the path comparison alone cannot see the change.
            self.live_scoped = cgroup.as_ref().map(ScopedCgroup::of);
            self.steam.game_pid = game_pid;
            self.steam.cgroup = cgroup;
        }
    }

    fn poll_install(&mut self) {
        let Some((app_id, rx)) = self.install_rx.take() else {
            return;
        };
        match rx.try_recv() {
            Ok(install) => {
                if app_id == self.settings.steam_app_id {
                    // Only the filesystem half is taken. The live half belongs
                    // to the prober, which refreshes it every couple of seconds
                    // and is therefore always at least as fresh as this scan.
                    self.steam.root = install.root;
                    self.steam.proton_prefix = install.proton_prefix;
                    self.steam.installed = install.installed;
                } else {
                    // The app id changed while this scan was in flight, so its
                    // answer is about another app. Drop it and look again.
                    self.refresh_install();
                }
            }
            Err(mpsc::TryRecvError::Empty) => self.install_rx = Some((app_id, rx)),
            Err(mpsc::TryRecvError::Disconnected) => {
                self.status = "Could not look for Steam.".to_owned();
            }
        }
    }

    fn poll_service(&mut self) {
        while let Ok((active, state)) = self.service_rx.try_recv() {
            // Only a settled answer is evidence. `activating`, `deactivating`,
            // `reloading` and a failed D-Bus round-trip all arrive as `None`,
            // and treating any of them as "not running" would hand the window
            // the manual path mid-restart — whose unlocked Disable can delete
            // the table the restarted watcher is about to re-create.
            if let Some(active) = active {
                self.service_active = Some(active);
                self.service_state = state;
            }
        }
    }

    /// Picks up a finished privileged run.
    fn poll_helper(&mut self) {
        let Some(rx) = self.helper_rx.take() else {
            return;
        };
        match rx.try_recv() {
            Ok(outcome) => {
                self.status = match outcome.result {
                    Ok(()) if outcome.action == "apply" => {
                        self.last_applied = outcome.applied;
                        "Blocks applied, scoped to Overwatch's process tree.".to_owned()
                    }
                    Ok(()) => {
                        self.last_applied = None;
                        "All Dropship SteamOS firewall rules were removed.".to_owned()
                    }
                    Err(error) => error,
                };
            }
            Err(mpsc::TryRecvError::Empty) => self.helper_rx = Some(rx),
            Err(mpsc::TryRecvError::Disconnected) => {
                self.status = "The privileged helper stopped unexpectedly.".to_owned();
            }
        }
    }

    /// The line under the toolbar buttons: what is happening right now.
    ///
    /// The administrator wait is derived rather than stored, so a catalogue or
    /// poll completion that lands while `pkexec` is up cannot overwrite it.
    /// That message is the only warning that the window is about to stop
    /// taking input behind a password prompt; losing it reads as a hang.
    fn status_text(&self) -> &str {
        if self.helper_rx.is_some() {
            "Waiting for administrator authorization…"
        } else {
            &self.status
        }
    }

    fn save_settings(&mut self) {
        if let Err(error) = settings::save(&self.settings) {
            self.status = format!("Could not save settings: {error}");
        }
    }

    /// Recomputes the cached selection from the catalogue and the ticked
    /// tokens.
    ///
    /// Called on the two paths that can change the answer — the catalogue
    /// landing, and a box being ticked — rather than from the frame loop, which
    /// would re-walk the whole catalogue sixty times a second.
    fn refresh_resolved(&mut self) {
        self.resolved = match &self.catalogue {
            Some(catalogue) => Ok(catalogue::selected_networks(
                catalogue,
                &self.settings.blocked_server_tokens,
            )),
            None => Err("The catalogue is not loaded yet".to_owned()),
        };
    }

    /// The cached selection: needs the catalogue but not the game.
    ///
    /// Split out from [`Self::plan`] because the service contract is written
    /// whether or not Overwatch is running — that is the whole point of being
    /// able to configure in advance.
    fn resolved_networks(&self) -> Result<&[IpNet], &str> {
        self.resolved.as_deref().map_err(|error| error.as_str())
    }

    /// A plan for the manual `pkexec` path, which needs a live cgroup.
    ///
    /// Only the manual path builds one. Once the service is running it owns
    /// the rules, and a plan built here would put "Start Overwatch first…" on
    /// screen over a deck that is blocking fine.
    fn plan(&self) -> Result<RulePlan, String> {
        let cgroup = self.steam.cgroup.clone().ok_or(
            "Start Overwatch first: blocks are scoped to its process tree, which only exists while it runs.",
        )?;
        Ok(RulePlan::from_networks(
            self.resolved_networks()?.to_vec(),
            cgroup,
        ))
    }

    /// Rewrites the contract if the selection actually changed.
    ///
    /// Called on the paths that can change the answer — a ticked box, a
    /// refreshed catalogue, a different app id. The comparison keeps the
    /// revision meaningful: it counts real changes, not window opens.
    fn sync_service_config(&mut self) {
        let networks = match self.resolved_networks() {
            Ok(networks) => networks.to_vec(),
            Err(error) => {
                // Before the catalogue arrives there is no decision to report.
                // Once it has, a failure means the selection never reached the
                // service, which the user must not mistake for "saved".
                if self.catalogue.is_some() {
                    self.status = format!("Could not prepare the blocking settings: {error}");
                }
                return;
            }
        };
        let current: BTreeSet<IpNet> = self.service.networks().into_iter().collect();
        let next: BTreeSet<IpNet> = networks.iter().copied().collect();
        if current == next {
            return;
        }
        self.save_service(networks);
    }

    /// Writes the contract unconditionally, bumping the revision.
    ///
    /// Callers that only mean to change the enabled flag pass the networks back
    /// in unchanged. That matters because resolving the selection needs the
    /// catalogue: toggling before it has loaded must not write an empty set and
    /// throw away a selection the user already made.
    fn save_service(&mut self, networks: Vec<IpNet>) {
        self.service.revision = self.service.revision.saturating_add(1);
        self.service = ServiceConfig::new(self.service.enabled, self.service.revision, networks);
        if let Err(error) = service_config::save(&self.service) {
            self.status = format!("Could not save the blocking settings: {error}");
        }
    }

    /// Asks the privileged helper to change the rules, and returns at once.
    ///
    /// The exchange runs on a thread because both of its waits are unbounded:
    /// `pkexec` will not read its input until the polkit agent has collected a
    /// password, and will not exit until the helper is done. Doing that inline
    /// is what used to freeze the window behind the password prompt — and, for a
    /// plan large enough to fill the pipe buffer, deadlock before `wait` was
    /// even reached.
    fn run_helper(&mut self, action: &'static str, plan: Option<&RulePlan>) {
        if self.helper_rx.is_some() {
            return;
        }
        let helper = std::env::var("DROPSHIP_STEAMOS_HELPER")
            .unwrap_or_else(|_| "dropship-steamos-helper".to_owned());
        let payload = match plan {
            Some(plan) => match serde_json::to_vec(plan) {
                Ok(payload) => Some(payload),
                Err(error) => {
                    self.status = format!("Could not prepare firewall rules: {error}");
                    return;
                }
            },
            None => None,
        };
        let applied_plan = plan.filter(|_| action == "apply").map(|plan| {
            (
                plan.cgroup.clone(),
                plan.ipv4.iter().chain(&plan.ipv6).copied().collect(),
            )
        });

        let rx = spawn_oneshot(self.ctx.clone(), move || {
            let result = run_privileged_helper(&helper, action, payload);
            // Read the scope *after* the rules are up, so what gets recorded is
            // the cgroup object nft has just bound them to. This side has to
            // read it for itself: `pkexec` returns only the helper's exit
            // status, not the identity the helper's own apply recorded.
            let applied = match &result {
                Ok(()) => applied_plan.map(|(cgroup, networks)| AppliedManual {
                    scope: ScopedCgroup::of(&cgroup),
                    networks,
                }),
                Err(_) => None,
            };
            HelperOutcome {
                action,
                applied,
                result,
            }
        });
        self.helper_rx = Some(rx);
        // The wait message is derived by [`Self::status_text`] from
        // `helper_rx`, so it cannot be overwritten by a poll landing mid-run.
    }
}

impl eframe::App for DropshipApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.watchdog.frame_started();
        // Every one of these collects what a thread has already finished. None
        // of them waits for anything, which is what keeps this window answering
        // the compositor even mid-shutdown.
        self.poll_catalogue();
        self.poll_game();
        self.poll_install();
        self.poll_service();
        self.poll_helper();

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("Dropship for SteamOS");
                // Right-aligned on the heading's own row. It is here so that
                // which build is running is answerable at a glance — this is a
                // device that gets its binaries from an artifact rather than
                // from a build you just made, and "did the install take?" is
                // otherwise a question with no answer in the window.
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        egui::RichText::new(concat!("v", env!("CARGO_PKG_VERSION"))).weak(),
                    );
                });
            });
            ui.label("Native Overwatch 2 server selection through nftables.");
            ui.separator();

            ui.horizontal(|ui| {
                if ui.button("Refresh server catalogue").clicked() {
                    self.refresh_catalogue();
                }
                if ui.button("Refresh Steam status").clicked() {
                    self.refresh_install();
                }
                ui.label(self.status_text());
            });

            ui.separator();
            ui.heading("Steam / Proton");
            let mut app_id = self.settings.steam_app_id;
            ui.horizontal(|ui| {
                ui.label("Steam App ID:");
                if ui
                    .add(egui::DragValue::new(&mut app_id).range(1..=u32::MAX))
                    .changed()
                {
                    self.settings.steam_app_id = app_id;
                    self.save_settings();
                    self.refresh_install();
                }
            });
            // An empty root means no answer yet, not no Steam — the scan is
            // what fills it in, and saying "not found" before it lands would be
            // a claim the window cannot support.
            if self.install_rx.is_some() {
                ui.label("Looking for Steam…");
            } else {
                ui.label(steam::steam_library_hint(&self.steam));
            }

            match (&self.steam.cgroup, self.steam.game_running()) {
                (Some(cgroup), _) => {
                    ui.colored_label(
                        egui::Color32::LIGHT_GREEN,
                        "Overwatch is running. Blocks will be scoped to its process tree.",
                    );
                    ui.label(format!("Process tree: {}", cgroup.path));
                }
                (None, true) => {
                    ui.colored_label(
                        egui::Color32::YELLOW,
                        "Overwatch is running, but its cgroup could not be read, so Apply stays disabled.",
                    );
                }
                (None, false) => {
                    ui.colored_label(
                        egui::Color32::YELLOW,
                        "Overwatch is not running. Dropship only scopes blocks to Overwatch's process tree and never blocks the whole device.",
                    );
                }
            }

            // Only warn while the manual path owns the rules. The running
            // service re-scopes and re-applies itself without being asked.
            //
            // Two kinds of staleness:
            // - the cgroup object changed, which a Steam restart does at an
            //   unchanged path, so the rules match nothing;
            // - the selection changed, so the rules still match but block the
            //   wrong regions.
            let manual = self.service_active != Some(true);
            let scope_replaced = manual
                && self.last_applied.as_ref().is_some_and(|applied| {
                    self.live_scoped
                        .as_ref()
                        .is_some_and(|live| !applied.scope.still_matches(live))
                });
            let selection_changed = manual
                && self.last_applied.as_ref().is_some_and(|applied| {
                    self.resolved_networks().ok().is_some_and(|networks| {
                        applied.networks != networks.iter().copied().collect()
                    })
                });
            if scope_replaced {
                ui.colored_label(
                    egui::Color32::YELLOW,
                    "Overwatch's process tree was replaced, so the existing blocks no longer match it. Click Apply blocks again to re-scope them.",
                );
            } else if selection_changed {
                ui.colored_label(
                    egui::Color32::YELLOW,
                    "The region selection changed since blocks were applied. Click Apply blocks again to update them.",
                );
            }

            ui.separator();
            ui.heading("Block regions");
            let mut selection_changed = false;
            if let Some(catalogue) = &self.catalogue {
                egui::ScrollArea::vertical().max_height(250.0).show(ui, |ui| {
                    for server in &catalogue.servers.overwatch {
                        let mut selected = self.settings.blocked_server_tokens.contains(&server.token);
                        if ui.checkbox(&mut selected, format!("{} ({})", server.title, server.token)).changed() {
                            selection_changed = true;
                            if selected {
                                self.settings.blocked_server_tokens.insert(server.token.clone());
                            } else {
                                self.settings.blocked_server_tokens.remove(&server.token);
                            }
                        }
                    }
                });
            } else {
                ui.spinner();
            }
            if selection_changed {
                self.save_settings();
                // The cache is an input to the contract, so it is refreshed
                // before the contract is rewritten.
                self.refresh_resolved();
                self.sync_service_config();
            }

            // The counts come from the cached selection, so they are right
            // whether or not Overwatch is running; only the plan itself needs
            // a live cgroup.
            match self.resolved_networks() {
                Ok(networks) => {
                    let ipv4 = networks
                        .iter()
                        .filter(|network| network.addr().is_ipv4())
                        .count();
                    ui.label(format!(
                        "Selected ranges: {ipv4} IPv4, {} IPv6",
                        networks.len() - ipv4
                    ));
                }
                Err(reason) => {
                    ui.colored_label(egui::Color32::GRAY, reason);
                }
            }

            ui.separator();
            match self.service_active {
                Some(true) => self.service_controls(ui),
                Some(false) => self.manual_controls(ui),
                None => {
                    // Showing the manual controls here would tell the user
                    // automatic blocking is not installed, which is a guess
                    // until systemd has answered.
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Checking whether automatic blocking is installed…");
                    });
                }
            }
        });
    }
}

impl DropshipApp {
    /// The UI when the watcher service owns the table.
    ///
    /// One control only. A manual apply button here would race the service for
    /// the same table and flap, so the toggle is the whole interface — its off
    /// position removes the rules, which is what disabling means now.
    fn service_controls(&mut self, ui: &mut egui::Ui) {
        ui.heading("Automatic blocking");
        let mut enabled = self.service.enabled;
        if ui
            .checkbox(&mut enabled, "Block while Overwatch runs")
            .changed()
        {
            self.service.enabled = enabled;
            // The selection is deliberately carried across unchanged: this
            // control changes *whether* to block, not *what*.
            self.save_service(self.service.networks());
            self.status = if enabled {
                "Blocking is armed. Rules will be applied when Overwatch starts.".to_owned()
            } else {
                "Blocking is off. Removing any installed rules shortly.".to_owned()
            };
        }

        match &self.service_state {
            Some(state) => match (&state.applied, state.table_present) {
                (Some(scoped), _) => {
                    ui.colored_label(
                        egui::Color32::LIGHT_GREEN,
                        "Blocks are installed, scoped to Overwatch's process tree.",
                    );
                    ui.label(format!("Scope: {}", scoped.cgroup.path));
                }
                (None, true) => {
                    ui.colored_label(
                        egui::Color32::YELLOW,
                        "A Dropship firewall table is installed, but the service has not identified its scope. It will be removed shortly.",
                    );
                }
                (None, false) => {
                    ui.colored_label(
                        egui::Color32::GRAY,
                        "No blocks installed right now. Start Overwatch and they will be applied.",
                    );
                }
            },
            None => {
                ui.colored_label(
                    egui::Color32::YELLOW,
                    "The service is running but has not published its state yet.",
                );
            }
        }

        if !enabled {
            ui.colored_label(
                egui::Color32::GRAY,
                "Turning this off removes the rules. Nothing is blocked while it is off.",
            );
        }
    }

    /// The UI when there is no service, which is the original manual flow.
    fn manual_controls(&mut self, ui: &mut egui::Ui) {
        // Only this path builds a plan. With the service running, the rules
        // are the service's to manage, and "Start Overwatch first…" over a
        // deck that is blocking fine would be a lie.
        let plan = self.plan();
        // The range counts above already report a missing catalogue, so only a
        // plan that failed for a different reason is shown here.
        if let Err(reason) = &plan
            && self.resolved.is_ok()
        {
            ui.colored_label(egui::Color32::GRAY, reason.as_str());
        }

        ui.colored_label(
            egui::Color32::GRAY,
            "Automatic blocking is not installed, so blocks are applied by hand and last until you remove them.",
        );
        ui.label(
            "To have them applied automatically while you play, run the installer once: \
             sudo packaging/install.sh",
        );

        if ui.checkbox(
            &mut self.settings.acknowledged_cgroup,
            "I understand: blocks are scoped to Overwatch's process tree, not applied to the whole device.",
        ).changed() {
            self.save_settings();
        }

        ui.horizontal(|ui| {
            if ui.button("Preview nftables rules").clicked() {
                self.show_rule_preview = !self.show_rule_preview;
            }
            // Disabled while one is in flight: the second would race the first
            // for the same table, and the user has a password prompt to answer.
            let busy = self.helper_rx.is_some();
            let can_apply = self.settings.acknowledged_cgroup
                && plan.as_ref().is_ok_and(|plan| !plan.is_empty());
            if ui
                .add_enabled(can_apply && !busy, egui::Button::new("Apply blocks"))
                .clicked()
                && let Ok(plan) = &plan
            {
                self.run_helper("apply", Some(plan));
            }
            if ui
                .add_enabled(!busy, egui::Button::new("Disable all Dropship blocks"))
                .clicked()
            {
                self.run_helper("disable", None);
            }
        });

        // The script is built only while the preview is open, and only on this
        // path: it is a projection of the plan, not state the window keeps.
        if self.show_rule_preview {
            ui.separator();
            ui.label("Rules that will be sent to the privileged helper:");
            egui::ScrollArea::vertical()
                .max_height(180.0)
                .show(ui, |ui| match &plan {
                    Ok(plan) => ui.code(plan.nft_script()),
                    Err(error) => ui.code(error.as_str()),
                });
        }
    }
}

/// Runs `work` on a thread of its own, waking the window when it is done.
///
/// The receiver is the thread's lifetime: dropping it makes the send fail,
/// which is how the thread learns to exit.
fn spawn_oneshot<T: Send + 'static>(
    ctx: egui::Context,
    work: impl FnOnce() -> T + Send + 'static,
) -> Receiver<T> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(work());
        ctx.request_repaint();
    });
    rx
}

/// Runs `work` every `interval`, sending each result and waking the window.
fn spawn_periodic<T: Send + 'static>(
    ctx: egui::Context,
    interval: Duration,
    mut work: impl FnMut() -> T + Send + 'static,
) -> Receiver<T> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        loop {
            if tx.send(work()).is_err() {
                return;
            }
            ctx.request_repaint();
            std::thread::sleep(interval);
        }
    });
    rx
}

/// Watches for the game on a thread of its own.
///
/// It reads nothing but `/proc`, so it cannot block; the thread is there because
/// *any* work on the UI thread is work the event loop cannot do, and an event
/// loop that stops servicing events is what the desktop reports as "not
/// responding".
///
/// Exits when the window drops the receiver, so it never outlives the app.
fn spawn_game_prober(ctx: egui::Context) -> Receiver<(Option<u32>, Option<CgroupMatch>)> {
    spawn_periodic(ctx, STEAM_POLL_INTERVAL, steam::game_state)
}

/// Asks systemd about the watcher service on a thread of its own.
///
/// `systemctl` is a D-Bus round-trip, which takes as long as systemd takes to
/// answer — and the longest it ever takes is while the machine is shutting down,
/// which is precisely when the window must not be waiting on it.
///
/// The first half of each message is tri-state: `None` means systemd did not
/// settle on an answer, not that the service stopped. The published state is
/// read only when the service is known to be running, so a stale `state.json`
/// from before a restart can never be sent alongside "cannot tell".
fn spawn_service_prober(
    ctx: egui::Context,
) -> Receiver<(Option<bool>, Option<service::PublishedState>)> {
    spawn_periodic(ctx, SERVICE_POLL_INTERVAL, || {
        let active = service::is_active();
        let state = match active {
            Some(true) => service::read_state().ok(),
            _ => None,
        };
        (active, state)
    })
}

/// Runs the privileged helper through `pkexec`, on a thread the caller owns.
///
/// Both waits here can last as long as the user takes to answer a password
/// prompt, which is why this must never be called from the UI thread.
fn run_privileged_helper(
    helper: &str,
    action: &str,
    payload: Option<Vec<u8>>,
) -> Result<(), String> {
    let mut child = Command::new("pkexec")
        .arg(helper)
        .arg(action)
        .stdin(Stdio::piped())
        .spawn()
        .map_err(|error| format!("Could not request administrator access: {error}"))?;
    if let Some(payload) = payload {
        child
            .stdin
            .take()
            .ok_or("Could not open helper input")?
            .write_all(&payload)
            .map_err(|error| format!("Could not send firewall rules: {error}"))?;
    }
    if child.wait().map_err(|error| error.to_string())?.success() {
        Ok(())
    } else {
        Err("The privileged helper did not complete successfully.".to_owned())
    }
}
