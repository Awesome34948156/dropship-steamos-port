use std::{
    collections::BTreeSet,
    io::Write,
    process::{Command, Stdio},
    sync::mpsc::{self, Receiver},
    time::{Duration, Instant},
};

use eframe::egui;
use ipnet::IpNet;

use crate::{
    catalogue::{self, Catalogue},
    firewall::{RulePlan, ScopedCgroup},
    service,
    service_config::{self, ServiceConfig},
    settings::{self, Settings},
    steam,
};

/// How often the running-game check is repeated so a newly launched Overwatch
/// is noticed without the user clicking anything.
const STEAM_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// How often to ask systemd about the service, and re-read what it published.
///
/// Slower than the game poll because neither answer changes quickly, and asking
/// systemd means forking `systemctl`.
const SERVICE_POLL_INTERVAL: Duration = Duration::from_secs(5);

pub struct DropshipApp {
    settings: Settings,
    /// The contract written for the privileged watcher. Held so the toggle's
    /// state and the revision survive between writes.
    service: ServiceConfig,
    /// Whether the watcher service is running. When it is, it owns the nft
    /// table and this window must not touch it.
    service_active: bool,
    /// What the service last published, for showing real status.
    service_state: Option<service::PublishedState>,
    catalogue: Option<Catalogue>,
    catalogue_rx: Option<Receiver<Result<Catalogue, String>>>,
    steam: steam::SteamInstall,
    status: String,
    show_rule_preview: bool,
    /// The cgroup the currently loaded rules were scoped to, so a relaunch of
    /// the game — or a restart of Steam, which rebuilds the game's cgroup at an
    /// unchanged path — can be detected and the user told to re-apply.
    ///
    /// Only meaningful in the manual path. Once the service is running it knows
    /// this itself and publishes it.
    last_applied: Option<ScopedCgroup>,
    last_steam_poll: Instant,
    last_service_poll: Instant,
}

impl DropshipApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
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
        let steam = steam::discover(settings.steam_app_id);
        let mut app = Self {
            settings,
            service,
            service_active: service::is_active(),
            service_state: None,
            catalogue: None,
            catalogue_rx: None,
            steam,
            status: "Loading the current server catalogue…".to_owned(),
            show_rule_preview: false,
            last_applied: None,
            last_steam_poll: Instant::now(),
            last_service_poll: Instant::now(),
        };
        app.refresh_catalogue();
        app
    }

    fn refresh_catalogue(&mut self) {
        if self.catalogue_rx.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(catalogue::fetch().map_err(|error| error.to_string()));
        });
        self.catalogue_rx = Some(rx);
        self.status = "Refreshing the server catalogue…".to_owned();
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
                // ticks a box. Skipping this would mean the first rotation
                // after an update never reached the service.
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

    fn poll_steam(&mut self, ctx: &egui::Context) {
        if self.last_steam_poll.elapsed() < STEAM_POLL_INTERVAL {
            ctx.request_repaint_after(STEAM_POLL_INTERVAL - self.last_steam_poll.elapsed());
            return;
        }
        self.steam = steam::discover(self.settings.steam_app_id);
        self.last_steam_poll = Instant::now();
        ctx.request_repaint_after(STEAM_POLL_INTERVAL);
    }

    fn poll_service(&mut self, ctx: &egui::Context) {
        if self.last_service_poll.elapsed() < SERVICE_POLL_INTERVAL {
            return;
        }
        self.service_active = service::is_active();
        self.service_state = if self.service_active {
            service::read_state().ok()
        } else {
            None
        };
        self.last_service_poll = Instant::now();
        ctx.request_repaint_after(SERVICE_POLL_INTERVAL);
    }

    fn save_settings(&mut self) {
        if let Err(error) = settings::save(&self.settings) {
            self.status = format!("Could not save settings: {error}");
        }
    }

    /// The selected networks, which needs the catalogue but not the game.
    ///
    /// Split out from [`Self::plan`] because the service contract is written
    /// whether or not Overwatch is running — that is the whole point of being
    /// able to configure in advance.
    fn resolved_networks(&self) -> Result<Vec<IpNet>, String> {
        let catalogue = self
            .catalogue
            .as_ref()
            .ok_or("The catalogue is not loaded yet")?;
        catalogue::selected_networks(catalogue, &self.settings.blocked_server_tokens)
            .map_err(|error| error.to_string())
    }

    /// A plan for the manual `pkexec` path, which needs a live cgroup.
    fn plan(&self) -> Result<RulePlan, String> {
        let cgroup = self.steam.cgroup.clone().ok_or(
            "Start Overwatch first: blocks are scoped to its process tree, which only exists while it runs.",
        )?;
        Ok(RulePlan::from_networks(self.resolved_networks()?, cgroup))
    }

    /// Rewrites the contract if the selection actually changed.
    ///
    /// Called on the paths that can change the answer — a ticked box, a
    /// refreshed catalogue, a different app id. The comparison keeps the
    /// revision meaningful: it counts real changes, not window opens.
    fn sync_service_config(&mut self) {
        let Ok(networks) = self.resolved_networks() else {
            return;
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

    fn run_helper(&mut self, action: &str, plan: Option<&RulePlan>) {
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

        let result = (|| -> Result<(), String> {
            let mut child = Command::new("pkexec")
                .arg(&helper)
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
        })();

        self.status = match result {
            Ok(()) if action == "apply" => {
                self.last_applied = plan.map(|plan| ScopedCgroup::of(&plan.cgroup));
                "Blocks applied, scoped to Overwatch's process tree.".to_owned()
            }
            Ok(()) => {
                self.last_applied = None;
                "All Dropship SteamOS firewall rules were removed.".to_owned()
            }
            Err(error) => error,
        };
    }
}

impl eframe::App for DropshipApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_catalogue();
        self.poll_steam(ctx);
        self.poll_service(ctx);
        if self.catalogue_rx.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Dropship for SteamOS");
            ui.label("Native Overwatch 2 server selection through nftables.");
            ui.separator();

            ui.horizontal(|ui| {
                if ui.button("Refresh server catalogue").clicked() {
                    self.refresh_catalogue();
                }
                if ui.button("Refresh Steam status").clicked() {
                    self.steam = steam::discover(self.settings.steam_app_id);
                    self.last_steam_poll = Instant::now();
                }
                ui.label(&self.status);
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
                    self.steam = steam::discover(app_id);
                    self.last_steam_poll = Instant::now();
                }
            });
            ui.label(steam::steam_library_hint(&self.steam));

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

            // Only warn while the game is actually running in a different
            // scope. A game that has simply exited is not a stale rule yet.
            // "Different" means the cgroup object, not just its path — a Steam
            // restart rebuilds app-steam@autostart.service at an identical
            // path, and rules bound to the old one then match nothing.
            //
            // Only relevant to the manual path; the running service re-scopes
            // itself without being asked.
            let stale = !self.service_active
                && self.last_applied.as_ref().is_some_and(|applied| {
                    self.steam
                        .cgroup
                        .as_ref()
                        .is_some_and(|live| !applied.still_matches(&ScopedCgroup::of(live)))
                });
            if stale {
                ui.colored_label(
                    egui::Color32::YELLOW,
                    "Overwatch's process tree was replaced, so the existing blocks no longer match it. Click Apply blocks again to re-scope them.",
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
                self.sync_service_config();
            }

            let plan = self.plan();
            match &plan {
                Ok(plan) => {
                    ui.label(format!("Selected ranges: {} IPv4, {} IPv6", plan.ipv4.len(), plan.ipv6.len()));
                }
                Err(reason) => {
                    ui.colored_label(egui::Color32::GRAY, reason.as_str());
                }
            }

            ui.separator();
            if self.service_active {
                self.service_controls(ui);
            } else {
                self.manual_controls(ui, &plan);
            }

            if self.show_rule_preview {
                ui.separator();
                ui.label("Rules that will be sent to the privileged helper:");
                egui::ScrollArea::vertical().max_height(180.0).show(ui, |ui| {
                    let script = plan.map(|plan| plan.nft_script()).unwrap_or_else(|error| error);
                    ui.code(script);
                });
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
            Some(state) => match &state.applied {
                Some(scoped) => {
                    ui.colored_label(
                        egui::Color32::LIGHT_GREEN,
                        "Blocks are installed, scoped to Overwatch's process tree.",
                    );
                    ui.label(format!("Scope: {}", scoped.cgroup.path));
                }
                None => {
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
    fn manual_controls(&mut self, ui: &mut egui::Ui, plan: &Result<RulePlan, String>) {
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
            let can_apply = self.settings.acknowledged_cgroup
                && plan.as_ref().is_ok_and(|plan| !plan.is_empty());
            if ui
                .add_enabled(can_apply, egui::Button::new("Apply blocks"))
                .clicked()
                && let Ok(plan) = plan
            {
                self.run_helper("apply", Some(plan));
            }
            if ui.button("Disable all Dropship blocks").clicked() {
                self.run_helper("disable", None);
            }
        });
    }
}
