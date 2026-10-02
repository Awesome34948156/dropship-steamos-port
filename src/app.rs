use std::{
    io::Write,
    process::{Command, Stdio},
    sync::mpsc::{self, Receiver},
    time::{Duration, Instant},
};

use eframe::egui;

use crate::{
    catalogue::{self, Catalogue},
    firewall::{self, RulePlan},
    settings::{self, Settings},
    steam,
};

/// How often the running-game check is repeated so a newly launched Overwatch
/// is noticed without the user clicking anything.
const STEAM_POLL_INTERVAL: Duration = Duration::from_secs(2);

pub struct DropshipApp {
    settings: Settings,
    catalogue: Option<Catalogue>,
    catalogue_rx: Option<Receiver<Result<Catalogue, String>>>,
    steam: steam::SteamInstall,
    status: String,
    show_rule_preview: bool,
    /// The cgroup the currently loaded rules were scoped to, so a relaunch of
    /// the game can be detected and the user told to re-apply.
    last_applied: Option<firewall::CgroupMatch>,
    last_steam_poll: Instant,
}

impl DropshipApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let settings = settings::load().unwrap_or_else(|error| {
            eprintln!("Could not load settings: {error:#}");
            Settings::default()
        });
        let steam = steam::discover(settings.steam_app_id);
        let mut app = Self {
            settings,
            catalogue: None,
            catalogue_rx: None,
            steam,
            status: "Loading the current server catalogue…".to_owned(),
            show_rule_preview: false,
            last_applied: None,
            last_steam_poll: Instant::now(),
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
            }
            Ok(Err(error)) => {
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

    fn save_settings(&mut self) {
        if let Err(error) = settings::save(&self.settings) {
            self.status = format!("Could not save settings: {error}");
        }
    }

    fn plan(&self) -> Result<RulePlan, String> {
        let catalogue = self
            .catalogue
            .as_ref()
            .ok_or("The catalogue is not loaded yet")?;
        let cgroup = self.steam.cgroup.clone().ok_or(
            "Start Overwatch first: blocks are scoped to its process tree, which only exists while it runs.",
        )?;
        let networks =
            catalogue::selected_networks(catalogue, &self.settings.blocked_server_tokens)
                .map_err(|error| error.to_string())?;
        Ok(RulePlan::from_networks(networks, cgroup))
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
                self.last_applied = plan.map(|plan| plan.cgroup.clone());
                "Blocks applied to Overwatch only. Other applications are unaffected.".to_owned()
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
                        "Start Overwatch to enable Apply. Dropship only scopes blocks to Overwatch's process tree and never blocks the whole device.",
                    );
                }
            }

            // Only warn while the game is actually running in a *different*
            // cgroup. A game that has simply exited is not a stale rule yet.
            let stale = self
                .last_applied
                .as_ref()
                .is_some_and(|applied| self.steam.cgroup.as_ref().is_some_and(|live| live != applied));
            if stale {
                ui.colored_label(
                    egui::Color32::YELLOW,
                    "Overwatch restarted — the existing blocks no longer match. Click Apply blocks again to re-scope them.",
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
            if selection_changed { self.save_settings(); }

            let plan = self.plan();
            match &plan {
                Ok(plan) => {
                    ui.label(format!("Selected ranges: {} IPv4, {} IPv6", plan.ipv4.len(), plan.ipv6.len()));
                }
                Err(reason) => {
                    ui.colored_label(egui::Color32::GRAY, reason.as_str());
                }
            }
            if ui.checkbox(
                &mut self.settings.acknowledged_cgroup,
                "I understand: blocks apply only to Overwatch's process tree, and other applications are not affected.",
            ).changed() {
                self.save_settings();
            }

            ui.horizontal(|ui| {
                if ui.button("Preview nftables rules").clicked() {
                    self.show_rule_preview = !self.show_rule_preview;
                }
                let can_apply = self.settings.acknowledged_cgroup
                    && plan.as_ref().is_ok_and(|plan| !plan.is_empty());
                if ui.add_enabled(can_apply, egui::Button::new("Apply blocks")).clicked()
                    && let Ok(plan) = &plan
                {
                    self.run_helper("apply", Some(plan));
                }
                if ui.button("Disable all Dropship blocks").clicked() {
                    self.run_helper("disable", None);
                }
            });

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
