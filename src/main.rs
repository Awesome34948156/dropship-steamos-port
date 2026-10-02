use dropship_steamos::app::DropshipApp;

fn main() -> eframe::Result<()> {
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
