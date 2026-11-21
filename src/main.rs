mod app;
mod config;
mod i18n;
mod otp;
mod tray;
mod ui;
mod vault;

use app::AegisApp;

fn main() -> eframe::Result<()> {
    if std::env::args().any(|a| a == "--tray-only") {
        tray::run_tray_only();
        return Ok(());
    }
    // A window is starting: drop any background tray process left from "close to tray".
    tray::stop_background_tray();

    let mut viewport = egui::ViewportBuilder::default()
        .with_title("Aegis Authenticator")
        .with_inner_size([720.0, 620.0])
        .with_min_inner_size([500.0, 420.0]);

    if let Ok(icon) = eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon.png")) {
        viewport = viewport.with_icon(std::sync::Arc::new(icon));
    }

    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "Aegis Authenticator",
        options,
        Box::new(|cc| Ok(Box::new(AegisApp::new(cc)))),
    )
}
