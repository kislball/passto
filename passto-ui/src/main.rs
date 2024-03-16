use crate::app::PasstoApp;
mod app;

#[cfg(not(target_arch = "wasm32"))]
fn main() -> eframe::Result<()> {
    env_logger::init();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_resizable(false)
            .with_min_inner_size([600.0, 250.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Passto",
        native_options,
        Box::new(|_| Box::<PasstoApp>::default()),
    )
}

#[cfg(target_arch = "wasm32")]
fn main() {
    // Redirect `log` message to `console.log` and friends:
    eframe::WebLogger::init(log::LevelFilter::Debug).ok();

    let web_options = eframe::WebOptions::default();

    wasm_bindgen_futures::spawn_local(async {
        eframe::WebRunner::new()
            .start(
                "the_canvas_id", // hardcode it
                web_options,
                Box::new(|_| Box::new(PasstoApp::default())),
            )
            .await
            .expect("failed to start eframe");
    });
}
