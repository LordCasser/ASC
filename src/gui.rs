use eframe::egui;

pub fn launch_gui(apk_path: std::path::PathBuf) -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1024.0, 768.0])
            .with_title("Droid ASC"),
        ..Default::default()
    };

    eframe::run_native(
        "Droid ASC",
        options,
        Box::new(|_cc| Box::new(AscApp::new(apk_path))),
    )
}

struct AscApp {
    apk_path: std::path::PathBuf,
    search_query: String,
}

impl AscApp {
    fn new(apk_path: std::path::PathBuf) -> Self {
        Self {
            apk_path,
            search_query: String::new(),
        }
    }
}

impl eframe::App for AscApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Search:");
                ui.text_edit_singleline(&mut self.search_query);
                if ui.button("Find").clicked() {
                    // Trigger search
                }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Droid ASC - Rust Rewrite");
            ui.label(format!("Loaded APK: {:?}", self.apk_path));
        });
    }
}
