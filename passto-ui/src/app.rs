use eframe::{App, Frame};
use egui::{Color32, ComboBox, Context, Grid, RichText, TextEdit, Ui};
use log::error;
use passto::{AlgorithmSettings, DigestAlgorithm, encode, HashingAlgorithm, SaltingAlgorithm};

#[derive(Debug, Default, Clone)]
pub struct PasstoApp {
    pub settings: AlgorithmSettings,
    pub salt: String,
    pub password: String,
    pub salt_loaded: bool,
    pub save_failed: bool,
}

impl PasstoApp {
    fn load_salt(&mut self, frame: &mut Frame) {
        if self.salt_loaded {
            return
        }
            
        if let Some(storage) = frame.storage_mut() {
            self.salt = storage.get_string("passphrase").unwrap_or_default();
        } else {
            error!("Storage unavailable");
            self.save_failed = true;
        }
        self.salt_loaded = true;
    }
    
    fn save_salt(&mut self, frame: &mut Frame) {
        if let Some(storage) = frame.storage_mut() {
            storage.set_string("passphrase", self.salt.clone());
        } else {
            error!("Storage unavailable");
            self.save_failed = true
        }
    }

    fn input_grid(&mut self, ui: &mut Ui, frame: &mut Frame) {
        ui.label("Passphrase");
        ui.horizontal(|ui| {
            if self.save_failed {
                let _ = ui.button("Failed");
            } else {
                if ui.button("Save").clicked() {
                    self.save_salt(frame);
                }
            }
            
            ui.add(
                TextEdit::singleline(&mut self.salt)
                    .password(true)
            );
        });
        ui.end_row();

        ui.label("Service");
        ui.text_edit_singleline(&mut self.password);
        ui.end_row();

        ui.label("Digest");
        ComboBox::from_id_source("Digest")
            .selected_text(format!("{:?}", self.settings.digest))
            .show_ui(ui, |ui| {
                ui.style_mut().wrap = Some(false);

                ui.selectable_value(&mut self.settings.digest, DigestAlgorithm::Hex, "HEX");
                ui.selectable_value(&mut self.settings.digest, DigestAlgorithm::Base64, "Base64");
                ui.selectable_value(&mut self.settings.digest, DigestAlgorithm::Base64Url, "Base64Url");
            });
        ui.end_row();

        ui.label("Hashing");
        ComboBox::from_id_source("Hashing")
            .selected_text(format!("{:?}", self.settings.hashing))
            .show_ui(ui, |ui| {
                ui.style_mut().wrap = Some(false);

                ui.selectable_value(&mut self.settings.hashing, HashingAlgorithm::Sha256, "SHA256");
                ui.selectable_value(&mut self.settings.hashing, HashingAlgorithm::Sha512, "SHA512");
            });
        ui.end_row();

        ui.label("Salting");
        ComboBox::from_id_source("Salting")
            .selected_text(format!("{:?}", self.settings.salting))
            .show_ui(ui, |ui| {
                ui.style_mut().wrap = Some(false);

                ui.selectable_value(&mut self.settings.salting, SaltingAlgorithm::Zip, "ZIP");
                ui.selectable_value(&mut self.settings.salting, SaltingAlgorithm::Prepend, "Prepend");
                ui.selectable_value(&mut self.settings.salting, SaltingAlgorithm::Append, "Append");
            });
        ui.end_row();
    }

    fn central_panel(&mut self, ui: &mut Ui, frame: &mut Frame) {
        ui.label(
            RichText::new("Passto")
                .heading()
                .color(Color32::from_rgb(255, 255, 255))
        );

        ui.separator();

        Grid::new("input_grid")
            .striped(true)
            .num_columns(2)
            .min_col_width(290.0)
            .show(ui, |ui| {
                self.input_grid(ui, frame);
            });

        let password = encode(self.salt.as_bytes(), self.password.as_bytes(), &self.settings);

        if self.salt.is_empty() || self.password.is_empty() {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("Please enter a passphrase and service first")
                        .color(Color32::from_rgb(255, 125, 125))
                );
            });
        } else {
            ui.horizontal(|ui| {
                ui.label("Output");
                ui.label(&password);
                
                if !frame.is_web() {
                    if ui.button("Copy").clicked() {
                        ui.output_mut(|ui| {
                            ui.copied_text = password.clone();
                        });
                    }
                }
            });
        }
    }
}

impl App for PasstoApp {
    fn update(&mut self, ctx: &Context, frame: &mut Frame) {
        self.load_salt(frame);
        egui::CentralPanel::default().show(ctx, |ui| self.central_panel(ui, frame));
    }
}
