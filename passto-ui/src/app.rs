use std::time;
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
    pub zip_raw: String,
    pub max_length_raw: String,
    pub custom_alphabet: String,
    pub hashing_iterations: String,
    pub salting_iterations: String,
}

impl PasstoApp {
    fn load_salt(&mut self, frame: &mut Frame) {
        if self.salt_loaded {
            return
        }
        self.zip_raw = "1".into();

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
            self.save_failed = true;
        }
    }

    fn input_grid(&mut self, ui: &mut Ui, frame: &mut Frame) {
        self.passphrase_row(ui, frame);
        self.service_row(ui);
        self.digest_row(ui);
        self.alphabet_row(ui);
        self.hashing_row(ui);
        self.salting_row(ui);
        self.zip_row(ui);
        self.length_row(ui);
    }

    fn alphabet_row(&mut self, ui: &mut Ui) {
        if let DigestAlgorithm::CustomAlphabet(_) = self.settings.digest {
            ui.label("Custom alphabet");
            ui.text_edit_singleline(&mut self.custom_alphabet);
            ui.end_row();
        }
    }
    
    fn length_row(&mut self, ui: &mut Ui) {
        ui.label("Max length");
        ui.text_edit_singleline(&mut self.max_length_raw);
        ui.end_row();
    }
    
    fn zip_row(&mut self, ui: &mut Ui) {
        if let SaltingAlgorithm::Zip(_) = self.settings.salting {
            ui.label("ZIP salting parameter");
            ui.text_edit_singleline(&mut self.zip_raw);
            ui.end_row();
        }
    }

    fn salting_row(&mut self, ui: &mut Ui) {
        ui.label("Salting");
        ComboBox::from_id_source("Salting")
            .selected_text(format!("{:?}", self.settings.salting))
            .show_ui(ui, |ui| {
                ui.style_mut().wrap = Some(false);

                ui.selectable_value(
                    &mut self.settings.salting,
                    SaltingAlgorithm::Zip(self.zip_raw.parse().unwrap_or(1)),
                    "ZIP"
                );
                ui.selectable_value(
                    &mut self.settings.salting,
                    SaltingAlgorithm::Prepend,
                    "Prepend"
                );
                ui.selectable_value(
                    &mut self.settings.salting,
                    SaltingAlgorithm::Append,
                    "Append"
                );
            });
        ui.end_row();
        
        ui.label("Salting iterations");
        ui.text_edit_singleline(&mut self.salting_iterations);
        ui.end_row();
    }

    fn hashing_row(&mut self, ui: &mut Ui) {
        ui.label("Hashing");
        ComboBox::from_id_source("Hashing")
            .selected_text(format!("{:?}", self.settings.hashing))
            .show_ui(ui, |ui| {
                ui.style_mut().wrap = Some(false);

                ui.selectable_value(&mut self.settings.hashing, HashingAlgorithm::Sha256, "SHA256");
                ui.selectable_value(&mut self.settings.hashing, HashingAlgorithm::Sha512, "SHA512");
            });
        ui.end_row();
        
        ui.label("Hashing iterations");
        ui.text_edit_singleline(&mut self.hashing_iterations);
        ui.end_row();
    }

    fn digest_row(&mut self, ui: &mut Ui) {
        ui.label("Digest");
        ComboBox::from_id_source("Digest")
            .selected_text(format!("{:?}", self.settings.digest))
            .show_ui(ui, |ui| {
                ui.style_mut().wrap = Some(false);

                ui.selectable_value(&mut self.settings.digest, DigestAlgorithm::Hex, "HEX");
                ui.selectable_value(&mut self.settings.digest, DigestAlgorithm::Base64, "Base64");
                ui.selectable_value(&mut self.settings.digest, DigestAlgorithm::Base64Url, "Base64Url");
                ui.selectable_value(
                    &mut self.settings.digest,
                    DigestAlgorithm::CustomAlphabet(self.custom_alphabet.clone()), 
                    "Custom alphabet"
                );
            });
        ui.end_row();
    }

    fn service_row(&mut self, ui: &mut Ui) {
        ui.label("Service");
        ui.text_edit_singleline(&mut self.password);
        ui.end_row();
    }

    fn passphrase_row(&mut self, ui: &mut Ui, frame: &mut Frame) {
        ui.label("Passphrase");
        ui.horizontal(|ui| {
            if self.save_failed {
                let _ = ui.button("Failed");
            } else if ui.button("Save").clicked() {
                self.save_salt(frame);
            }

            ui.add(
                TextEdit::singleline(&mut self.salt)
                    .password(true)
            );
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

        self.grid_wrapper(ui, frame);
        self.handle_variants();
        self.output_password(ui, frame);
    }
    
    fn resolve_error(&mut self, res: &passto::Result<String>) -> Option<String> {
        if self.salt.is_empty() || self.password.is_empty() {
            Some("Please enter a passphrase and service first".into())
        } else if let Err(e) = res {
            return Some(format!("{e}"))
        } else {
            return None
        }
    }

    fn output_password(&mut self, ui: &mut Ui, frame: &mut Frame) {
        self.settings.hashing_iterations = self.hashing_iterations.parse().unwrap_or(1);
        self.settings.salting_iterations = self.salting_iterations.parse().unwrap_or(1);
        
        let begin = time::Instant::now();
        let password = encode(self.salt.as_bytes(), self.password.as_bytes(), &self.settings);
        let end = time::Instant::now();
        
        let duration = end - begin;
        
        let possible_error = self.resolve_error(&password);
        
        if let Some(err) = possible_error {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(err)
                        .color(Color32::from_rgb(255, 125, 125))
                );
            });
        } else {
            ui.horizontal(|ui| {
                let password = password.unwrap();
                ui.label(format!("Output({duration:?}): "));
                
                if !frame.is_web() && ui.button("Copy").clicked() {
                    ui.output_mut(|ui| {
                        ui.copied_text = password.clone();
                    });
                }
                
                if password.len() > 64 {
                    ui.label(format!("{}...", &password[..64]));                    
                } else {
                    ui.label(password);
                }
            });
        }
        
        ui.end_row();
    }

    fn handle_variants(&mut self) {
        if let SaltingAlgorithm::Zip(_) = self.settings.salting {
            self.settings.salting = SaltingAlgorithm::Zip(
                self.zip_raw.parse().unwrap_or(1),
            );
        }
        
        if let DigestAlgorithm::CustomAlphabet(_) = self.settings.digest {
            self.settings.digest = DigestAlgorithm::CustomAlphabet(
                self.custom_alphabet.clone(),
            );
        }
        
        self.settings.max_length = self.max_length_raw.parse::<usize>().ok();
    }

    fn grid_wrapper(&mut self, ui: &mut Ui, frame: &mut Frame) {
        Grid::new("input_grid")
            .striped(true)
            .num_columns(2)
            .min_col_width(290.0)
            .show(ui, |ui| {
                self.input_grid(ui, frame);
            });
    }
}

impl App for PasstoApp {
    fn update(&mut self, ctx: &Context, frame: &mut Frame) {
        self.load_salt(frame);
        egui::CentralPanel::default().show(ctx, |ui| self.central_panel(ui, frame));
    }
}
