//! European national-identifier methods — Finland (HETU), Spain (NIF + NIE),
//! Italy (Codice Fiscale), Poland (PESEL).

use super::*;

impl GovernmentBuilder {
    // ---- Finland HETU --------------------------------------------------------

    /// Check if value matches a Finnish HETU pattern
    #[must_use]
    pub fn is_finland_hetu(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_finland_hetu(value);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result {
                increment_by(metric_names::detected(), 1);
                increment_by(metric_names::government_data_found(), 1);
            }
        }
        result
    }

    /// Validate Finnish HETU format
    pub fn validate_finland_hetu(&self, hetu: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_finland_hetu(hetu);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "finland_hetu_validation_failed",
                    "Invalid Finland HETU format",
                );
            }
        }
        result
    }

    /// Validate Finnish HETU with mod-31 checksum verification
    pub fn validate_finland_hetu_with_checksum(&self, hetu: &str) -> Result<(), Problem> {
        self.inner.validate_finland_hetu_with_checksum(hetu)
    }

    // ---- Spain NIF -----------------------------------------------------------

    /// Check if value matches a Spanish NIF pattern
    #[must_use]
    pub fn is_spain_nif(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_spain_nif(value);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result {
                increment_by(metric_names::detected(), 1);
                increment_by(metric_names::government_data_found(), 1);
            }
        }
        result
    }

    /// Validate Spanish NIF format
    pub fn validate_spain_nif(&self, nif: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_spain_nif(nif);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn("spain_nif_validation_failed", "Invalid Spain NIF format");
            }
        }
        result
    }

    /// Validate Spanish NIF with mod-23 checksum verification
    pub fn validate_spain_nif_with_checksum(&self, nif: &str) -> Result<(), Problem> {
        self.inner.validate_spain_nif_with_checksum(nif)
    }

    // ---- Spain NIE -----------------------------------------------------------

    /// Check if value matches a Spanish NIE pattern
    #[must_use]
    pub fn is_spain_nie(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_spain_nie(value);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result {
                increment_by(metric_names::detected(), 1);
                increment_by(metric_names::government_data_found(), 1);
            }
        }
        result
    }

    /// Validate Spanish NIE format
    pub fn validate_spain_nie(&self, nie: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_spain_nie(nie);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn("spain_nie_validation_failed", "Invalid Spain NIE format");
            }
        }
        result
    }

    /// Validate Spanish NIE with mod-23 checksum verification
    pub fn validate_spain_nie_with_checksum(&self, nie: &str) -> Result<(), Problem> {
        self.inner.validate_spain_nie_with_checksum(nie)
    }

    // ---- Italy Codice Fiscale ------------------------------------------------

    /// Check if value matches an Italian Codice Fiscale pattern
    #[must_use]
    pub fn is_italy_fiscal_code(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_italy_fiscal_code(value);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result {
                increment_by(metric_names::detected(), 1);
                increment_by(metric_names::government_data_found(), 1);
            }
        }
        result
    }

    /// Validate Italian Codice Fiscale format
    pub fn validate_italy_fiscal_code(&self, cf: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_italy_fiscal_code(cf);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "italy_fiscal_code_validation_failed",
                    "Invalid Italy Codice Fiscale format",
                );
            }
        }
        result
    }

    /// Validate Italian Codice Fiscale with check character verification
    pub fn validate_italy_fiscal_code_with_checksum(&self, cf: &str) -> Result<(), Problem> {
        self.inner.validate_italy_fiscal_code_with_checksum(cf)
    }

    // ---- Italy Partita IVA (VAT) ---------------------------------------------

    /// Check if value matches an Italy VAT pattern
    #[must_use]
    pub fn is_italy_vat(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_italy_vat(value);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result {
                increment_by(metric_names::detected(), 1);
                increment_by(metric_names::government_data_found(), 1);
            }
        }
        result
    }

    /// Validate Italy VAT format
    pub fn validate_italy_vat(&self, vat: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_italy_vat(vat);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn("italy_vat_validation_failed", "Invalid Italy VAT format");
            }
        }
        result
    }

    /// Validate Italy VAT with mod-10 Luhn-style checksum verification
    pub fn validate_italy_vat_with_checksum(&self, vat: &str) -> Result<(), Problem> {
        self.inner.validate_italy_vat_with_checksum(vat)
    }

    /// Find all Italy VAT mentions in text
    #[must_use]
    pub fn find_italy_vats_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_italy_vats_in_text(text);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !matches.is_empty() {
                increment_by(metric_names::detected(), matches.len() as u64);
            }
        }
        matches
    }

    // ---- Italy Passport ------------------------------------------------------

    /// Check if value matches an Italy passport pattern
    #[must_use]
    pub fn is_italy_passport(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_italy_passport(value);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result {
                increment_by(metric_names::detected(), 1);
                increment_by(metric_names::government_data_found(), 1);
            }
        }
        result
    }

    /// Validate Italy passport format
    pub fn validate_italy_passport(&self, passport: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_italy_passport(passport);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "italy_passport_validation_failed",
                    "Invalid Italy passport format",
                );
            }
        }
        result
    }

    /// Find all Italy passport mentions in text
    #[must_use]
    pub fn find_italy_passports_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_italy_passports_in_text(text);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !matches.is_empty() {
                increment_by(metric_names::detected(), matches.len() as u64);
            }
        }
        matches
    }

    // ---- Italy Identity Card (Carta d'Identità) ------------------------------

    /// Check if value matches an Italy identity card pattern (paper, CIE 2.0,
    /// or CIE 3.0)
    #[must_use]
    pub fn is_italy_identity_card(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_italy_identity_card(value);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result {
                increment_by(metric_names::detected(), 1);
                increment_by(metric_names::government_data_found(), 1);
            }
        }
        result
    }

    /// Validate Italy identity card format
    pub fn validate_italy_identity_card(&self, card: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_italy_identity_card(card);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "italy_identity_card_validation_failed",
                    "Invalid Italy identity card format",
                );
            }
        }
        result
    }

    /// Find all Italy identity card mentions in text
    #[must_use]
    pub fn find_italy_identity_cards_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_italy_identity_cards_in_text(text);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !matches.is_empty() {
                increment_by(metric_names::detected(), matches.len() as u64);
            }
        }
        matches
    }

    // ---- Italy Driver License (Patente di Guida) -----------------------------

    /// Check if value matches an Italy driver license pattern (standard or
    /// legacy U1 Carta Conducente)
    #[must_use]
    pub fn is_italy_driver_license(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_italy_driver_license(value);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result {
                increment_by(metric_names::detected(), 1);
                increment_by(metric_names::government_data_found(), 1);
            }
        }
        result
    }

    /// Validate Italy driver license format
    pub fn validate_italy_driver_license(&self, license: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_italy_driver_license(license);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "italy_driver_license_validation_failed",
                    "Invalid Italy driver license format",
                );
            }
        }
        result
    }

    /// Find all Italy driver license mentions in text
    #[must_use]
    pub fn find_italy_driver_licenses_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_italy_driver_licenses_in_text(text);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !matches.is_empty() {
                increment_by(metric_names::detected(), matches.len() as u64);
            }
        }
        matches
    }

    // ---- Poland PESEL --------------------------------------------------------

    /// Check if value matches a Polish PESEL pattern
    #[must_use]
    pub fn is_poland_pesel(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_poland_pesel(value);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result {
                increment_by(metric_names::detected(), 1);
                increment_by(metric_names::government_data_found(), 1);
            }
        }
        result
    }

    /// Validate Polish PESEL format
    pub fn validate_poland_pesel(&self, pesel: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_poland_pesel(pesel);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "poland_pesel_validation_failed",
                    "Invalid Poland PESEL format",
                );
            }
        }
        result
    }

    /// Validate Polish PESEL with weighted checksum verification
    pub fn validate_poland_pesel_with_checksum(&self, pesel: &str) -> Result<(), Problem> {
        self.inner.validate_poland_pesel_with_checksum(pesel)
    }
}
