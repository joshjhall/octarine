//! India identifier methods — Aadhaar, PAN, GSTIN, vehicle registration,
//! voter ID (EPIC), and Indian passports.

use super::*;

impl GovernmentBuilder {
    // ---- Aadhaar -------------------------------------------------------------

    /// Check if value matches an Indian Aadhaar number pattern
    #[must_use]
    pub fn is_india_aadhaar(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_india_aadhaar(value);
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

    /// Validate Indian Aadhaar number format
    pub fn validate_india_aadhaar(&self, aadhaar: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_india_aadhaar(aadhaar);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "india_aadhaar_validation_failed",
                    "Invalid India Aadhaar format",
                );
            }
        }
        result
    }

    /// Validate Indian Aadhaar with Verhoeff checksum verification
    pub fn validate_india_aadhaar_with_checksum(&self, aadhaar: &str) -> Result<(), Problem> {
        self.inner.validate_india_aadhaar_with_checksum(aadhaar)
    }

    // ---- PAN -----------------------------------------------------------------

    /// Check if value matches an Indian PAN number pattern
    #[must_use]
    pub fn is_india_pan(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_india_pan(value);
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

    /// Validate Indian PAN format
    pub fn validate_india_pan(&self, pan: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_india_pan(pan);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn("india_pan_validation_failed", "Invalid India PAN format");
            }
        }
        result
    }

    // ---- GSTIN ---------------------------------------------------------------

    /// Check if value matches an India GSTIN pattern
    #[must_use]
    pub fn is_india_gstin(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_india_gstin(value);
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

    /// Find all India GSTINs in text
    #[must_use]
    pub fn find_india_gstins_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_india_gstins_in_text(text);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !matches.is_empty() {
                increment_by(metric_names::detected(), matches.len() as u64);
                increment_by(metric_names::government_data_found(), matches.len() as u64);
            }
        }
        matches
    }

    /// Validate India GSTIN format (without checksum)
    pub fn validate_india_gstin(&self, gstin: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_india_gstin(gstin);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "india_gstin_validation_failed",
                    "Invalid India GSTIN format",
                );
            }
        }
        result
    }

    /// Validate India GSTIN with MOD-36 checksum
    pub fn validate_india_gstin_with_checksum(&self, gstin: &str) -> Result<(), Problem> {
        self.inner.validate_india_gstin_with_checksum(gstin)
    }

    // ---- Vehicle Registration ------------------------------------------------

    /// Check if value matches an Indian vehicle registration pattern
    #[must_use]
    pub fn is_india_vehicle_registration(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_india_vehicle_registration(value);
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

    /// Find all Indian vehicle registrations in text
    #[must_use]
    pub fn find_india_vehicle_registrations_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_india_vehicle_registrations_in_text(text);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !matches.is_empty() {
                increment_by(metric_names::detected(), matches.len() as u64);
                increment_by(metric_names::government_data_found(), matches.len() as u64);
            }
        }
        matches
    }

    /// Validate Indian vehicle registration format
    pub fn validate_india_vehicle_registration(&self, reg: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_india_vehicle_registration(reg);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "india_vehicle_reg_validation_failed",
                    "Invalid India vehicle registration format",
                );
            }
        }
        result
    }

    // ---- Voter ID (EPIC) -----------------------------------------------------

    /// Check if value matches an Indian Voter ID pattern
    #[must_use]
    pub fn is_india_voter_id(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_india_voter_id(value);
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

    /// Find all Indian Voter IDs in text
    #[must_use]
    pub fn find_india_voter_ids_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_india_voter_ids_in_text(text);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !matches.is_empty() {
                increment_by(metric_names::detected(), matches.len() as u64);
                increment_by(metric_names::government_data_found(), matches.len() as u64);
            }
        }
        matches
    }

    /// Validate Indian Voter ID format
    pub fn validate_india_voter_id(&self, voter_id: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_india_voter_id(voter_id);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "india_voter_id_validation_failed",
                    "Invalid India Voter ID format",
                );
            }
        }
        result
    }

    // ---- Indian passport -----------------------------------------------------

    /// Check if value matches an Indian passport pattern
    #[must_use]
    pub fn is_india_passport(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_india_passport(value);
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

    /// Find all Indian passport numbers in text (label-gated)
    #[must_use]
    pub fn find_india_passports_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_india_passports_in_text(text);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !matches.is_empty() {
                increment_by(metric_names::detected(), matches.len() as u64);
                increment_by(metric_names::government_data_found(), matches.len() as u64);
            }
        }
        matches
    }

    /// Validate Indian passport format
    pub fn validate_india_passport(&self, passport: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_india_passport(passport);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "india_passport_validation_failed",
                    "Invalid Indian passport format",
                );
            }
        }
        result
    }
}
