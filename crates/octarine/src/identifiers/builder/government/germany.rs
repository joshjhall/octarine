//! German government-identifier methods — Steuer-IdNr (tax ID),
//! Personalausweis (nPA), Reisepass (passport).

use super::*;

impl GovernmentBuilder {
    // ---- Steuer-IdNr ---------------------------------------------------------

    /// Check if value matches a German Steuer-IdNr
    #[must_use]
    pub fn is_germany_tax_id(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_germany_tax_id(value);
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

    /// Validate German Steuer-IdNr format
    pub fn validate_germany_tax_id(&self, value: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_germany_tax_id(value);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "germany_tax_id_validation_failed",
                    "Invalid Germany Steuer-IdNr format",
                );
            }
        }
        result
    }

    /// Validate German Steuer-IdNr with ISO 7064 mod-11,10 checksum verification
    pub fn validate_germany_tax_id_with_checksum(&self, value: &str) -> Result<(), Problem> {
        self.inner.validate_germany_tax_id_with_checksum(value)
    }

    /// Find all German Steuer-IdNr mentions in text
    #[must_use]
    pub fn find_germany_tax_ids_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_germany_tax_ids_in_text(text);
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

    // ---- Personalausweis (nPA) -----------------------------------------------

    /// Check if value matches a German Personalausweis (nPA) number
    #[must_use]
    pub fn is_germany_id_card(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_germany_id_card(value);
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

    /// Validate German Personalausweis format
    pub fn validate_germany_id_card(&self, value: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_germany_id_card(value);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "germany_id_card_validation_failed",
                    "Invalid Germany Personalausweis format",
                );
            }
        }
        result
    }

    /// Validate German Personalausweis with ICAO Doc 9303 check-digit verification
    pub fn validate_germany_id_card_with_checksum(&self, value: &str) -> Result<(), Problem> {
        self.inner.validate_germany_id_card_with_checksum(value)
    }

    /// Find all German Personalausweis mentions in text
    #[must_use]
    pub fn find_germany_id_cards_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_germany_id_cards_in_text(text);
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

    // ---- Reisepass (passport) ------------------------------------------------

    /// Check if value matches a German Reisepass (passport) number
    #[must_use]
    pub fn is_germany_passport(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_germany_passport(value);
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

    /// Validate German Reisepass format
    pub fn validate_germany_passport(&self, value: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_germany_passport(value);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "germany_passport_validation_failed",
                    "Invalid Germany Reisepass format",
                );
            }
        }
        result
    }

    /// Validate German Reisepass with ICAO Doc 9303 check-digit verification
    pub fn validate_germany_passport_with_checksum(&self, value: &str) -> Result<(), Problem> {
        self.inner.validate_germany_passport_with_checksum(value)
    }

    /// Find all German Reisepass mentions in text
    #[must_use]
    pub fn find_germany_passports_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_germany_passports_in_text(text);
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
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    const VALID_TAX_ID: &str = "10002345676";
    const VALID_ID_CARD: &str = "CH20064148";
    const VALID_PASSPORT: &str = "T220001293";

    #[test]
    fn test_germany_tax_id() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_germany_tax_id(VALID_TAX_ID));
        assert!(b.validate_germany_tax_id(VALID_TAX_ID).is_ok());
        // Wrong length.
        assert!(b.validate_germany_tax_id("1000234567").is_err());
        assert!(
            b.validate_germany_tax_id_with_checksum(VALID_TAX_ID)
                .is_ok()
        );
        // Tampered check digit.
        assert!(
            b.validate_germany_tax_id_with_checksum("10002345675")
                .is_err()
        );
        assert!(
            !b.find_germany_tax_ids_in_text(&format!("Steuer-IdNr: {VALID_TAX_ID}"))
                .is_empty()
        );
    }

    #[test]
    fn test_germany_tax_id_events_enabled() {
        let b = GovernmentBuilder::new();
        assert!(b.is_germany_tax_id(VALID_TAX_ID));
        assert!(b.validate_germany_tax_id(VALID_TAX_ID).is_ok());
    }

    #[test]
    fn test_germany_id_card() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_germany_id_card(VALID_ID_CARD));
        assert!(b.validate_germany_id_card(VALID_ID_CARD).is_ok());
        assert!(b.validate_germany_id_card("!!!").is_err());
        assert!(
            b.validate_germany_id_card_with_checksum(VALID_ID_CARD)
                .is_ok()
        );
        // Tampered check digit.
        assert!(
            b.validate_germany_id_card_with_checksum("CH20064149")
                .is_err()
        );
        assert!(
            !b.find_germany_id_cards_in_text(&format!("Personalausweis {VALID_ID_CARD}"))
                .is_empty()
        );
    }

    #[test]
    fn test_germany_passport() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_germany_passport(VALID_PASSPORT));
        assert!(b.validate_germany_passport(VALID_PASSPORT).is_ok());
        assert!(b.validate_germany_passport("!!!").is_err());
        assert!(
            b.validate_germany_passport_with_checksum(VALID_PASSPORT)
                .is_ok()
        );
        // Tampered check digit.
        assert!(
            b.validate_germany_passport_with_checksum("T220001294")
                .is_err()
        );
        assert!(
            !b.find_germany_passports_in_text(&format!("Reisepass {VALID_PASSPORT}"))
                .is_empty()
        );
    }
}
