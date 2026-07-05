//! European national-identifier methods — Finland (HETU), Spain (NIF + NIE),
//! Italy (Codice Fiscale), Poland (PESEL), Sweden (Personnummer +
//! Organisationsnummer).

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

    // ---- Spain passport ------------------------------------------------------

    /// Check if value matches a Spanish passport pattern
    #[must_use]
    pub fn is_spain_passport(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_spain_passport(value);
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

    /// Find all Spanish passport mentions in text (label-anchored only)
    #[must_use]
    pub fn find_spain_passports_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_spain_passports_in_text(text);
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

    /// Validate Spanish passport format (3 letters + 6 digits, no checksum)
    pub fn validate_spain_passport(&self, value: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_spain_passport(value);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "spain_passport_validation_failed",
                    "Invalid Spain passport format",
                );
            }
        }
        result
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

    // ---- Sweden Personnummer -------------------------------------------------

    /// Check if value matches a Swedish personnummer pattern
    #[must_use]
    pub fn is_sweden_personnummer(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_sweden_personnummer(value);
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

    /// Validate Swedish personnummer format
    pub fn validate_sweden_personnummer(&self, value: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_sweden_personnummer(value);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "sweden_personnummer_validation_failed",
                    "Invalid Sweden personnummer format",
                );
            }
        }
        result
    }

    /// Validate Swedish personnummer with Luhn checksum verification
    pub fn validate_sweden_personnummer_with_checksum(&self, value: &str) -> Result<(), Problem> {
        self.inner.validate_sweden_personnummer_with_checksum(value)
    }

    /// Find all Swedish personnummer mentions in text
    #[must_use]
    pub fn find_sweden_personnummers_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_sweden_personnummers_in_text(text);
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

    // ---- Sweden Organisationsnummer ------------------------------------------

    /// Check if value matches a Swedish organisationsnummer pattern
    #[must_use]
    pub fn is_sweden_orgnummer(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_sweden_orgnummer(value);
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

    /// Validate Swedish organisationsnummer format
    pub fn validate_sweden_orgnummer(&self, value: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_sweden_orgnummer(value);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "sweden_orgnummer_validation_failed",
                    "Invalid Sweden organisationsnummer format",
                );
            }
        }
        result
    }

    /// Validate Swedish organisationsnummer with Luhn checksum verification
    pub fn validate_sweden_orgnummer_with_checksum(&self, value: &str) -> Result<(), Problem> {
        self.inner.validate_sweden_orgnummer_with_checksum(value)
    }

    /// Find all Swedish organisationsnummer mentions in text
    #[must_use]
    pub fn find_sweden_orgnummers_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_sweden_orgnummers_in_text(text);
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

    // Verified valid samples (checksums computed with each country's
    // official algorithm and cross-checked against the primitive tests):
    //   Finland HETU "010190-123M" (mod-31 check char M)
    //   Spain NIF "12345678Z" (mod-23), NIE "X1234567L" (mod-23)
    //   Italy CF "RSSMRA85M01H501Q" (mod-26 check char Q), VAT "12345678903"
    //   Poland PESEL "85061512347" (weighted mod-10 check 7)
    //   Sweden personnummer "19121212-1212", orgnummer "5560160680" (Luhn)
    const VALID_HETU: &str = "010190-123M";
    const VALID_NIF: &str = "12345678Z";
    const VALID_NIE: &str = "X1234567L";
    const VALID_CF: &str = "RSSMRA85M01H501Q";
    const VALID_VAT: &str = "12345678903";
    const VALID_PESEL: &str = "85061512347";
    const VALID_PERSONNUMMER: &str = "19121212-1212";
    const VALID_ORGNUMMER: &str = "5560160680";

    #[test]
    fn test_finland_hetu() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_finland_hetu(VALID_HETU));
        assert!(!b.is_finland_hetu("123"));
        assert!(b.validate_finland_hetu(VALID_HETU).is_ok());
        // Month 13 is invalid.
        assert!(b.validate_finland_hetu("011390-1230").is_err());
        assert!(b.validate_finland_hetu_with_checksum(VALID_HETU).is_ok());
        // Wrong check char.
        assert!(
            b.validate_finland_hetu_with_checksum("010190-123A")
                .is_err()
        );
    }

    #[test]
    fn test_finland_hetu_events_enabled() {
        let b = GovernmentBuilder::new();
        assert!(b.is_finland_hetu(VALID_HETU));
        assert!(b.validate_finland_hetu(VALID_HETU).is_ok());
    }

    #[test]
    fn test_spain_nif() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_spain_nif(VALID_NIF));
        assert!(b.validate_spain_nif(VALID_NIF).is_ok());
        // 8 chars — wrong length.
        assert!(b.validate_spain_nif("1234567A").is_err());
        assert!(b.validate_spain_nif_with_checksum(VALID_NIF).is_ok());
        // Wrong check letter.
        assert!(b.validate_spain_nif_with_checksum("12345678A").is_err());
    }

    #[test]
    fn test_spain_nie() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_spain_nie(VALID_NIE));
        assert!(b.validate_spain_nie(VALID_NIE).is_ok());
        assert!(b.validate_spain_nie("X123456A").is_err());
        assert!(b.validate_spain_nie_with_checksum(VALID_NIE).is_ok());
        // Wrong check letter.
        assert!(b.validate_spain_nie_with_checksum("X1234567A").is_err());
    }

    #[test]
    fn test_italy_fiscal_code() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_italy_fiscal_code(VALID_CF));
        assert!(b.validate_italy_fiscal_code(VALID_CF).is_ok());
        // 14 chars — wrong length.
        assert!(b.validate_italy_fiscal_code("RSSMRA85M01H50").is_err());
        assert!(b.validate_italy_fiscal_code_with_checksum(VALID_CF).is_ok());
        // Wrong check char (Q -> A).
        assert!(
            b.validate_italy_fiscal_code_with_checksum("RSSMRA85M01H501A")
                .is_err()
        );
    }

    #[test]
    fn test_italy_vat() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_italy_vat(VALID_VAT));
        assert!(b.validate_italy_vat(VALID_VAT).is_ok());
        assert!(b.validate_italy_vat("123").is_err());
        assert!(b.validate_italy_vat_with_checksum(VALID_VAT).is_ok());
        // Break the Luhn-style checksum (last digit 3 -> 4).
        assert!(b.validate_italy_vat_with_checksum("12345678904").is_err());
        assert!(!b.find_italy_vats_in_text("VAT 12345678903").is_empty());
    }

    #[test]
    fn test_italy_passport() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_italy_passport("AA1234567"));
        assert!(b.validate_italy_passport("AA1234567").is_ok());
        assert!(b.validate_italy_passport("!!!").is_err());
        assert!(
            !b.find_italy_passports_in_text("passport AA1234567")
                .is_empty()
        );
    }

    #[test]
    fn test_italy_identity_card() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_italy_identity_card("CA1234567"));
        assert!(b.validate_italy_identity_card("CA1234567").is_ok());
        assert!(b.validate_italy_identity_card("!!!").is_err());
        // Detection is label-anchored ("identity card", "CIE", ...).
        assert!(
            !b.find_italy_identity_cards_in_text("identity card CA1234567")
                .is_empty()
        );
    }

    #[test]
    fn test_italy_driver_license() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_italy_driver_license("AB1234567C"));
        assert!(b.validate_italy_driver_license("AB1234567C").is_ok());
        assert!(b.validate_italy_driver_license("!!!").is_err());
        assert!(
            !b.find_italy_driver_licenses_in_text("patente AB1234567C")
                .is_empty()
        );
    }

    #[test]
    fn test_poland_pesel() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_poland_pesel(VALID_PESEL));
        assert!(b.validate_poland_pesel(VALID_PESEL).is_ok());
        // 10 digits — wrong length.
        assert!(b.validate_poland_pesel("1234567890").is_err());
        assert!(b.validate_poland_pesel_with_checksum(VALID_PESEL).is_ok());
        // Break the checksum (last digit 7 -> 8).
        assert!(
            b.validate_poland_pesel_with_checksum("85061512348")
                .is_err()
        );
    }

    #[test]
    fn test_sweden_personnummer() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_sweden_personnummer(VALID_PERSONNUMMER));
        assert!(b.validate_sweden_personnummer(VALID_PERSONNUMMER).is_ok());
        assert!(b.validate_sweden_personnummer("123").is_err());
        assert!(
            b.validate_sweden_personnummer_with_checksum(VALID_PERSONNUMMER)
                .is_ok()
        );
        // Break the Luhn checksum (last digit 2 -> 3).
        assert!(
            b.validate_sweden_personnummer_with_checksum("19121212-1213")
                .is_err()
        );
        // Detection is label-anchored ("personnummer:", ...).
        assert!(
            !b.find_sweden_personnummers_in_text("personnummer: 19121212-1212")
                .is_empty()
        );
    }

    #[test]
    fn test_sweden_orgnummer() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_sweden_orgnummer(VALID_ORGNUMMER));
        assert!(b.validate_sweden_orgnummer(VALID_ORGNUMMER).is_ok());
        // Third digit < 2 → not an orgnummer.
        assert!(b.validate_sweden_orgnummer("5510160687").is_err());
        assert!(
            b.validate_sweden_orgnummer_with_checksum(VALID_ORGNUMMER)
                .is_ok()
        );
        // Break the Luhn checksum (last digit 0 -> 1).
        assert!(
            b.validate_sweden_orgnummer_with_checksum("5560160681")
                .is_err()
        );
        // Detection is label-anchored ("orgnr:", ...).
        assert!(
            !b.find_sweden_orgnummers_in_text("orgnr: 556016-0680")
                .is_empty()
        );
    }
}
