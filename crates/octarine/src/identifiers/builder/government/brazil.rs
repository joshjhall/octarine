//! Brazil CPF and CNPJ methods.

use super::*;

impl GovernmentBuilder {
    /// Check if value matches a Brazilian CPF pattern
    #[must_use]
    pub fn is_brazil_cpf(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_brazil_cpf(value);
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

    /// Find all Brazilian CPFs in text
    #[must_use]
    pub fn find_brazil_cpfs_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_brazil_cpfs_in_text(text);
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

    /// Validate Brazilian CPF format (without checksum)
    pub fn validate_brazil_cpf(&self, cpf: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_brazil_cpf(cpf);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn("brazil_cpf_validation_failed", "Invalid Brazil CPF format");
            }
        }
        result
    }

    /// Validate Brazilian CPF with mod-11 dual check digit verification
    pub fn validate_brazil_cpf_with_checksum(&self, cpf: &str) -> Result<(), Problem> {
        self.inner.validate_brazil_cpf_with_checksum(cpf)
    }

    /// Check if value matches a Brazilian CNPJ pattern
    #[must_use]
    pub fn is_brazil_cnpj(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_brazil_cnpj(value);
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

    /// Find all Brazilian CNPJs in text
    #[must_use]
    pub fn find_brazil_cnpjs_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let matches = self.inner.find_brazil_cnpjs_in_text(text);
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

    /// Validate Brazilian CNPJ format (without checksum)
    pub fn validate_brazil_cnpj(&self, cnpj: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_brazil_cnpj(cnpj);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                observe::warn(
                    "brazil_cnpj_validation_failed",
                    "Invalid Brazil CNPJ format",
                );
            }
        }
        result
    }

    /// Validate Brazilian CNPJ with mod-11 dual check digit verification
    pub fn validate_brazil_cnpj_with_checksum(&self, cnpj: &str) -> Result<(), Problem> {
        self.inner.validate_brazil_cnpj_with_checksum(cnpj)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // "111.444.777-35" is a CPF with genuinely valid mod-11 check digits.
    // "11.222.333/0001-81" is a CNPJ with valid mod-11 check digits.
    const VALID_CPF: &str = "111.444.777-35";
    const VALID_CNPJ: &str = "11.222.333/0001-81";

    #[test]
    fn test_is_brazil_cpf() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_brazil_cpf(VALID_CPF));
        assert!(!b.is_brazil_cpf("not-a-cpf"));
    }

    #[test]
    fn test_is_brazil_cpf_events_enabled() {
        let b = GovernmentBuilder::new();
        assert!(b.is_brazil_cpf(VALID_CPF));
    }

    #[test]
    fn test_find_brazil_cpfs_in_text() {
        let b = GovernmentBuilder::silent();
        let matches = b.find_brazil_cpfs_in_text("CPF 111.444.777-35 registrado");
        assert!(!matches.is_empty());
        assert!(b.find_brazil_cpfs_in_text("nada aqui").is_empty());
    }

    #[test]
    fn test_validate_brazil_cpf() {
        let b = GovernmentBuilder::silent();
        assert!(b.validate_brazil_cpf(VALID_CPF).is_ok());
        // 10 digits — wrong length.
        assert!(b.validate_brazil_cpf("1234567890").is_err());
        // All-identical digits are rejected.
        assert!(b.validate_brazil_cpf("111.111.111-11").is_err());
    }

    #[test]
    fn test_validate_brazil_cpf_with_checksum() {
        let b = GovernmentBuilder::silent();
        assert!(b.validate_brazil_cpf_with_checksum(VALID_CPF).is_ok());
        // Tamper the final check digit (35 -> 34).
        assert!(
            b.validate_brazil_cpf_with_checksum("111.444.777-34")
                .is_err()
        );
    }

    #[test]
    fn test_is_brazil_cnpj() {
        let b = GovernmentBuilder::silent();
        assert!(b.is_brazil_cnpj(VALID_CNPJ));
        assert!(!b.is_brazil_cnpj("not-a-cnpj"));
    }

    #[test]
    fn test_find_brazil_cnpjs_in_text() {
        let b = GovernmentBuilder::silent();
        let matches = b.find_brazil_cnpjs_in_text("CNPJ 11.222.333/0001-81");
        assert!(!matches.is_empty());
        assert!(b.find_brazil_cnpjs_in_text("nada").is_empty());
    }

    #[test]
    fn test_validate_brazil_cnpj() {
        let b = GovernmentBuilder::silent();
        assert!(b.validate_brazil_cnpj(VALID_CNPJ).is_ok());
        // All-identical digits are rejected.
        assert!(b.validate_brazil_cnpj("11.111.111/1111-11").is_err());
    }

    #[test]
    fn test_validate_brazil_cnpj_with_checksum() {
        let b = GovernmentBuilder::silent();
        assert!(b.validate_brazil_cnpj_with_checksum(VALID_CNPJ).is_ok());
        // Tamper the final check digit (81 -> 80).
        assert!(
            b.validate_brazil_cnpj_with_checksum("11.222.333/0001-80")
                .is_err()
        );
    }
}
