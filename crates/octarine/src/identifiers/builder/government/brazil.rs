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
