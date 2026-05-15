//! Brazil CPF and CNPJ operations on `GovernmentIdentifierBuilder`.

use super::*;

impl GovernmentIdentifierBuilder {
    /// Check if value matches Brazil CPF format
    #[must_use]
    pub fn is_brazil_cpf(&self, value: &str) -> bool {
        detection::is_brazil_cpf(value)
    }

    /// Find all Brazil CPF numbers in text
    #[must_use]
    pub fn find_brazil_cpfs_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_brazil_cpfs_in_text(text)
    }

    /// Validate Brazil CPF format (without checksum)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the CPF format is invalid
    pub fn validate_brazil_cpf(&self, cpf: &str) -> Result<(), Problem> {
        validation::validate_brazil_cpf(cpf)
    }

    /// Validate Brazil CPF with mod-11 dual check digit verification
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the CPF format or checksum is invalid
    pub fn validate_brazil_cpf_with_checksum(&self, cpf: &str) -> Result<(), Problem> {
        validation::validate_brazil_cpf_with_checksum(cpf)
    }

    /// Check if a Brazil CPF is a test/dummy pattern
    #[must_use]
    pub fn is_test_brazil_cpf(&self, cpf: &str) -> bool {
        validation::is_test_brazil_cpf(cpf)
    }

    /// Check if value matches Brazil CNPJ format
    #[must_use]
    pub fn is_brazil_cnpj(&self, value: &str) -> bool {
        detection::is_brazil_cnpj(value)
    }

    /// Find all Brazil CNPJ numbers in text
    #[must_use]
    pub fn find_brazil_cnpjs_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_brazil_cnpjs_in_text(text)
    }

    /// Validate Brazil CNPJ format (without checksum)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the CNPJ format is invalid
    pub fn validate_brazil_cnpj(&self, cnpj: &str) -> Result<(), Problem> {
        validation::validate_brazil_cnpj(cnpj)
    }

    /// Validate Brazil CNPJ with mod-11 dual check digit verification
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the CNPJ format or checksum is invalid
    pub fn validate_brazil_cnpj_with_checksum(&self, cnpj: &str) -> Result<(), Problem> {
        validation::validate_brazil_cnpj_with_checksum(cnpj)
    }

    /// Check if a Brazil CNPJ is a test/dummy pattern
    #[must_use]
    pub fn is_test_brazil_cnpj(&self, cnpj: &str) -> bool {
        validation::is_test_brazil_cnpj(cnpj)
    }
}
