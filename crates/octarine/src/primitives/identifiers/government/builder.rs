//! Government identifier builder (primitives layer)
//!
//! Provides a unified API for government identifier operations.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.
//! The builder routes to detection, validation, sanitization, and conversion modules.
//!
//! # Usage
//!
//! ```ignore
//! use crate::primitives::identifiers::IdentifierBuilder;
//!
//! let builder = IdentifierBuilder::new();
//! let gov = builder.government();
//!
//! // Detection
//! let is_ssn = gov.is_ssn("900-00-0001");
//! let matches = gov.find_ssns_in_text("SSN: 900-00-0001");
//!
//! // Validation
//! let valid = gov.validate_ssn("234-56-7890");
//!
//! // Sanitization (with explicit strategy)
//! let redacted = gov.redact_ssn_with_strategy("900-00-0001", SsnRedactionStrategy::Token);
//!
//! // Conversion
//! let normalized = gov.normalize_ssn("900 00 0001");
//! ```

use super::super::types::IdentifierMatch;
use crate::primitives::Problem;
use crate::primitives::collections::CacheStats;

use super::conversion;
use super::detection;
use super::redaction::TextRedactionPolicy;
use super::sanitization::{
    self, DriverLicenseRedactionStrategy, NationalIdRedactionStrategy, PassportRedactionStrategy,
    SsnRedactionStrategy, TaxIdRedactionStrategy, VehicleIdRedactionStrategy,
};
use super::validation;

/// Builder for government identifier operations
///
/// Provides a unified interface to all government identifier functionality:
/// - SSN detection, validation, and sanitization
/// - Tax ID (EIN, ITIN) operations
/// - Driver's license operations
/// - Passport operations
/// - National ID operations
/// - VIN operations
#[derive(Debug, Clone, Copy)]
pub struct GovernmentIdentifierBuilder;

impl Default for GovernmentIdentifierBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl GovernmentIdentifierBuilder {
    /// Create a new government identifier builder
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    // ========================================================================
    // SSN Operations
    // ========================================================================

    /// Check if value matches SSN format
    #[must_use]
    pub fn is_ssn(&self, value: &str) -> bool {
        detection::is_ssn(value)
    }

    /// Find all SSNs in text
    #[must_use]
    pub fn find_ssns_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_ssns_in_text(text)
    }

    /// Validate SSN format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the SSN format is invalid
    pub fn validate_ssn(&self, ssn: &str) -> Result<(), Problem> {
        validation::validate_ssn(ssn)
    }

    /// Check if SSN area code indicates ITIN
    #[must_use]
    pub fn is_itin_area(&self, ssn: &str) -> bool {
        validation::is_itin_area(ssn)
    }

    /// Redact SSN with explicit strategy
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::government::{
    ///     GovernmentIdentifierBuilder, SsnRedactionStrategy,
    /// };
    ///
    /// let builder = GovernmentIdentifierBuilder::new();
    /// let result = builder.redact_ssn_with_strategy("900-00-0001", SsnRedactionStrategy::Token);
    /// assert_eq!(result, "[SSN]");
    /// ```
    #[must_use]
    pub fn redact_ssn_with_strategy(&self, ssn: &str, strategy: SsnRedactionStrategy) -> String {
        sanitization::redact_ssn_with_strategy(ssn, strategy)
    }

    /// Redact all SSNs in text with explicit strategy
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::government::{
    ///     GovernmentIdentifierBuilder, SsnRedactionStrategy,
    /// };
    ///
    /// let builder = GovernmentIdentifierBuilder::new();
    /// let result = builder.redact_ssns_in_text_with_strategy(
    ///     "SSN: 900-00-0001",
    ///     SsnRedactionStrategy::LastFour,
    /// );
    /// assert!(result.contains("***-**-0001"));
    /// ```
    #[must_use]
    pub fn redact_ssns_in_text_with_strategy(
        &self,
        text: &str,
        strategy: SsnRedactionStrategy,
    ) -> String {
        sanitization::redact_ssns_in_text_with_strategy(text, strategy).into_owned()
    }

    /// Normalize SSN to digits only
    #[must_use]
    pub fn normalize_ssn(&self, ssn: &str) -> String {
        conversion::normalize_ssn(ssn)
    }

    /// Convert SSN to standard hyphenated format
    #[must_use]
    pub fn to_ssn_with_hyphens(self, ssn: &str) -> String {
        conversion::to_ssn_with_hyphens(ssn)
    }

    /// Convert SSN to safe display format (masked)
    #[must_use]
    pub fn to_ssn_display(self, ssn: &str) -> String {
        conversion::to_ssn_display(ssn)
    }

    /// Sanitize SSN strict (normalize + validate)
    ///
    /// Combines normalization and validation in one step.
    /// Returns formatted SSN if valid, error otherwise.
    pub fn sanitize_ssn(&self, ssn: &str) -> Result<String, Problem> {
        sanitization::sanitize_ssn_strict(ssn)
    }

    // ========================================================================
    // Tax ID Operations
    // ========================================================================

    /// Check if value matches tax ID format (EIN, TIN, ITIN)
    #[must_use]
    pub fn is_tax_id(&self, value: &str) -> bool {
        detection::is_tax_id(value)
    }

    /// Find all tax IDs in text
    #[must_use]
    pub fn find_tax_ids_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_tax_ids_in_text(text)
    }

    /// Validate EIN format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the EIN format is invalid
    pub fn validate_ein(&self, ein: &str) -> Result<(), Problem> {
        validation::validate_ein(ein)
    }

    /// Redact tax ID with explicit strategy
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::government::{
    ///     GovernmentIdentifierBuilder, TaxIdRedactionStrategy,
    /// };
    ///
    /// let builder = GovernmentIdentifierBuilder::new();
    /// let result = builder.redact_tax_id_with_strategy("12-3456789", TaxIdRedactionStrategy::Token);
    /// assert_eq!(result, "[TAX_ID]");
    /// ```
    #[must_use]
    pub fn redact_tax_id_with_strategy(
        &self,
        tax_id: &str,
        strategy: TaxIdRedactionStrategy,
    ) -> String {
        sanitization::redact_tax_id_with_strategy(tax_id, strategy)
    }

    /// Redact all tax IDs in text with explicit strategy
    #[must_use]
    pub fn redact_tax_ids_in_text_with_strategy(
        &self,
        text: &str,
        strategy: TaxIdRedactionStrategy,
    ) -> String {
        sanitization::redact_tax_ids_in_text_with_strategy(text, strategy).into_owned()
    }

    /// Normalize EIN to digits only
    #[must_use]
    pub fn normalize_ein(&self, ein: &str) -> String {
        conversion::normalize_ein(ein)
    }

    /// Convert EIN to standard hyphenated format
    #[must_use]
    pub fn to_ein_with_hyphen(self, ein: &str) -> String {
        conversion::to_ein_with_hyphen(ein)
    }

    /// Sanitize EIN strict (normalize + validate)
    ///
    /// Combines normalization and validation in one step.
    /// Returns formatted EIN if valid, error otherwise.
    pub fn sanitize_ein(&self, ein: &str) -> Result<String, Problem> {
        sanitization::sanitize_ein_strict(ein)
    }

    // ========================================================================
    // Driver's License Operations
    // ========================================================================

    /// Check if value matches driver's license format
    #[must_use]
    pub fn is_driver_license(&self, value: &str) -> bool {
        detection::is_driver_license(value)
    }

    /// Find all driver's licenses in text
    #[must_use]
    pub fn find_driver_licenses_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_driver_licenses_in_text(text)
    }

    /// Validate driver's license format for a specific state
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the license format is invalid for the specified state
    pub fn validate_driver_license(&self, license: &str, state: &str) -> Result<(), Problem> {
        validation::validate_driver_license(license, state)
    }

    /// Redact driver's license with explicit strategy
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::government::{
    ///     GovernmentIdentifierBuilder, DriverLicenseRedactionStrategy,
    /// };
    ///
    /// let builder = GovernmentIdentifierBuilder::new();
    /// let result = builder.redact_driver_license_with_strategy(
    ///     "D1234567",
    ///     DriverLicenseRedactionStrategy::Token,
    /// );
    /// assert_eq!(result, "[DRIVER_LICENSE]");
    /// ```
    #[must_use]
    pub fn redact_driver_license_with_strategy(
        &self,
        license: &str,
        strategy: DriverLicenseRedactionStrategy,
    ) -> String {
        sanitization::redact_driver_license_with_strategy(license, strategy)
    }

    /// Redact all driver's licenses in text with explicit strategy
    #[must_use]
    pub fn redact_driver_licenses_in_text_with_strategy(
        &self,
        text: &str,
        strategy: DriverLicenseRedactionStrategy,
    ) -> String {
        sanitization::redact_driver_licenses_in_text_with_strategy(text, strategy).into_owned()
    }

    /// Normalize driver's license to alphanumeric only
    #[must_use]
    pub fn normalize_driver_license(&self, license: &str) -> String {
        conversion::normalize_driver_license(license)
    }

    /// Sanitize driver's license strict (normalize + validate)
    ///
    /// Combines normalization and validation in one step.
    /// Returns normalized license if valid, error otherwise.
    pub fn sanitize_driver_license(&self, license: &str, state: &str) -> Result<String, Problem> {
        sanitization::sanitize_driver_license_strict(license, state)
    }

    // ========================================================================
    // Passport Operations
    // ========================================================================

    /// Check if value matches passport format
    #[must_use]
    pub fn is_passport(&self, value: &str) -> bool {
        detection::is_passport(value)
    }

    /// Find all passports in text
    #[must_use]
    pub fn find_passports_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_passports_in_text(text)
    }

    /// Validate passport number format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the passport number format is invalid
    pub fn validate_passport(&self, passport: &str) -> Result<(), Problem> {
        validation::validate_passport(passport)
    }

    /// Redact passport with explicit strategy
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::government::{
    ///     GovernmentIdentifierBuilder, PassportRedactionStrategy,
    /// };
    ///
    /// let builder = GovernmentIdentifierBuilder::new();
    /// let result = builder.redact_passport_with_strategy(
    ///     "US1234567",
    ///     PassportRedactionStrategy::Token,
    /// );
    /// assert_eq!(result, "[PASSPORT]");
    /// ```
    #[must_use]
    pub fn redact_passport_with_strategy(
        &self,
        passport: &str,
        strategy: PassportRedactionStrategy,
    ) -> String {
        sanitization::redact_passport_with_strategy(passport, strategy)
    }

    /// Redact all passports in text with explicit strategy
    #[must_use]
    pub fn redact_passports_in_text_with_strategy(
        &self,
        text: &str,
        strategy: PassportRedactionStrategy,
    ) -> String {
        sanitization::redact_passports_in_text_with_strategy(text, strategy).into_owned()
    }

    // ========================================================================
    // National ID Operations
    // ========================================================================

    /// Check if value matches national ID format
    #[must_use]
    pub fn is_national_id(&self, value: &str) -> bool {
        detection::is_national_id(value)
    }

    /// Find all national IDs in text
    #[must_use]
    pub fn find_national_ids_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_national_ids_in_text(text)
    }

    /// Validate national ID format (auto-detects UK NI, Canada SIN, or generic)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the national ID format is invalid
    pub fn validate_national_id(&self, national_id: &str) -> Result<(), Problem> {
        validation::validate_national_id(national_id)
    }

    /// Validate UK National Insurance Number
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the NI number format is invalid
    pub fn validate_uk_ni(&self, ni: &str) -> Result<(), Problem> {
        validation::validate_uk_ni(ni)
    }

    /// Validate Canadian Social Insurance Number with Luhn checksum
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the SIN format is invalid or checksum fails
    pub fn validate_canada_sin(&self, sin: &str) -> Result<(), Problem> {
        validation::validate_canada_sin(sin)
    }

    /// Redact national ID with explicit strategy
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::government::{
    ///     GovernmentIdentifierBuilder, NationalIdRedactionStrategy,
    /// };
    ///
    /// let builder = GovernmentIdentifierBuilder::new();
    /// let result = builder.redact_national_id_with_strategy(
    ///     "AB123456C",
    ///     NationalIdRedactionStrategy::Token,
    /// );
    /// assert_eq!(result, "[NATIONAL_ID]");
    /// ```
    #[must_use]
    pub fn redact_national_id_with_strategy(
        &self,
        national_id: &str,
        strategy: NationalIdRedactionStrategy,
    ) -> String {
        sanitization::redact_national_id_with_strategy(national_id, strategy)
    }

    /// Redact all national IDs in text with explicit strategy
    #[must_use]
    pub fn redact_national_ids_in_text_with_strategy(
        &self,
        text: &str,
        strategy: NationalIdRedactionStrategy,
    ) -> String {
        sanitization::redact_national_ids_in_text_with_strategy(text, strategy).into_owned()
    }

    // ========================================================================
    // Australia TFN Operations
    // ========================================================================

    /// Check if value matches Australian TFN format
    #[must_use]
    pub fn is_australia_tfn(&self, value: &str) -> bool {
        detection::is_australia_tfn(value)
    }

    /// Find all Australian TFNs in text
    #[must_use]
    pub fn find_australia_tfns_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_australia_tfns_in_text(text)
    }

    /// Validate Australian TFN format (without checksum)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the TFN format is invalid
    pub fn validate_australia_tfn(&self, tfn: &str) -> Result<(), Problem> {
        validation::validate_australia_tfn(tfn)
    }

    /// Validate Australian TFN with mod-11 weighted checksum
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the TFN format is invalid or checksum fails
    pub fn validate_australia_tfn_with_checksum(&self, tfn: &str) -> Result<(), Problem> {
        validation::validate_australia_tfn_with_checksum(tfn)
    }

    /// Check if an Australian TFN is a test/dummy pattern
    #[must_use]
    pub fn is_test_australia_tfn(&self, tfn: &str) -> bool {
        validation::is_test_australia_tfn(tfn)
    }

    // ========================================================================
    // Australia ABN Operations
    // ========================================================================

    /// Check if value matches Australian ABN format
    #[must_use]
    pub fn is_australia_abn(&self, value: &str) -> bool {
        detection::is_australia_abn(value)
    }

    /// Find all Australian ABNs in text
    #[must_use]
    pub fn find_australia_abns_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_australia_abns_in_text(text)
    }

    /// Validate Australian ABN format (without checksum)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the ABN format is invalid
    pub fn validate_australia_abn(&self, abn: &str) -> Result<(), Problem> {
        validation::validate_australia_abn(abn)
    }

    /// Validate Australian ABN with mod-89 weighted checksum
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the ABN format is invalid or checksum fails
    pub fn validate_australia_abn_with_checksum(&self, abn: &str) -> Result<(), Problem> {
        validation::validate_australia_abn_with_checksum(abn)
    }

    /// Check if an Australian ABN is a test/dummy pattern
    #[must_use]
    pub fn is_test_australia_abn(&self, abn: &str) -> bool {
        validation::is_test_australia_abn(abn)
    }

    // ========================================================================
    // India Aadhaar Operations
    // ========================================================================

    /// Check if value matches India Aadhaar format
    #[must_use]
    pub fn is_india_aadhaar(&self, value: &str) -> bool {
        detection::is_india_aadhaar(value)
    }

    /// Find all India Aadhaar numbers in text
    #[must_use]
    pub fn find_india_aadhaars_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_india_aadhaars_in_text(text)
    }

    /// Validate India Aadhaar format (without checksum)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the Aadhaar format is invalid
    pub fn validate_india_aadhaar(&self, aadhaar: &str) -> Result<(), Problem> {
        validation::validate_india_aadhaar(aadhaar)
    }

    /// Validate India Aadhaar with Verhoeff checksum
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the Aadhaar format is invalid or checksum fails
    pub fn validate_india_aadhaar_with_checksum(&self, aadhaar: &str) -> Result<(), Problem> {
        validation::validate_india_aadhaar_with_checksum(aadhaar)
    }

    /// Check if an India Aadhaar is a test/dummy pattern
    #[must_use]
    pub fn is_test_india_aadhaar(&self, aadhaar: &str) -> bool {
        validation::is_test_india_aadhaar(aadhaar)
    }

    // ========================================================================
    // India PAN Operations
    // ========================================================================

    /// Check if value matches India PAN format
    #[must_use]
    pub fn is_india_pan(&self, value: &str) -> bool {
        detection::is_india_pan(value)
    }

    /// Find all India PAN numbers in text
    #[must_use]
    pub fn find_india_pans_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_india_pans_in_text(text)
    }

    /// Validate India PAN format and holder type
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the PAN format or holder type is invalid
    pub fn validate_india_pan(&self, pan: &str) -> Result<(), Problem> {
        validation::validate_india_pan(pan)
    }

    /// Check if an India PAN is a test/dummy pattern
    #[must_use]
    pub fn is_test_india_pan(&self, pan: &str) -> bool {
        validation::is_test_india_pan(pan)
    }

    // ========================================================================
    // Singapore NRIC/FIN Operations
    // ========================================================================

    /// Check if value matches Singapore NRIC/FIN format
    #[must_use]
    pub fn is_singapore_nric(&self, value: &str) -> bool {
        detection::is_singapore_nric(value)
    }

    /// Find all Singapore NRIC/FIN numbers in text
    #[must_use]
    pub fn find_singapore_nrics_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_singapore_nrics_in_text(text)
    }

    /// Validate Singapore NRIC/FIN format (without checksum)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the NRIC/FIN format is invalid
    pub fn validate_singapore_nric(&self, nric: &str) -> Result<(), Problem> {
        validation::validate_singapore_nric(nric)
    }

    /// Validate Singapore NRIC/FIN with weighted checksum and check letter
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the NRIC/FIN format is invalid or checksum fails
    pub fn validate_singapore_nric_with_checksum(&self, nric: &str) -> Result<(), Problem> {
        validation::validate_singapore_nric_with_checksum(nric)
    }

    /// Check if a Singapore NRIC/FIN is a test/dummy pattern
    #[must_use]
    pub fn is_test_singapore_nric(&self, nric: &str) -> bool {
        validation::is_test_singapore_nric(nric)
    }

    // ========================================================================
    // Korea RRN Operations
    // ========================================================================

    /// Check if value matches South Korea RRN format
    #[must_use]
    pub fn is_korea_rrn(&self, value: &str) -> bool {
        detection::is_korea_rrn(value)
    }

    /// Find all Korea RRNs in text
    #[must_use]
    pub fn find_korea_rrns_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_korea_rrns_in_text(text)
    }

    /// Validate Korea RRN format (without checksum)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the RRN format is invalid
    pub fn validate_korea_rrn(&self, rrn: &str) -> Result<(), Problem> {
        validation::validate_korea_rrn(rrn)
    }

    /// Validate Korea RRN with weighted checksum verification
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the RRN format is invalid or checksum fails
    pub fn validate_korea_rrn_with_checksum(&self, rrn: &str) -> Result<(), Problem> {
        validation::validate_korea_rrn_with_checksum(rrn)
    }

    /// Check if a Korea RRN is a test/dummy pattern
    #[must_use]
    pub fn is_test_korea_rrn(&self, rrn: &str) -> bool {
        validation::is_test_korea_rrn(rrn)
    }

    // ========================================================================
    // Vehicle ID Operations
    // ========================================================================

    /// Check if value matches VIN format
    #[must_use]
    pub fn is_vehicle_id(&self, value: &str) -> bool {
        detection::is_vehicle_id(value)
    }

    /// Find all vehicle IDs in text
    #[must_use]
    pub fn find_vehicle_ids_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_vehicle_ids_in_text(text)
    }

    /// Validate VIN format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the VIN format is invalid
    pub fn validate_vin(&self, vin: &str) -> Result<(), Problem> {
        validation::validate_vin(vin)
    }

    /// Validate VIN with checksum verification
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the VIN format is invalid or checksum fails
    pub fn validate_vin_with_checksum(&self, vin: &str) -> Result<(), Problem> {
        validation::validate_vin_with_checksum(vin)
    }

    /// Redact vehicle ID with explicit strategy
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::government::{
    ///     GovernmentIdentifierBuilder, VehicleIdRedactionStrategy,
    /// };
    ///
    /// let builder = GovernmentIdentifierBuilder::new();
    /// let result = builder.redact_vehicle_id_with_strategy(
    ///     "1HGBH41JXMN109186",
    ///     VehicleIdRedactionStrategy::Token,
    /// );
    /// assert_eq!(result, "[VEHICLE_ID]");
    /// ```
    #[must_use]
    pub fn redact_vehicle_id_with_strategy(
        &self,
        vehicle_id: &str,
        strategy: VehicleIdRedactionStrategy,
    ) -> String {
        sanitization::redact_vehicle_id_with_strategy(vehicle_id, strategy)
    }

    /// Redact all vehicle IDs in text with explicit strategy
    #[must_use]
    pub fn redact_vehicle_ids_in_text_with_strategy(
        &self,
        text: &str,
        strategy: VehicleIdRedactionStrategy,
    ) -> String {
        sanitization::redact_vehicle_ids_in_text_with_strategy(text, strategy).into_owned()
    }

    /// Normalize VIN to uppercase
    #[must_use]
    pub fn normalize_vin(&self, vin: &str) -> String {
        conversion::normalize_vin(vin)
    }

    /// Convert VIN to display format with spaces
    #[must_use]
    pub fn to_vin_display(self, vin: &str) -> String {
        conversion::to_vin_display(vin)
    }

    /// Sanitize VIN strict (normalize + validate with checksum)
    ///
    /// Combines normalization and validation in one step.
    /// Returns normalized VIN if valid, error otherwise.
    pub fn sanitize_vin(&self, vin: &str) -> Result<String, Problem> {
        sanitization::sanitize_vin_strict(vin)
    }

    // ========================================================================
    // Aggregate Operations
    // ========================================================================

    /// Check if value is any government identifier
    #[must_use]
    pub fn is_government_identifier(&self, value: &str) -> bool {
        detection::is_government_identifier(value)
    }

    /// Check if text contains any government identifier
    #[must_use]
    pub fn is_government_present(&self, text: &str) -> bool {
        detection::is_government_present(text)
    }

    /// Find all government IDs in text
    #[must_use]
    pub fn find_all_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::find_all_government_ids_in_text(text)
    }

    /// Redact all government IDs in text with explicit policy
    ///
    /// # Arguments
    ///
    /// * `text` - The text to scan for government identifiers
    /// * `policy` - The redaction policy to apply
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use crate::primitives::identifiers::government::{
    ///     GovernmentIdentifierBuilder, TextRedactionPolicy,
    /// };
    ///
    /// let builder = GovernmentIdentifierBuilder::new();
    ///
    /// // Complete - use type tokens like [SSN], [VEHICLE_ID]
    /// let result = builder.redact_all_in_text_with_policy(
    ///     "SSN: 900-00-0001",
    ///     TextRedactionPolicy::Complete,
    /// );
    /// assert!(result.contains("[SSN]"));
    ///
    /// // Partial - shows last 4 digits for SSN
    /// let result = builder.redact_all_in_text_with_policy(
    ///     "SSN: 900-00-0001",
    ///     TextRedactionPolicy::Partial,
    /// );
    /// assert!(result.contains("***-**-0001"));
    /// ```
    #[must_use]
    pub fn redact_all_in_text_with_policy(
        &self,
        text: &str,
        policy: TextRedactionPolicy,
    ) -> String {
        sanitization::redact_all_government_ids_in_text_with_policy(text, Some(policy))
    }

    // ========================================================================
    // Cache Operations
    // ========================================================================

    /// Get combined cache statistics for all government identifier caches
    ///
    /// Returns aggregated stats across SSN and VIN validation caches.
    /// Use this for overall module performance monitoring.
    #[must_use]
    pub fn cache_stats(&self) -> CacheStats {
        validation::ssn_cache_stats().combine(&validation::vin_cache_stats())
    }

    /// Get SSN validation cache statistics
    ///
    /// Use this for debugging specific cache performance.
    #[must_use]
    pub fn ssn_cache_stats(&self) -> CacheStats {
        validation::ssn_cache_stats()
    }

    /// Get VIN checksum cache statistics
    ///
    /// Use this for debugging specific cache performance.
    #[must_use]
    pub fn vin_cache_stats(&self) -> CacheStats {
        validation::vin_cache_stats()
    }

    /// Clear all validation caches
    ///
    /// Use this when memory pressure is high or to reset cache state.
    pub fn clear_caches(&self) {
        validation::clear_government_caches();
    }

    // ========================================================================
    // Test Pattern Detection
    // ========================================================================

    /// Check if VIN is a known test/sample pattern
    ///
    /// Test VINs like "11111111111111111" or common documentation examples
    /// should not be treated as real vehicle identifiers.
    #[must_use]
    pub fn is_test_vin(&self, vin: &str) -> bool {
        validation::is_test_vin(vin)
    }

    /// Check if EIN is a known test/sample pattern
    ///
    /// Test EINs like "12-3456789" or "00-0000000" should not be
    /// treated as real employer identifiers.
    #[must_use]
    pub fn is_test_ein(&self, ein: &str) -> bool {
        validation::is_test_ein(ein)
    }

    /// Check if driver's license is a known test/sample pattern
    ///
    /// Test patterns like "TEST1234" or "A0000000" should not be
    /// treated as real driver's licenses.
    #[must_use]
    pub fn is_test_driver_license(&self, license: &str) -> bool {
        validation::is_test_driver_license(license)
    }

    /// Check if SSN is a known test/sample pattern
    ///
    /// Test SSNs like "123-45-6789", "078-05-1120" (Woolworth's wallet),
    /// or all same digit patterns (555-55-5555) should not be treated
    /// as real Social Security Numbers.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use crate::primitives::identifiers::government::GovernmentIdentifierBuilder;
    ///
    /// let builder = GovernmentIdentifierBuilder::new();
    /// assert!(builder.is_test_ssn("123-45-6789"));
    /// assert!(builder.is_test_ssn("078-05-1120")); // Woolworth's wallet SSN
    /// assert!(builder.is_test_ssn("555-55-5555")); // All fives
    /// assert!(!builder.is_test_ssn("142-58-3697")); // Not a test pattern
    /// ```
    #[must_use]
    pub fn is_test_ssn(&self, ssn: &str) -> bool {
        validation::is_test_ssn(ssn)
    }

    /// Check if passport number is a known test/sample pattern
    #[must_use]
    pub fn is_test_passport(&self, passport: &str) -> bool {
        validation::is_test_passport(passport)
    }

    /// Check if national ID is a known test/sample pattern
    #[must_use]
    pub fn is_test_national_id(&self, national_id: &str) -> bool {
        validation::is_test_national_id(national_id)
    }

    /// Check if EIN prefix is a valid IRS campus code
    #[must_use]
    pub fn is_valid_ein_prefix(&self, prefix: u8) -> bool {
        validation::is_valid_ein_prefix(prefix)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use serial_test::serial;

    fn builder() -> GovernmentIdentifierBuilder {
        GovernmentIdentifierBuilder::new()
    }

    // ===== SSN Tests =====

    #[test]
    fn test_ssn_detection() {
        let gov = builder();
        assert!(gov.is_ssn("517-29-8346"));
        assert!(!gov.is_ssn("invalid"));
    }

    #[test]
    fn test_ssn_validation() {
        let gov = builder();
        assert!(gov.validate_ssn("517-29-8346").is_ok());
        assert!(gov.validate_ssn("123-45-6789").is_err()); // Test pattern
        assert!(gov.validate_ssn("000-12-3456").is_err()); // Invalid area
    }

    #[test]
    fn test_ssn_sanitization() {
        let gov = builder();
        assert_eq!(
            gov.redact_ssn_with_strategy("517-29-8346", SsnRedactionStrategy::Token),
            "[SSN]"
        );
        assert_eq!(
            gov.redact_ssn_with_strategy("517-29-8346", SsnRedactionStrategy::LastFour),
            "***-**-8346"
        );
    }

    #[test]
    fn test_ssn_conversion() {
        let gov = builder();
        assert_eq!(gov.normalize_ssn("123-45-6789"), "123456789");
        assert_eq!(gov.to_ssn_with_hyphens("123456789"), "123-45-6789");
    }

    // ===== Tax ID Tests =====

    #[test]
    fn test_tax_id_operations() {
        let gov = builder();
        assert!(gov.is_tax_id("00-0000001"));
        assert_eq!(
            gov.redact_tax_id_with_strategy("00-0000001", TaxIdRedactionStrategy::Token),
            "[TAX_ID]"
        );
        assert_eq!(gov.to_ein_with_hyphen("123456789"), "12-3456789");
    }

    // ===== Driver's License Tests =====

    #[test]
    fn test_driver_license_operations() {
        let gov = builder();
        assert!(gov.is_driver_license("A1234567"));
        assert!(gov.validate_driver_license("A1234567", "CA").is_ok());
        assert_eq!(
            gov.redact_driver_license_with_strategy(
                "A1234567",
                DriverLicenseRedactionStrategy::Token
            ),
            "[DRIVER_LICENSE]"
        );
    }

    // ===== VIN Tests =====

    #[test]
    fn test_vin_operations() {
        let gov = builder();
        assert!(gov.is_vehicle_id("1HGBH41JXMN109186"));
        assert!(gov.validate_vin("1HGBH41JXMN109186").is_ok());
        assert_eq!(gov.normalize_vin("1hgbh41jxmn109186"), "1HGBH41JXMN109186");
    }

    // ===== Aggregate Tests =====

    #[test]
    fn test_aggregate_operations() {
        let gov = builder();

        // Detection
        assert!(gov.is_government_identifier("900-00-0001"));
        assert!(gov.is_government_present("SSN: 900-00-0001"));

        // Redaction with policy
        let text = "SSN: 900-00-0001, VIN: 1HGBH41JXMN109186";
        let redacted = gov.redact_all_in_text_with_policy(text, TextRedactionPolicy::Complete);
        assert!(redacted.contains("[SSN]"));
        assert!(redacted.contains("[VEHICLE_ID]"));
    }

    // ===== Cache Tests =====

    #[test]
    #[serial]
    fn test_cache_stats() {
        let gov = builder();

        // Perform some validations to populate cache
        gov.validate_ssn("567-89-0123").ok();
        let _ = gov.validate_vin_with_checksum("55555555555555555");

        // Check stats are accessible - just verify they return without panic
        let _ssn_stats = gov.ssn_cache_stats();
        let _vin_stats = gov.vin_cache_stats();
    }

    #[test]
    #[serial]
    fn test_clear_caches() {
        let gov = builder();

        // Populate cache
        gov.validate_ssn("678-90-1234").ok();

        // Clear should not panic
        gov.clear_caches();

        // After clear, next validation should miss
        let stats_before = gov.ssn_cache_stats();
        gov.validate_ssn("678-90-1234").ok();
        let stats_after = gov.ssn_cache_stats();

        assert!(stats_after.misses > stats_before.misses);
    }

    // ===== Test Pattern Detection Tests =====

    #[test]
    fn test_test_pattern_detection() {
        let gov = builder();

        // VIN test patterns
        assert!(gov.is_test_vin("11111111111111111"));
        assert!(!gov.is_test_vin("WF0XXXGCDW1234567"));

        // EIN test patterns
        assert!(gov.is_test_ein("12-3456789"));
        assert!(!gov.is_test_ein("46-1234567"));

        // Driver's license test patterns
        assert!(gov.is_test_driver_license("TEST1234"));
        assert!(!gov.is_test_driver_license("D1234567"));

        // SSN test patterns
        assert!(gov.is_test_ssn("123-45-6789")); // Sequential
        assert!(gov.is_test_ssn("078-05-1120")); // Woolworth's wallet
        assert!(gov.is_test_ssn("555-55-5555")); // All fives
        assert!(!gov.is_test_ssn("142-58-3697")); // Not a test pattern
    }

    #[test]
    fn test_ein_prefix_validation() {
        let gov = builder();

        // Valid prefixes
        assert!(gov.is_valid_ein_prefix(12));
        assert!(gov.is_valid_ein_prefix(95));

        // Invalid prefixes
        assert!(!gov.is_valid_ein_prefix(0));
        assert!(!gov.is_valid_ein_prefix(7));
    }
}
