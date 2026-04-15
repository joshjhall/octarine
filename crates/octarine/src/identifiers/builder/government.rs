//! Government identifier builder with observability
//!
//! Wraps `primitives::identifiers::GovernmentIdentifierBuilder` with observe instrumentation.
//!
//! This is the **public API** (Layer 3) that wraps the primitive builder
//! with observe instrumentation for compliance-grade audit trails.
//!
//! # Why Wrapper Types?
//!
//! Wrapper types are necessary for two reasons:
//! 1. **Visibility bridging**: Primitives are `pub(crate)`, so we can't directly
//!    re-export them as `pub`. Wrapper types provide the public API surface.
//! 2. **API stability**: Wrappers allow the public API to evolve independently
//!    from internal primitives.

use std::time::Instant;

use crate::observe::metrics::{MetricName, increment_by, record};
use crate::observe::{Problem, event};
use crate::primitives::identifiers::{
    DriverLicenseRedactionStrategy, GovernmentIdentifierBuilder, NationalIdRedactionStrategy,
    PassportRedactionStrategy, SsnRedactionStrategy, TaxIdRedactionStrategy,
    VehicleIdRedactionStrategy,
};

use super::super::types::IdentifierMatch;

#[allow(clippy::expect_used)]
mod metric_names {
    use super::MetricName;

    pub fn detect_ms() -> MetricName {
        MetricName::new("data.identifiers.government.detect_ms").expect("valid metric name")
    }

    pub fn validate_ms() -> MetricName {
        MetricName::new("data.identifiers.government.validate_ms").expect("valid metric name")
    }

    pub fn redact_ms() -> MetricName {
        MetricName::new("data.identifiers.government.redact_ms").expect("valid metric name")
    }

    pub fn detected() -> MetricName {
        MetricName::new("data.identifiers.government.detected").expect("valid metric name")
    }

    pub fn government_data_found() -> MetricName {
        MetricName::new("data.identifiers.government.government_data_found")
            .expect("valid metric name")
    }
}

/// Government identifier builder with observability
///
/// Provides detection, validation, and sanitization for government identifiers
/// (SSNs, EINs, driver's licenses, passports, VINs) with full audit trail via observe.
///
/// # Example
///
/// ```ignore
/// use octarine::data::identifiers::GovernmentBuilder;
///
/// let builder = GovernmentBuilder::new();
///
/// // Detection
/// if builder.is_ssn("123-45-6789") {
///     println!("Found SSN");
/// }
///
/// // Silent mode (no events)
/// let silent = GovernmentBuilder::silent();
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct GovernmentBuilder {
    /// The underlying primitive builder
    inner: GovernmentIdentifierBuilder,
    /// Whether to emit observe events
    emit_events: bool,
}

impl GovernmentBuilder {
    /// Create a new GovernmentBuilder with observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: GovernmentIdentifierBuilder::new(),
            emit_events: true,
        }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self {
            inner: GovernmentIdentifierBuilder::new(),
            emit_events: false,
        }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    // ========================================================================
    // SSN Operations
    // ========================================================================

    /// Check if value is an SSN
    pub fn is_ssn(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_ssn(value);

        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result {
                increment_by(metric_names::detected(), 1);
                increment_by(metric_names::government_data_found(), 1);
                event::debug("SSN pattern detected".to_string());
            }
        }

        result
    }

    /// Find all SSNs in text
    #[must_use]
    pub fn find_ssns_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let results = self.inner.find_ssns_in_text(text);

        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !results.is_empty() {
                increment_by(metric_names::detected(), results.len() as u64);
                event::debug(format!("Found {} SSN(s) in text", results.len()));
            }
        }

        results
    }

    /// Validate SSN format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the SSN format is invalid
    pub fn validate_ssn(&self, ssn: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_ssn(ssn);

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                event::warn("Invalid SSN format".to_string());
            }
        }

        result
    }

    /// Check if SSN is in ITIN area range
    #[must_use]
    pub fn is_itin_area(&self, ssn: &str) -> bool {
        self.inner.is_itin_area(ssn)
    }

    /// Redact an SSN with explicit strategy
    #[must_use]
    pub fn redact_ssn_with_strategy(&self, ssn: &str, strategy: SsnRedactionStrategy) -> String {
        self.inner.redact_ssn_with_strategy(ssn, strategy)
    }

    /// Redact all SSNs in text with explicit strategy
    #[must_use]
    pub fn redact_ssns_in_text_with_strategy(
        &self,
        text: &str,
        strategy: SsnRedactionStrategy,
    ) -> String {
        self.inner.redact_ssns_in_text_with_strategy(text, strategy)
    }

    /// Normalize an SSN (remove formatting)
    #[must_use]
    pub fn normalize_ssn(&self, ssn: &str) -> String {
        self.inner.normalize_ssn(ssn)
    }

    /// Convert SSN to standard hyphenated format
    #[must_use]
    pub fn to_ssn_with_hyphens(&self, ssn: &str) -> String {
        self.inner.to_ssn_with_hyphens(ssn)
    }

    /// Convert SSN to safe display format (masked)
    #[must_use]
    pub fn to_ssn_display(&self, ssn: &str) -> String {
        self.inner.to_ssn_display(ssn)
    }

    /// Sanitize an SSN (normalize + validate)
    pub fn sanitize_ssn(&self, ssn: &str) -> Result<String, Problem> {
        self.inner.sanitize_ssn(ssn)
    }

    // ========================================================================
    // Tax ID Operations
    // ========================================================================

    /// Check if value is a tax ID
    #[must_use]
    pub fn is_tax_id(&self, value: &str) -> bool {
        self.inner.is_tax_id(value)
    }

    /// Find all tax IDs in text
    #[must_use]
    pub fn find_tax_ids_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_tax_ids_in_text(text)
    }

    /// Validate EIN format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the EIN format is invalid
    pub fn validate_ein(&self, ein: &str) -> Result<(), Problem> {
        self.inner.validate_ein(ein)
    }

    /// Redact a tax ID with explicit strategy
    #[must_use]
    pub fn redact_tax_id_with_strategy(
        &self,
        tax_id: &str,
        strategy: TaxIdRedactionStrategy,
    ) -> String {
        self.inner.redact_tax_id_with_strategy(tax_id, strategy)
    }

    /// Redact all tax IDs in text with explicit strategy
    #[must_use]
    pub fn redact_tax_ids_in_text_with_strategy(
        &self,
        text: &str,
        strategy: TaxIdRedactionStrategy,
    ) -> String {
        self.inner
            .redact_tax_ids_in_text_with_strategy(text, strategy)
    }

    /// Normalize an EIN (remove formatting)
    #[must_use]
    pub fn normalize_ein(&self, ein: &str) -> String {
        self.inner.normalize_ein(ein)
    }

    /// Convert EIN to standard hyphenated format
    #[must_use]
    pub fn to_ein_with_hyphen(&self, ein: &str) -> String {
        self.inner.to_ein_with_hyphen(ein)
    }

    /// Sanitize an EIN (normalize + validate)
    pub fn sanitize_ein(&self, ein: &str) -> Result<String, Problem> {
        self.inner.sanitize_ein(ein)
    }

    // ========================================================================
    // Driver's License Operations
    // ========================================================================

    /// Check if value is a driver's license
    #[must_use]
    pub fn is_driver_license(&self, value: &str) -> bool {
        self.inner.is_driver_license(value)
    }

    /// Find all driver's licenses in text
    #[must_use]
    pub fn find_driver_licenses_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_driver_licenses_in_text(text)
    }

    /// Validate driver's license format for a specific state
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the license format is invalid for the specified state
    pub fn validate_driver_license(&self, license: &str, state: &str) -> Result<(), Problem> {
        self.inner.validate_driver_license(license, state)
    }

    /// Redact a driver's license with explicit strategy
    #[must_use]
    pub fn redact_driver_license_with_strategy(
        &self,
        license: &str,
        strategy: DriverLicenseRedactionStrategy,
    ) -> String {
        self.inner
            .redact_driver_license_with_strategy(license, strategy)
    }

    /// Redact all driver's licenses in text with explicit strategy
    #[must_use]
    pub fn redact_driver_licenses_in_text_with_strategy(
        &self,
        text: &str,
        strategy: DriverLicenseRedactionStrategy,
    ) -> String {
        self.inner
            .redact_driver_licenses_in_text_with_strategy(text, strategy)
    }

    /// Normalize a driver's license (uppercase, remove formatting)
    #[must_use]
    pub fn normalize_driver_license(&self, license: &str) -> String {
        self.inner.normalize_driver_license(license)
    }

    /// Sanitize a driver's license (normalize + validate)
    pub fn sanitize_driver_license(&self, license: &str, state: &str) -> Result<String, Problem> {
        self.inner.sanitize_driver_license(license, state)
    }

    // ========================================================================
    // Passport Operations
    // ========================================================================

    /// Check if value is a passport number
    #[must_use]
    pub fn is_passport(&self, value: &str) -> bool {
        self.inner.is_passport(value)
    }

    /// Find all passport numbers in text
    #[must_use]
    pub fn find_passports_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_passports_in_text(text)
    }

    /// Validate passport number format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the passport number format is invalid
    pub fn validate_passport(&self, passport: &str) -> Result<(), Problem> {
        let result = self.inner.validate_passport(passport);

        if self.emit_events && result.is_err() {
            event::warn("Invalid passport number format".to_string());
        }

        result
    }

    /// Redact a passport number with explicit strategy
    #[must_use]
    pub fn redact_passport_with_strategy(
        &self,
        passport: &str,
        strategy: PassportRedactionStrategy,
    ) -> String {
        self.inner.redact_passport_with_strategy(passport, strategy)
    }

    /// Redact all passport numbers in text with explicit strategy
    #[must_use]
    pub fn redact_passports_in_text_with_strategy(
        &self,
        text: &str,
        strategy: PassportRedactionStrategy,
    ) -> String {
        self.inner
            .redact_passports_in_text_with_strategy(text, strategy)
    }

    // ========================================================================
    // National ID Operations
    // ========================================================================

    /// Check if value is a national ID
    #[must_use]
    pub fn is_national_id(&self, value: &str) -> bool {
        self.inner.is_national_id(value)
    }

    /// Find all national IDs in text
    #[must_use]
    pub fn find_national_ids_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_national_ids_in_text(text)
    }

    /// Validate national ID format (auto-detects UK NI, Canada SIN, or generic)
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the national ID format is invalid
    pub fn validate_national_id(&self, national_id: &str) -> Result<(), Problem> {
        let result = self.inner.validate_national_id(national_id);

        if self.emit_events && result.is_err() {
            event::warn("Invalid national ID format".to_string());
        }

        result
    }

    /// Validate UK National Insurance Number
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the NI number format is invalid
    pub fn validate_uk_ni(&self, ni: &str) -> Result<(), Problem> {
        self.inner.validate_uk_ni(ni)
    }

    /// Validate Canadian Social Insurance Number with Luhn checksum
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the SIN format is invalid or checksum fails
    pub fn validate_canada_sin(&self, sin: &str) -> Result<(), Problem> {
        self.inner.validate_canada_sin(sin)
    }

    /// Redact a national ID with explicit strategy
    #[must_use]
    pub fn redact_national_id_with_strategy(
        &self,
        national_id: &str,
        strategy: NationalIdRedactionStrategy,
    ) -> String {
        self.inner
            .redact_national_id_with_strategy(national_id, strategy)
    }

    /// Redact all national IDs in text with explicit strategy
    #[must_use]
    pub fn redact_national_ids_in_text_with_strategy(
        &self,
        text: &str,
        strategy: NationalIdRedactionStrategy,
    ) -> String {
        self.inner
            .redact_national_ids_in_text_with_strategy(text, strategy)
    }

    // ========================================================================
    // Vehicle ID Operations
    // ========================================================================

    /// Check if value is a vehicle ID (VIN)
    #[must_use]
    pub fn is_vehicle_id(&self, value: &str) -> bool {
        self.inner.is_vehicle_id(value)
    }

    /// Find all vehicle IDs in text
    #[must_use]
    pub fn find_vehicle_ids_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_vehicle_ids_in_text(text)
    }

    /// Validate VIN format
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the VIN format is invalid
    pub fn validate_vin(&self, vin: &str) -> Result<(), Problem> {
        self.inner.validate_vin(vin)
    }

    /// Validate VIN with checksum verification
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the VIN format is invalid or checksum fails
    pub fn validate_vin_with_checksum(&self, vin: &str) -> Result<(), Problem> {
        self.inner.validate_vin_with_checksum(vin)
    }

    /// Redact a vehicle ID with explicit strategy
    #[must_use]
    pub fn redact_vehicle_id_with_strategy(
        &self,
        vehicle_id: &str,
        strategy: VehicleIdRedactionStrategy,
    ) -> String {
        self.inner
            .redact_vehicle_id_with_strategy(vehicle_id, strategy)
    }

    /// Redact all vehicle IDs in text with explicit strategy
    #[must_use]
    pub fn redact_vehicle_ids_in_text_with_strategy(
        &self,
        text: &str,
        strategy: VehicleIdRedactionStrategy,
    ) -> String {
        self.inner
            .redact_vehicle_ids_in_text_with_strategy(text, strategy)
    }

    /// Normalize a VIN (uppercase)
    #[must_use]
    pub fn normalize_vin(&self, vin: &str) -> String {
        self.inner.normalize_vin(vin)
    }

    /// Convert VIN to display format with spaces
    #[must_use]
    pub fn to_vin_display(&self, vin: &str) -> String {
        self.inner.to_vin_display(vin)
    }

    /// Sanitize a VIN (normalize + validate)
    pub fn sanitize_vin(&self, vin: &str) -> Result<String, Problem> {
        self.inner.sanitize_vin(vin)
    }

    // ========================================================================
    // Aggregate Operations
    // ========================================================================

    /// Check if value is any government identifier
    #[must_use]
    pub fn is_government_identifier(&self, value: &str) -> bool {
        self.inner.is_government_identifier(value)
    }

    /// Check if text contains any government identifier
    pub fn is_government_present(&self, text: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_government_present(text);

        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result {
                increment_by(metric_names::government_data_found(), 1);
                event::debug("Government identifier present in text".to_string());
            }
        }

        result
    }

    /// Find all government IDs in text
    #[must_use]
    pub fn find_all_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let start = Instant::now();
        let results = self.inner.find_all_in_text(text);

        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !results.is_empty() {
                increment_by(metric_names::detected(), results.len() as u64);
            }
        }

        results
    }

    /// Redact all government IDs in text with explicit policy
    ///
    /// # Arguments
    ///
    /// * `text` - The text to scan for government identifiers
    /// * `policy` - The redaction policy to apply
    #[must_use]
    pub fn redact_all_in_text_with_policy(
        &self,
        text: &str,
        policy: super::super::types::GovernmentTextPolicy,
    ) -> String {
        let start = Instant::now();
        let result = self.inner.redact_all_in_text_with_policy(text, policy);

        if self.emit_events {
            record(
                metric_names::redact_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }

        result
    }

    // ========================================================================
    // Test Pattern Detection
    // ========================================================================

    /// Check if VIN is a known test pattern
    #[must_use]
    pub fn is_test_vin(&self, vin: &str) -> bool {
        self.inner.is_test_vin(vin)
    }

    /// Check if EIN is a known test pattern
    #[must_use]
    pub fn is_test_ein(&self, ein: &str) -> bool {
        self.inner.is_test_ein(ein)
    }

    /// Check if driver's license is a known test pattern
    #[must_use]
    pub fn is_test_driver_license(&self, license: &str) -> bool {
        self.inner.is_test_driver_license(license)
    }

    /// Check if SSN is a known test/sample pattern
    ///
    /// Test SSNs like "123-45-6789", "078-05-1120" (Woolworth's wallet),
    /// or all same digit patterns (555-55-5555) should not be treated
    /// as real Social Security Numbers.
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::identifiers::GovernmentBuilder;
    ///
    /// let builder = GovernmentBuilder::new();
    /// assert!(builder.is_test_ssn("123-45-6789"));
    /// assert!(builder.is_test_ssn("078-05-1120")); // Woolworth's wallet
    /// assert!(builder.is_test_ssn("555-55-5555")); // All fives
    /// assert!(!builder.is_test_ssn("142-58-3697")); // Not a test pattern
    /// ```
    #[must_use]
    pub fn is_test_ssn(&self, ssn: &str) -> bool {
        self.inner.is_test_ssn(ssn)
    }

    /// Check if passport number is a known test/sample pattern
    #[must_use]
    pub fn is_test_passport(&self, passport: &str) -> bool {
        self.inner.is_test_passport(passport)
    }

    /// Check if national ID is a known test/sample pattern
    #[must_use]
    pub fn is_test_national_id(&self, national_id: &str) -> bool {
        self.inner.is_test_national_id(national_id)
    }

    /// Check if EIN prefix is valid
    #[must_use]
    pub fn is_valid_ein_prefix(&self, prefix: u8) -> bool {
        self.inner.is_valid_ein_prefix(prefix)
    }

    // =========================================================================
    // Cache Management
    // =========================================================================

    /// Get combined cache statistics for all government identifier caches
    ///
    /// Returns aggregated stats across SSN and VIN validation caches.
    /// Use this for overall module performance monitoring.
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::identifiers::GovernmentBuilder;
    ///
    /// let builder = GovernmentBuilder::new();
    /// let stats = builder.cache_stats();
    ///
    /// println!("Cache size: {}/{}", stats.size, stats.capacity);
    /// println!("Hit rate: {:.1}%", stats.hit_rate());
    /// ```
    #[must_use]
    pub fn cache_stats(&self) -> super::super::types::CacheStats {
        self.inner.cache_stats()
    }

    /// Get SSN validation cache statistics
    ///
    /// Use this for debugging specific cache performance.
    #[must_use]
    pub fn ssn_cache_stats(&self) -> super::super::types::CacheStats {
        self.inner.ssn_cache_stats()
    }

    /// Get VIN validation cache statistics
    ///
    /// Use this for debugging specific cache performance.
    #[must_use]
    pub fn vin_cache_stats(&self) -> super::super::types::CacheStats {
        self.inner.vin_cache_stats()
    }

    /// Clear all government identifier caches
    ///
    /// Use this to reset cache state, typically for testing or memory management.
    pub fn clear_caches(&self) {
        self.inner.clear_caches();
    }

    // ========================================================================
    // Australia: TFN and ABN
    // ========================================================================

    /// Check if value matches an Australian Tax File Number pattern
    #[must_use]
    pub fn is_australia_tfn(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_australia_tfn(value);
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

    /// Validate Australian TFN format
    pub fn validate_australia_tfn(&self, tfn: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_australia_tfn(tfn);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                event::warn("Invalid Australia TFN format".to_string());
            }
        }
        result
    }

    /// Validate Australian TFN with weighted checksum verification
    pub fn validate_australia_tfn_with_checksum(&self, tfn: &str) -> Result<(), Problem> {
        self.inner.validate_australia_tfn_with_checksum(tfn)
    }

    /// Check if value matches an Australian Business Number pattern
    #[must_use]
    pub fn is_australia_abn(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_australia_abn(value);
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

    /// Validate Australian ABN format
    pub fn validate_australia_abn(&self, abn: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_australia_abn(abn);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                event::warn("Invalid Australia ABN format".to_string());
            }
        }
        result
    }

    /// Validate Australian ABN with weighted checksum verification
    pub fn validate_australia_abn_with_checksum(&self, abn: &str) -> Result<(), Problem> {
        self.inner.validate_australia_abn_with_checksum(abn)
    }

    // ========================================================================
    // India: Aadhaar and PAN
    // ========================================================================

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
                event::warn("Invalid India Aadhaar format".to_string());
            }
        }
        result
    }

    /// Validate Indian Aadhaar with Verhoeff checksum verification
    pub fn validate_india_aadhaar_with_checksum(&self, aadhaar: &str) -> Result<(), Problem> {
        self.inner.validate_india_aadhaar_with_checksum(aadhaar)
    }

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
                event::warn("Invalid India PAN format".to_string());
            }
        }
        result
    }

    // ========================================================================
    // Finland: HETU
    // ========================================================================

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
                event::warn("Invalid Finland HETU format".to_string());
            }
        }
        result
    }

    /// Validate Finnish HETU with mod-31 checksum verification
    pub fn validate_finland_hetu_with_checksum(&self, hetu: &str) -> Result<(), Problem> {
        self.inner.validate_finland_hetu_with_checksum(hetu)
    }

    // ========================================================================
    // Spain: NIF and NIE
    // ========================================================================

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
                event::warn("Invalid Spain NIF format".to_string());
            }
        }
        result
    }

    /// Validate Spanish NIF with mod-23 checksum verification
    pub fn validate_spain_nif_with_checksum(&self, nif: &str) -> Result<(), Problem> {
        self.inner.validate_spain_nif_with_checksum(nif)
    }

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
                event::warn("Invalid Spain NIE format".to_string());
            }
        }
        result
    }

    /// Validate Spanish NIE with mod-23 checksum verification
    pub fn validate_spain_nie_with_checksum(&self, nie: &str) -> Result<(), Problem> {
        self.inner.validate_spain_nie_with_checksum(nie)
    }

    // ========================================================================
    // Italy: Codice Fiscale
    // ========================================================================

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
                event::warn("Invalid Italy Codice Fiscale format".to_string());
            }
        }
        result
    }

    /// Validate Italian Codice Fiscale with check character verification
    pub fn validate_italy_fiscal_code_with_checksum(&self, cf: &str) -> Result<(), Problem> {
        self.inner.validate_italy_fiscal_code_with_checksum(cf)
    }

    // ========================================================================
    // Poland: PESEL
    // ========================================================================

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
                event::warn("Invalid Poland PESEL format".to_string());
            }
        }
        result
    }

    /// Validate Polish PESEL with weighted checksum verification
    pub fn validate_poland_pesel_with_checksum(&self, pesel: &str) -> Result<(), Problem> {
        self.inner.validate_poland_pesel_with_checksum(pesel)
    }

    // ========================================================================
    // Singapore: NRIC/FIN
    // ========================================================================

    /// Check if value matches a Singapore NRIC/FIN pattern
    #[must_use]
    pub fn is_singapore_nric(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_singapore_nric(value);
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

    /// Validate Singapore NRIC/FIN format
    pub fn validate_singapore_nric(&self, nric: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_singapore_nric(nric);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                event::warn("Invalid Singapore NRIC format".to_string());
            }
        }
        result
    }

    /// Validate Singapore NRIC/FIN with check letter verification
    pub fn validate_singapore_nric_with_checksum(&self, nric: &str) -> Result<(), Problem> {
        self.inner.validate_singapore_nric_with_checksum(nric)
    }

    // ========================================================================
    // South Korea: RRN
    // ========================================================================

    /// Check if value matches a South Korean RRN pattern
    #[must_use]
    pub fn is_korea_rrn(&self, value: &str) -> bool {
        let start = Instant::now();
        let result = self.inner.is_korea_rrn(value);
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

    /// Validate South Korean RRN format
    pub fn validate_korea_rrn(&self, rrn: &str) -> Result<(), Problem> {
        let start = Instant::now();
        let result = self.inner.validate_korea_rrn(rrn);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if result.is_err() {
                event::warn("Invalid Korea RRN format".to_string());
            }
        }
        result
    }

    /// Validate South Korean RRN with weighted checksum verification
    pub fn validate_korea_rrn_with_checksum(&self, rrn: &str) -> Result<(), Problem> {
        self.inner.validate_korea_rrn_with_checksum(rrn)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = GovernmentBuilder::new();
        assert!(builder.emit_events);

        let silent = GovernmentBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = GovernmentBuilder::new().with_events(false);
        assert!(!builder.emit_events);

        let builder = GovernmentBuilder::silent().with_events(true);
        assert!(builder.emit_events);
    }

    #[test]
    fn test_ssn_detection() {
        let builder = GovernmentBuilder::silent();
        assert!(builder.is_ssn("517-29-8346"));
    }

    #[test]
    fn test_ssn_redaction_with_strategy() {
        let builder = GovernmentBuilder::silent();
        assert_eq!(
            builder.redact_ssn_with_strategy("517-29-8346", SsnRedactionStrategy::Token),
            "[SSN]"
        );
        assert_eq!(
            builder.redact_ssn_with_strategy("517-29-8346", SsnRedactionStrategy::LastFour),
            "***-**-8346"
        );
    }
}
