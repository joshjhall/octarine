//! Location identifier builder with observability
//!
//! Wraps `primitives::identifiers::LocationIdentifierBuilder` with observe instrumentation.
//!
//! This is the **public API** (Layer 3) that wraps the primitive builder
//! with observe instrumentation for compliance-grade audit trails.

use std::borrow::Cow;

use crate::observe::Problem;
use crate::primitives::identifiers::{
    AddressRedactionStrategy, GpsRedactionStrategy, LocationIdentifierBuilder,
    PostalCodeRedactionStrategy,
};

use super::super::types::{
    GpsFormat, IdentifierMatch, IdentifierType, LocationTextPolicy, PostalCodeNormalization,
    PostalCodeType,
};

/// Location identifier builder with observability
#[derive(Debug, Clone, Copy, Default)]
pub struct LocationBuilder {
    inner: LocationIdentifierBuilder,
    emit_events: bool,
}

impl LocationBuilder {
    /// Create a new LocationBuilder with observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: LocationIdentifierBuilder::new(),
            emit_events: true,
        }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self {
            inner: LocationIdentifierBuilder::new(),
            emit_events: false,
        }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    // =========================================================================
    // Detection Methods
    // =========================================================================

    /// Detect location identifier type from input string
    #[must_use]
    pub fn detect(&self, value: &str) -> Option<IdentifierType> {
        self.inner.detect(value)
    }

    /// Check if value is a location identifier
    #[must_use]
    pub fn is_location_identifier(&self, value: &str) -> bool {
        self.inner.is_location_identifier(value)
    }

    /// Check if value is a GPS coordinate
    #[must_use]
    pub fn is_gps_coordinate(&self, value: &str) -> bool {
        self.inner.is_gps_coordinate(value)
    }

    /// Check if value is a street address
    #[must_use]
    pub fn is_street_address(&self, value: &str) -> bool {
        self.inner.is_street_address(value)
    }

    /// Check if value is a postal code
    #[must_use]
    pub fn is_postal_code(&self, value: &str) -> bool {
        self.inner.is_postal_code(value)
    }

    /// Find all GPS coordinates in text
    #[must_use]
    pub fn find_gps_coordinates_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_gps_coordinates_in_text(text)
    }

    /// Find all street addresses in text
    #[must_use]
    pub fn find_addresses_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_addresses_in_text(text)
    }

    /// Find all postal codes in text
    #[must_use]
    pub fn find_postal_codes_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_postal_codes_in_text(text)
    }

    /// Find all location identifiers in text
    #[must_use]
    pub fn find_all_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.find_all_in_text(text)
    }

    // =========================================================================
    // Test Data Detection Methods
    // =========================================================================

    /// Check if GPS coordinate is likely test/dummy data
    #[must_use]
    pub fn is_test_gps_coordinate(&self, coordinate: &str) -> bool {
        self.inner.is_test_gps_coordinate(coordinate)
    }

    /// Check if postal code is likely test/dummy data
    #[must_use]
    pub fn is_test_postal_code(&self, postal_code: &str) -> bool {
        self.inner.is_test_postal_code(postal_code)
    }

    // =========================================================================
    // Validation Methods
    // =========================================================================

    /// Validate GPS coordinate format (returns Result)
    pub fn validate_gps_coordinate(&self, coordinate: &str) -> Result<GpsFormat, Problem> {
        self.inner.validate_gps_coordinate(coordinate)
    }

    /// Validate street address format (returns Result)
    pub fn validate_street_address(&self, address: &str) -> Result<(), Problem> {
        self.inner.validate_street_address(address)
    }

    /// Validate postal code format (returns Result)
    pub fn validate_postal_code(&self, postal_code: &str) -> Result<PostalCodeType, Problem> {
        self.inner.validate_postal_code(postal_code)
    }

    // =========================================================================
    // Sanitization Methods - Individual Redaction (Strategy Required)
    // =========================================================================

    /// Redact GPS coordinate with explicit strategy
    #[must_use]
    pub fn redact_gps_coordinate_with_strategy(
        &self,
        coord: &str,
        strategy: GpsRedactionStrategy,
    ) -> String {
        self.inner
            .redact_gps_coordinate_with_strategy(coord, strategy)
    }

    /// Redact street address with explicit strategy
    #[must_use]
    pub fn redact_street_address_with_strategy(
        &self,
        address: &str,
        strategy: AddressRedactionStrategy,
    ) -> String {
        self.inner
            .redact_street_address_with_strategy(address, strategy)
    }

    /// Redact postal code with explicit strategy
    #[must_use]
    pub fn redact_postal_code_with_strategy(
        &self,
        code: &str,
        strategy: PostalCodeRedactionStrategy,
    ) -> String {
        self.inner.redact_postal_code_with_strategy(code, strategy)
    }

    // =========================================================================
    // Sanitization Methods - Text Redaction (Strategy Required)
    // =========================================================================

    /// Redact all GPS coordinates in text with explicit strategy
    #[must_use]
    pub fn redact_gps_coordinates_in_text_with_strategy<'a>(
        &self,
        text: &'a str,
        policy: LocationTextPolicy,
    ) -> Cow<'a, str> {
        self.inner
            .redact_gps_coordinates_in_text_with_strategy(text, policy)
    }

    /// Redact all street addresses in text with explicit strategy
    #[must_use]
    pub fn redact_addresses_in_text_with_strategy<'a>(
        &self,
        text: &'a str,
        policy: LocationTextPolicy,
    ) -> Cow<'a, str> {
        self.inner
            .redact_addresses_in_text_with_strategy(text, policy)
    }

    /// Redact all postal codes in text with explicit strategy
    #[must_use]
    pub fn redact_postal_codes_in_text_with_strategy<'a>(
        &self,
        text: &'a str,
        policy: LocationTextPolicy,
    ) -> Cow<'a, str> {
        self.inner
            .redact_postal_codes_in_text_with_strategy(text, policy)
    }

    /// Redact all location data with explicit strategy
    #[must_use]
    pub fn redact_all_in_text_with_strategy(
        &self,
        text: &str,
        policy: LocationTextPolicy,
    ) -> String {
        self.inner.redact_all_in_text_with_strategy(text, policy)
    }

    // =========================================================================
    // Strict Sanitization (Normalize + Validate)
    // =========================================================================

    /// Sanitize GPS coordinate strict (normalize format + validate)
    pub fn sanitize_gps_coordinate(&self, coord: &str) -> Result<String, Problem> {
        self.inner.sanitize_gps_coordinate(coord)
    }

    /// Sanitize postal code strict (normalize format + validate)
    pub fn sanitize_postal_code(&self, code: &str) -> Result<String, Problem> {
        self.inner.sanitize_postal_code(code)
    }

    /// Sanitize street address strict (normalize format + validate)
    pub fn sanitize_street_address(&self, address: &str) -> Result<String, Problem> {
        self.inner.sanitize_street_address(address)
    }

    // =========================================================================
    // Cache Management
    // =========================================================================

    /// Get combined cache statistics for all location identifier caches
    ///
    /// Returns aggregated stats across GPS and postal code validation caches.
    /// Use this for overall module performance monitoring.
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::identifiers::LocationBuilder;
    ///
    /// let builder = LocationBuilder::new();
    /// let stats = builder.cache_stats();
    ///
    /// println!("Cache size: {}/{}", stats.size, stats.capacity);
    /// println!("Hit rate: {:.1}%", stats.hit_rate());
    /// ```
    #[must_use]
    pub fn cache_stats(&self) -> super::super::types::CacheStats {
        self.inner.cache_stats()
    }

    /// Get GPS coordinate validation cache statistics
    ///
    /// Use this for debugging specific cache performance.
    #[must_use]
    pub fn gps_cache_stats(&self) -> super::super::types::CacheStats {
        self.inner.gps_cache_stats()
    }

    /// Get postal code validation cache statistics
    ///
    /// Use this for debugging specific cache performance.
    #[must_use]
    pub fn postal_cache_stats(&self) -> super::super::types::CacheStats {
        self.inner.postal_cache_stats()
    }

    /// Clear all location identifier caches
    ///
    /// Use this to reset cache state, typically for testing or memory management.
    pub fn clear_caches(&self) {
        self.inner.clear_caches();
    }

    /// Clear GPS coordinate validation cache
    pub fn clear_gps_cache(&self) {
        self.inner.clear_gps_cache();
    }

    /// Clear postal code validation cache
    pub fn clear_postal_cache(&self) {
        self.inner.clear_postal_cache();
    }

    // =========================================================================
    // Conversion Methods
    // =========================================================================

    /// Normalize GPS coordinate to canonical decimal degrees format
    ///
    /// Converts various GPS coordinate formats to standard decimal degrees
    /// with consistent spacing and precision.
    pub fn normalize_gps_coordinate(&self, coordinate: &str) -> Result<String, Problem> {
        self.inner.normalize_gps_coordinate(coordinate)
    }

    /// Detect GPS coordinate format
    ///
    /// Returns the format of a GPS coordinate string, or None if not recognized.
    #[must_use]
    pub fn detect_gps_format(&self, coordinate: &str) -> Option<GpsFormat> {
        self.inner.detect_gps_format(coordinate)
    }

    /// Normalize postal code to standard format
    ///
    /// Converts various postal code formats to standardized representation
    /// with consistent spacing, capitalization, and formatting.
    pub fn normalize_postal_code(
        &self,
        postal_code: &str,
        mode: PostalCodeNormalization,
    ) -> Result<String, Problem> {
        self.inner.normalize_postal_code(postal_code, mode)
    }

    /// Detect the type of postal code
    ///
    /// Determines whether a postal code is a US ZIP, US ZIP+4, UK postcode,
    /// or Canadian postal code based on format patterns.
    #[must_use]
    pub fn detect_postal_code_type(&self, postal_code: &str) -> Option<PostalCodeType> {
        self.inner.detect_postal_code_type(postal_code)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = LocationBuilder::new();
        assert!(builder.emit_events);

        let silent = LocationBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = LocationBuilder::new().with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_gps_detection() {
        let builder = LocationBuilder::silent();
        assert!(builder.is_gps_coordinate("40.7128, -74.0060"));
    }
}
