//! Test/dummy pattern detection on `GovernmentIdentifierBuilder`.
//!
//! Per-country `is_test_*` methods live with their domain (e.g.
//! `is_test_india_aadhaar` is in `india.rs`). This module covers the
//! shared cross-domain test-pattern checks and the EIN prefix validator.

use super::*;

impl GovernmentIdentifierBuilder {
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
        common::is_test_ssn(ssn)
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

    fn builder() -> GovernmentIdentifierBuilder {
        GovernmentIdentifierBuilder::new()
    }

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
