//! Test-pattern detection methods.

use super::*;

impl GovernmentBuilder {
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
}
