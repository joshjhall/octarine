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

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_test_vin() {
        let b = GovernmentBuilder::silent();
        // All-ones and the documented "1HGBH41JXMN109186" example are known
        // placeholders; "WF0XXXGCDW1234567" is a real-format VIN.
        assert!(b.is_test_vin("11111111111111111"));
        assert!(b.is_test_vin("1HGBH41JXMN109186"));
        assert!(!b.is_test_vin("WF0XXXGCDW1234567"));
    }

    #[test]
    fn test_is_test_ssn() {
        let b = GovernmentBuilder::silent();
        // Documented sample SSNs.
        assert!(b.is_test_ssn("123-45-6789"));
        assert!(b.is_test_ssn("078-05-1120")); // Woolworth's wallet
        assert!(b.is_test_ssn("555-55-5555")); // all fives
        assert!(!b.is_test_ssn("142-58-3697"));
    }

    #[test]
    fn test_is_test_ein() {
        let b = GovernmentBuilder::silent();
        // "00-0000000" (all zeros) and "12-3456789" (121234567, a documented
        // sample) are placeholders; "46-1234567" is a real-format EIN.
        assert!(b.is_test_ein("00-0000000"));
        assert!(b.is_test_ein("12-3456789"));
        assert!(!b.is_test_ein("46-1234567"));
    }

    #[test]
    fn test_is_test_driver_license() {
        let b = GovernmentBuilder::silent();
        // "TEST1234" / "A0000000" are placeholder DLs; "D1234567" is not.
        assert!(b.is_test_driver_license("TEST1234"));
        assert!(b.is_test_driver_license("A0000000"));
        assert!(!b.is_test_driver_license("D1234567"));
    }

    #[test]
    fn test_is_test_passport() {
        let b = GovernmentBuilder::silent();
        // "C12345678" is a documented sample passport; "L83726159" is not.
        assert!(b.is_test_passport("C12345678"));
        assert!(!b.is_test_passport("L83726159"));
    }

    #[test]
    fn test_is_test_national_id() {
        let b = GovernmentBuilder::silent();
        // Sequential ascending 9-digit is a placeholder national ID.
        assert!(b.is_test_national_id("123456789"));
        assert!(!b.is_test_national_id("AB123456C"));
    }

    #[test]
    fn test_is_valid_ein_prefix() {
        let b = GovernmentBuilder::silent();
        // 12 is the Brookhaven IRS campus code (valid); 00 is not assigned.
        assert!(b.is_valid_ein_prefix(12));
        assert!(!b.is_valid_ein_prefix(0));
    }
}
