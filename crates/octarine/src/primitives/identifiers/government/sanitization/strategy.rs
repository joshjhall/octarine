//! Government identifier redaction strategies
//!
//! Defines the available strategies for redacting government identifiers.

// ============================================================================
// SSN Redaction Strategies
// ============================================================================

/// SSN redaction strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SsnRedactionStrategy {
    /// Replace with `[SSN]` token
    #[default]
    Token,
    /// Replace all digits with asterisks, preserve format
    Mask,
    /// Replace with generic `[REDACTED]`
    Anonymous,
    /// Show last 4 digits: `***-**-6789`
    LastFour,
    /// Show first 5 digits: `123-45-****` (RISKY - leaks geographic area)
    FirstFive,
    /// Skip redaction (pass-through)
    Skip,
}

impl SsnRedactionStrategy {
    /// Check if strategy is risky for production use
    #[must_use]
    pub fn is_risky(&self) -> bool {
        matches!(self, Self::FirstFive | Self::Skip)
    }
}

// ============================================================================
// Tax ID Redaction Strategies
// ============================================================================

/// Tax ID (EIN/TIN/ITIN) redaction strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TaxIdRedactionStrategy {
    /// Replace with `[TAX_ID]` token
    #[default]
    Token,
    /// Replace all digits with asterisks, preserve format
    Mask,
    /// Replace with generic `[REDACTED]`
    Anonymous,
    /// Show first 2 digits (IRS campus code): `12-*******`
    ShowPrefix,
    /// Skip redaction (pass-through)
    Skip,
}

impl TaxIdRedactionStrategy {
    /// Check if strategy is risky for production use
    #[must_use]
    pub fn is_risky(&self) -> bool {
        matches!(self, Self::Skip)
    }
}

// ============================================================================
// Driver License Redaction Strategies
// ============================================================================

/// Driver's license redaction strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DriverLicenseRedactionStrategy {
    /// Replace with `[DRIVER_LICENSE]` token
    #[default]
    Token,
    /// Replace all characters with asterisks
    Mask,
    /// Replace with generic `[REDACTED]`
    Anonymous,
    /// Show last 4 characters: `****4567`
    LastFour,
    /// Skip redaction (pass-through)
    Skip,
}

impl DriverLicenseRedactionStrategy {
    /// Check if strategy is risky for production use
    #[must_use]
    pub fn is_risky(&self) -> bool {
        matches!(self, Self::Skip)
    }
}

// ============================================================================
// Passport Redaction Strategies
// ============================================================================

/// Passport redaction strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PassportRedactionStrategy {
    /// Replace with `[PASSPORT]` token
    #[default]
    Token,
    /// Replace all characters with asterisks
    Mask,
    /// Replace with generic `[REDACTED]`
    Anonymous,
    /// Show first 2 characters (country code): `US*******`
    ShowCountry,
    /// Skip redaction (pass-through)
    Skip,
}

impl PassportRedactionStrategy {
    /// Check if strategy is risky for production use
    #[must_use]
    pub fn is_risky(&self) -> bool {
        matches!(self, Self::Skip)
    }
}

// ============================================================================
// National ID Redaction Strategies
// ============================================================================

/// National ID redaction strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NationalIdRedactionStrategy {
    /// Replace with `[NATIONAL_ID]` token
    #[default]
    Token,
    /// Replace all characters with asterisks
    Mask,
    /// Replace with generic `[REDACTED]`
    Anonymous,
    /// Show last 4 characters: `****456C`
    LastFour,
    /// Skip redaction (pass-through)
    Skip,
}

impl NationalIdRedactionStrategy {
    /// Check if strategy is risky for production use
    #[must_use]
    pub fn is_risky(&self) -> bool {
        matches!(self, Self::Skip)
    }
}

// ============================================================================
// Vehicle ID Redaction Strategies
// ============================================================================

/// Vehicle ID (VIN) redaction strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VehicleIdRedactionStrategy {
    /// Replace with `[VEHICLE_ID]` token
    #[default]
    Token,
    /// Replace all characters with asterisks
    Mask,
    /// Replace with generic `[REDACTED]`
    Anonymous,
    /// Show WMI (first 3 characters): `1HG**************`
    ShowWmi,
    /// Skip redaction (pass-through)
    Skip,
}

impl VehicleIdRedactionStrategy {
    /// Check if strategy is risky for production use
    #[must_use]
    pub fn is_risky(&self) -> bool {
        matches!(self, Self::Skip)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_ssn_strategy_risky() {
        assert!(!SsnRedactionStrategy::Token.is_risky());
        assert!(!SsnRedactionStrategy::Mask.is_risky());
        assert!(!SsnRedactionStrategy::LastFour.is_risky());
        assert!(SsnRedactionStrategy::FirstFive.is_risky());
        assert!(SsnRedactionStrategy::Skip.is_risky());
    }

    #[test]
    fn test_tax_id_strategy_risky() {
        assert!(!TaxIdRedactionStrategy::Token.is_risky());
        assert!(!TaxIdRedactionStrategy::ShowPrefix.is_risky());
        assert!(TaxIdRedactionStrategy::Skip.is_risky());
    }

    #[test]
    fn test_driver_license_strategy_risky() {
        assert!(!DriverLicenseRedactionStrategy::Token.is_risky());
        assert!(!DriverLicenseRedactionStrategy::LastFour.is_risky());
        assert!(DriverLicenseRedactionStrategy::Skip.is_risky());
    }

    #[test]
    fn test_passport_strategy_risky() {
        assert!(!PassportRedactionStrategy::Token.is_risky());
        assert!(!PassportRedactionStrategy::ShowCountry.is_risky());
        assert!(PassportRedactionStrategy::Skip.is_risky());
    }

    #[test]
    fn test_national_id_strategy_risky() {
        assert!(!NationalIdRedactionStrategy::Token.is_risky());
        assert!(!NationalIdRedactionStrategy::LastFour.is_risky());
        assert!(NationalIdRedactionStrategy::Skip.is_risky());
    }

    #[test]
    fn test_vehicle_id_strategy_risky() {
        assert!(!VehicleIdRedactionStrategy::Token.is_risky());
        assert!(!VehicleIdRedactionStrategy::ShowWmi.is_risky());
        assert!(VehicleIdRedactionStrategy::Skip.is_risky());
    }
}
