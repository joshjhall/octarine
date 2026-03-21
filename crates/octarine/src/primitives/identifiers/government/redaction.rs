//! Government identifier redaction strategies (primitives layer)
//!
//! Type-safe redaction strategies for government identifiers with NO logging.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - defines redaction strategies with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Type-safe strategy enums
//!
//! # Design Pattern: Two-Tier Strategy Architecture
//!
//! ## Tier 1: Domain-Specific Strategies (For Individual Identifiers)
//!
//! Each government identifier type has its own strategy enum with specific options:
//! - `SsnRedactionStrategy` - For single SSNs
//! - `TaxIdRedactionStrategy` - For EIN/TIN/ITIN
//! - `DriverLicenseRedactionStrategy` - For driver's licenses
//! - `PassportRedactionStrategy` - For passports
//! - `NationalIdRedactionStrategy` - For national IDs
//! - `VehicleIdRedactionStrategy` - For VINs
//!
//! ## Tier 2: Generic Text Policy (For Text Scanning)
//!
//! `TextRedactionPolicy` provides a simpler, generic interface for text scanning:
//! - Maps to appropriate domain strategy for each identifier type
//! - Used by `*_in_text()` functions
//! - Consistent across all identifier types
//!
//! # Compliance Coverage
//!
//! Government identifiers handled by this module are protected under:
//!
//! | Identifier | Privacy Risk | Recommended Policy |
//! |------------|--------------|-------------------|
//! | SSN | Very High (identity theft) | Complete or Anonymous |
//! | EIN | Medium (business identity) | Partial or Complete |
//! | Driver License | High (identity verification) | Complete |
//! | Passport | High (international identity) | Complete |
//! | VIN | Low (vehicle tracking) | Partial |
//! | National ID | Very High (varies by country) | Complete |
//!
//! # Usage
//!
//! ```ignore
//! use octarine::primitives::identifiers::government::{
//!     TextRedactionPolicy, redact_all_government_ids_in_text_with_policy
//! };
//!
//! // Text scanning with generic policy
//! let redacted = redact_all_government_ids_in_text_with_policy(
//!     "SSN: 900-00-0001, VIN: 1HGBH41JXMN109186",
//!     Some(TextRedactionPolicy::Complete)
//! );
//! // Result: "SSN: [SSN], VIN: [VEHICLE_ID]"
//! ```

use super::sanitization::{
    DriverLicenseRedactionStrategy, NationalIdRedactionStrategy, PassportRedactionStrategy,
    SsnRedactionStrategy, TaxIdRedactionStrategy, VehicleIdRedactionStrategy,
};

/// Generic redaction policy for text scanning
///
/// Simpler interface that maps to domain-specific strategies.
/// Used by `*_in_text()` functions for consistent text redaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TextRedactionPolicy {
    /// Skip redaction - pass through unchanged
    Skip,
    /// Partial redaction (show last 4 for SSN, show WMI for VIN, etc.)
    Partial,
    /// Complete redaction (use type tokens like [SSN], [VEHICLE_ID])
    #[default]
    Complete,
    /// Anonymous redaction (generic `[REDACTED]` for all types)
    Anonymous,
}

impl TextRedactionPolicy {
    /// Convert policy to SSN redaction strategy
    #[must_use]
    pub const fn to_ssn_strategy(self) -> SsnRedactionStrategy {
        match self {
            Self::Skip => SsnRedactionStrategy::Skip,
            Self::Partial => SsnRedactionStrategy::LastFour,
            Self::Complete => SsnRedactionStrategy::Token,
            Self::Anonymous => SsnRedactionStrategy::Anonymous,
        }
    }

    /// Convert policy to Tax ID redaction strategy
    #[must_use]
    pub const fn to_tax_id_strategy(self) -> TaxIdRedactionStrategy {
        match self {
            Self::Skip => TaxIdRedactionStrategy::Skip,
            Self::Partial => TaxIdRedactionStrategy::ShowPrefix,
            Self::Complete => TaxIdRedactionStrategy::Token,
            Self::Anonymous => TaxIdRedactionStrategy::Anonymous,
        }
    }

    /// Convert policy to Driver License redaction strategy
    #[must_use]
    pub const fn to_driver_license_strategy(self) -> DriverLicenseRedactionStrategy {
        match self {
            Self::Skip => DriverLicenseRedactionStrategy::Skip,
            Self::Partial => DriverLicenseRedactionStrategy::LastFour,
            Self::Complete => DriverLicenseRedactionStrategy::Token,
            Self::Anonymous => DriverLicenseRedactionStrategy::Anonymous,
        }
    }

    /// Convert policy to Passport redaction strategy
    #[must_use]
    pub const fn to_passport_strategy(self) -> PassportRedactionStrategy {
        match self {
            Self::Skip => PassportRedactionStrategy::Skip,
            Self::Partial => PassportRedactionStrategy::ShowCountry,
            Self::Complete => PassportRedactionStrategy::Token,
            Self::Anonymous => PassportRedactionStrategy::Anonymous,
        }
    }

    /// Convert policy to National ID redaction strategy
    #[must_use]
    pub const fn to_national_id_strategy(self) -> NationalIdRedactionStrategy {
        match self {
            Self::Skip => NationalIdRedactionStrategy::Skip,
            Self::Partial => NationalIdRedactionStrategy::LastFour,
            Self::Complete => NationalIdRedactionStrategy::Token,
            Self::Anonymous => NationalIdRedactionStrategy::Anonymous,
        }
    }

    /// Convert policy to Vehicle ID redaction strategy
    #[must_use]
    pub const fn to_vehicle_id_strategy(self) -> VehicleIdRedactionStrategy {
        match self {
            Self::Skip => VehicleIdRedactionStrategy::Skip,
            Self::Partial => VehicleIdRedactionStrategy::ShowWmi,
            Self::Complete => VehicleIdRedactionStrategy::Token,
            Self::Anonymous => VehicleIdRedactionStrategy::Anonymous,
        }
    }

    /// Check if this policy performs any redaction
    #[must_use]
    pub const fn is_active(&self) -> bool {
        !matches!(self, Self::Skip)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_text_policy_to_ssn_strategy() {
        assert_eq!(
            TextRedactionPolicy::Skip.to_ssn_strategy(),
            SsnRedactionStrategy::Skip
        );
        assert_eq!(
            TextRedactionPolicy::Partial.to_ssn_strategy(),
            SsnRedactionStrategy::LastFour
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_ssn_strategy(),
            SsnRedactionStrategy::Token
        );
        assert_eq!(
            TextRedactionPolicy::Anonymous.to_ssn_strategy(),
            SsnRedactionStrategy::Anonymous
        );
    }

    #[test]
    fn test_text_policy_to_tax_id_strategy() {
        assert_eq!(
            TextRedactionPolicy::Skip.to_tax_id_strategy(),
            TaxIdRedactionStrategy::Skip
        );
        assert_eq!(
            TextRedactionPolicy::Partial.to_tax_id_strategy(),
            TaxIdRedactionStrategy::ShowPrefix
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_tax_id_strategy(),
            TaxIdRedactionStrategy::Token
        );
        assert_eq!(
            TextRedactionPolicy::Anonymous.to_tax_id_strategy(),
            TaxIdRedactionStrategy::Anonymous
        );
    }

    #[test]
    fn test_text_policy_to_driver_license_strategy() {
        assert_eq!(
            TextRedactionPolicy::Skip.to_driver_license_strategy(),
            DriverLicenseRedactionStrategy::Skip
        );
        assert_eq!(
            TextRedactionPolicy::Partial.to_driver_license_strategy(),
            DriverLicenseRedactionStrategy::LastFour
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_driver_license_strategy(),
            DriverLicenseRedactionStrategy::Token
        );
        assert_eq!(
            TextRedactionPolicy::Anonymous.to_driver_license_strategy(),
            DriverLicenseRedactionStrategy::Anonymous
        );
    }

    #[test]
    fn test_text_policy_to_passport_strategy() {
        assert_eq!(
            TextRedactionPolicy::Skip.to_passport_strategy(),
            PassportRedactionStrategy::Skip
        );
        assert_eq!(
            TextRedactionPolicy::Partial.to_passport_strategy(),
            PassportRedactionStrategy::ShowCountry
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_passport_strategy(),
            PassportRedactionStrategy::Token
        );
        assert_eq!(
            TextRedactionPolicy::Anonymous.to_passport_strategy(),
            PassportRedactionStrategy::Anonymous
        );
    }

    #[test]
    fn test_text_policy_to_national_id_strategy() {
        assert_eq!(
            TextRedactionPolicy::Skip.to_national_id_strategy(),
            NationalIdRedactionStrategy::Skip
        );
        assert_eq!(
            TextRedactionPolicy::Partial.to_national_id_strategy(),
            NationalIdRedactionStrategy::LastFour
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_national_id_strategy(),
            NationalIdRedactionStrategy::Token
        );
        assert_eq!(
            TextRedactionPolicy::Anonymous.to_national_id_strategy(),
            NationalIdRedactionStrategy::Anonymous
        );
    }

    #[test]
    fn test_text_policy_to_vehicle_id_strategy() {
        assert_eq!(
            TextRedactionPolicy::Skip.to_vehicle_id_strategy(),
            VehicleIdRedactionStrategy::Skip
        );
        assert_eq!(
            TextRedactionPolicy::Partial.to_vehicle_id_strategy(),
            VehicleIdRedactionStrategy::ShowWmi
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_vehicle_id_strategy(),
            VehicleIdRedactionStrategy::Token
        );
        assert_eq!(
            TextRedactionPolicy::Anonymous.to_vehicle_id_strategy(),
            VehicleIdRedactionStrategy::Anonymous
        );
    }

    #[test]
    fn test_default_is_complete() {
        assert_eq!(
            TextRedactionPolicy::default(),
            TextRedactionPolicy::Complete
        );
    }

    #[test]
    fn test_is_active() {
        assert!(!TextRedactionPolicy::Skip.is_active());
        assert!(TextRedactionPolicy::Partial.is_active());
        assert!(TextRedactionPolicy::Complete.is_active());
        assert!(TextRedactionPolicy::Anonymous.is_active());
    }
}
