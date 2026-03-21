//! Strategy-based redaction functions for government IDs
//!
//! Functions that redact various government identifiers using explicit strategies.

use super::super::super::common::masking;
use super::strategy::{
    DriverLicenseRedactionStrategy, NationalIdRedactionStrategy, PassportRedactionStrategy,
    TaxIdRedactionStrategy, VehicleIdRedactionStrategy,
};

// ============================================================================
// Tax ID Redaction
// ============================================================================

/// Redact Tax ID (EIN/TIN/ITIN) with explicit strategy
///
/// # Strategies
///
/// - `Token` → `[TAX_ID]`
/// - `Mask` → `**-*******`
/// - `Anonymous` → `[Redacted]`
/// - `ShowPrefix` → `12-*******` (shows IRS campus code)
/// - `Skip` → unchanged
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::sanitization::{
///     redact_tax_id_with_strategy, TaxIdRedactionStrategy
/// };
///
/// let token = redact_tax_id_with_strategy("12-3456789", TaxIdRedactionStrategy::Token);
/// assert_eq!(token, "[TAX_ID]");
///
/// let prefix = redact_tax_id_with_strategy("12-3456789", TaxIdRedactionStrategy::ShowPrefix);
/// assert_eq!(prefix, "12-*******");
/// ```
#[must_use]
pub fn redact_tax_id_with_strategy(tax_id: &str, strategy: TaxIdRedactionStrategy) -> String {
    let cleaned: String = tax_id.chars().filter(|c| c.is_numeric()).collect();

    match strategy {
        TaxIdRedactionStrategy::Token => "[TAX_ID]".to_string(),

        TaxIdRedactionStrategy::Mask => {
            // Complete masking, preserve format
            if cleaned.len() == 9 {
                "**-*******".to_string()
            } else {
                masking::mask_all(tax_id, '*')
            }
        }

        TaxIdRedactionStrategy::Anonymous => "[Redacted]".to_string(),

        TaxIdRedactionStrategy::ShowPrefix => {
            // Show first 2 digits (IRS campus code): "12-*******"
            if cleaned.len() == 9 {
                format!("{}-*******", &cleaned[0..2])
            } else {
                "[TAX_ID]".to_string()
            }
        }

        TaxIdRedactionStrategy::Skip => tax_id.to_string(),
    }
}

// ============================================================================
// Driver License Redaction
// ============================================================================

/// Redact driver's license with explicit strategy
///
/// # Strategies
///
/// - `Token` → `[DRIVER_LICENSE]`
/// - `Mask` → `********`
/// - `Anonymous` → `[Redacted]`
/// - `LastFour` → `****4567`
/// - `Skip` → unchanged
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::sanitization::{
///     redact_driver_license_with_strategy, DriverLicenseRedactionStrategy
/// };
///
/// let token = redact_driver_license_with_strategy("D1234567", DriverLicenseRedactionStrategy::Token);
/// assert_eq!(token, "[DRIVER_LICENSE]");
///
/// let last4 = redact_driver_license_with_strategy("D1234567", DriverLicenseRedactionStrategy::LastFour);
/// assert_eq!(last4, "****4567");
/// ```
#[must_use]
pub fn redact_driver_license_with_strategy(
    license: &str,
    strategy: DriverLicenseRedactionStrategy,
) -> String {
    let cleaned: String = license.chars().filter(|c| c.is_alphanumeric()).collect();

    match strategy {
        DriverLicenseRedactionStrategy::Token => "[DRIVER_LICENSE]".to_string(),

        DriverLicenseRedactionStrategy::Mask => masking::mask_all(&cleaned, '*'),

        DriverLicenseRedactionStrategy::Anonymous => "[Redacted]".to_string(),

        DriverLicenseRedactionStrategy::LastFour => {
            if cleaned.len() >= 4 {
                let start_pos = cleaned.len().saturating_sub(4);
                let last_four = &cleaned[start_pos..];
                format!("****{}", last_four)
            } else {
                "[DRIVER_LICENSE]".to_string()
            }
        }

        DriverLicenseRedactionStrategy::Skip => license.to_string(),
    }
}

// ============================================================================
// Passport Redaction
// ============================================================================

/// Redact passport with explicit strategy
///
/// # Strategies
///
/// - `Token` → `[PASSPORT]`
/// - `Mask` → `*********`
/// - `Anonymous` → `[Redacted]`
/// - `ShowCountry` → `US*******` (shows first 2 characters)
/// - `Skip` → unchanged
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::sanitization::{
///     redact_passport_with_strategy, PassportRedactionStrategy
/// };
///
/// let token = redact_passport_with_strategy("US1234567", PassportRedactionStrategy::Token);
/// assert_eq!(token, "[PASSPORT]");
///
/// let country = redact_passport_with_strategy("US1234567", PassportRedactionStrategy::ShowCountry);
/// assert_eq!(country, "US*******");
/// ```
#[must_use]
pub fn redact_passport_with_strategy(
    passport: &str,
    strategy: PassportRedactionStrategy,
) -> String {
    let cleaned: String = passport.chars().filter(|c| c.is_alphanumeric()).collect();

    match strategy {
        PassportRedactionStrategy::Token => "[PASSPORT]".to_string(),

        PassportRedactionStrategy::Mask => masking::mask_all(&cleaned, '*'),

        PassportRedactionStrategy::Anonymous => "[Redacted]".to_string(),

        PassportRedactionStrategy::ShowCountry => {
            if cleaned.len() >= 2 {
                let prefix = &cleaned[0..2];
                let mask_len = cleaned.len().saturating_sub(2);
                format!("{}{}", prefix, "*".repeat(mask_len))
            } else {
                "[PASSPORT]".to_string()
            }
        }

        PassportRedactionStrategy::Skip => passport.to_string(),
    }
}

// ============================================================================
// National ID Redaction
// ============================================================================

/// Redact national ID with explicit strategy
///
/// # Strategies
///
/// - `Token` → `[NATIONAL_ID]`
/// - `Mask` → `*********`
/// - `Anonymous` → `[Redacted]`
/// - `LastFour` → `****456C`
/// - `Skip` → unchanged
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::sanitization::{
///     redact_national_id_with_strategy, NationalIdRedactionStrategy
/// };
///
/// let token = redact_national_id_with_strategy("AB123456C", NationalIdRedactionStrategy::Token);
/// assert_eq!(token, "[NATIONAL_ID]");
///
/// let last4 = redact_national_id_with_strategy("AB123456C", NationalIdRedactionStrategy::LastFour);
/// assert_eq!(last4, "****456C");
/// ```
#[must_use]
pub fn redact_national_id_with_strategy(
    national_id: &str,
    strategy: NationalIdRedactionStrategy,
) -> String {
    let cleaned: String = national_id
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect();

    match strategy {
        NationalIdRedactionStrategy::Token => "[NATIONAL_ID]".to_string(),

        NationalIdRedactionStrategy::Mask => masking::mask_all(&cleaned, '*'),

        NationalIdRedactionStrategy::Anonymous => "[Redacted]".to_string(),

        NationalIdRedactionStrategy::LastFour => {
            if cleaned.len() >= 4 {
                let start_pos = cleaned.len().saturating_sub(4);
                let last_four = &cleaned[start_pos..];
                format!("****{}", last_four)
            } else {
                "[NATIONAL_ID]".to_string()
            }
        }

        NationalIdRedactionStrategy::Skip => national_id.to_string(),
    }
}

// ============================================================================
// Vehicle ID Redaction
// ============================================================================

/// Redact vehicle ID (VIN) with explicit strategy
///
/// # Strategies
///
/// - `Token` → `[VEHICLE_ID]`
/// - `Mask` → `*****************`
/// - `Anonymous` → `[Redacted]`
/// - `ShowWmi` → `1HG**************` (shows World Manufacturer Identifier)
/// - `Skip` → unchanged
///
/// # Examples
///
/// ```ignore
/// use crate::primitives::identifiers::government::sanitization::{
///     redact_vehicle_id_with_strategy, VehicleIdRedactionStrategy
/// };
///
/// let token = redact_vehicle_id_with_strategy("1HGBH41JXMN109186", VehicleIdRedactionStrategy::Token);
/// assert_eq!(token, "[VEHICLE_ID]");
///
/// let wmi = redact_vehicle_id_with_strategy("1HGBH41JXMN109186", VehicleIdRedactionStrategy::ShowWmi);
/// assert_eq!(wmi, "1HG**************");
/// ```
#[must_use]
pub fn redact_vehicle_id_with_strategy(
    vehicle_id: &str,
    strategy: VehicleIdRedactionStrategy,
) -> String {
    let cleaned: String = vehicle_id
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect::<String>()
        .to_uppercase();

    match strategy {
        VehicleIdRedactionStrategy::Token => "[VEHICLE_ID]".to_string(),

        VehicleIdRedactionStrategy::Mask => {
            if cleaned.len() == 17 {
                "*".repeat(17)
            } else {
                masking::mask_all(&cleaned, '*')
            }
        }

        VehicleIdRedactionStrategy::Anonymous => "[Redacted]".to_string(),

        VehicleIdRedactionStrategy::ShowWmi => {
            // Show first 3 characters (World Manufacturer Identifier)
            if cleaned.len() == 17 {
                format!("{}**************", &cleaned[0..3])
            } else {
                "[VEHICLE_ID]".to_string()
            }
        }

        VehicleIdRedactionStrategy::Skip => vehicle_id.to_string(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ========================================================================
    // Tax ID Tests
    // ========================================================================

    #[test]
    fn test_redact_tax_id_with_strategy() {
        // Token
        assert_eq!(
            redact_tax_id_with_strategy("12-3456789", TaxIdRedactionStrategy::Token),
            "[TAX_ID]"
        );

        // Mask
        assert_eq!(
            redact_tax_id_with_strategy("12-3456789", TaxIdRedactionStrategy::Mask),
            "**-*******"
        );

        // Anonymous
        assert_eq!(
            redact_tax_id_with_strategy("12-3456789", TaxIdRedactionStrategy::Anonymous),
            "[Redacted]"
        );

        // ShowPrefix
        assert_eq!(
            redact_tax_id_with_strategy("12-3456789", TaxIdRedactionStrategy::ShowPrefix),
            "12-*******"
        );

        // Skip
        assert_eq!(
            redact_tax_id_with_strategy("12-3456789", TaxIdRedactionStrategy::Skip),
            "12-3456789"
        );
    }

    #[test]
    fn test_redact_tax_id_invalid_length() {
        // Invalid length - fallback to token for ShowPrefix
        assert_eq!(
            redact_tax_id_with_strategy("123", TaxIdRedactionStrategy::ShowPrefix),
            "[TAX_ID]"
        );
    }

    // ========================================================================
    // Driver License Tests
    // ========================================================================

    #[test]
    fn test_redact_driver_license_with_strategy() {
        // Token
        assert_eq!(
            redact_driver_license_with_strategy("D1234567", DriverLicenseRedactionStrategy::Token),
            "[DRIVER_LICENSE]"
        );

        // Mask
        assert_eq!(
            redact_driver_license_with_strategy("D1234567", DriverLicenseRedactionStrategy::Mask),
            "********"
        );

        // Anonymous
        assert_eq!(
            redact_driver_license_with_strategy(
                "D1234567",
                DriverLicenseRedactionStrategy::Anonymous
            ),
            "[Redacted]"
        );

        // LastFour
        assert_eq!(
            redact_driver_license_with_strategy(
                "D1234567",
                DriverLicenseRedactionStrategy::LastFour
            ),
            "****4567"
        );

        // Skip
        assert_eq!(
            redact_driver_license_with_strategy("D1234567", DriverLicenseRedactionStrategy::Skip),
            "D1234567"
        );
    }

    #[test]
    fn test_redact_driver_license_short() {
        // Too short for LastFour
        assert_eq!(
            redact_driver_license_with_strategy("ABC", DriverLicenseRedactionStrategy::LastFour),
            "[DRIVER_LICENSE]"
        );
    }

    // ========================================================================
    // Passport Tests
    // ========================================================================

    #[test]
    fn test_redact_passport_with_strategy() {
        // Token
        assert_eq!(
            redact_passport_with_strategy("US1234567", PassportRedactionStrategy::Token),
            "[PASSPORT]"
        );

        // Mask
        assert_eq!(
            redact_passport_with_strategy("US1234567", PassportRedactionStrategy::Mask),
            "*********"
        );

        // Anonymous
        assert_eq!(
            redact_passport_with_strategy("US1234567", PassportRedactionStrategy::Anonymous),
            "[Redacted]"
        );

        // ShowCountry
        assert_eq!(
            redact_passport_with_strategy("US1234567", PassportRedactionStrategy::ShowCountry),
            "US*******"
        );

        // Skip
        assert_eq!(
            redact_passport_with_strategy("US1234567", PassportRedactionStrategy::Skip),
            "US1234567"
        );
    }

    #[test]
    fn test_redact_passport_short() {
        // Too short for ShowCountry
        assert_eq!(
            redact_passport_with_strategy("A", PassportRedactionStrategy::ShowCountry),
            "[PASSPORT]"
        );
    }

    // ========================================================================
    // National ID Tests
    // ========================================================================

    #[test]
    fn test_redact_national_id_with_strategy() {
        // Token
        assert_eq!(
            redact_national_id_with_strategy("AB123456C", NationalIdRedactionStrategy::Token),
            "[NATIONAL_ID]"
        );

        // Mask
        assert_eq!(
            redact_national_id_with_strategy("AB123456C", NationalIdRedactionStrategy::Mask),
            "*********"
        );

        // Anonymous
        assert_eq!(
            redact_national_id_with_strategy("AB123456C", NationalIdRedactionStrategy::Anonymous),
            "[Redacted]"
        );

        // LastFour
        assert_eq!(
            redact_national_id_with_strategy("AB123456C", NationalIdRedactionStrategy::LastFour),
            "****456C"
        );

        // Skip
        assert_eq!(
            redact_national_id_with_strategy("AB123456C", NationalIdRedactionStrategy::Skip),
            "AB123456C"
        );
    }

    #[test]
    fn test_redact_national_id_short() {
        // Too short for LastFour
        assert_eq!(
            redact_national_id_with_strategy("ABC", NationalIdRedactionStrategy::LastFour),
            "[NATIONAL_ID]"
        );
    }

    // ========================================================================
    // Vehicle ID Tests
    // ========================================================================

    #[test]
    fn test_redact_vehicle_id_with_strategy() {
        // Token
        assert_eq!(
            redact_vehicle_id_with_strategy("1HGBH41JXMN109186", VehicleIdRedactionStrategy::Token),
            "[VEHICLE_ID]"
        );

        // Mask
        assert_eq!(
            redact_vehicle_id_with_strategy("1HGBH41JXMN109186", VehicleIdRedactionStrategy::Mask),
            "*****************"
        );

        // Anonymous
        assert_eq!(
            redact_vehicle_id_with_strategy(
                "1HGBH41JXMN109186",
                VehicleIdRedactionStrategy::Anonymous
            ),
            "[Redacted]"
        );

        // ShowWmi
        assert_eq!(
            redact_vehicle_id_with_strategy(
                "1HGBH41JXMN109186",
                VehicleIdRedactionStrategy::ShowWmi
            ),
            "1HG**************"
        );

        // Skip
        assert_eq!(
            redact_vehicle_id_with_strategy("1HGBH41JXMN109186", VehicleIdRedactionStrategy::Skip),
            "1HGBH41JXMN109186"
        );
    }

    #[test]
    fn test_redact_vehicle_id_invalid_length() {
        // Invalid length - fallback to token for ShowWmi
        assert_eq!(
            redact_vehicle_id_with_strategy("ABC123", VehicleIdRedactionStrategy::ShowWmi),
            "[VEHICLE_ID]"
        );
    }
}
