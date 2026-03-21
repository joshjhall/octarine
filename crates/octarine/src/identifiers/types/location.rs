//! Location identifier types
//!
//! Types related to location identifiers:
//! - `GpsFormat` - GPS coordinate formats
//! - `PostalCodeType` - Types of postal codes
//! - `PostalCodeNormalization` - Postal code normalization modes
//! - `LocationTextPolicy` - Redaction policy for location data

// ============================================================================
// GPS Format
// ============================================================================

/// GPS coordinate format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpsFormat {
    /// Decimal degrees: 40.7128, -74.0060
    DecimalDegrees,
    /// Degrees minutes seconds: 40°42'46"N 74°00'21"W
    DegreesMinutesSeconds,
    /// Degrees decimal minutes: 40°42.767'N 74°00.36'W
    DegreesDecimalMinutes,
}

impl From<crate::primitives::identifiers::GpsFormat> for GpsFormat {
    fn from(f: crate::primitives::identifiers::GpsFormat) -> Self {
        use crate::primitives::identifiers::GpsFormat as P;
        match f {
            P::DecimalDegrees => Self::DecimalDegrees,
            P::DegreesMinutesSeconds => Self::DegreesMinutesSeconds,
            P::DegreesDecimalMinutes => Self::DegreesDecimalMinutes,
        }
    }
}

impl From<GpsFormat> for crate::primitives::identifiers::GpsFormat {
    fn from(f: GpsFormat) -> Self {
        match f {
            GpsFormat::DecimalDegrees => Self::DecimalDegrees,
            GpsFormat::DegreesMinutesSeconds => Self::DegreesMinutesSeconds,
            GpsFormat::DegreesDecimalMinutes => Self::DegreesDecimalMinutes,
        }
    }
}

// ============================================================================
// Postal Code Types
// ============================================================================

/// Postal code type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostalCodeType {
    /// US ZIP code (5 digits)
    UsZip,
    /// US ZIP+4 code (9 digits)
    UsZipPlus4,
    /// UK postcode (various formats with space)
    UkPostcode,
    /// Canadian postal code (A1A 1B1 format)
    CanadianPostal,
}

impl From<crate::primitives::identifiers::PostalCodeType> for PostalCodeType {
    fn from(t: crate::primitives::identifiers::PostalCodeType) -> Self {
        use crate::primitives::identifiers::PostalCodeType as P;
        match t {
            P::UsZip => Self::UsZip,
            P::UsZipPlus4 => Self::UsZipPlus4,
            P::UkPostcode => Self::UkPostcode,
            P::CanadianPostal => Self::CanadianPostal,
        }
    }
}

impl From<PostalCodeType> for crate::primitives::identifiers::PostalCodeType {
    fn from(t: PostalCodeType) -> Self {
        match t {
            PostalCodeType::UsZip => Self::UsZip,
            PostalCodeType::UsZipPlus4 => Self::UsZipPlus4,
            PostalCodeType::UkPostcode => Self::UkPostcode,
            PostalCodeType::CanadianPostal => Self::CanadianPostal,
        }
    }
}

/// Postal code normalization mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostalCodeNormalization {
    /// Keep original format (5 or 5+4 for US ZIP)
    Preserve,
    /// Normalize to base format (5 digits for US ZIP, remove +4)
    BaseOnly,
    /// Normalize to extended format (5+4 for US ZIP if available)
    Extended,
}

impl From<crate::primitives::identifiers::PostalCodeNormalization> for PostalCodeNormalization {
    fn from(n: crate::primitives::identifiers::PostalCodeNormalization) -> Self {
        use crate::primitives::identifiers::PostalCodeNormalization as P;
        match n {
            P::Preserve => Self::Preserve,
            P::BaseOnly => Self::BaseOnly,
            P::Extended => Self::Extended,
        }
    }
}

impl From<PostalCodeNormalization> for crate::primitives::identifiers::PostalCodeNormalization {
    fn from(n: PostalCodeNormalization) -> Self {
        match n {
            PostalCodeNormalization::Preserve => Self::Preserve,
            PostalCodeNormalization::BaseOnly => Self::BaseOnly,
            PostalCodeNormalization::Extended => Self::Extended,
        }
    }
}

// ============================================================================
// Location Text Policy
// ============================================================================

/// Policy for redacting location identifiers in text
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LocationTextPolicy {
    /// Skip redaction - return text as-is (dev/qa only)
    Skip,
    /// Partial redaction - show regional context (city/state level)
    Partial,
    /// Complete redaction - type-specific tokens
    #[default]
    Complete,
    /// Anonymous redaction - generic `[REDACTED]` for all
    Anonymous,
}

impl From<crate::primitives::identifiers::LocationTextPolicy> for LocationTextPolicy {
    fn from(p: crate::primitives::identifiers::LocationTextPolicy) -> Self {
        use crate::primitives::identifiers::LocationTextPolicy as P;
        match p {
            P::Skip => Self::Skip,
            P::Partial => Self::Partial,
            P::Complete => Self::Complete,
            P::Anonymous => Self::Anonymous,
        }
    }
}

impl From<LocationTextPolicy> for crate::primitives::identifiers::LocationTextPolicy {
    fn from(p: LocationTextPolicy) -> Self {
        match p {
            LocationTextPolicy::Skip => Self::Skip,
            LocationTextPolicy::Partial => Self::Partial,
            LocationTextPolicy::Complete => Self::Complete,
            LocationTextPolicy::Anonymous => Self::Anonymous,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_gps_format_conversion() {
        let public = GpsFormat::DecimalDegrees;
        let primitive: crate::primitives::identifiers::GpsFormat = public.into();
        let back: GpsFormat = primitive.into();
        assert_eq!(back, GpsFormat::DecimalDegrees);
    }

    #[test]
    fn test_postal_code_type() {
        let zip = PostalCodeType::UsZip;
        let primitive: crate::primitives::identifiers::PostalCodeType = zip.into();
        let back: PostalCodeType = primitive.into();
        assert_eq!(back, PostalCodeType::UsZip);
    }

    #[test]
    fn test_location_text_policy_default() {
        assert_eq!(LocationTextPolicy::default(), LocationTextPolicy::Complete);
    }
}
