//! Location identifier redaction strategies
//!
//! Domain-specific redaction strategies for location identifiers with privacy-aware options.
//!
//! # Two-Tier Redaction API
//!
//! ## Domain-Specific Strategies (Single Identifiers)
//! Each identifier type has its own strategy enum with only valid options:
//! - `redact_gps_coordinate(coord, GpsRedactionStrategy)` - Precision levels or token
//! - `redact_street_address(address, AddressRedactionStrategy)` - Show region or token
//! - `redact_postal_code(code, PostalCodeRedactionStrategy)` - Show prefix/region or token
//! - `redact_country(country, CountryRedactionStrategy)` - Show continent or token
//!
//! ## Generic Text Policy (Text Scanning)
//! For scanning text with multiple identifier types, use `TextRedactionPolicy`:
//! - `None` - Skip redaction (dev/qa only)
//! - `Partial` - Show regional information (city/state level)
//! - `Complete` - Full token redaction ([GPS], [ADDRESS], etc.)
//! - `Anonymous` - Generic [REDACTED] for everything
//!
//! # Privacy Compliance
//!
//! Default strategies align with privacy regulations:
//! - **GDPR Article 4(1)**: Location data is personal data - default to Complete
//! - **CCPA 1798.140**: Geolocation requires opt-in - default to Complete
//! - **COPPA**: Cannot collect precise geolocation from children - default to Complete
//! - **HIPAA**: ZIP codes beyond first 3 digits are PHI - Partial shows ZIP-3
//!
//! # Examples
//!
//! ```ignore
//! use octarine::primitives::identifiers::location::redaction::{
//!     GpsRedactionStrategy, AddressRedactionStrategy, PostalCodeRedactionStrategy
//! };
//!
//! // GPS with precision levels
//! let gps = "40.7128, -74.0060";
//! let city_level = redact_gps_coordinate(gps, GpsRedactionStrategy::CityLevel);
//! // Result: "40.71, -74.01" (±1km precision)
//!
//! // Address with regional info
//! let addr = "123 Main St, New York, NY 10001";
//! let partial = redact_street_address(addr, AddressRedactionStrategy::ShowCityState);
//! // Result: "[ADDRESS-NewYork-NY]"
//!
//! // Postal code showing state
//! let zip = "10001";
//! let state_level = redact_postal_code(zip, PostalCodeRedactionStrategy::ShowPrefix);
//! // Result: "100**" (state-level)
//! ```

/// GPS coordinate redaction strategies
///
/// Provides different precision levels for location privacy.
///
/// # Privacy Implications
///
/// - **Precision1Degree**: ±111km (city-level, GDPR compliant for analytics)
/// - **Precision2Digits**: ±1.1km (neighborhood-level, use with caution)
/// - **Precision3Digits**: ±110m (street-level, requires consent)
/// - **Precision4Digits**: ±11m (building-level, COPPA prohibited)
/// - **Token**: Complete redaction (recommended default)
/// - **Anonymous**: Generic redaction
/// - **None**: Skip redaction (dev/qa only, never production)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GpsRedactionStrategy {
    /// Skip redaction - return as-is (dev/qa only, NOT for production)
    Skip,

    /// City-level precision (~111km accuracy)
    ///
    /// Rounds to 1 decimal place. Suitable for city-level analytics.
    /// GDPR compliant when aggregated with sufficient k-anonymity.
    ///
    /// Example: `40.7128, -74.0060` → `40.7, -74.0`
    CityLevel,

    /// Neighborhood-level precision (~1.1km accuracy)
    ///
    /// Rounds to 2 decimal places. Use only with explicit consent.
    ///
    /// Example: `40.7128, -74.0060` → `40.71, -74.01`
    NeighborhoodLevel,

    /// Street-level precision (~110m accuracy)
    ///
    /// Rounds to 3 decimal places. Requires consent under CCPA/GDPR.
    ///
    /// Example: `40.7128, -74.0060` → `40.713, -74.006`
    StreetLevel,

    /// Building-level precision (~11m accuracy)
    ///
    /// Rounds to 4 decimal places. COPPA prohibited for children.
    /// Requires explicit consent and business justification.
    ///
    /// Example: `40.7128, -74.0060` → `40.7128, -74.0060`
    BuildingLevel,

    /// Complete token redaction (recommended default)
    ///
    /// Replaces with `[GPS]` token. GDPR/CCPA/COPPA/HIPAA compliant.
    ///
    /// Example: `40.7128, -74.0060` → `[GPS]`
    #[default]
    Token,

    /// Generic anonymous redaction
    ///
    /// Replaces with `[REDACTED]` token. Use when redaction type
    /// itself should not be revealed.
    ///
    /// Example: `40.7128, -74.0060` → `[REDACTED]`
    Anonymous,

    /// Asterisks (length-preserving)
    ///
    /// Example: `40.7128, -74.0060` → `*****************`
    Asterisks,

    /// Hashes (length-preserving)
    ///
    /// Example: `40.7128, -74.0060` → `#################`
    Hashes,
}

impl GpsRedactionStrategy {
    /// Check if strategy is risky for production use
    ///
    /// Returns `true` for strategies that may violate privacy regulations
    /// without explicit user consent and business justification.
    #[must_use]
    pub const fn is_risky(&self) -> bool {
        matches!(self, Self::Skip | Self::BuildingLevel | Self::StreetLevel)
    }

    /// Get decimal places for precision-based strategies
    ///
    /// Returns `None` for token-based strategies.
    #[must_use]
    pub const fn decimal_places(&self) -> Option<u8> {
        match self {
            Self::CityLevel => Some(1),
            Self::NeighborhoodLevel => Some(2),
            Self::StreetLevel => Some(3),
            Self::BuildingLevel => Some(4),
            _ => None,
        }
    }
}

/// Street address redaction strategies
///
/// Provides options for showing regional context while protecting specific location.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddressRedactionStrategy {
    /// Skip redaction - return as-is (dev/qa only)
    Skip,

    /// Show city and state only: `[ADDRESS-SanFrancisco-CA]`
    ///
    /// Preserves city-level geographic context. Requires consent under CCPA.
    ShowCityState,

    /// Show state only: `[ADDRESS-CA]`
    ///
    /// Preserves state-level geographic context. GDPR compliant for analytics.
    ShowState,

    /// Show country only: `[ADDRESS-US]`
    ///
    /// Preserves country-level context. Lowest privacy risk.
    ShowCountry,

    /// Complete token redaction (recommended default): `[ADDRESS]`
    ///
    /// GDPR/CCPA/COPPA/HIPAA compliant.
    #[default]
    Token,

    /// Generic anonymous redaction: `[REDACTED]`
    Anonymous,

    /// Asterisks (length-preserving)
    Asterisks,

    /// Hashes (length-preserving)
    Hashes,
}

impl AddressRedactionStrategy {
    /// Check if strategy is risky for production use
    #[must_use]
    pub const fn is_risky(&self) -> bool {
        matches!(self, Self::Skip | Self::ShowCityState)
    }
}

/// Postal code redaction strategies
///
/// Provides options for regional anonymization following HIPAA Safe Harbor guidelines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PostalCodeRedactionStrategy {
    /// Skip redaction - return as-is (dev/qa only)
    Skip,

    /// Show first 3 digits (ZIP-3 level): `100**`
    ///
    /// State/regional level. HIPAA Safe Harbor compliant.
    /// Safe for analytics when population > 20,000.
    ShowPrefix,

    /// Show first digit (USPS region): `1****`
    ///
    /// National region level. Lowest geographic precision.
    ShowRegion,

    /// Complete token redaction (recommended default): `[POSTAL_CODE]`
    ///
    /// GDPR/CCPA/COPPA/HIPAA compliant.
    #[default]
    Token,

    /// Generic anonymous redaction: `[REDACTED]`
    Anonymous,

    /// Asterisks (length-preserving)
    Asterisks,

    /// Hashes (length-preserving)
    Hashes,
}

impl PostalCodeRedactionStrategy {
    /// Check if strategy is risky for production use
    #[must_use]
    pub const fn is_risky(&self) -> bool {
        matches!(self, Self::Skip)
    }
}

/// Country code redaction strategies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CountryRedactionStrategy {
    /// Skip redaction - return as-is
    Skip,

    /// Show continent: `[COUNTRY-NorthAmerica]`
    ShowContinent,

    /// Complete token redaction: `[COUNTRY]`
    #[default]
    Token,

    /// Generic anonymous redaction: `[REDACTED]`
    Anonymous,
}

impl CountryRedactionStrategy {
    /// Check if strategy is risky for production use
    #[must_use]
    pub const fn is_risky(&self) -> bool {
        matches!(self, Self::Skip)
    }
}

/// Generic text redaction policy
///
/// Maps to sensible defaults for each identifier type when scanning text.
///
/// # Mapping
///
/// - **None**: All strategies set to None (dev/qa only)
/// - **Partial**: Regional context preserved (city/state level)
/// - **Complete**: Type-specific tokens (`[GPS]`, `[ADDRESS]`, etc.)
/// - **Anonymous**: Generic `[REDACTED]` for all types
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::location::redaction::TextRedactionPolicy;
///
/// let text = "Meet at 40.7128,-74.0060 or 123 Main St, NY 10001";
///
/// // Partial - shows regional context
/// let partial = redact_all_location_data(text, TextRedactionPolicy::Partial);
/// // Result: "Meet at 40.7,-74.0 or [ADDRESS-NY] 100**"
///
/// // Complete - type tokens
/// let complete = redact_all_location_data(text, TextRedactionPolicy::Complete);
/// // Result: "Meet at [GPS] or [ADDRESS] [POSTAL_CODE]"
///
/// // Anonymous - generic redaction
/// let anon = redact_all_location_data(text, TextRedactionPolicy::Anonymous);
/// // Result: "Meet at [REDACTED] or [REDACTED] [REDACTED]"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TextRedactionPolicy {
    /// Skip redaction - return text as-is (dev/qa only)
    Skip,

    /// Partial redaction - show regional context (city/state level)
    ///
    /// Uses precision levels and regional indicators:
    /// - GPS: City-level precision (±111km)
    /// - Address: Show state
    /// - Postal: Show prefix (ZIP-3)
    /// - Country: Show continent
    Partial,

    /// Complete redaction - type-specific tokens (recommended default)
    ///
    /// Uses type tokens (`[GPS]`, `[ADDRESS]`, `[POSTAL_CODE]`, `[COUNTRY]`).
    /// GDPR/CCPA/COPPA/HIPAA compliant.
    #[default]
    Complete,

    /// Anonymous redaction - generic `[REDACTED]` for all types
    ///
    /// Use when redaction type itself should not be revealed.
    Anonymous,
}

impl TextRedactionPolicy {
    /// Convert to GPS coordinate strategy
    #[must_use]
    pub const fn to_gps_strategy(self) -> GpsRedactionStrategy {
        match self {
            Self::Skip => GpsRedactionStrategy::Skip,
            Self::Partial => GpsRedactionStrategy::CityLevel,
            Self::Complete => GpsRedactionStrategy::Token,
            Self::Anonymous => GpsRedactionStrategy::Anonymous,
        }
    }

    /// Convert to address strategy
    #[must_use]
    pub const fn to_address_strategy(self) -> AddressRedactionStrategy {
        match self {
            Self::Skip => AddressRedactionStrategy::Skip,
            Self::Partial => AddressRedactionStrategy::ShowState,
            Self::Complete => AddressRedactionStrategy::Token,
            Self::Anonymous => AddressRedactionStrategy::Anonymous,
        }
    }

    /// Convert to postal code strategy
    #[must_use]
    pub const fn to_postal_code_strategy(self) -> PostalCodeRedactionStrategy {
        match self {
            Self::Skip => PostalCodeRedactionStrategy::Skip,
            Self::Partial => PostalCodeRedactionStrategy::ShowPrefix,
            Self::Complete => PostalCodeRedactionStrategy::Token,
            Self::Anonymous => PostalCodeRedactionStrategy::Anonymous,
        }
    }

    /// Convert to country strategy
    #[must_use]
    pub const fn to_country_strategy(self) -> CountryRedactionStrategy {
        match self {
            Self::Skip => CountryRedactionStrategy::Skip,
            Self::Partial => CountryRedactionStrategy::ShowContinent,
            Self::Complete => CountryRedactionStrategy::Token,
            Self::Anonymous => CountryRedactionStrategy::Anonymous,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_gps_strategy_risky() {
        assert!(!GpsRedactionStrategy::Token.is_risky());
        assert!(!GpsRedactionStrategy::CityLevel.is_risky());
        assert!(GpsRedactionStrategy::Skip.is_risky());
        assert!(GpsRedactionStrategy::BuildingLevel.is_risky());
    }

    #[test]
    fn test_gps_strategy_decimal_places() {
        assert_eq!(GpsRedactionStrategy::CityLevel.decimal_places(), Some(1));
        assert_eq!(
            GpsRedactionStrategy::NeighborhoodLevel.decimal_places(),
            Some(2)
        );
        assert_eq!(GpsRedactionStrategy::Token.decimal_places(), None);
    }

    #[test]
    fn test_address_strategy_risky() {
        assert!(!AddressRedactionStrategy::Token.is_risky());
        assert!(!AddressRedactionStrategy::ShowState.is_risky());
        assert!(AddressRedactionStrategy::Skip.is_risky());
        assert!(AddressRedactionStrategy::ShowCityState.is_risky());
    }

    #[test]
    fn test_postal_code_strategy_risky() {
        assert!(!PostalCodeRedactionStrategy::Token.is_risky());
        assert!(!PostalCodeRedactionStrategy::ShowPrefix.is_risky());
        assert!(PostalCodeRedactionStrategy::Skip.is_risky());
    }

    #[test]
    fn test_text_policy_conversions() {
        let policy = TextRedactionPolicy::Partial;
        assert_eq!(policy.to_gps_strategy(), GpsRedactionStrategy::CityLevel);
        assert_eq!(
            policy.to_address_strategy(),
            AddressRedactionStrategy::ShowState
        );
        assert_eq!(
            policy.to_postal_code_strategy(),
            PostalCodeRedactionStrategy::ShowPrefix
        );

        let policy = TextRedactionPolicy::Complete;
        assert_eq!(policy.to_gps_strategy(), GpsRedactionStrategy::Token);
        assert_eq!(
            policy.to_address_strategy(),
            AddressRedactionStrategy::Token
        );
        assert_eq!(
            policy.to_postal_code_strategy(),
            PostalCodeRedactionStrategy::Token
        );
    }

    #[test]
    fn test_default_strategies() {
        assert_eq!(GpsRedactionStrategy::default(), GpsRedactionStrategy::Token);
        assert_eq!(
            AddressRedactionStrategy::default(),
            AddressRedactionStrategy::Token
        );
        assert_eq!(
            PostalCodeRedactionStrategy::default(),
            PostalCodeRedactionStrategy::Token
        );
        assert_eq!(
            TextRedactionPolicy::default(),
            TextRedactionPolicy::Complete
        );
    }
}
