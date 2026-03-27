//! Network identifier types
//!
//! Types related to network identifiers:
//! - `UuidVersion` - UUID version enumeration
//! - `ApiKeyProvider` - API key provider/service

// ============================================================================
// UUID Version
// ============================================================================

/// Version of a UUID
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UuidVersion {
    /// Version 1 - Time-based
    V1,
    /// Version 2 - DCE Security
    V2,
    /// Version 3 - MD5 hash
    V3,
    /// Version 4 - Random
    V4,
    /// Version 5 - SHA-1 hash
    V5,
    /// Unknown or non-standard version
    Unknown,
}

impl std::fmt::Display for UuidVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::V1 => write!(f, "v1"),
            Self::V2 => write!(f, "v2"),
            Self::V3 => write!(f, "v3"),
            Self::V4 => write!(f, "v4"),
            Self::V5 => write!(f, "v5"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

impl From<crate::primitives::identifiers::UuidVersion> for UuidVersion {
    fn from(v: crate::primitives::identifiers::UuidVersion) -> Self {
        use crate::primitives::identifiers::UuidVersion as P;
        match v {
            P::V1 => Self::V1,
            P::V2 => Self::V2,
            P::V3 => Self::V3,
            P::V4 => Self::V4,
            P::V5 => Self::V5,
            P::Unknown => Self::Unknown,
        }
    }
}

impl From<UuidVersion> for crate::primitives::identifiers::UuidVersion {
    fn from(v: UuidVersion) -> Self {
        match v {
            UuidVersion::V1 => Self::V1,
            UuidVersion::V2 => Self::V2,
            UuidVersion::V3 => Self::V3,
            UuidVersion::V4 => Self::V4,
            UuidVersion::V5 => Self::V5,
            UuidVersion::Unknown => Self::Unknown,
        }
    }
}

// ============================================================================
// API Key Provider
// ============================================================================

/// API key provider/service
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyProvider {
    /// AWS API key
    Aws,
    /// Google Cloud Platform API key
    Gcp,
    /// Azure API key
    Azure,
    /// GitHub API key
    Github,
    /// Stripe API key
    Stripe,
    /// 1Password API key
    OnePassword,
    /// Square API key
    Square,
    /// PayPal/Braintree API key
    PayPal,
    /// Shopify API key
    Shopify,
    /// Generic/unknown provider
    Generic,
}

impl std::fmt::Display for ApiKeyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aws => write!(f, "AWS"),
            Self::Gcp => write!(f, "GCP"),
            Self::Azure => write!(f, "Azure"),
            Self::Github => write!(f, "GitHub"),
            Self::Stripe => write!(f, "Stripe"),
            Self::OnePassword => write!(f, "1Password"),
            Self::Square => write!(f, "Square"),
            Self::PayPal => write!(f, "PayPal"),
            Self::Shopify => write!(f, "Shopify"),
            Self::Generic => write!(f, "Generic"),
        }
    }
}

impl From<crate::primitives::identifiers::ApiKeyProvider> for ApiKeyProvider {
    fn from(p: crate::primitives::identifiers::ApiKeyProvider) -> Self {
        use crate::primitives::identifiers::ApiKeyProvider as P;
        match p {
            P::Aws => Self::Aws,
            P::Gcp => Self::Gcp,
            P::Azure => Self::Azure,
            P::Github => Self::Github,
            P::Stripe => Self::Stripe,
            P::OnePassword => Self::OnePassword,
            P::Square => Self::Square,
            P::PayPal => Self::PayPal,
            P::Shopify => Self::Shopify,
            P::Generic => Self::Generic,
        }
    }
}

impl From<ApiKeyProvider> for crate::primitives::identifiers::ApiKeyProvider {
    fn from(p: ApiKeyProvider) -> Self {
        match p {
            ApiKeyProvider::Aws => Self::Aws,
            ApiKeyProvider::Gcp => Self::Gcp,
            ApiKeyProvider::Azure => Self::Azure,
            ApiKeyProvider::Github => Self::Github,
            ApiKeyProvider::Stripe => Self::Stripe,
            ApiKeyProvider::OnePassword => Self::OnePassword,
            ApiKeyProvider::Square => Self::Square,
            ApiKeyProvider::PayPal => Self::PayPal,
            ApiKeyProvider::Shopify => Self::Shopify,
            ApiKeyProvider::Generic => Self::Generic,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_uuid_version_display() {
        assert_eq!(UuidVersion::V4.to_string(), "v4");
        assert_eq!(UuidVersion::Unknown.to_string(), "unknown");
    }

    #[test]
    fn test_api_key_provider_display() {
        assert_eq!(ApiKeyProvider::Aws.to_string(), "AWS");
        assert_eq!(ApiKeyProvider::Github.to_string(), "GitHub");
    }

    #[test]
    fn test_uuid_version_conversion() {
        let public = UuidVersion::V4;
        let primitive: crate::primitives::identifiers::UuidVersion = public.into();
        let back: UuidVersion = primitive.into();
        assert_eq!(back, UuidVersion::V4);
    }
}
