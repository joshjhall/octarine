//! Network identifier redaction strategies (primitives layer)
//!
//! Type-safe redaction strategies for network identifiers with NO logging.
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
//! Each network identifier type has its own strategy enum with specific options:
//! - `UuidRedactionStrategy` - For single UUIDs
//! - `IpRedactionStrategy` - For single IP addresses
//! - `MacRedactionStrategy` - For single MAC addresses
//! - `UrlRedactionStrategy` - For single URLs
//! - `ApiKeyRedactionStrategy` - For single API keys
//! - `HostnameRedactionStrategy` - For single hostnames
//! - `PortRedactionStrategy` - For single port numbers
//! - `PhoneRedactionStrategy` - For single phone numbers
//!
//! ## Tier 2: Generic Text Policy (For Text Scanning)
//!
//! `TextRedactionPolicy` provides a simpler, generic interface for text scanning:
//! - Maps to appropriate domain strategy for each identifier type
//! - Used by `*_in_text()` functions
//! - Consistent across all identifier types
//!
//! # GDPR & Privacy Compliance
//!
//! Network identifiers have varying sensitivity under GDPR:
//! - **IP Addresses**: Can be PII under GDPR Article 4(1)
//! - **MAC Addresses**: Hardware identifiers - persistent tracking risk
//! - **API Keys**: Security-critical - unauthorized access risk
//! - **UUIDs**: May be linkable across systems
//!
//! # Usage
//!
//! ```ignore
//! use octarine::primitives::identifiers::network::{
//!     UuidRedactionStrategy, TextRedactionPolicy, redact_uuid, redact_uuids_in_text
//! };
//!
//! // Individual identifier with specific strategy
//! let redacted = redact_uuid("550e8400-e29b-41d4-a716-446655440000", UuidRedactionStrategy::ShowPrefix);
//! // Result: "550e8400-****"
//!
//! // Text scanning with generic policy
//! let redacted = redact_uuids_in_text(
//!     "User UUID: 550e8400-e29b-41d4-a716-446655440000",
//!     TextRedactionPolicy::Partial
//! );
//! // Result: "User UUID: 550e8400-****"
//! ```

/// UUID redaction strategies
///
/// Controls how UUIDs are redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UuidRedactionStrategy {
    /// Skip redaction - return original
    Skip,
    /// Show version: `<UUID-v4>` or `<UUID-v5>`
    ShowVersion,
    /// Show prefix (first 8 chars): `550e8400-****`
    ShowPrefix,
    /// Mask (existing behavior): `550e8400-****-****-****-************`
    Mask,
    /// Token placeholder: `<UUID>`
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Asterisk replacement
    Asterisks,
    /// Hash replacement
    Hashes,
}

/// IP address redaction strategies
///
/// Controls how IP addresses are redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpRedactionStrategy {
    /// Skip redaction - return original
    Skip,
    /// Show first octet (IPv4) or segment (IPv6): `192.***.***.***/2001:****:...`
    ShowFirstOctet,
    /// Show subnet: `192.168.***.***/2001:db8:****:...`
    ShowSubnet,
    /// Show type only: `<IPv4>` or `<IPv6>`
    ShowType,
    /// Mask (existing behavior): `192.***.***.***`
    Mask,
    /// Token placeholder: `[IP]`
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Asterisk replacement
    Asterisks,
    /// Hash replacement
    Hashes,
}

/// MAC address redaction strategies
///
/// Controls how MAC addresses are redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacRedactionStrategy {
    /// Skip redaction - return original
    Skip,
    /// Show vendor (OUI - first 3 bytes): `00:1B:44:***:***:***`
    ShowVendor,
    /// Mask (existing behavior): `00:1B:44:***:***:***`
    Mask,
    /// Token placeholder: `<MAC>`
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Asterisk replacement
    Asterisks,
    /// Hash replacement
    Hashes,
}

/// URL redaction strategies
///
/// Controls how URLs are redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UrlRedactionStrategy {
    /// Skip redaction - return original
    Skip,
    /// Show domain: `https://example.com/***`
    ShowDomain,
    /// Show scheme only: `https://***`
    ShowScheme,
    /// Mask (existing behavior): `https://example.com/***`
    Mask,
    /// Token placeholder: `<URL>`
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Asterisk replacement
    Asterisks,
    /// Hash replacement
    Hashes,
}

/// API key redaction strategies
///
/// Controls how API keys are redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyRedactionStrategy {
    /// Skip redaction - return original
    Skip,
    /// Show prefix: `sk_live_****`
    ShowPrefix,
    /// Mask (existing behavior): `sk_live_1234***`
    Mask,
    /// Token placeholder: `<API_KEY>`
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Asterisk replacement
    Asterisks,
    /// Hash replacement
    Hashes,
}

/// Hostname redaction strategies
///
/// Controls how hostnames are redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostnameRedactionStrategy {
    /// Skip redaction - return original
    Skip,
    /// Show domain: `***.example.com`
    ShowDomain,
    /// Token placeholder: `<HOSTNAME>`
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Asterisk replacement
    Asterisks,
    /// Hash replacement
    Hashes,
}

/// Port number redaction strategies
///
/// Controls how port numbers are redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortRedactionStrategy {
    /// Skip redaction - return original
    Skip,
    /// Show well-known ports (80, 443, 22, etc.), redact others
    ShowWellKnown,
    /// Token placeholder: `<PORT>`
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Asterisk replacement
    Asterisks,
    /// Hash replacement
    Hashes,
}

/// Phone number redaction strategies (network module variant)
///
/// Controls how phone numbers are redacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhoneRedactionStrategy {
    /// Skip redaction - return original
    Skip,
    /// Show country code: `+1-***-***-****`
    ShowCountryCode,
    /// Token placeholder: `[PHONE]`
    Token,
    /// Generic placeholder: `[REDACTED]`
    Anonymous,
    /// Asterisk replacement
    Asterisks,
    /// Hash replacement
    Hashes,
}

/// Generic redaction policy for text scanning
///
/// Simpler interface that maps to domain-specific strategies.
/// Used by `*_in_text()` functions for consistent text redaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TextRedactionPolicy {
    /// Skip redaction
    Skip,
    /// Partial redaction (show prefix, domain, etc.)
    Partial,
    /// Complete redaction (use type tokens)
    #[default]
    Complete,
    /// Anonymous redaction (generic `[REDACTED]`)
    Anonymous,
}

impl TextRedactionPolicy {
    /// Convert policy to UUID strategy
    #[must_use]
    pub const fn to_uuid_strategy(self) -> UuidRedactionStrategy {
        match self {
            Self::Skip => UuidRedactionStrategy::Skip,
            Self::Partial => UuidRedactionStrategy::ShowPrefix,
            Self::Complete => UuidRedactionStrategy::Token,
            Self::Anonymous => UuidRedactionStrategy::Anonymous,
        }
    }

    /// Convert policy to IP address strategy
    #[must_use]
    pub const fn to_ip_strategy(self) -> IpRedactionStrategy {
        match self {
            Self::Skip => IpRedactionStrategy::Skip,
            Self::Partial => IpRedactionStrategy::ShowFirstOctet,
            Self::Complete => IpRedactionStrategy::Token,
            Self::Anonymous => IpRedactionStrategy::Anonymous,
        }
    }

    /// Convert policy to MAC address strategy
    #[must_use]
    pub const fn to_mac_strategy(self) -> MacRedactionStrategy {
        match self {
            Self::Skip => MacRedactionStrategy::Skip,
            Self::Partial => MacRedactionStrategy::ShowVendor,
            Self::Complete => MacRedactionStrategy::Token,
            Self::Anonymous => MacRedactionStrategy::Anonymous,
        }
    }

    /// Convert policy to URL strategy
    #[must_use]
    pub const fn to_url_strategy(self) -> UrlRedactionStrategy {
        match self {
            Self::Skip => UrlRedactionStrategy::Skip,
            Self::Partial => UrlRedactionStrategy::ShowDomain,
            Self::Complete => UrlRedactionStrategy::Token,
            Self::Anonymous => UrlRedactionStrategy::Anonymous,
        }
    }

    /// Convert policy to API key strategy
    #[must_use]
    pub const fn to_api_key_strategy(self) -> ApiKeyRedactionStrategy {
        match self {
            Self::Skip => ApiKeyRedactionStrategy::Skip,
            Self::Partial => ApiKeyRedactionStrategy::ShowPrefix,
            Self::Complete => ApiKeyRedactionStrategy::Token,
            Self::Anonymous => ApiKeyRedactionStrategy::Anonymous,
        }
    }

    /// Convert policy to hostname strategy
    #[must_use]
    pub const fn to_hostname_strategy(self) -> HostnameRedactionStrategy {
        match self {
            Self::Skip => HostnameRedactionStrategy::Skip,
            Self::Partial => HostnameRedactionStrategy::ShowDomain,
            Self::Complete => HostnameRedactionStrategy::Token,
            Self::Anonymous => HostnameRedactionStrategy::Anonymous,
        }
    }

    /// Convert policy to port strategy
    #[must_use]
    pub const fn to_port_strategy(self) -> PortRedactionStrategy {
        match self {
            Self::Skip => PortRedactionStrategy::Skip,
            Self::Partial => PortRedactionStrategy::ShowWellKnown,
            Self::Complete => PortRedactionStrategy::Token,
            Self::Anonymous => PortRedactionStrategy::Anonymous,
        }
    }

    /// Convert policy to phone strategy
    #[must_use]
    pub const fn to_phone_strategy(self) -> PhoneRedactionStrategy {
        match self {
            Self::Skip => PhoneRedactionStrategy::Skip,
            Self::Partial => PhoneRedactionStrategy::ShowCountryCode,
            Self::Complete => PhoneRedactionStrategy::Token,
            Self::Anonymous => PhoneRedactionStrategy::Anonymous,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_text_policy_to_uuid_strategy() {
        assert_eq!(
            TextRedactionPolicy::Skip.to_uuid_strategy(),
            UuidRedactionStrategy::Skip
        );
        assert_eq!(
            TextRedactionPolicy::Partial.to_uuid_strategy(),
            UuidRedactionStrategy::ShowPrefix
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_uuid_strategy(),
            UuidRedactionStrategy::Token
        );
        assert_eq!(
            TextRedactionPolicy::Anonymous.to_uuid_strategy(),
            UuidRedactionStrategy::Anonymous
        );
    }

    #[test]
    fn test_text_policy_to_ip_strategy() {
        assert_eq!(
            TextRedactionPolicy::Partial.to_ip_strategy(),
            IpRedactionStrategy::ShowFirstOctet
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_ip_strategy(),
            IpRedactionStrategy::Token
        );
    }

    #[test]
    fn test_text_policy_to_mac_strategy() {
        assert_eq!(
            TextRedactionPolicy::Partial.to_mac_strategy(),
            MacRedactionStrategy::ShowVendor
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_mac_strategy(),
            MacRedactionStrategy::Token
        );
    }

    #[test]
    fn test_text_policy_to_url_strategy() {
        assert_eq!(
            TextRedactionPolicy::Partial.to_url_strategy(),
            UrlRedactionStrategy::ShowDomain
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_url_strategy(),
            UrlRedactionStrategy::Token
        );
    }

    #[test]
    fn test_text_policy_to_api_key_strategy() {
        assert_eq!(
            TextRedactionPolicy::Partial.to_api_key_strategy(),
            ApiKeyRedactionStrategy::ShowPrefix
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_api_key_strategy(),
            ApiKeyRedactionStrategy::Token
        );
    }

    #[test]
    fn test_text_policy_to_hostname_strategy() {
        assert_eq!(
            TextRedactionPolicy::Partial.to_hostname_strategy(),
            HostnameRedactionStrategy::ShowDomain
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_hostname_strategy(),
            HostnameRedactionStrategy::Token
        );
    }

    #[test]
    fn test_text_policy_to_port_strategy() {
        assert_eq!(
            TextRedactionPolicy::Partial.to_port_strategy(),
            PortRedactionStrategy::ShowWellKnown
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_port_strategy(),
            PortRedactionStrategy::Token
        );
    }

    #[test]
    fn test_text_policy_to_phone_strategy() {
        assert_eq!(
            TextRedactionPolicy::Partial.to_phone_strategy(),
            PhoneRedactionStrategy::ShowCountryCode
        );
        assert_eq!(
            TextRedactionPolicy::Complete.to_phone_strategy(),
            PhoneRedactionStrategy::Token
        );
    }
}
