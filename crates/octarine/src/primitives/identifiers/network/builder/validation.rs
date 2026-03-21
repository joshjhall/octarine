//! Network identifier validation methods
//!
//! Builder methods for validating network identifiers.
//!
//! # Naming Convention
//!
//! - `validate_*` methods return `Result<T, E>` for validation with error details
//! - For bool checks, use detection layer methods or call `validate_*.is_ok()`

use super::super::super::token::{ApiKeyProvider, TokenIdentifierBuilder};
use super::super::{detection, validation};
use super::NetworkIdentifierBuilder;
use crate::primitives::Problem;

// Re-export UUID types for convenience
pub use super::super::detection::UuidVersion;

impl NetworkIdentifierBuilder {
    // =========================================================================
    // UUID Validation
    // =========================================================================

    /// Validate UUID v4 format
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let builder = NetworkIdentifierBuilder::new();
    /// let version = builder.validate_uuid_v4("550e8400-e29b-41d4-a716-446655440000")?;
    ///
    /// // For bool check, use .is_ok()
    /// if builder.validate_uuid_v4(user_input).is_ok() {
    ///     println!("Valid UUID v4!");
    /// }
    /// ```
    pub fn validate_uuid_v4(&self, uuid: &str) -> Result<UuidVersion, Problem> {
        validation::validate_uuid_v4(uuid)
    }

    /// Validate UUID v5 format
    pub fn validate_uuid_v5(&self, uuid: &str) -> Result<UuidVersion, Problem> {
        validation::validate_uuid_v5(uuid)
    }

    /// Validate UUID format (any version)
    ///
    /// Detects and returns the actual UUID version.
    pub fn validate_uuid(&self, uuid: &str) -> Result<UuidVersion, Problem> {
        validation::validate_uuid(uuid)
    }

    // =========================================================================
    // MAC Address Validation
    // =========================================================================

    /// Validate MAC address format
    ///
    /// Validates format and rejects special addresses (broadcast, null).
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let builder = NetworkIdentifierBuilder::new();
    /// builder.validate_mac_address("00:1B:44:11:3A:B7")?;
    ///
    /// // For bool check, use .is_ok()
    /// if builder.validate_mac_address(user_input).is_ok() {
    ///     println!("Valid MAC!");
    /// }
    /// ```
    pub fn validate_mac_address(&self, mac: &str) -> Result<(), Problem> {
        validation::validate_mac_address(mac)
    }

    // =========================================================================
    // IPv4 Address Classification
    // =========================================================================

    /// Check if IPv4 address is private (RFC 1918)
    #[must_use]
    pub fn is_private_ipv4(&self, ip: &str) -> bool {
        validation::is_private_ipv4(ip)
    }

    /// Check if IPv4 address is loopback (127.0.0.0/8)
    #[must_use]
    pub fn is_loopback_ipv4(&self, ip: &str) -> bool {
        validation::is_loopback_ipv4(ip)
    }

    /// Check if IPv4 address is link-local (169.254.0.0/16)
    #[must_use]
    pub fn is_link_local_ipv4(&self, ip: &str) -> bool {
        validation::is_link_local_ipv4(ip)
    }

    /// Check if IPv4 address is multicast (224.0.0.0/4)
    #[must_use]
    pub fn is_multicast_ipv4(&self, ip: &str) -> bool {
        validation::is_multicast_ipv4(ip)
    }

    /// Check if IPv4 address is reserved (240.0.0.0/4)
    #[must_use]
    pub fn is_reserved_ipv4(&self, ip: &str) -> bool {
        validation::is_reserved_ipv4(ip)
    }

    /// Check if IPv4 address is broadcast (255.255.255.255)
    #[must_use]
    pub fn is_broadcast_ipv4(&self, ip: &str) -> bool {
        validation::is_broadcast_ipv4(ip)
    }

    /// Check if IPv4 address is public (routable on Internet)
    #[must_use]
    pub fn is_public_ipv4(&self, ip: &str) -> bool {
        validation::is_public_ipv4(ip)
    }

    // =========================================================================
    // IPv6 Address Classification
    // =========================================================================

    /// Check if IPv6 address is loopback (::1)
    #[must_use]
    pub fn is_loopback_ipv6(&self, ip: &str) -> bool {
        validation::is_loopback_ipv6(ip)
    }

    /// Check if IPv6 address is link-local (fe80::/10)
    #[must_use]
    pub fn is_link_local_ipv6(&self, ip: &str) -> bool {
        validation::is_link_local_ipv6(ip)
    }

    /// Check if IPv6 address is multicast (ff00::/8)
    #[must_use]
    pub fn is_multicast_ipv6(&self, ip: &str) -> bool {
        validation::is_multicast_ipv6(ip)
    }

    /// Check if IPv6 address is unique local (fc00::/7)
    #[must_use]
    pub fn is_unique_local_ipv6(&self, ip: &str) -> bool {
        validation::is_unique_local_ipv6(ip)
    }

    /// Check if IPv6 address is public (globally routable)
    #[must_use]
    pub fn is_public_ipv6(&self, ip: &str) -> bool {
        validation::is_public_ipv6(ip)
    }

    // =========================================================================
    // Phone Number Validation
    // =========================================================================

    /// Validate international phone number
    ///
    /// Requires 7-15 digits per E.164/OWASP guidelines.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let builder = NetworkIdentifierBuilder::new();
    /// builder.validate_phone_international("+1-555-123-4567")?;
    ///
    /// // For bool check, use .is_ok()
    /// if builder.validate_phone_international(user_input).is_ok() {
    ///     println!("Valid phone!");
    /// }
    /// ```
    pub fn validate_phone_international(&self, phone: &str) -> Result<(), Problem> {
        validation::validate_phone_international(phone)
    }

    // =========================================================================
    // API Key Validation
    // =========================================================================

    /// Validate API key format
    ///
    /// Returns the detected provider on success.
    pub fn validate_api_key(
        &self,
        key: &str,
        min_length: usize,
        max_length: usize,
    ) -> Result<ApiKeyProvider, Problem> {
        let token_builder = TokenIdentifierBuilder::new();
        token_builder.validate_api_key(key, min_length, max_length)
    }

    // =========================================================================
    // JWT Validation
    // =========================================================================

    /// Validate JWT token format
    pub fn validate_jwt(&self, token: &str) -> Result<(), Problem> {
        let token_builder = TokenIdentifierBuilder::new();
        token_builder.validate_jwt(token)
    }

    // =========================================================================
    // Session ID Validation
    // =========================================================================

    /// Validate session ID format
    pub fn validate_session_id(
        &self,
        session_id: &str,
        min_length: usize,
        max_length: usize,
    ) -> Result<(), Problem> {
        let token_builder = TokenIdentifierBuilder::new();
        token_builder.validate_session_id(session_id, min_length, max_length)
    }
}
