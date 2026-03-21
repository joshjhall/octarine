//! Port number validation functions
//!
//! Pure validation functions for network port numbers.
//!
//! # Usage
//!
//! For bool checks, call `validate_port_number().is_ok()`.

use crate::primitives::Problem;

// Re-export shared PortRange type
pub use crate::primitives::types::PortRange;

// ============================================================================
// Port Number Validation
// ============================================================================

/// Get the port range classification for a given port
///
/// This is an alias for `PortRange::classify()` for backwards compatibility.
#[must_use]
pub fn get_port_range(port: u16) -> PortRange {
    PortRange::classify(port)
}

/// Check if port is a commonly used port
///
/// Includes: HTTP (80), HTTPS (443), SSH (22), FTP (20, 21), SMTP (25, 587),
/// DNS (53), IMAP (143, 993), POP3 (110, 995), MySQL (3306), PostgreSQL (5432)
#[must_use]
pub fn is_common_port(port: u16) -> bool {
    matches!(
        port,
        20 | 21
            | 22
            | 23
            | 25
            | 53
            | 80
            | 110
            | 143
            | 443
            | 465
            | 587
            | 993
            | 995
            | 3306
            | 5432
            | 8080
            | 8443
    )
}

/// Validate port number
///
/// # Examples
///
/// ```ignore
/// // Result-based validation
/// validate_port_number(8080)?;
///
/// // Bool check using .is_ok()
/// if validate_port_number(user_port).is_ok() {
///     println!("Valid port!");
/// }
/// ```
pub fn validate_port_number(port: u32) -> Result<(), Problem> {
    if port > 65535 {
        return Err(Problem::Validation(format!(
            "Port number {} out of valid range (0-65535)",
            port
        )));
    }
    Ok(())
}

/// Validate port is in well-known range (0-1023)
///
/// # Examples
///
/// ```ignore
/// validate_port_well_known(80)?; // OK - HTTP
/// validate_port_well_known(8080)?; // Err - not well-known
/// ```
pub fn validate_port_well_known(port: u32) -> Result<(), Problem> {
    validate_port_number(port)?;
    if port > 1023 {
        return Err(Problem::Validation(
            "Port number not in well-known range (0-1023)".into(),
        ));
    }
    Ok(())
}

/// Validate port is user-safe (>= 1024)
///
/// User-safe ports don't require root/admin privileges.
///
/// # Examples
///
/// ```ignore
/// validate_port_user_safe(8080)?; // OK - user-safe
/// validate_port_user_safe(80)?; // Err - privileged
/// ```
pub fn validate_port_user_safe(port: u32) -> Result<(), Problem> {
    validate_port_number(port)?;
    if port < 1024 {
        return Err(Problem::Validation(
            "Port number in privileged range (requires root)".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;

    // Note: PortRange type tests are in primitives/types/network.rs
    // These tests focus on the validation functions defined in this module

    #[test]
    fn test_port_validation() {
        // Valid ports
        assert!(validate_port_number(80).is_ok());
        assert!(validate_port_number(443).is_ok());
        assert!(validate_port_number(65535).is_ok());

        // Invalid ports
        assert!(validate_port_number(65536).is_err());
        assert!(validate_port_number(100000).is_err());
    }

    #[test]
    fn test_port_ranges() {
        assert_eq!(get_port_range(80), PortRange::WellKnown);
        assert_eq!(get_port_range(8080), PortRange::Registered);
        assert_eq!(get_port_range(50000), PortRange::Dynamic);
    }

    #[test]
    fn test_common_ports() {
        assert!(is_common_port(80));
        assert!(is_common_port(443));
        assert!(!is_common_port(12345));
    }

    #[test]
    fn test_well_known_validation() {
        assert!(validate_port_well_known(80).is_ok());
        assert!(validate_port_well_known(1023).is_ok());
        assert!(validate_port_well_known(1024).is_err());
    }

    #[test]
    fn test_user_safe_validation() {
        assert!(validate_port_user_safe(1024).is_ok());
        assert!(validate_port_user_safe(8080).is_ok());
        assert!(validate_port_user_safe(80).is_err());
    }

    // ============================================================================
    // Adversarial and Property-Based Tests
    // ============================================================================

    #[test]
    fn test_adversarial_port_boundary() {
        // Port 0 (valid but unusual)
        assert!(validate_port_number(0).is_ok());

        // Port 65535 (maximum valid)
        assert!(validate_port_number(65535).is_ok());

        // Port 65536 (just over boundary)
        assert!(validate_port_number(65536).is_err());

        // Well-known boundary (port 1023/1024)
        assert!(validate_port_well_known(1023).is_ok());
        assert!(validate_port_well_known(1024).is_err());

        // Registered boundary (port 49151/49152)
        assert_eq!(get_port_range(49151), PortRange::Registered);
        assert_eq!(get_port_range(49152), PortRange::Dynamic);
    }

    #[test]
    fn test_adversarial_port_negative_via_overflow() {
        // Attempting negative ports via u32 overflow
        assert!(validate_port_number(u32::MAX).is_err());
        assert!(validate_port_number(u32::MAX - 1).is_err());

        // Large values that might cause issues
        assert!(validate_port_number(100000).is_err());
        assert!(validate_port_number(1000000).is_err());
    }
}
