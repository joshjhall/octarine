//! Port validation primitives
//!
//! Pure validation functions for network port security.

// Allow dead_code: These are Layer 1 primitives that will be used by observe module
#![allow(dead_code)]

use crate::primitives::types::Problem;

// Re-export shared PortRange type
pub use crate::primitives::types::PortRange;

// ============================================================================
// Validation Functions
// ============================================================================

/// Validate a port number
///
/// # Errors
///
/// Returns `Problem::validation` if port is invalid (0 or > 65535).
pub fn validate_port(port: u16) -> Result<(), Problem> {
    if port == 0 {
        return Err(Problem::validation("Port 0 is reserved and cannot be used"));
    }
    Ok(())
}

/// Validate a port is within a specific range
///
/// # Errors
///
/// Returns `Problem::validation` if port is outside the range.
pub fn validate_port_range(port: u16, range: PortRange) -> Result<(), Problem> {
    validate_port(port)?;

    if !range.contains(port) {
        return Err(Problem::validation(format!(
            "Port {port} is outside allowed range ({}-{})",
            range.min(),
            range.max()
        )));
    }

    Ok(())
}

/// Parse and validate a port from a string
///
/// # Errors
///
/// Returns `Problem::validation` if string is not a valid port.
pub fn parse_port(s: &str) -> Result<u16, Problem> {
    let trimmed = s.trim();

    let port: u16 = trimmed
        .parse()
        .map_err(|_| Problem::validation(format!("Invalid port number: '{trimmed}'")))?;

    validate_port(port)?;

    Ok(port)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Note: PortRange type tests are in primitives/types/network.rs
    // These tests focus on the validation functions

    #[test]
    fn test_validate_port() {
        assert!(validate_port(1).is_ok());
        assert!(validate_port(80).is_ok());
        assert!(validate_port(443).is_ok());
        assert!(validate_port(8080).is_ok());
        assert!(validate_port(65535).is_ok());
        assert!(validate_port(0).is_err());
    }

    #[test]
    fn test_validate_port_range() {
        assert!(validate_port_range(80, PortRange::WellKnown).is_ok());
        assert!(validate_port_range(8080, PortRange::WellKnown).is_err());
        assert!(validate_port_range(8080, PortRange::Registered).is_ok());
        assert!(validate_port_range(50000, PortRange::Dynamic).is_ok());

        // Custom range
        let custom = PortRange::Custom {
            min: 8000,
            max: 9000,
        };
        assert!(validate_port_range(8080, custom).is_ok());
        assert!(validate_port_range(7999, custom).is_err());
    }

    #[test]
    fn test_parse_port() {
        assert!(matches!(parse_port("80"), Ok(80)));
        assert!(matches!(parse_port(" 443 "), Ok(443)));
        assert!(parse_port("0").is_err());
        assert!(parse_port("invalid").is_err());
        assert!(parse_port("99999").is_err());
    }
}
