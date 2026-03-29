//! Domain, hostname, and port redaction functions
//!
//! Redaction for domain names, hostnames, and port numbers.

use super::super::redaction::{HostnameRedactionStrategy, PortRedactionStrategy};
use crate::primitives::data::tokens::RedactionTokenCore;

// ============================================================================
// Hostname Redaction
// ============================================================================

/// Redact a single hostname with explicit strategy
///
/// # Arguments
/// * `hostname` - The hostname to redact
/// * `strategy` - How to redact the hostname
#[must_use]
pub fn redact_hostname_with_strategy(
    hostname: &str,
    strategy: HostnameRedactionStrategy,
) -> String {
    if matches!(strategy, HostnameRedactionStrategy::Skip) {
        return hostname.to_string();
    }

    match strategy {
        HostnameRedactionStrategy::Skip => hostname.to_string(),
        HostnameRedactionStrategy::ShowDomain => {
            // Show domain (last 2 parts)
            let parts: Vec<&str> = hostname.split('.').collect();
            if parts.len() >= 2 {
                let len = parts.len();
                if let (Some(second_last), Some(last)) = (
                    parts.get(len.wrapping_sub(2)),
                    parts.get(len.wrapping_sub(1)),
                ) {
                    format!("***.{}.{}", second_last, last)
                } else {
                    RedactionTokenCore::Hostname.into()
                }
            } else {
                RedactionTokenCore::Hostname.into()
            }
        }
        HostnameRedactionStrategy::Token => RedactionTokenCore::Hostname.into(),
        HostnameRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        HostnameRedactionStrategy::Asterisks => "*".repeat(hostname.len()),
        HostnameRedactionStrategy::Hashes => "#".repeat(hostname.len()),
    }
}

// ============================================================================
// Port Redaction
// ============================================================================

/// Redact a single port number
///
/// # Arguments
/// * `port` - The port number to redact
/// * `strategy` - How to redact the port
#[must_use]
pub fn redact_port(port: &str, strategy: PortRedactionStrategy) -> String {
    if matches!(strategy, PortRedactionStrategy::Skip) {
        return port.to_string();
    }

    match strategy {
        PortRedactionStrategy::Skip => port.to_string(),
        PortRedactionStrategy::ShowWellKnown => {
            // Show well-known ports (80, 443, 22, 21, 25, 53, etc.)
            match port {
                "80" | "443" | "22" | "21" | "25" | "53" | "110" | "143" | "3306" | "5432"
                | "6379" | "27017" => port.to_string(),
                _ => RedactionTokenCore::Port.into(),
            }
        }
        PortRedactionStrategy::Token => RedactionTokenCore::Port.into(),
        PortRedactionStrategy::Anonymous => RedactionTokenCore::Redacted.into(),
        PortRedactionStrategy::Asterisks => "*".repeat(port.len()),
        PortRedactionStrategy::Hashes => "#".repeat(port.len()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_redact_hostname_with_strategy_token() {
        assert_eq!(
            redact_hostname_with_strategy("www.example.com", HostnameRedactionStrategy::Token),
            "[HOSTNAME]"
        );
    }

    #[test]
    fn test_redact_hostname_with_strategy_show_domain() {
        assert_eq!(
            redact_hostname_with_strategy("www.example.com", HostnameRedactionStrategy::ShowDomain),
            "***.example.com"
        );
    }

    #[test]
    fn test_redact_port_token() {
        assert_eq!(redact_port("8080", PortRedactionStrategy::Token), "[PORT]");
    }

    #[test]
    fn test_redact_port_show_well_known() {
        assert_eq!(
            redact_port("443", PortRedactionStrategy::ShowWellKnown),
            "443"
        );
        assert_eq!(
            redact_port("8080", PortRedactionStrategy::ShowWellKnown),
            "[PORT]"
        );
    }
}
