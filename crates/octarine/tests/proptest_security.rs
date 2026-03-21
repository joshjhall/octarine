//! Property-based tests for security-critical functions
//!
//! Uses proptest to verify that security detection functions
//! correctly identify attack patterns without false negatives.

#![cfg(all(feature = "testing", feature = "security"))]
#![allow(clippy::panic, clippy::expect_used)]

use octarine::testing::generators::{arb_command_injection, arb_path_traversal, arb_ssrf_url};
use proptest::prelude::*;
use proptest::strategy::BoxedStrategy;

// Create boxed versions of our strategies to help with type inference
fn path_traversal_strategy() -> BoxedStrategy<String> {
    arb_path_traversal().boxed()
}

fn command_injection_strategy() -> BoxedStrategy<String> {
    arb_command_injection().boxed()
}

fn ssrf_url_strategy() -> BoxedStrategy<String> {
    arb_ssrf_url().boxed()
}

// ============================================================================
// Path Traversal Detection
// ============================================================================

proptest! {
    /// Verify path traversal detection never has false negatives
    ///
    /// All attack patterns from arb_path_traversal() must be detected.
    #[test]
    fn path_traversal_detected(attack in path_traversal_strategy()) {
        use octarine::security::paths;

        // Primary detection function must catch all traversal attacks
        // The attack contains either traversal (..) or injection patterns
        let has_threat = paths::is_threat_present(&attack);

        prop_assert!(
            has_threat,
            "Path traversal attack not detected: {}",
            attack
        );
    }

    /// Verify safe paths are not flagged as threats
    #[test]
    fn safe_paths_not_flagged(
        prefix in "[a-zA-Z0-9_]{1,20}",
        suffix in "[a-zA-Z0-9_]{1,20}"
    ) {
        use octarine::security::paths;

        // Build a path that should be safe: only alphanumeric and underscores
        let safe_path = format!("{}/{}", prefix, suffix);

        // Safe paths should not trigger threat detection
        if !safe_path.contains("..") && !safe_path.contains("%2e") {
            prop_assert!(
                !paths::is_threat_present(&safe_path),
                "Safe path incorrectly flagged: {}",
                safe_path
            );
        }
    }
}

// ============================================================================
// Command Injection Detection
// ============================================================================

proptest! {
    /// Verify command injection detection catches all patterns
    #[test]
    fn command_injection_detected(attack in command_injection_strategy()) {
        use octarine::security::commands;

        // Commands module should detect dangerous patterns
        let has_threat = commands::is_dangerous_arg(&attack);

        // Every command injection attack should trigger detection
        prop_assert!(
            has_threat,
            "Command injection attack not detected: {}",
            attack
        );
    }
}

// ============================================================================
// SSRF Detection
// ============================================================================

proptest! {
    /// Verify SSRF detection catches all internal/dangerous URLs
    #[test]
    fn ssrf_attacks_detected(url in ssrf_url_strategy()) {
        use octarine::security::network;

        // SSRF validation should reject these URLs
        let result = network::validate_ssrf_safe(&url);

        // All attack URLs from arb_ssrf_url() target internal resources
        // or use dangerous schemes - they should all be rejected
        prop_assert!(
            result.is_err(),
            "SSRF attack URL passed validation: {}",
            url
        );
    }
}

// ============================================================================
// Null Byte Detection (via path security)
// ============================================================================

proptest! {
    /// Verify null bytes are always detected in paths
    #[test]
    fn null_bytes_detected(
        prefix in "[a-zA-Z0-9]{0,20}",
        suffix in "[a-zA-Z0-9]{0,20}"
    ) {
        use octarine::security::paths;

        let with_null = format!("{}\0{}", prefix, suffix);

        prop_assert!(
            paths::is_null_bytes_present(&with_null),
            "Null byte not detected in: {:?}",
            with_null
        );
    }
}

// ============================================================================
// Safe URL Validation
// ============================================================================

#[test]
fn safe_urls_are_allowed() {
    use octarine::security::network;

    let safe_urls = [
        "https://api.example.com/path",
        "https://www.test.org/resource",
        "https://cdn.demo.net/assets",
    ];

    for url in safe_urls {
        let result = network::validate_ssrf_safe(url);
        assert!(
            result.is_ok(),
            "Safe URL incorrectly blocked: {} - {:?}",
            url,
            result.err()
        );
    }
}

// ============================================================================
// SQL Injection Detection (requires database feature)
// ============================================================================

#[cfg(feature = "database")]
mod sql_injection_tests {
    use super::*;
    use octarine::testing::generators::arb_sql_injection;

    fn sql_injection_strategy() -> BoxedStrategy<String> {
        arb_sql_injection().boxed()
    }

    proptest! {
        /// Verify SQL injection detection catches all patterns
        #[test]
        fn sql_injection_detected(attack in sql_injection_strategy()) {
            use octarine::security::queries;

            // detect_sql_threats should find threats in all attack patterns
            let threats = queries::detect_sql_threats(&attack);

            // Every SQL injection attack should trigger detection
            // Note: Reserved keywords alone may not trigger if detector requires context
            let is_keyword_only = matches!(
                attack.to_uppercase().as_str(),
                "SELECT" | "DROP" | "DELETE" | "INSERT" | "UPDATE"
            );

            prop_assert!(
                !threats.is_empty() || is_keyword_only,
                "SQL injection attack not detected: {}",
                attack
            );
        }
    }
}
