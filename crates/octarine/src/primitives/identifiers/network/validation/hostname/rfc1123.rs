//! RFC 1123 hostname validation
//!
//! Pure validation functions for hostnames according to RFC 1123.

use crate::primitives::Problem;

// ============================================================================
// Hostname Validation (RFC 1123)
// ============================================================================

/// Validate hostname according to RFC 1123
///
/// Validates that a hostname conforms to RFC 1123 specifications:
/// - Total length: 1-253 characters
/// - Label length: 1-63 characters each
/// - Labels must start and end with alphanumeric characters
/// - Labels can contain hyphens (but not at start/end)
/// - Labels separated by dots
/// - No underscores (stricter than some implementations)
/// - Case insensitive
///
/// # RFC 1123 Requirements
///
/// From RFC 1123 Section 2.1:
/// - Each label must be 1-63 characters
/// - Total hostname must be 1-253 characters
/// - Labels must start with alphanumeric
/// - Labels must end with alphanumeric
/// - Labels may contain hyphens in the middle
///
/// For bool check, use `validate_hostname_rfc1123(..).is_ok()`.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::identifiers::network::validation::validate_hostname_rfc1123;
///
/// // Valid hostnames
/// assert!(validate_hostname_rfc1123("example.com").is_ok());
/// assert!(validate_hostname_rfc1123("sub-domain.example.com").is_ok());
/// assert!(validate_hostname_rfc1123("localhost").is_ok());
///
/// // Invalid hostnames
/// assert!(validate_hostname_rfc1123("-invalid.com").is_err()); // Starts with hyphen
/// assert!(validate_hostname_rfc1123("invalid-.com").is_err()); // Ends with hyphen
/// assert!(validate_hostname_rfc1123("invalid_name.com").is_err()); // Contains underscore
/// ```
pub fn validate_hostname_rfc1123(hostname: &str) -> Result<(), Problem> {
    // Empty check
    if hostname.is_empty() {
        return Err(Problem::Validation("Hostname cannot be empty".into()));
    }

    // Total length check (RFC 1123: max 253 characters)
    if hostname.len() > 253 {
        return Err(Problem::Validation(format!(
            "Hostname too long ({} characters, max 253)",
            hostname.len()
        )));
    }

    // Remove trailing dot if present (FQDN format)
    let hostname = hostname.strip_suffix('.').unwrap_or(hostname);

    // Split into labels
    let labels: Vec<&str> = hostname.split('.').collect();

    if labels.is_empty() {
        return Err(Problem::Validation("Hostname has no labels".into()));
    }

    // Validate each label
    for (i, label) in labels.iter().enumerate() {
        // Label must not be empty
        if label.is_empty() {
            return Err(Problem::Validation(format!(
                "Label {} is empty (consecutive dots)",
                i.saturating_add(1)
            )));
        }

        // Label length check (RFC 1123: 1-63 characters)
        if label.len() > 63 {
            return Err(Problem::Validation(format!(
                "Label '{}' too long ({} characters, max 63)",
                label,
                label.len()
            )));
        }

        // Label must start with alphanumeric
        let first_char = label
            .chars()
            .next()
            .ok_or_else(|| Problem::Validation("Label has no characters".into()))?;

        if !first_char.is_ascii_alphanumeric() {
            return Err(Problem::Validation(format!(
                "Label '{}' must start with alphanumeric character",
                label
            )));
        }

        // Label must end with alphanumeric
        let last_char = label
            .chars()
            .last()
            .ok_or_else(|| Problem::Validation("Label has no characters".into()))?;

        if !last_char.is_ascii_alphanumeric() {
            return Err(Problem::Validation(format!(
                "Label '{}' must end with alphanumeric character",
                label
            )));
        }

        // Check all characters in label
        for c in label.chars() {
            if !c.is_ascii_alphanumeric() && c != '-' {
                return Err(Problem::Validation(format!(
                    "Label '{}' contains invalid character '{}' (only alphanumeric and hyphens allowed)",
                    label, c
                )));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_validate_hostname_rfc1123_valid() {
        // Single label
        assert!(validate_hostname_rfc1123("localhost").is_ok());
        assert!(validate_hostname_rfc1123("server01").is_ok());

        // Multiple labels
        assert!(validate_hostname_rfc1123("example.com").is_ok());
        assert!(validate_hostname_rfc1123("www.example.com").is_ok());
        assert!(validate_hostname_rfc1123("sub-domain.example.com").is_ok());

        // With hyphens in the middle
        assert!(validate_hostname_rfc1123("my-server.example.com").is_ok());
        assert!(validate_hostname_rfc1123("api-v2.example.com").is_ok());

        // With numbers
        assert!(validate_hostname_rfc1123("server01.dc2.example.com").is_ok());
        assert!(validate_hostname_rfc1123("192-168-1-1.local").is_ok());

        // FQDN with trailing dot
        assert!(validate_hostname_rfc1123("example.com.").is_ok());
    }

    #[test]
    fn test_validate_hostname_rfc1123_invalid_empty() {
        assert!(validate_hostname_rfc1123("").is_err());
    }

    #[test]
    fn test_validate_hostname_rfc1123_invalid_start_hyphen() {
        assert!(validate_hostname_rfc1123("-invalid.com").is_err());
        assert!(validate_hostname_rfc1123("example.-invalid.com").is_err());
    }

    #[test]
    fn test_validate_hostname_rfc1123_invalid_end_hyphen() {
        assert!(validate_hostname_rfc1123("invalid-.com").is_err());
        assert!(validate_hostname_rfc1123("example.invalid-.com").is_err());
    }

    #[test]
    fn test_validate_hostname_rfc1123_invalid_underscore() {
        assert!(validate_hostname_rfc1123("invalid_name.com").is_err());
        assert!(validate_hostname_rfc1123("my_server.example.com").is_err());
    }

    #[test]
    fn test_validate_hostname_rfc1123_invalid_consecutive_dots() {
        assert!(validate_hostname_rfc1123("example..com").is_err());
        assert!(validate_hostname_rfc1123("...example.com").is_err());
    }

    #[test]
    fn test_validate_hostname_rfc1123_invalid_special_chars() {
        assert!(validate_hostname_rfc1123("example@.com").is_err());
        assert!(validate_hostname_rfc1123("example!.com").is_err());
        assert!(validate_hostname_rfc1123("example#.com").is_err());
        assert!(validate_hostname_rfc1123("example$.com").is_err());
    }

    #[test]
    fn test_validate_hostname_rfc1123_max_label_length() {
        // Label of exactly 63 characters (valid)
        let label_63 = "a".repeat(63);
        let hostname = format!("{}.com", label_63);
        assert!(validate_hostname_rfc1123(&hostname).is_ok());

        // Label of 64 characters (invalid)
        let label_64 = "a".repeat(64);
        let hostname = format!("{}.com", label_64);
        assert!(validate_hostname_rfc1123(&hostname).is_err());
    }

    #[test]
    fn test_validate_hostname_rfc1123_max_total_length() {
        // Total of 253 characters (valid)
        // Create labels that sum to exactly 253 characters including dots
        // Format: 63 + 1 (dot) + 63 + 1 (dot) + 63 + 1 (dot) + 61 = 253
        let label = "a".repeat(63);
        let hostname = format!("{}.{}.{}.{}", label, label, label, "a".repeat(61));
        assert_eq!(hostname.len(), 253);
        assert!(validate_hostname_rfc1123(&hostname).is_ok());

        // Total of 254 characters (invalid)
        let label = "a".repeat(63);
        let hostname = format!("{}.{}.{}.{}", label, label, label, "a".repeat(62));
        assert_eq!(hostname.len(), 254);
        assert!(validate_hostname_rfc1123(&hostname).is_err());
    }

    #[test]
    fn test_validate_hostname_rfc1123_single_char_labels() {
        // Single character labels are valid
        assert!(validate_hostname_rfc1123("a.b.c").is_ok());
        assert!(validate_hostname_rfc1123("x.example.com").is_ok());
    }

    #[test]
    fn test_validate_hostname_rfc1123_numeric_labels() {
        // Numeric-only labels are valid (not IP addresses in this context)
        assert!(validate_hostname_rfc1123("123.456.789").is_ok());
        assert!(validate_hostname_rfc1123("2023.example.com").is_ok());
    }

    #[test]
    fn test_validate_hostname_rfc1123_case_insensitive() {
        // RFC 1123 hostnames are case insensitive
        assert!(validate_hostname_rfc1123("Example.COM").is_ok());
        assert!(validate_hostname_rfc1123("WWW.EXAMPLE.COM").is_ok());
        assert!(validate_hostname_rfc1123("MixedCase.Example.Com").is_ok());
    }

    #[test]
    fn test_validate_hostname_rfc1123_errors() {
        // Test that validation returns proper errors
        let result = validate_hostname_rfc1123("");
        assert!(result.is_err());

        let result = validate_hostname_rfc1123("-invalid.com");
        assert!(result.is_err());

        let result = validate_hostname_rfc1123("invalid_.com");
        assert!(result.is_err());
    }

    // ============================================================================
    // Adversarial Tests
    // ============================================================================

    #[test]
    fn test_adversarial_hostname_unicode_tricks() {
        // Unicode homograph attacks (IDN homographs)
        assert!(validate_hostname_rfc1123("exаmple.com").is_err()); // Cyrillic 'а' instead of 'a'
        assert!(validate_hostname_rfc1123("еxample.com").is_err()); // Cyrillic 'е' instead of 'e'

        // Unicode normalization tricks
        assert!(validate_hostname_rfc1123("café.com").is_err()); // Contains non-ASCII
        assert!(validate_hostname_rfc1123("naïve.com").is_err()); // Contains diacritic
        assert!(validate_hostname_rfc1123("🚀rocket.com").is_err()); // Contains emoji

        // Zero-width characters
        assert!(validate_hostname_rfc1123("exam\u{200B}ple.com").is_err()); // Zero-width space
        assert!(validate_hostname_rfc1123("exam\u{FEFF}ple.com").is_err()); // Zero-width no-break space
    }

    #[test]
    fn test_adversarial_hostname_length_boundary() {
        // Exactly at boundary (valid)
        let label_63 = "a".repeat(63);
        assert!(validate_hostname_rfc1123(&label_63).is_ok());

        // Just over boundary (invalid)
        let label_64 = "a".repeat(64);
        assert!(validate_hostname_rfc1123(&label_64).is_err());

        // Total length at boundary (253 chars)
        let hostname_253 = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert!(validate_hostname_rfc1123(&hostname_253).is_ok());

        // Total length over boundary (254 chars)
        let hostname_254 = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(62)
        );
        assert!(validate_hostname_rfc1123(&hostname_254).is_err());
    }

    #[test]
    fn test_adversarial_hostname_special_chars() {
        // Attempting to inject special characters
        assert!(validate_hostname_rfc1123("ex<ample.com").is_err());
        assert!(validate_hostname_rfc1123("ex>ample.com").is_err());
        assert!(validate_hostname_rfc1123("ex'ample.com").is_err());
        assert!(validate_hostname_rfc1123("ex\"ample.com").is_err());
        assert!(validate_hostname_rfc1123("ex;ample.com").is_err());
        assert!(validate_hostname_rfc1123("ex&ample.com").is_err());
        assert!(validate_hostname_rfc1123("ex|ample.com").is_err());
        assert!(validate_hostname_rfc1123("ex`ample.com").is_err());
        assert!(validate_hostname_rfc1123("ex$ample.com").is_err());
        assert!(validate_hostname_rfc1123("ex(ample.com").is_err());
        assert!(validate_hostname_rfc1123("ex)ample.com").is_err());
        assert!(validate_hostname_rfc1123("ex{ample.com").is_err());
        assert!(validate_hostname_rfc1123("ex}ample.com").is_err());
        assert!(validate_hostname_rfc1123("ex[ample.com").is_err());
        assert!(validate_hostname_rfc1123("ex]ample.com").is_err());
    }

    #[test]
    fn test_adversarial_hostname_null_bytes() {
        // Null byte injection attempts
        assert!(validate_hostname_rfc1123("example\0.com").is_err());
        assert!(validate_hostname_rfc1123("example.com\0").is_err());
        assert!(validate_hostname_rfc1123("\0example.com").is_err());
    }

    #[test]
    fn test_adversarial_hostname_case_confusion() {
        // These should all be valid (case insensitive)
        assert!(validate_hostname_rfc1123("EXAMPLE.COM").is_ok());
        assert!(validate_hostname_rfc1123("ExAmPlE.CoM").is_ok());
        assert!(validate_hostname_rfc1123("eXaMpLe.cOm").is_ok());

        // But invalid patterns should still fail regardless of case
        assert!(validate_hostname_rfc1123("-EXAMPLE.COM").is_err());
        assert!(validate_hostname_rfc1123("EXAMPLE-.COM").is_err());
    }

    #[test]
    fn test_adversarial_hostname_consecutive_separators() {
        // Multiple consecutive dots
        assert!(validate_hostname_rfc1123("example..com").is_err());
        assert!(validate_hostname_rfc1123("example...com").is_err());
        assert!(validate_hostname_rfc1123("...example.com").is_err());
        assert!(validate_hostname_rfc1123("example.com...").is_err());

        // Leading/trailing dots (except single trailing dot for FQDN)
        assert!(validate_hostname_rfc1123("example.com.").is_ok()); // FQDN - valid
        assert!(validate_hostname_rfc1123(".example.com").is_err());
    }

    #[test]
    #[ignore = "perf test - timing-sensitive, run manually with: cargo test -p octarine test_adversarial_ -- --ignored"]
    fn test_adversarial_hostname_redos_prevention() {
        // Patterns that might cause ReDoS in poorly written regex
        // Our implementation should handle these efficiently

        // Many hyphens
        let many_hyphens = "a".to_string() + &"-a".repeat(100);
        let start = std::time::Instant::now();
        let _ = validate_hostname_rfc1123(&many_hyphens);
        let duration = start.elapsed();
        // Should complete quickly without hanging
        assert!(duration.as_millis() < 100);

        // Alternating characters
        let alternating = "ab".repeat(100);
        let start = std::time::Instant::now();
        let _ = validate_hostname_rfc1123(&alternating);
        let duration = start.elapsed();
        assert!(duration.as_millis() < 100);

        // Many dots (but not consecutive)
        let many_labels = format!("{}com", "a.".repeat(50));
        let start = std::time::Instant::now();
        let _ = validate_hostname_rfc1123(&many_labels);
        let duration = start.elapsed();
        assert!(duration.as_millis() < 100);
    }
}

#[cfg(test)]
mod proptests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_no_panic_hostname_validation(s in "\\PC*") {
            let _ = validate_hostname_rfc1123(&s);
        }

        #[test]
        fn prop_hostname_label_length(label_len in 1usize..100) {
            let label = "a".repeat(label_len);
            let hostname = format!("{}.com", label);

            let result = validate_hostname_rfc1123(&hostname);

            // Labels > 63 chars should be rejected
            if label_len > 63 {
                assert!(result.is_err(), "Label length {} accepted", label_len);
            } else {
                assert!(result.is_ok(), "Valid label length {} rejected", label_len);
            }
        }

        #[test]
        fn prop_no_resource_exhaustion_hostname(len in 0usize..10_000) {
            let long_hostname = format!("{}.com", "a".repeat(len));

            let start = std::time::Instant::now();
            let _ = validate_hostname_rfc1123(&long_hostname);
            let duration = start.elapsed();

            // Should complete quickly even for long inputs
            assert!(
                duration.as_millis() < 50,
                "Hostname validation took {}ms for {} chars",
                duration.as_millis(),
                len
            );
        }
    }
}
