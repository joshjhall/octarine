//! Security Assertions
//!
//! Assertions for validating security properties in tests.

/// Assert that a string contains no path traversal sequences
///
/// # Panics
///
/// Panics if the input contains path traversal patterns like `..` or `%2e%2e`.
///
/// # Example
///
/// ```rust,ignore
/// use octarine::testing::assertions::assert_no_path_traversal;
///
/// assert_no_path_traversal("/safe/path/file.txt"); // OK
/// assert_no_path_traversal("../etc/passwd"); // Panics!
/// ```
#[track_caller]
pub fn assert_no_path_traversal(input: &str) {
    let traversal_patterns = [
        "..",
        "%2e%2e",
        "%252e%252e",
        "..%c0%af",
        "..%c1%9c",
        "....//",
    ];

    for pattern in &traversal_patterns {
        if input.to_lowercase().contains(pattern) {
            panic!(
                "Path traversal detected: '{}' contains pattern '{}'",
                input, pattern
            );
        }
    }
}

/// Assert that a string contains no command injection patterns
///
/// # Panics
///
/// Panics if the input contains shell metacharacters or command substitution.
///
/// # Example
///
/// ```rust,ignore
/// use octarine::testing::assertions::assert_no_command_injection;
///
/// assert_no_command_injection("safe_filename.txt"); // OK
/// assert_no_command_injection("$(whoami)"); // Panics!
/// ```
#[track_caller]
pub fn assert_no_command_injection(input: &str) {
    let injection_patterns = [
        ("$(", "command substitution"),
        ("${", "variable expansion"),
        ("`", "backtick substitution"),
        (";", "command separator"),
        ("|", "pipe"),
        ("&&", "and operator"),
        ("||", "or operator"),
        ("\n", "newline injection"),
        ("\r", "carriage return injection"),
    ];

    for (pattern, description) in &injection_patterns {
        if input.contains(pattern) {
            panic!(
                "Command injection detected: '{}' contains {} ('{}')",
                input, description, pattern
            );
        }
    }
}

/// Assert that a string contains no SQL injection patterns
///
/// # Panics
///
/// Panics if the input contains common SQL injection patterns.
///
/// # Example
///
/// ```rust,ignore
/// use octarine::testing::assertions::assert_no_sql_injection;
///
/// assert_no_sql_injection("normal_user"); // OK
/// assert_no_sql_injection("'; DROP TABLE users;--"); // Panics!
/// ```
#[track_caller]
pub fn assert_no_sql_injection(input: &str) {
    let upper = input.to_uppercase();
    let sql_patterns = [
        ("'", "single quote"),
        ("--", "SQL comment"),
        (";", "statement terminator"),
    ];

    let sql_keywords = [
        "DROP TABLE",
        "DELETE FROM",
        "INSERT INTO",
        "UPDATE ",
        "UNION SELECT",
        "UNION ALL",
        "OR 1=1",
        "AND 1=1",
        " OR '",
        " AND '",
    ];

    for (pattern, description) in &sql_patterns {
        if input.contains(pattern) && sql_keywords.iter().any(|kw| upper.contains(kw)) {
            panic!(
                "SQL injection detected: '{}' contains {} with SQL keyword",
                input, description
            );
        }
    }

    for keyword in &sql_keywords {
        if upper.contains(keyword) {
            panic!(
                "SQL injection detected: '{}' contains keyword '{}'",
                input, keyword
            );
        }
    }
}

/// Assert that a string contains no XSS patterns
///
/// # Panics
///
/// Panics if the input contains HTML/JavaScript injection patterns.
///
/// # Example
///
/// ```rust,ignore
/// use octarine::testing::assertions::assert_no_xss;
///
/// assert_no_xss("Hello, World!"); // OK
/// assert_no_xss("<script>alert(1)</script>"); // Panics!
/// ```
#[track_caller]
pub fn assert_no_xss(input: &str) {
    let lower = input.to_lowercase();
    let xss_patterns = [
        ("<script", "script tag"),
        ("javascript:", "javascript URL"),
        ("onerror=", "onerror handler"),
        ("onload=", "onload handler"),
        ("onclick=", "onclick handler"),
        ("onmouseover=", "onmouseover handler"),
        ("data:text/html", "data URL"),
        ("&#", "HTML entity encoding"),
        ("%3c", "URL-encoded angle bracket"),
    ];

    for (pattern, description) in &xss_patterns {
        if lower.contains(pattern) {
            panic!("XSS detected: '{}' contains {} pattern", input, description);
        }
    }
}

/// Assert that a string contains no null bytes
///
/// # Panics
///
/// Panics if the input contains null bytes which can be used for injection.
///
/// # Example
///
/// ```rust,ignore
/// use octarine::testing::assertions::assert_no_null_bytes;
///
/// assert_no_null_bytes("normal_string"); // OK
/// assert_no_null_bytes("file.txt\0.jpg"); // Panics!
/// ```
#[track_caller]
pub fn assert_no_null_bytes(input: &str) {
    if input.contains('\0') {
        panic!(
            "Null byte injection detected in: '{}'",
            input.escape_debug()
        );
    }
}

/// Assert that a string represents a safe URL (no SSRF patterns)
///
/// # Panics
///
/// Panics if the URL targets internal resources.
///
/// # Example
///
/// ```rust,ignore
/// use octarine::testing::assertions::assert_safe_url;
///
/// assert_safe_url("https://example.com/api"); // OK
/// assert_safe_url("http://169.254.169.254/"); // Panics! (AWS metadata)
/// ```
#[track_caller]
pub fn assert_safe_url(url: &str) {
    let lower = url.to_lowercase();
    let unsafe_patterns = [
        ("169.254.169.254", "AWS metadata endpoint"),
        ("metadata.google", "GCP metadata endpoint"),
        ("localhost", "localhost"),
        ("127.0.0.1", "loopback IPv4"),
        ("[::1]", "loopback IPv6"),
        ("0.0.0.0", "any address"),
        ("10.", "private network 10.x"),
        ("192.168.", "private network 192.168.x"),
        ("file://", "file protocol"),
        ("gopher://", "gopher protocol"),
        ("dict://", "dict protocol"),
    ];

    for (pattern, description) in &unsafe_patterns {
        if lower.contains(pattern) {
            panic!(
                "Unsafe URL detected: '{}' targets {} ('{}')",
                url, description, pattern
            );
        }
    }
}

/// Assert that a string is properly redacted (contains no PII patterns)
///
/// # Panics
///
/// Panics if the input contains unredacted PII-like patterns.
///
/// # Example
///
/// ```rust,ignore
/// use octarine::testing::assertions::assert_properly_redacted;
///
/// assert_properly_redacted("User ID: [SSN]"); // OK
/// assert_properly_redacted("SSN: 123-45-6789"); // Panics!
/// ```
#[track_caller]
pub fn assert_properly_redacted(input: &str) {
    // Check for SSN-like patterns
    let ssn_pattern =
        regex::Regex::new(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b").expect("Invalid SSN regex pattern");
    if ssn_pattern.is_match(input) {
        panic!("Unredacted SSN-like pattern found in: '{}'", input);
    }

    // Check for email patterns
    let email_pattern = regex::Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
        .expect("Invalid email regex pattern");
    if email_pattern.is_match(input) {
        panic!("Unredacted email pattern found in: '{}'", input);
    }

    // Check for credit card-like patterns
    let cc_pattern = regex::Regex::new(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b")
        .expect("Invalid credit card regex pattern");
    if cc_pattern.is_match(input) {
        panic!("Unredacted credit card-like pattern found in: '{}'", input);
    }
}

/// Assert that log output is safe (no injection patterns)
///
/// # Panics
///
/// Panics if the input contains log injection patterns.
///
/// # Example
///
/// ```rust,ignore
/// use octarine::testing::assertions::assert_safe_log_output;
///
/// assert_safe_log_output("User logged in successfully"); // OK
/// assert_safe_log_output("User\n[ERROR] Fake error"); // Panics!
/// ```
#[track_caller]
pub fn assert_safe_log_output(input: &str) {
    let unsafe_patterns = [
        ("\n[", "newline followed by log prefix"),
        ("\r\n[", "CRLF followed by log prefix"),
        ("\x1b[", "ANSI escape sequence"),
        ("\x1b]", "OSC escape sequence"),
        ("\u{202E}", "right-to-left override"),
    ];

    for (pattern, description) in &unsafe_patterns {
        if input.contains(pattern) {
            panic!(
                "Log injection detected: output contains {} pattern",
                description
            );
        }
    }
}

/// Assert that two values are equal in a security-relevant way
///
/// This performs constant-time comparison to prevent timing attacks.
/// Note: The actual comparison in this test helper is not constant-time,
/// but production security code should use proper constant-time comparison.
///
/// # Panics
///
/// Panics if the values are not equal.
#[track_caller]
pub fn assert_secure_eq(left: &[u8], right: &[u8]) {
    if left.len() != right.len() {
        panic!(
            "Secure comparison failed: lengths differ ({} vs {})",
            left.len(),
            right.len()
        );
    }

    // In production, use constant_time_eq or similar
    // This is just for test assertions
    if left != right {
        panic!("Secure comparison failed: values differ");
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_no_path_traversal_safe() {
        assert_no_path_traversal("/safe/path/file.txt");
        assert_no_path_traversal("file.txt");
        assert_no_path_traversal("/home/user/documents");
    }

    #[test]
    #[should_panic(expected = "Path traversal")]
    fn test_no_path_traversal_unsafe() {
        assert_no_path_traversal("../etc/passwd");
    }

    #[test]
    fn test_no_command_injection_safe() {
        assert_no_command_injection("safe_filename.txt");
        assert_no_command_injection("normal input");
    }

    #[test]
    #[should_panic(expected = "Command injection")]
    fn test_no_command_injection_unsafe() {
        assert_no_command_injection("$(whoami)");
    }

    #[test]
    fn test_no_sql_injection_safe() {
        assert_no_sql_injection("normal_username");
        assert_no_sql_injection("user123");
    }

    #[test]
    #[should_panic(expected = "SQL injection")]
    fn test_no_sql_injection_unsafe() {
        assert_no_sql_injection("' OR 1=1 --");
    }

    #[test]
    fn test_no_xss_safe() {
        assert_no_xss("Hello, World!");
        assert_no_xss("Just some text");
    }

    #[test]
    #[should_panic(expected = "XSS")]
    fn test_no_xss_unsafe() {
        assert_no_xss("<script>alert(1)</script>");
    }

    #[test]
    fn test_no_null_bytes_safe() {
        assert_no_null_bytes("normal string");
    }

    #[test]
    #[should_panic(expected = "Null byte")]
    fn test_no_null_bytes_unsafe() {
        assert_no_null_bytes("file.txt\0.jpg");
    }

    #[test]
    fn test_safe_url_safe() {
        assert_safe_url("https://example.com/api");
        assert_safe_url("https://api.service.com/v1/users");
    }

    #[test]
    #[should_panic(expected = "Unsafe URL")]
    fn test_safe_url_unsafe() {
        assert_safe_url("http://169.254.169.254/latest/meta-data/");
    }

    #[test]
    fn test_properly_redacted_safe() {
        assert_properly_redacted("User ID: [SSN]");
        assert_properly_redacted("Email: [EMAIL]");
    }

    #[test]
    #[should_panic(expected = "Unredacted")]
    fn test_properly_redacted_unsafe() {
        assert_properly_redacted("SSN: 123-45-6789");
    }

    #[test]
    fn test_safe_log_output_safe() {
        assert_safe_log_output("User logged in successfully");
        assert_safe_log_output("Request processed");
    }

    #[test]
    #[should_panic(expected = "Log injection")]
    fn test_safe_log_output_unsafe() {
        assert_safe_log_output("User input\n[ERROR] Fake error");
    }

    #[test]
    fn test_secure_eq_equal() {
        assert_secure_eq(b"hello", b"hello");
    }

    #[test]
    #[should_panic(expected = "values differ")]
    fn test_secure_eq_not_equal() {
        assert_secure_eq(b"hello", b"world");
    }
}
