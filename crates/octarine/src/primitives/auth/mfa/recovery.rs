//! Recovery codes for MFA
//!
//! Backup codes that can be used when TOTP is unavailable.

use crate::primitives::types::Problem;
use rand::RngExt;

// ============================================================================
// Recovery Code
// ============================================================================

/// A single recovery code
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCode {
    /// The code value
    code: String,
    /// Whether this code has been used
    used: bool,
}

impl RecoveryCode {
    /// Create a new recovery code
    #[must_use]
    pub fn new(code: String) -> Self {
        Self { code, used: false }
    }

    /// Get the code value
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Check if this code has been used
    #[must_use]
    pub fn is_used(&self) -> bool {
        self.used
    }

    /// Mark this code as used
    pub fn mark_used(&mut self) {
        self.used = true;
    }

    /// Get the code formatted for display (with hyphen in middle)
    #[must_use]
    pub fn formatted(&self) -> String {
        let len = self.code.len();
        if len > 4 {
            let mid = len / 2;
            format!(
                "{}-{}",
                self.code.get(..mid).unwrap_or(""),
                self.code.get(mid..).unwrap_or("")
            )
        } else {
            self.code.clone()
        }
    }
}

impl std::fmt::Display for RecoveryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.formatted())
    }
}

// ============================================================================
// Recovery Codes Collection
// ============================================================================

/// A set of recovery codes
#[derive(Debug, Clone)]
pub struct RecoveryCodes {
    /// The recovery codes
    codes: Vec<RecoveryCode>,
}

impl RecoveryCodes {
    /// Create a new set of recovery codes
    #[must_use]
    pub fn new(codes: Vec<RecoveryCode>) -> Self {
        Self { codes }
    }

    /// Get all codes
    #[must_use]
    pub fn codes(&self) -> &[RecoveryCode] {
        &self.codes
    }

    /// Get mutable access to codes
    pub fn codes_mut(&mut self) -> &mut [RecoveryCode] {
        &mut self.codes
    }

    /// Get unused codes
    #[must_use]
    pub fn unused_codes(&self) -> Vec<&RecoveryCode> {
        self.codes.iter().filter(|c| !c.is_used()).collect()
    }

    /// Get the count of unused codes
    #[must_use]
    pub fn unused_count(&self) -> usize {
        self.codes.iter().filter(|c| !c.is_used()).count()
    }

    /// Try to consume a recovery code
    ///
    /// Returns `true` if the code was valid and unused (now consumed), `false` otherwise.
    pub fn try_consume(&mut self, code: &str) -> bool {
        // Normalize the code (remove hyphens, spaces, lowercase)
        let normalized = code
            .chars()
            .filter(|c| c.is_alphanumeric())
            .collect::<String>()
            .to_uppercase();

        for recovery_code in &mut self.codes {
            if !recovery_code.is_used() && recovery_code.code().to_uppercase() == normalized {
                recovery_code.mark_used();
                return true;
            }
        }

        false
    }

    /// Check if a code is valid without consuming it
    #[must_use]
    pub fn is_valid(&self, code: &str) -> bool {
        let normalized = code
            .chars()
            .filter(|c| c.is_alphanumeric())
            .collect::<String>()
            .to_uppercase();

        self.codes
            .iter()
            .any(|c| !c.is_used() && c.code().to_uppercase() == normalized)
    }

    /// Get all codes as formatted strings
    #[must_use]
    pub fn formatted_codes(&self) -> Vec<String> {
        self.codes.iter().map(RecoveryCode::formatted).collect()
    }
}

// ============================================================================
// Generation
// ============================================================================

/// Generate a set of recovery codes
///
/// # Arguments
///
/// * `count` - Number of codes to generate
/// * `length` - Length of each code (characters)
///
/// # Returns
///
/// A `RecoveryCodes` set containing the generated codes.
///
/// # Errors
///
/// Returns an error if generation fails.
pub fn generate_recovery_codes(count: usize, length: usize) -> Result<RecoveryCodes, Problem> {
    if count == 0 {
        return Err(Problem::Validation(
            "Must generate at least one recovery code".to_string(),
        ));
    }

    if length < 4 {
        return Err(Problem::Validation(
            "Recovery codes must be at least 4 characters".to_string(),
        ));
    }

    let mut rng = rand::rng();
    let mut codes = Vec::with_capacity(count);

    // Use alphanumeric characters (excluding confusing ones like 0, O, 1, l, I)
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

    for _ in 0..count {
        let code: String = (0..length)
            .map(|_| {
                let idx = rng.random_range(0..ALPHABET.len());
                char::from(ALPHABET.get(idx).copied().unwrap_or(b'A'))
            })
            .collect();

        codes.push(RecoveryCode::new(code));
    }

    Ok(RecoveryCodes::new(codes))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_recovery_code_formatting() {
        let code = RecoveryCode::new("ABCD1234".to_string());
        assert_eq!(code.formatted(), "ABCD-1234");
    }

    #[test]
    fn test_recovery_code_used() {
        let mut code = RecoveryCode::new("ABCD1234".to_string());
        assert!(!code.is_used());
        code.mark_used();
        assert!(code.is_used());
    }

    #[test]
    fn test_generate_recovery_codes() {
        let codes = generate_recovery_codes(10, 8).expect("should generate codes");
        assert_eq!(codes.codes().len(), 10);
        assert_eq!(codes.unused_count(), 10);

        for code in codes.codes() {
            assert_eq!(code.code().len(), 8);
            assert!(!code.is_used());
        }
    }

    #[test]
    fn test_try_consume() {
        let mut codes = generate_recovery_codes(5, 8).expect("should generate codes");

        let first_code = codes
            .codes()
            .first()
            .expect("should have code")
            .code()
            .to_string();

        // First use should succeed
        assert!(codes.try_consume(&first_code));
        assert_eq!(codes.unused_count(), 4);

        // Second use should fail
        assert!(!codes.try_consume(&first_code));
        assert_eq!(codes.unused_count(), 4);
    }

    #[test]
    fn test_verify_with_formatting() {
        let mut codes = RecoveryCodes::new(vec![RecoveryCode::new("ABCD1234".to_string())]);

        // Should accept with hyphen
        assert!(codes.try_consume("ABCD-1234"));
    }

    #[test]
    fn test_verify_case_insensitive() {
        let mut codes = RecoveryCodes::new(vec![RecoveryCode::new("ABCD1234".to_string())]);

        // Should accept lowercase
        assert!(codes.try_consume("abcd1234"));
    }

    #[test]
    fn test_is_valid_without_consuming() {
        let codes = RecoveryCodes::new(vec![RecoveryCode::new("ABCD1234".to_string())]);

        assert!(codes.is_valid("ABCD1234"));
        assert_eq!(codes.unused_count(), 1); // Still unused
    }

    #[test]
    fn test_generate_zero_codes_fails() {
        let result = generate_recovery_codes(0, 8);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_short_codes_fails() {
        let result = generate_recovery_codes(10, 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_unused_codes() {
        let mut codes = generate_recovery_codes(5, 8).expect("should generate codes");

        let first_code = codes
            .codes()
            .first()
            .expect("should have code")
            .code()
            .to_string();
        codes.try_consume(&first_code);

        let unused = codes.unused_codes();
        assert_eq!(unused.len(), 4);
        assert!(unused.iter().all(|c| !c.is_used()));
    }

    #[test]
    fn test_try_consume_empty_string() {
        let mut codes = RecoveryCodes::new(vec![RecoveryCode::new("ABCD1234".to_string())]);
        assert!(!codes.try_consume(""));
        assert_eq!(codes.unused_count(), 1);
    }

    #[test]
    fn test_try_consume_whitespace_only() {
        let mut codes = RecoveryCodes::new(vec![RecoveryCode::new("ABCD1234".to_string())]);
        assert!(!codes.try_consume("   "));
        assert_eq!(codes.unused_count(), 1);
    }

    #[test]
    fn test_try_consume_with_spaces() {
        let mut codes = RecoveryCodes::new(vec![RecoveryCode::new("ABCD1234".to_string())]);
        // Spaces should be stripped, then code should match
        assert!(codes.try_consume("ABCD 1234"));
        assert_eq!(codes.unused_count(), 0);
    }

    #[test]
    fn test_try_consume_nonexistent() {
        let mut codes = RecoveryCodes::new(vec![RecoveryCode::new("ABCD1234".to_string())]);
        assert!(!codes.try_consume("WXYZ9999"));
        assert_eq!(codes.unused_count(), 1);
    }

    #[test]
    fn test_try_consume_all_used() {
        let mut codes = RecoveryCodes::new(vec![RecoveryCode::new("ABCD1234".to_string())]);
        assert!(codes.try_consume("ABCD1234"));
        assert!(!codes.try_consume("ABCD1234")); // Already used
        assert_eq!(codes.unused_count(), 0);
    }

    #[test]
    fn test_is_valid_empty_string() {
        let codes = RecoveryCodes::new(vec![RecoveryCode::new("ABCD1234".to_string())]);
        assert!(!codes.is_valid(""));
    }

    #[test]
    fn test_is_valid_used_code() {
        let mut codes = RecoveryCodes::new(vec![RecoveryCode::new("ABCD1234".to_string())]);
        codes.try_consume("ABCD1234");
        // Used code should not be valid
        assert!(!codes.is_valid("ABCD1234"));
    }
}
