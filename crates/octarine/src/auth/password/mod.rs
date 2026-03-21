//! Password operations with observe integration
//!
//! This module wraps password primitives with observe instrumentation for
//! compliance-grade audit trails.
//!
//! # Features
//!
//! - Password policy validation with audit events
//! - Password strength estimation
//! - Username similarity checking
//! - Password history checking
//! - HIBP breach checking (requires `auth-hibp` feature)
//!
//! # Audit Events
//!
//! All operations emit observe events:
//! - `auth.password.validated` - Password passed policy
//! - `auth.password.policy_violation` - Password rejected
//! - `auth.password.strength_checked` - Strength estimation performed
//! - `auth.password.breach_check` - HIBP check performed (auth-hibp feature)
//! - `auth.password.breach_detected` - Password found in breaches (auth-hibp feature)

#[cfg(feature = "auth-hibp")]
mod hibp;

use std::time::Instant;

use crate::observe;
use crate::primitives::auth::password as prim;
use crate::primitives::types::Problem;

// Re-export types from primitives
pub use prim::{PasswordPolicy, PasswordPolicyBuilder, PasswordPolicyViolation, PasswordStrength};

// Re-export HIBP types (auth-hibp feature)
#[cfg(feature = "auth-hibp")]
pub use hibp::{HibpClient, HibpConfig, HibpConfigBuilder, check_breach};

// ============================================================================
// Public API
// ============================================================================

/// Validate a password against a policy with audit logging
///
/// This function wraps the primitive `validate_password` with observe
/// instrumentation, emitting events for compliance tracking.
///
/// # Arguments
///
/// * `password` - The password to validate
/// * `policy` - The policy to validate against
/// * `username` - Optional username for similarity checking
///
/// # Returns
///
/// `Ok(())` if the password passes all policy checks, or
/// `Err(Problem)` with details about the violation.
///
/// # Audit Events
///
/// - On success: `auth.password.validated` (INFO)
/// - On failure: `auth.password.policy_violation` (WARN)
///
/// # Example
///
/// ```ignore
/// use octarine::auth::{PasswordPolicy, validate_password};
///
/// let policy = PasswordPolicy::default();
/// match validate_password("MySecure#Password123!", &policy, Some("user@example.com")) {
///     Ok(()) => println!("Password is valid"),
///     Err(e) => println!("Password rejected: {}", e),
/// }
/// ```
pub fn validate_password(
    password: &str,
    policy: &PasswordPolicy,
    username: Option<&str>,
) -> Result<(), Problem> {
    validate_password_with_history(password, policy, username, &[])
}

/// Validate a password with history checking
///
/// Like `validate_password`, but also checks against a list of previous
/// password hashes to prevent password reuse.
///
/// # Arguments
///
/// * `password` - The password to validate
/// * `policy` - The policy to validate against
/// * `username` - Optional username for similarity checking
/// * `password_history` - List of previous passwords to check against
///
/// # Audit Events
///
/// - `auth.password.history_violation` if password was recently used
pub fn validate_password_with_history(
    password: &str,
    policy: &PasswordPolicy,
    username: Option<&str>,
    password_history: &[&str],
) -> Result<(), Problem> {
    let start = Instant::now();

    let result = prim::validate_password(password, policy, username, password_history);

    let elapsed = start.elapsed();

    match &result {
        Ok(()) => {
            observe::debug(
                "auth.password.validated",
                format!("Password validated in {:?}", elapsed),
            );
        }
        Err(e) => {
            observe::warn(
                "auth.password.policy_violation",
                format!("Password policy violation: {}", e),
            );
        }
    }

    result
}

/// Estimate password strength with audit logging
///
/// Uses the zxcvbn algorithm (Dropbox's password strength estimator) to
/// analyze password strength, considering:
/// - Common passwords (30k+ list)
/// - Dictionary words
/// - Keyboard patterns
/// - L33t speak substitutions
/// - Dates and sequences
///
/// # Arguments
///
/// * `password` - The password to analyze
///
/// # Returns
///
/// `PasswordStrength` indicating the estimated strength (0-4 scale).
///
/// # Audit Events
///
/// - `auth.password.strength_checked` (DEBUG)
///
/// # Example
///
/// ```ignore
/// use octarine::auth::estimate_strength;
///
/// let strength = estimate_strength("MySecure#Password123!");
/// if strength.is_acceptable() {
///     println!("Password is acceptable");
/// }
/// ```
#[must_use]
pub fn estimate_strength(password: &str) -> PasswordStrength {
    estimate_strength_with_context(password, None)
}

/// Estimate password strength with user context
///
/// Like `estimate_strength`, but considers user-specific inputs (username,
/// email) that should be penalized if found in the password.
///
/// # Arguments
///
/// * `password` - The password to analyze
/// * `user_input` - Optional user-specific input to penalize
#[must_use]
pub fn estimate_strength_with_context(
    password: &str,
    user_input: Option<&str>,
) -> PasswordStrength {
    let strength = prim::estimate_strength(password, user_input);

    observe::debug(
        "auth.password.strength_checked",
        format!(
            "Password strength: {:?} (score {})",
            strength,
            strength.score()
        ),
    );

    strength
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_password_success() {
        let policy = PasswordPolicy::default();
        let result = validate_password("MySecure#Password123!", &policy, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_password_too_short() {
        let policy = PasswordPolicy::default();
        let result = validate_password("short", &policy, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_password_with_username() {
        let policy = PasswordPolicy::default();
        // Password contains username - should fail
        let result = validate_password("john_password123", &policy, Some("john"));
        assert!(result.is_err());
    }

    #[test]
    fn test_estimate_strength() {
        // Weak password
        let weak = estimate_strength("password");
        assert!(!weak.is_acceptable());

        // Strong password
        let strong = estimate_strength("Tr0ub4dor&3#horse!battery");
        assert!(strong.is_acceptable());
    }

    #[test]
    fn test_validate_with_history() {
        let policy = PasswordPolicy::default();
        let history = vec!["OldPassword123!"];

        // New password should pass
        let result =
            validate_password_with_history("NewSecure#Password456!", &policy, None, &history);
        assert!(result.is_ok());

        // Old password should fail
        let result = validate_password_with_history("OldPassword123!", &policy, None, &history);
        assert!(result.is_err());
    }
}
