//! Password policy configuration and validation
//!
//! Implements OWASP ASVS V2.1 password requirements with configurable policies.

use zxcvbn::{Score, zxcvbn};

use crate::primitives::types::Problem;

// ============================================================================
// Password Strength
// ============================================================================

/// Password strength level from zxcvbn analysis
///
/// Maps to zxcvbn's 0-4 score with semantic meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PasswordStrength {
    /// Score 0: Too guessable - risky password
    VeryWeak,
    /// Score 1: Very guessable - protection from throttled online attacks
    Weak,
    /// Score 2: Somewhat guessable - protection from unthrottled online attacks
    Fair,
    /// Score 3: Safely unguessable - moderate protection from offline attacks
    Strong,
    /// Score 4: Very unguessable - strong protection from offline attacks
    VeryStrong,
}

impl PasswordStrength {
    /// Create from zxcvbn Score enum
    #[must_use]
    pub fn from_zxcvbn_score(score: Score) -> Self {
        match score {
            Score::Zero => Self::VeryWeak,
            Score::One => Self::Weak,
            Score::Two => Self::Fair,
            Score::Three => Self::Strong,
            Score::Four => Self::VeryStrong,
            // Handle any future Score variants conservatively
            _ => Self::VeryStrong,
        }
    }

    /// Create from numeric score (0-4)
    #[must_use]
    pub fn from_score(score: u8) -> Self {
        match score {
            0 => Self::VeryWeak,
            1 => Self::Weak,
            2 => Self::Fair,
            3 => Self::Strong,
            _ => Self::VeryStrong,
        }
    }

    /// Check if strength meets minimum requirements (Fair or better)
    #[must_use]
    pub fn is_acceptable(&self) -> bool {
        *self >= Self::Fair
    }

    /// Check if strength is recommended for sensitive use (Strong or better)
    #[must_use]
    pub fn is_recommended(&self) -> bool {
        *self >= Self::Strong
    }

    /// Get the numeric score (0-4)
    #[must_use]
    pub fn score(&self) -> u8 {
        match self {
            Self::VeryWeak => 0,
            Self::Weak => 1,
            Self::Fair => 2,
            Self::Strong => 3,
            Self::VeryStrong => 4,
        }
    }
}

// ============================================================================
// Password Policy Violation
// ============================================================================

/// Specific password policy violation
#[derive(Debug, Clone, PartialEq)]
pub enum PasswordPolicyViolation {
    /// Password is too short
    TooShort {
        /// Minimum required length
        min: usize,
        /// Actual password length
        actual: usize,
    },
    /// Password is too long
    TooLong {
        /// Maximum allowed length
        max: usize,
        /// Actual password length
        actual: usize,
    },
    /// Password strength is too weak
    TooWeak {
        /// Minimum required strength
        required: PasswordStrength,
        /// Actual password strength
        actual: PasswordStrength,
    },
    /// Password is too similar to username
    TooSimilarToUsername {
        /// Calculated similarity (0.0 - 1.0)
        similarity: f32,
        /// Maximum allowed similarity
        max_allowed: f32,
    },
    /// Password was recently used
    RecentlyUsed {
        /// Position in history (1 = most recent)
        within_last: usize,
    },
    /// Password contains the username
    ContainsUsername,
}

impl std::fmt::Display for PasswordPolicyViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort { min, actual } => {
                write!(f, "Password too short: {actual} chars, minimum is {min}")
            }
            Self::TooLong { max, actual } => {
                write!(f, "Password too long: {actual} chars, maximum is {max}")
            }
            Self::TooWeak { required, actual } => {
                write!(
                    f,
                    "Password too weak: score {}, minimum is {}",
                    actual.score(),
                    required.score()
                )
            }
            Self::TooSimilarToUsername {
                similarity,
                max_allowed,
            } => {
                write!(
                    f,
                    "Password too similar to username: {:.0}% similar, maximum is {:.0}%",
                    similarity * 100.0,
                    max_allowed * 100.0
                )
            }
            Self::RecentlyUsed { within_last } => {
                write!(
                    f,
                    "Password was used within the last {within_last} passwords"
                )
            }
            Self::ContainsUsername => {
                write!(f, "Password cannot contain username")
            }
        }
    }
}

impl std::error::Error for PasswordPolicyViolation {}

// ============================================================================
// Password Policy
// ============================================================================

/// Password policy configuration
///
/// Follows OWASP ASVS V2.1 requirements with sensible defaults.
///
/// # Example
///
/// ```ignore
/// use octarine::primitives::auth::password::{PasswordPolicy, validate_password};
///
/// let policy = PasswordPolicy::default();
/// let result = validate_password("my_secure_password_123", &policy, None, &[]);
/// ```
#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    /// Minimum password length (ASVS V2.1.1: >= 8)
    pub min_length: usize,
    /// Maximum password length (ASVS V2.1.2: >= 64)
    pub max_length: usize,
    /// Minimum required strength level
    pub min_strength: PasswordStrength,
    /// Maximum similarity to username (0.0 - 1.0)
    pub max_username_similarity: f32,
    /// Number of previous passwords to check against
    pub history_count: usize,
    /// Whether to reject passwords containing the username
    pub reject_username_in_password: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            min_length: 8,                        // ASVS V2.1.1
            max_length: 128,                      // ASVS V2.1.2 (>= 64)
            min_strength: PasswordStrength::Fair, // Require score >= 2
            max_username_similarity: 0.8,         // 80% similarity threshold
            history_count: 5,                     // ASVS V2.3.1
            reject_username_in_password: true,
        }
    }
}

impl PasswordPolicy {
    /// Create a new policy with default values
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder for custom policy configuration
    #[must_use]
    pub fn builder() -> PasswordPolicyBuilder {
        PasswordPolicyBuilder::new()
    }

    /// Create a strict policy for high-security applications
    #[must_use]
    pub fn strict() -> Self {
        Self {
            min_length: 12,
            max_length: 128,
            min_strength: PasswordStrength::Strong,
            max_username_similarity: 0.6,
            history_count: 10,
            reject_username_in_password: true,
        }
    }

    /// Create a lenient policy for development/testing
    #[must_use]
    pub fn lenient() -> Self {
        Self {
            min_length: 6,
            max_length: 256,
            min_strength: PasswordStrength::Weak,
            max_username_similarity: 0.9,
            history_count: 0,
            reject_username_in_password: false,
        }
    }
}

// ============================================================================
// Password Policy Builder
// ============================================================================

/// Builder for creating custom password policies
#[derive(Debug, Clone, Default)]
pub struct PasswordPolicyBuilder {
    policy: PasswordPolicy,
}

impl PasswordPolicyBuilder {
    /// Create a new builder with default policy
    #[must_use]
    pub fn new() -> Self {
        Self {
            policy: PasswordPolicy::default(),
        }
    }

    /// Set minimum password length
    #[must_use]
    pub fn min_length(mut self, length: usize) -> Self {
        self.policy.min_length = length;
        self
    }

    /// Set maximum password length
    #[must_use]
    pub fn max_length(mut self, length: usize) -> Self {
        self.policy.max_length = length;
        self
    }

    /// Set minimum required strength
    #[must_use]
    pub fn min_strength(mut self, strength: PasswordStrength) -> Self {
        self.policy.min_strength = strength;
        self
    }

    /// Set maximum username similarity (0.0 - 1.0)
    #[must_use]
    pub fn max_username_similarity(mut self, similarity: f32) -> Self {
        self.policy.max_username_similarity = similarity.clamp(0.0, 1.0);
        self
    }

    /// Set password history count
    #[must_use]
    pub fn history_count(mut self, count: usize) -> Self {
        self.policy.history_count = count;
        self
    }

    /// Set whether to reject passwords containing username
    #[must_use]
    pub fn reject_username_in_password(mut self, reject: bool) -> Self {
        self.policy.reject_username_in_password = reject;
        self
    }

    /// Build the policy
    #[must_use]
    pub fn build(self) -> PasswordPolicy {
        self.policy
    }
}

// ============================================================================
// Validation Functions
// ============================================================================

/// Validate a password against a policy
///
/// # Arguments
///
/// * `password` - The password to validate
/// * `policy` - The policy to validate against
/// * `username` - Optional username for similarity checking
/// * `password_history` - List of previous password hashes (for history checking)
///
/// # Returns
///
/// `Ok(())` if the password passes all policy checks, or
/// `Err(Problem)` with details about the first violation found.
///
/// # Example
///
/// ```ignore
/// use octarine::primitives::auth::password::{PasswordPolicy, validate_password};
///
/// let policy = PasswordPolicy::default();
/// match validate_password("secure_password_123", &policy, Some("user@example.com"), &[]) {
///     Ok(()) => println!("Password is valid"),
///     Err(e) => println!("Password rejected: {}", e),
/// }
/// ```
pub fn validate_password(
    password: &str,
    policy: &PasswordPolicy,
    username: Option<&str>,
    password_history: &[&str],
) -> Result<(), Problem> {
    // Check length constraints
    let len = password.len();

    if len < policy.min_length {
        return Err(Problem::Validation(
            PasswordPolicyViolation::TooShort {
                min: policy.min_length,
                actual: len,
            }
            .to_string(),
        ));
    }

    if len > policy.max_length {
        return Err(Problem::Validation(
            PasswordPolicyViolation::TooLong {
                max: policy.max_length,
                actual: len,
            }
            .to_string(),
        ));
    }

    // Check strength using zxcvbn
    let strength = estimate_strength(password, username);
    if strength < policy.min_strength {
        return Err(Problem::Validation(
            PasswordPolicyViolation::TooWeak {
                required: policy.min_strength,
                actual: strength,
            }
            .to_string(),
        ));
    }

    // Check username-related constraints
    if let Some(username) = username {
        // Check if password contains username
        if policy.reject_username_in_password {
            let password_lower = password.to_lowercase();
            let username_lower = username.to_lowercase();

            // Extract username part before @ if email
            let username_part = username_lower.split('@').next().unwrap_or(&username_lower);

            if username_part.len() >= 3 && password_lower.contains(username_part) {
                return Err(Problem::Validation(
                    PasswordPolicyViolation::ContainsUsername.to_string(),
                ));
            }
        }

        // Check similarity to username
        let similarity = calculate_similarity(password, username);
        if similarity > policy.max_username_similarity {
            return Err(Problem::Validation(
                PasswordPolicyViolation::TooSimilarToUsername {
                    similarity,
                    max_allowed: policy.max_username_similarity,
                }
                .to_string(),
            ));
        }
    }

    // Check password history
    if policy.history_count > 0 && !password_history.is_empty() {
        let history_to_check = password_history.iter().take(policy.history_count);

        for (index, &old_hash) in history_to_check.enumerate() {
            // Note: In production, this would use verify_password from crypto module
            // For now, we do a simple comparison (caller should pass hashes)
            if password == old_hash {
                return Err(Problem::Validation(
                    PasswordPolicyViolation::RecentlyUsed {
                        within_last: index.saturating_add(1),
                    }
                    .to_string(),
                ));
            }
        }
    }

    Ok(())
}

/// Estimate password strength using zxcvbn
///
/// Uses Dropbox's zxcvbn algorithm which considers:
/// - Common passwords (30k+ list)
/// - Dictionary words
/// - Keyboard patterns (qwerty, etc.)
/// - L33t speak substitutions
/// - Dates and years
/// - Sequences and repeats
///
/// # Arguments
///
/// * `password` - The password to analyze
/// * `user_input` - Optional user-specific input (username, email) to penalize
///
/// # Returns
///
/// `PasswordStrength` indicating the estimated strength (0-4 scale).
#[must_use]
pub fn estimate_strength(password: &str, user_input: Option<&str>) -> PasswordStrength {
    let user_inputs: Vec<&str> = user_input.into_iter().collect();

    let entropy = zxcvbn(password, &user_inputs);
    PasswordStrength::from_zxcvbn_score(entropy.score())
}

/// Calculate similarity between two strings (0.0 - 1.0)
///
/// Uses a simple Levenshtein-based similarity metric.
fn calculate_similarity(a: &str, b: &str) -> f32 {
    let a_lower = a.to_lowercase();
    let b_lower = b.to_lowercase();

    if a_lower == b_lower {
        return 1.0;
    }

    let max_len = a_lower.len().max(b_lower.len());
    if max_len == 0 {
        return 1.0;
    }

    let distance = levenshtein_distance(&a_lower, &b_lower);
    1.0 - (distance as f32 / max_len as f32)
}

/// Calculate Levenshtein distance between two strings
///
/// Uses a space-optimized algorithm that only keeps two rows in memory.
#[allow(clippy::arithmetic_side_effects)] // Safe: indices bounded by string lengths
fn levenshtein_distance(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();

    let a_len = a_chars.len();
    let b_len = b_chars.len();

    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    // Use two rows instead of full matrix (space optimization)
    let mut prev_row: Vec<usize> = (0..=b_len).collect();
    let mut curr_row: Vec<usize> = vec![0; b_len + 1];

    for (i, a_char) in a_chars.iter().enumerate() {
        if let Some(cell) = curr_row.first_mut() {
            *cell = i + 1;
        }

        for (j, b_char) in b_chars.iter().enumerate() {
            let cost = if a_char == b_char { 0 } else { 1 };

            // All indices are guaranteed valid due to loop bounds
            let deletion = prev_row.get(j + 1).copied().unwrap_or(usize::MAX);
            let insertion = curr_row.get(j).copied().unwrap_or(usize::MAX);
            let substitution = prev_row.get(j).copied().unwrap_or(usize::MAX);

            if let Some(cell) = curr_row.get_mut(j + 1) {
                *cell = deletion
                    .saturating_add(1)
                    .min(insertion.saturating_add(1))
                    .min(substitution.saturating_add(cost));
            }
        }

        std::mem::swap(&mut prev_row, &mut curr_row);
    }

    prev_row.get(b_len).copied().unwrap_or(0)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_password_strength_ordering() {
        assert!(PasswordStrength::VeryWeak < PasswordStrength::Weak);
        assert!(PasswordStrength::Weak < PasswordStrength::Fair);
        assert!(PasswordStrength::Fair < PasswordStrength::Strong);
        assert!(PasswordStrength::Strong < PasswordStrength::VeryStrong);
    }

    #[test]
    fn test_password_strength_acceptable() {
        assert!(!PasswordStrength::VeryWeak.is_acceptable());
        assert!(!PasswordStrength::Weak.is_acceptable());
        assert!(PasswordStrength::Fair.is_acceptable());
        assert!(PasswordStrength::Strong.is_acceptable());
        assert!(PasswordStrength::VeryStrong.is_acceptable());
    }

    #[test]
    fn test_password_strength_recommended() {
        assert!(!PasswordStrength::VeryWeak.is_recommended());
        assert!(!PasswordStrength::Weak.is_recommended());
        assert!(!PasswordStrength::Fair.is_recommended());
        assert!(PasswordStrength::Strong.is_recommended());
        assert!(PasswordStrength::VeryStrong.is_recommended());
    }

    #[test]
    fn test_policy_default() {
        let policy = PasswordPolicy::default();
        assert_eq!(policy.min_length, 8);
        assert_eq!(policy.max_length, 128);
        assert_eq!(policy.min_strength, PasswordStrength::Fair);
    }

    #[test]
    fn test_policy_builder() {
        let policy = PasswordPolicy::builder()
            .min_length(12)
            .max_length(64)
            .min_strength(PasswordStrength::Strong)
            .history_count(10)
            .build();

        assert_eq!(policy.min_length, 12);
        assert_eq!(policy.max_length, 64);
        assert_eq!(policy.min_strength, PasswordStrength::Strong);
        assert_eq!(policy.history_count, 10);
    }

    #[test]
    fn test_validate_too_short() {
        let policy = PasswordPolicy::default();
        let result = validate_password("short", &policy, None, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_too_long() {
        let policy = PasswordPolicy::builder().max_length(20).build();
        let password = "a".repeat(25);
        let result = validate_password(&password, &policy, None, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_good_password() {
        let policy = PasswordPolicy::default();
        // A reasonably strong password
        let result = validate_password("MySecure#Password123!", &policy, None, &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_contains_username() {
        let policy = PasswordPolicy::default();
        let result = validate_password("john_password123", &policy, Some("john"), &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_history() {
        let policy = PasswordPolicy::default();
        let history = vec!["old_password"];
        let result = validate_password("old_password", &policy, None, &history);
        assert!(result.is_err());
    }

    #[test]
    fn test_estimate_strength_weak() {
        let strength = estimate_strength("password", None);
        assert!(strength <= PasswordStrength::Weak);
    }

    #[test]
    fn test_estimate_strength_strong() {
        let strength = estimate_strength("Tr0ub4dor&3#horse!battery", None);
        assert!(strength >= PasswordStrength::Strong);
    }

    #[test]
    fn test_levenshtein_distance() {
        assert_eq!(levenshtein_distance("", ""), 0);
        assert_eq!(levenshtein_distance("abc", "abc"), 0);
        assert_eq!(levenshtein_distance("abc", ""), 3);
        assert_eq!(levenshtein_distance("", "abc"), 3);
        assert_eq!(levenshtein_distance("abc", "abd"), 1);
        assert_eq!(levenshtein_distance("kitten", "sitting"), 3);
    }

    #[test]
    fn test_calculate_similarity() {
        assert!((calculate_similarity("abc", "abc") - 1.0).abs() < 0.001);
        assert!((calculate_similarity("abc", "abd") - 0.666).abs() < 0.1);
        assert!(calculate_similarity("abc", "xyz") < 0.5);
    }
}
