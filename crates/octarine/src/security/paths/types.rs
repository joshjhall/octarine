//! Security-related path types
//!
//! These types form the canonical location for path security types.
//! They are re-exported from `data::paths` for convenience.

// ============================================================================
// Security Threat Types
// ============================================================================

/// Security threat type detected in path
///
/// These threats correspond to common path-based attacks
/// documented in CWE and OWASP guidelines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityThreat {
    /// Directory traversal attempt (`..`)
    /// CWE-22: Improper Limitation of a Pathname to a Restricted Directory
    Traversal,
    /// Encoded traversal (`%2e%2e`, `..%2f`)
    /// CWE-22 variant with encoding bypass
    EncodedTraversal,
    /// Command injection (`$()`, backticks)
    /// CWE-78: Improper Neutralization of Special Elements used in an OS Command
    CommandInjection,
    /// Variable expansion (`${VAR}`, `$HOME`)
    /// CWE-78 variant through environment variable injection
    VariableExpansion,
    /// Shell metacharacters (`;`, `|`, `&`)
    /// CWE-78 variant through shell metacharacters
    ShellMetacharacters,
    /// Null byte injection (`\0`)
    /// CWE-158: Improper Neutralization of Null Byte or NUL Character
    NullByte,
    /// Control characters (newline, carriage return, etc.)
    /// CWE-707: Improper Neutralization
    ControlCharacters,
    /// Double/multiple encoding (`%252e%252e`)
    /// CWE-175: Improper Handling of Mixed Encoding
    DoubleEncoding,
    /// Absolute path when relative expected
    /// Boundary violation attempt
    AbsolutePath,
}

impl SecurityThreat {
    /// Get the CWE identifier for this threat
    #[must_use]
    pub const fn cwe(&self) -> &'static str {
        match self {
            Self::Traversal | Self::EncodedTraversal | Self::AbsolutePath => "CWE-22",
            Self::CommandInjection | Self::VariableExpansion | Self::ShellMetacharacters => {
                "CWE-78"
            }
            Self::NullByte => "CWE-158",
            Self::ControlCharacters => "CWE-707",
            Self::DoubleEncoding => "CWE-175",
        }
    }

    /// Get the severity level (1-5, higher = more severe)
    #[must_use]
    pub const fn severity(&self) -> u8 {
        match self {
            Self::CommandInjection => 5,    // Critical - RCE possible
            Self::NullByte => 5,            // Critical - can bypass checks
            Self::Traversal => 4,           // High - data access
            Self::EncodedTraversal => 4,    // High - bypass attempt
            Self::DoubleEncoding => 4,      // High - bypass attempt
            Self::VariableExpansion => 3,   // Medium - information disclosure
            Self::ShellMetacharacters => 3, // Medium - command chaining
            Self::ControlCharacters => 2,   // Low - log injection
            Self::AbsolutePath => 2,        // Low - boundary violation
        }
    }

    /// Get a human-readable description
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::Traversal => "Directory traversal attempt using '..'",
            Self::EncodedTraversal => "Encoded directory traversal bypass attempt",
            Self::CommandInjection => "Command injection through substitution",
            Self::VariableExpansion => "Environment variable expansion attempt",
            Self::ShellMetacharacters => "Shell metacharacter injection",
            Self::NullByte => "Null byte injection for truncation attack",
            Self::ControlCharacters => "Control character injection",
            Self::DoubleEncoding => "Double/multiple encoding bypass attempt",
            Self::AbsolutePath => "Absolute path escaping boundary",
        }
    }
}

impl std::fmt::Display for SecurityThreat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.description(), self.cwe())
    }
}

impl From<crate::primitives::data::paths::SecurityThreat> for SecurityThreat {
    fn from(t: crate::primitives::data::paths::SecurityThreat) -> Self {
        use crate::primitives::data::paths::SecurityThreat as P;
        match t {
            P::Traversal => Self::Traversal,
            P::EncodedTraversal => Self::EncodedTraversal,
            P::CommandInjection => Self::CommandInjection,
            P::VariableExpansion => Self::VariableExpansion,
            P::ShellMetacharacters => Self::ShellMetacharacters,
            P::NullByte => Self::NullByte,
            P::ControlCharacters => Self::ControlCharacters,
            P::DoubleEncoding => Self::DoubleEncoding,
            P::AbsolutePath => Self::AbsolutePath,
        }
    }
}

// ============================================================================
// Sanitization Strategy
// ============================================================================

/// Path sanitization strategy
///
/// Determines how dangerous patterns in paths are handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PathSanitizationStrategy {
    /// Remove dangerous patterns, keep safe parts (default)
    #[default]
    Clean,
    /// Reject if any dangerous patterns present (strict)
    Strict,
    /// Escape dangerous patterns (for display only)
    Escape,
}

impl From<PathSanitizationStrategy> for crate::primitives::data::paths::PathSanitizationStrategy {
    fn from(s: PathSanitizationStrategy) -> Self {
        match s {
            PathSanitizationStrategy::Clean => Self::Clean,
            PathSanitizationStrategy::Strict => Self::Strict,
            PathSanitizationStrategy::Escape => Self::Escape,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_security_threat() {
        assert_eq!(SecurityThreat::Traversal.cwe(), "CWE-22");
        assert_eq!(SecurityThreat::CommandInjection.severity(), 5);
        assert!(!SecurityThreat::Traversal.description().is_empty());
    }

    #[test]
    fn test_sanitization_strategy_default() {
        assert_eq!(
            PathSanitizationStrategy::default(),
            PathSanitizationStrategy::Clean
        );
    }
}
