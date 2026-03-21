//! Environment variable identifier validation and detection
//!
//! Pure functions for validating environment variable names to ensure they
//! are safe and follow best practices across operating systems.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.
//! - No observe:: dependencies (uses Problem type from primitives::types)
//! - Returns data, no side effects
//! - Used by security modules
//!
//! # Security Threats Addressed
//!
//! 1. **Command Injection**: Through variable expansion
//! 2. **Path Manipulation**: Via PATH, LD_LIBRARY_PATH, etc.
//! 3. **Privilege Escalation**: Through LD_PRELOAD and similar
//! 4. **Information Disclosure**: Through debug/trace variables
//!
//! # Naming Conventions
//!
//! - **Unix/Linux**: Typically UPPERCASE_WITH_UNDERSCORES
//! - **Windows**: Case-insensitive, but uppercase by convention
//! - **Cross-platform**: Use uppercase letters, numbers, and underscores only
//!
//! # Usage
//!
//! ```ignore
//! use octarine::primitives::identifiers::environment::EnvironmentBuilder;
//!
//! let env = EnvironmentBuilder::new();
//!
//! // Detection (bool)
//! if env.is_valid_env_var("MY_APP_CONFIG") {
//!     println!("Valid environment variable name");
//! }
//!
//! // Validation (Result)
//! env.validate_env_var("MY_APP_CONFIG")?;
//! ```

// Internal modules - not directly accessible outside environment/
mod detection;
mod validation;

// Public builder module
pub mod builder;

// Re-export builder for convenience
pub use builder::EnvironmentBuilder;

/// Default maximum length for environment variable names
pub const MAX_ENV_VAR_LENGTH: usize = 256;

/// Reserved/critical environment variables that shouldn't be overwritten
pub const RESERVED_VARS: &[&str] = &[
    "PATH", "HOME", "USER", "SHELL", "TERM", "LANG", "LC_ALL", "TZ", "PWD", "OLDPWD",
];

/// Critical system variables that are security-sensitive
pub const CRITICAL_VARS: &[&str] = &[
    "LD_LIBRARY_PATH",
    "LD_PRELOAD",
    "PATH",
    "IFS",
    "DYLD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
];

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_module_integration() {
        // Detection
        assert!(detection::is_valid_env_var("MY_APP_CONFIG"));
        assert!(detection::is_valid_env_var("DEBUG_MODE"));
        assert!(!detection::is_valid_env_var("123_VAR")); // starts with number
        assert!(!detection::is_valid_env_var("PATH")); // reserved

        // Validation
        assert!(validation::validate_env_var("MY_APP_CONFIG").is_ok());
        assert!(validation::validate_env_var("").is_err());
        assert!(validation::validate_env_var("PATH").is_err());
    }

    #[test]
    fn test_builder_integration() {
        let env = EnvironmentBuilder::new();

        // Detection via builder (bool)
        assert!(env.is_valid_env_var("MY_VAR"));
        assert!(!env.is_valid_env_var("LD_PRELOAD"));

        // Validation via builder (Result)
        assert!(env.validate_env_var("MY_VAR").is_ok());
        assert!(env.validate_env_var("PATH").is_err());
    }

    #[test]
    fn test_security_detection() {
        // Critical vars detected
        assert!(detection::is_reserved_var("PATH"));
        assert!(detection::is_critical_var("LD_PRELOAD"));
        assert!(detection::is_critical_var("LD_LIBRARY_PATH"));
    }
}
