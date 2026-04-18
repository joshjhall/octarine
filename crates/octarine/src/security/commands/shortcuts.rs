//! Shortcut functions for common command security operations
//!
//! These functions provide quick access to common operations without
//! needing to create builder instances. All shortcuts use the Layer 3
//! `CommandSecurityBuilder` which provides full observability.
//!
//! For command execution, use `runtime::process::SecureCommand`.

use crate::observe::Problem;

use super::builder::CommandSecurityBuilder;
use super::types::{AllowList, CommandThreat};

// ============================================================================
// Detection Shortcuts
// ============================================================================

/// Check if an argument contains dangerous patterns
///
/// This is a quick check that logs security events when threats are detected.
///
/// # Example
///
/// ```ignore
/// use octarine::security::commands::is_dangerous_arg;
///
/// if is_dangerous_arg(user_input) {
///     // Block dangerous input
/// }
/// # let user_input = "safe";
/// ```
#[must_use]
pub fn is_dangerous_arg(arg: &str) -> bool {
    CommandSecurityBuilder::new().is_dangerous(arg)
}

/// Detect all threats in an argument
///
/// Returns a vector of all detected threats and logs them.
///
/// # Example
///
/// ```ignore
/// use octarine::security::commands::detect_threats;
///
/// let threats = detect_threats(user_input);
/// for threat in threats {
///     println!("Detected: {}", threat);
/// }
/// # let user_input = "safe";
/// ```
#[must_use]
pub fn detect_threats(arg: &str) -> Vec<CommandThreat> {
    CommandSecurityBuilder::new().detect_threats(arg)
}

/// Check for command chaining patterns
#[must_use]
pub fn is_any_chain_present(arg: &str) -> bool {
    CommandSecurityBuilder::new().is_any_chain_present(arg)
}

/// Check for shell expansion patterns
#[must_use]
pub fn is_shell_expansion_present(arg: &str) -> bool {
    CommandSecurityBuilder::new().is_shell_expansion_present(arg)
}

/// Check for command substitution
#[must_use]
pub fn is_command_substitution_present(arg: &str) -> bool {
    CommandSecurityBuilder::new().is_command_substitution_present(arg)
}

/// Check for variable expansion
#[must_use]
pub fn is_variable_expansion_present(arg: &str) -> bool {
    CommandSecurityBuilder::new().is_variable_expansion_present(arg)
}

/// Check for redirection patterns
#[must_use]
pub fn is_redirection_present(arg: &str) -> bool {
    CommandSecurityBuilder::new().is_redirection_present(arg)
}

/// Check for glob patterns
#[must_use]
pub fn is_glob_present(arg: &str) -> bool {
    CommandSecurityBuilder::new().is_glob_present(arg)
}

// ============================================================================
// Validation Shortcuts
// ============================================================================

/// Validate that an argument is safe
///
/// Returns `Ok(())` if safe, or an error with details about the threat.
///
/// # Example
///
/// ```ignore
/// use octarine::security::commands::validate_safe_arg;
///
/// validate_safe_arg(user_input)?;
/// // Argument is safe to use
/// # let user_input = "safe";
/// # Ok::<(), octarine::observe::Problem>(())
/// ```
pub fn validate_safe_arg(arg: &str) -> Result<(), Problem> {
    CommandSecurityBuilder::new().validate_safe(arg)
}

/// Validate that a command is in the allow-list
///
/// # Example
///
/// ```ignore
/// use octarine::security::commands::{validate_command_allowed, AllowList};
///
/// let allowlist = AllowList::git_operations();
/// validate_command_allowed("git", &allowlist)?;
/// # Ok::<(), octarine::observe::Problem>(())
/// ```
pub fn validate_command_allowed(command: &str, allowlist: &AllowList) -> Result<(), Problem> {
    CommandSecurityBuilder::new().validate_command_allowed(command, allowlist)
}

/// Validate a command name (no path traversal, injection, etc.)
pub fn validate_command_name(command: &str) -> Result<(), Problem> {
    CommandSecurityBuilder::new().validate_command_name(command)
}

/// Validate environment variable name and value
pub fn validate_env(name: &str, value: &str) -> Result<(), Problem> {
    CommandSecurityBuilder::new().validate_env(name, value)
}

/// Validate multiple arguments
pub fn validate_args<I, S>(args: I) -> Result<(), Problem>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    CommandSecurityBuilder::new().validate_args(args)
}

// ============================================================================
// Sanitization Shortcuts
// ============================================================================

/// Escape a shell argument for the current platform
///
/// Returns a safely escaped argument that can be passed to a shell.
///
/// # Example
///
/// ```ignore
/// use octarine::security::commands::escape_shell_arg;
///
/// let safe = escape_shell_arg("user's input")?;
/// // Unix: 'user'\\''s input'
/// // Windows: "user's input"
/// # Ok::<(), octarine::observe::Problem>(())
/// ```
pub fn escape_shell_arg(arg: &str) -> Result<String, Problem> {
    CommandSecurityBuilder::new().escape_shell_arg(arg)
}

/// Escape a shell argument using Unix conventions
#[must_use]
pub fn escape_shell_arg_unix(arg: &str) -> String {
    CommandSecurityBuilder::new().escape_shell_arg_unix(arg)
}

/// Escape a shell argument using Windows conventions
#[must_use]
pub fn escape_shell_arg_windows(arg: &str) -> String {
    CommandSecurityBuilder::new().escape_shell_arg_windows(arg)
}

/// Escape multiple shell arguments
pub fn escape_shell_args<I, S>(args: I) -> Result<Vec<String>, Problem>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    CommandSecurityBuilder::new().escape_shell_args(args)
}

/// Join escaped arguments into a command string
pub fn join_shell_args<I, S>(args: I) -> Result<String, Problem>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    CommandSecurityBuilder::new().join_shell_args(args)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_dangerous_arg() {
        assert!(is_dangerous_arg("$(whoami)"));
        assert!(is_dangerous_arg("; rm -rf /"));
        assert!(!is_dangerous_arg("safe-arg"));
    }

    #[test]
    fn test_detect_threats() {
        let threats = detect_threats("$(cmd); ls");
        assert!(!threats.is_empty());
        assert!(threats.contains(&CommandThreat::CommandSubstitution));
        assert!(threats.contains(&CommandThreat::CommandChain));
    }

    #[test]
    fn test_validate_safe_arg() {
        assert!(validate_safe_arg("safe").is_ok());
        assert!(validate_safe_arg("$(whoami)").is_err());
    }

    #[test]
    fn test_validate_command_allowed() {
        let allowlist = AllowList::git_operations();

        assert!(validate_command_allowed("git", &allowlist).is_ok());
        assert!(validate_command_allowed("rm", &allowlist).is_err());
    }

    #[test]
    fn test_escape_shell_arg() {
        let escaped = escape_shell_arg("safe").expect("valid");
        assert!(!escaped.is_empty());
    }

    #[test]
    fn test_escape_shell_arg_unix() {
        assert_eq!(escape_shell_arg_unix("simple"), "'simple'");
        assert_eq!(escape_shell_arg_unix("user's"), "'user'\\''s'");
    }

    #[test]
    fn test_escape_shell_arg_windows() {
        assert_eq!(escape_shell_arg_windows("simple"), "\"simple\"");
    }

    #[test]
    fn test_is_any_chain_present() {
        assert!(is_any_chain_present("ls; rm -rf /"));
        assert!(is_any_chain_present("a && b"));
        assert!(!is_any_chain_present("safe-arg"));
    }

    #[test]
    fn test_is_shell_expansion_present() {
        assert!(is_shell_expansion_present("${HOME}"));
        assert!(is_shell_expansion_present("$(whoami)"));
        assert!(!is_shell_expansion_present("plain"));
    }

    #[test]
    fn test_is_command_substitution_present() {
        assert!(is_command_substitution_present("$(whoami)"));
        assert!(is_command_substitution_present("`id`"));
        assert!(!is_command_substitution_present("plain"));
    }

    #[test]
    fn test_is_variable_expansion_present() {
        assert!(is_variable_expansion_present("${VAR}"));
        assert!(is_variable_expansion_present("$HOME"));
        assert!(!is_variable_expansion_present("plain"));
    }

    #[test]
    fn test_is_redirection_present() {
        assert!(is_redirection_present("cmd > /etc/x"));
        assert!(is_redirection_present("cmd < input"));
        assert!(!is_redirection_present("plain"));
    }

    #[test]
    fn test_is_glob_present() {
        assert!(is_glob_present("*.txt"));
        assert!(is_glob_present("file?.log"));
        assert!(!is_glob_present("plain.txt"));
    }

    #[test]
    fn test_validate_command_name() {
        assert!(validate_command_name("git").is_ok());
        // Path traversal is rejected.
        assert!(validate_command_name("../bin/sh").is_err());
        // Empty command is rejected.
        assert!(validate_command_name("").is_err());
    }

    #[test]
    fn test_validate_env() {
        assert!(validate_env("MY_VAR", "safe value").is_ok());
        // Dangerous name (contains `=`).
        assert!(validate_env("BAD=NAME", "value").is_err());
        // Dangerous value (command substitution).
        assert!(validate_env("MY_VAR", "$(whoami)").is_err());
    }

    #[test]
    fn test_validate_args() {
        assert!(validate_args(["ls", "-la"]).is_ok());
        assert!(validate_args(["ls", "$(whoami)"]).is_err());
    }

    #[test]
    fn test_escape_shell_args() {
        let escaped = escape_shell_args(["ls", "-la"]).expect("valid");
        assert_eq!(escaped.len(), 2);
        assert!(!escaped.first().expect("at least one arg").is_empty());
        // Null bytes cannot be safely escaped.
        assert!(escape_shell_args(["ls", "bad\0arg"]).is_err());
    }

    #[test]
    fn test_join_shell_args() {
        let joined = join_shell_args(["echo", "hello"]).expect("valid");
        assert!(joined.contains("echo"));
        assert!(joined.contains("hello"));
        assert!(joined.contains(' '));
        // Null bytes propagate the error.
        assert!(join_shell_args(["echo", "bad\0arg"]).is_err());
    }
}
