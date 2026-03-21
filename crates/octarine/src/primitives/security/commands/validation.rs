//! Validation functions for command arguments
//!
//! Provides strict validation with detailed error reporting.
//! Validators call detection functions internally (DRY principle).

use super::detection;
use super::types::{AllowList, CommandThreat};
use crate::primitives::types::Problem;

/// Result type for validation operations
pub type ValidationResult = Result<(), Problem>;

// ============================================================================
// Argument Validation
// ============================================================================

/// Validate that an argument contains no dangerous patterns
///
/// Returns `Ok(())` if the argument is safe, or `Err(Problem)` with details.
///
/// # Example
///
/// ```ignore
/// use octarine::security::commands::validation;
///
/// assert!(validation::validate_safe_arg("--option=value").is_ok());
/// assert!(validation::validate_safe_arg("$(whoami)").is_err());
/// ```
pub fn validate_safe_arg(arg: &str) -> ValidationResult {
    let threats = detection::detect_threats(arg);

    if threats.is_empty() {
        Ok(())
    } else {
        let threat_names: Vec<_> = threats.iter().map(|t| t.description()).collect();
        Err(Problem::validation(format!(
            "Argument contains dangerous patterns: {}",
            threat_names.join(", ")
        )))
    }
}

/// Validate that an argument contains no command chaining
pub fn validate_no_chaining(arg: &str) -> ValidationResult {
    if detection::is_any_chain_present(arg) {
        Err(Problem::validation(
            "Argument contains command chaining patterns (;, |, &, &&, ||)",
        ))
    } else {
        Ok(())
    }
}

/// Validate that an argument contains no shell expansion
pub fn validate_no_expansion(arg: &str) -> ValidationResult {
    if detection::is_shell_expansion_present(arg) {
        Err(Problem::validation(
            "Argument contains shell expansion patterns ($(), ``, $VAR, ${VAR})",
        ))
    } else {
        Ok(())
    }
}

/// Validate that an argument contains no redirection
pub fn validate_no_redirection(arg: &str) -> ValidationResult {
    if detection::is_redirection_present(arg) {
        Err(Problem::validation(
            "Argument contains redirection patterns (>, >>, <)",
        ))
    } else {
        Ok(())
    }
}

/// Validate that an argument contains no glob patterns
pub fn validate_no_globs(arg: &str) -> ValidationResult {
    if detection::is_glob_present(arg) {
        Err(Problem::validation(
            "Argument contains glob patterns (*, ?, [...])",
        ))
    } else {
        Ok(())
    }
}

/// Validate that an argument contains no null bytes
pub fn validate_no_null_bytes(arg: &str) -> ValidationResult {
    if detection::is_null_byte_present(arg) {
        Err(Problem::validation("Argument contains null bytes"))
    } else {
        Ok(())
    }
}

/// Validate that an argument contains no control characters
pub fn validate_no_control_chars(arg: &str) -> ValidationResult {
    if detection::is_control_character_present(arg) {
        Err(Problem::validation("Argument contains control characters"))
    } else {
        Ok(())
    }
}

// ============================================================================
// Command Validation
// ============================================================================

/// Validate that a command is in the allow-list
pub fn validate_command_allowed(command: &str, allowlist: &AllowList) -> ValidationResult {
    if allowlist.is_allowed(command) {
        Ok(())
    } else {
        Err(Problem::validation(format!(
            "Command '{}' is not in the allow-list",
            command
        )))
    }
}

/// Validate that a command name is safe (no path traversal, etc.)
pub fn validate_command_name(command: &str) -> ValidationResult {
    // Empty command is invalid
    if command.is_empty() {
        return Err(Problem::validation("Command cannot be empty"));
    }

    // Check for dangerous patterns in the command itself
    if detection::is_dangerous_arg(command) {
        return Err(Problem::validation(format!(
            "Command '{}' contains dangerous patterns",
            command
        )));
    }

    // Check for path traversal in command
    if command.contains("..") {
        return Err(Problem::validation("Command contains path traversal (..)"));
    }

    Ok(())
}

// ============================================================================
// Environment Variable Validation
// ============================================================================

/// Validate an environment variable name
pub fn validate_env_name(name: &str) -> ValidationResult {
    if detection::is_dangerous_env_name(name) {
        Err(Problem::validation(format!(
            "Environment variable name '{}' is dangerous",
            name
        )))
    } else {
        Ok(())
    }
}

/// Validate an environment variable value
pub fn validate_env_value(value: &str) -> ValidationResult {
    if detection::is_dangerous_env_value(value) {
        let threats = detection::detect_threats(value);
        let threat_names: Vec<_> = threats.iter().map(|t| t.description()).collect();
        Err(Problem::validation(format!(
            "Environment variable value contains dangerous patterns: {}",
            threat_names.join(", ")
        )))
    } else {
        Ok(())
    }
}

/// Validate both environment variable name and value
pub fn validate_env(name: &str, value: &str) -> ValidationResult {
    validate_env_name(name)?;
    validate_env_value(value)
}

// ============================================================================
// Path Validation (for current_dir, etc.)
// ============================================================================

/// Validate a path for use as working directory
pub fn validate_working_dir(path: &str) -> ValidationResult {
    // Empty path is invalid
    if path.is_empty() {
        return Err(Problem::validation("Working directory cannot be empty"));
    }

    // Check for dangerous patterns
    if detection::is_dangerous_arg(path) {
        return Err(Problem::validation(format!(
            "Working directory '{}' contains dangerous patterns",
            path
        )));
    }

    Ok(())
}

// ============================================================================
// Bulk Validation
// ============================================================================

/// Validate multiple arguments
pub fn validate_args<I, S>(args: I) -> ValidationResult
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    for (i, arg) in args.into_iter().enumerate() {
        validate_safe_arg(arg.as_ref())
            .map_err(|e| Problem::validation(format!("Argument {} is invalid: {}", i, e)))?;
    }
    Ok(())
}

/// Validate multiple environment variables
pub fn validate_envs<I, K, V>(envs: I) -> ValidationResult
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    for (name, value) in envs {
        validate_env(name.as_ref(), value.as_ref())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]
    use super::*;

    #[test]
    fn test_validate_safe_arg_ok() {
        assert!(validate_safe_arg("--option=value").is_ok());
        assert!(validate_safe_arg("-v").is_ok());
        assert!(validate_safe_arg("path/to/file.txt").is_ok());
        assert!(validate_safe_arg("https://example.com").is_ok());
    }

    #[test]
    fn test_validate_safe_arg_dangerous() {
        assert!(validate_safe_arg("$(whoami)").is_err());
        assert!(validate_safe_arg("; rm -rf /").is_err());
        assert!(validate_safe_arg("| cat /etc/passwd").is_err());
        assert!(validate_safe_arg("$HOME").is_err());
    }

    #[test]
    fn test_validate_no_chaining() {
        assert!(validate_no_chaining("safe").is_ok());
        assert!(validate_no_chaining("cmd; cmd2").is_err());
        assert!(validate_no_chaining("cmd | cmd2").is_err());
        assert!(validate_no_chaining("cmd && cmd2").is_err());
    }

    #[test]
    fn test_validate_no_expansion() {
        assert!(validate_no_expansion("safe").is_ok());
        assert!(validate_no_expansion("$(whoami)").is_err());
        assert!(validate_no_expansion("$HOME").is_err());
        assert!(validate_no_expansion("`cmd`").is_err());
    }

    #[test]
    fn test_validate_command_allowed() {
        let allowlist = AllowList::new().allow("git").allow("docker");

        assert!(validate_command_allowed("git", &allowlist).is_ok());
        assert!(validate_command_allowed("docker", &allowlist).is_ok());
        assert!(validate_command_allowed("rm", &allowlist).is_err());
    }

    #[test]
    fn test_validate_command_name() {
        assert!(validate_command_name("git").is_ok());
        assert!(validate_command_name("/usr/bin/git").is_ok());
        assert!(validate_command_name("").is_err()); // Empty
        assert!(validate_command_name("../../../bin/sh").is_err()); // Traversal
        assert!(validate_command_name("$(whoami)").is_err()); // Injection
    }

    #[test]
    fn test_validate_env_name() {
        assert!(validate_env_name("PATH").is_ok());
        assert!(validate_env_name("MY_VAR").is_ok());
        assert!(validate_env_name("").is_err());
        assert!(validate_env_name("VAR=value").is_err());
        assert!(validate_env_name("VAR;cmd").is_err());
    }

    #[test]
    fn test_validate_env_value() {
        assert!(validate_env_value("/usr/local/bin").is_ok());
        assert!(validate_env_value("normal value").is_ok());
        assert!(validate_env_value("$(whoami)").is_err());
        assert!(validate_env_value("; rm -rf /").is_err());
    }

    #[test]
    fn test_validate_env() {
        assert!(validate_env("PATH", "/usr/local/bin").is_ok());
        assert!(validate_env("", "value").is_err()); // Bad name
        assert!(validate_env("NAME", "$(whoami)").is_err()); // Bad value
    }

    #[test]
    fn test_validate_working_dir() {
        assert!(validate_working_dir("/home/user").is_ok());
        assert!(validate_working_dir("/tmp").is_ok());
        assert!(validate_working_dir("").is_err());
        assert!(validate_working_dir("$(whoami)").is_err());
    }

    #[test]
    fn test_validate_args() {
        assert!(validate_args(["--flag", "-v", "file.txt"]).is_ok());
        assert!(validate_args(["--flag", "$(whoami)"]).is_err());
    }

    #[test]
    fn test_validate_envs() {
        assert!(validate_envs([("PATH", "/bin"), ("HOME", "/home/user")]).is_ok());
        assert!(validate_envs([("PATH", "$(whoami)")]).is_err());
    }

    #[test]
    fn test_error_messages_are_descriptive() {
        let result = validate_safe_arg("$(whoami); rm -rf /");
        assert!(result.is_err());

        let err = result.unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("dangerous patterns"));
    }
}
