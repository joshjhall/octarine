// Allow dead code and unused imports - this module provides API primitives
// that may not all be consumed yet.
#![allow(dead_code)]
#![allow(unused_imports)]

//! OS Command Injection Prevention (CWE-78)
//!
//! This module provides security primitives for command argument validation,
//! threat detection, and shell escaping.
//!
//! ## Architecture
//!
//! The commands security module provides detection, validation, and sanitization:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    runtime/process/SecureCommand                 │
//! │  (High-level command execution with full observability)         │
//! └─────────────────────────────────────────────────────────────────┘
//!                              │
//!          ┌───────────────────┼───────────────────┐
//!          ▼                   ▼                   ▼
//! ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
//! │   detection     │ │   validation    │ │  sanitization   │
//! │                 │ │                 │ │                 │
//! │ - is_*_present  │ │ - validate_*    │ │ - escape_*      │
//! │ - detect_threats│ │   returns       │ │ - join_*        │
//! │   returns Vec   │ │   Result        │ │                 │
//! └─────────────────┘ └─────────────────┘ └─────────────────┘
//! ```
//!
//! ## Security Threats Covered
//!
//! | Threat | CWE | Description |
//! |--------|-----|-------------|
//! | CommandChain | CWE-78 | Semicolon chaining (`;`) |
//! | PipeChain | CWE-78 | Pipe chaining (`\|`) |
//! | BackgroundExecution | CWE-78 | Background execution (`&`) |
//! | ConditionalChain | CWE-78 | Conditional chaining (`&&`, `\|\|`) |
//! | CommandSubstitution | CWE-78 | Subshell execution (`$()`, backticks) |
//! | VariableExpansion | CWE-78 | Variable injection (`$VAR`) |
//! | IndirectExpansion | CWE-78 | Indirect variable (`${!VAR}`) |
//! | ArithmeticExpansion | CWE-78 | Arithmetic (`$((expr))`) |
//! | OutputRedirect | CWE-78 | Output redirection (`>`, `>>`) |
//! | InputRedirect | CWE-78 | Input redirection (`<`) |
//! | GlobPattern | CWE-200 | Glob expansion (`*`, `?`, `[...]`) |
//! | NullByte | CWE-158 | String truncation (`\0`) |
//! | ControlCharacter | CWE-707 | Terminal manipulation |
//!
//! ## When to Use What
//!
//! | Task | Module | Example |
//! |------|--------|---------|
//! | Execute commands securely | `runtime::process` | `SecureCommand::new("git")` |
//! | Check if string is dangerous | `security::commands` | `is_dangerous_arg(input)` |
//! | Escape for shell string | `security::commands` | `escape_shell_arg(input)` |
//! | Validate safely | `security::commands` | `validate_safe_arg(input)?` |
//! | Restrict to allowed commands | `runtime::process` | `cmd.with_allowlist(&list)?` |
//!
//! ## Usage Examples
//!
//! ```ignore
//! use octarine::security::commands::{detection, validation, sanitization};
//!
//! // Detection - find patterns
//! let is_dangerous = detection::is_dangerous_arg(user_input);
//! let threats = detection::detect_threats(user_input);
//!
//! // Validation - enforce policy
//! validation::validate_safe_arg(user_input)?;
//!
//! // Sanitization - escape for shell
//! let safe = sanitization::escape_shell_arg(user_input)?;
//! # let user_input = "safe";
//! ```
//!
//! ## Platform-Specific Shell Escaping
//!
//! ```ignore
//! use octarine::security::commands::sanitization;
//!
//! // Automatic platform detection
//! let escaped = sanitization::escape_shell_arg(user_input)?;
//!
//! // Explicit Unix escaping (single quotes)
//! let unix = sanitization::escape_shell_arg_unix(user_input);
//! // "user's input" -> "'user'\\''s input'"
//!
//! // Explicit Windows escaping (double quotes)
//! let windows = sanitization::escape_shell_arg_windows(user_input);
//! // "user's input" -> "\"user's input\""
//! # let user_input = "safe";
//! ```

pub(crate) mod builder;
pub(crate) mod detection;
pub(crate) mod sanitization;
pub(crate) mod types;
pub(crate) mod validation;

// Re-export builder as primary API
pub use builder::CommandSecurityBuilder;

// Re-export types for convenience
pub use types::{AllowList, AllowListMode, CommandThreat};

// Re-export result types
pub use sanitization::SanitizationResult;
pub use validation::ValidationResult;

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_module_integration() {
        // Detection
        assert!(detection::is_dangerous_arg("$(whoami)"));
        assert!(detection::is_any_chain_present("; rm -rf /"));

        let threats = detection::detect_threats("$(cmd); ls | cat");
        assert!(threats.contains(&CommandThreat::CommandSubstitution));
        assert!(threats.contains(&CommandThreat::CommandChain));
        assert!(threats.contains(&CommandThreat::PipeChain));

        // Validation
        assert!(validation::validate_safe_arg("safe-arg").is_ok());
        assert!(validation::validate_safe_arg("$(whoami)").is_err());

        // Sanitization
        let escaped = sanitization::escape_shell_arg("user's input").expect("valid");
        assert!(escaped.contains("user"));
    }

    #[test]
    fn test_allowlist_integration() {
        let allowlist = AllowList::git_operations();
        assert!(allowlist.is_allowed("git"));
        assert!(!allowlist.is_allowed("rm"));
    }

    #[test]
    fn test_comprehensive_threat_detection() {
        // All threat types should be detected
        assert!(detection::is_command_chain_present(";"));
        assert!(detection::is_pipe_chain_present("|"));
        assert!(detection::is_background_execution_present("&"));
        assert!(detection::is_conditional_chain_present("&&"));
        assert!(detection::is_command_substitution_present("$()"));
        assert!(detection::is_variable_expansion_present("$VAR"));
        assert!(detection::is_output_redirect_present(">"));
        assert!(detection::is_input_redirect_present("<"));
        assert!(detection::is_glob_present("*"));
        assert!(detection::is_null_byte_present("\0"));
        assert!(detection::is_control_character_present("\x01"));
    }

    #[test]
    fn test_shell_escaping_unix() {
        let escaped = sanitization::escape_shell_arg_unix("user's input");
        assert_eq!(escaped, "'user'\\''s input'");

        // Shell metacharacters are safely wrapped
        let escaped = sanitization::escape_shell_arg_unix("; rm -rf /");
        assert_eq!(escaped, "'; rm -rf /'");
    }

    #[test]
    fn test_shell_escaping_windows() {
        let escaped = sanitization::escape_shell_arg_windows("with \"quotes\"");
        assert_eq!(escaped, "\"with \\\"quotes\\\"\"");
    }

    #[test]
    fn test_allowlist_presets() {
        let shell = AllowList::shell_safe();
        assert!(shell.is_allowed("ls"));
        assert!(shell.is_allowed("cat"));
        assert!(!shell.is_allowed("rm"));

        let git = AllowList::git_operations();
        assert!(git.is_allowed("git"));
        assert!(!git.is_allowed("docker"));

        let docker = AllowList::docker_operations();
        assert!(docker.is_allowed("docker"));
        assert!(docker.is_allowed("docker-compose"));

        let node = AllowList::node_operations();
        assert!(node.is_allowed("npm"));
        assert!(node.is_allowed("yarn"));

        let rust = AllowList::rust_operations();
        assert!(rust.is_allowed("cargo"));
        assert!(rust.is_allowed("rustc"));
    }
}
