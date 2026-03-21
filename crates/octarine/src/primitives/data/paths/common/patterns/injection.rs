//! Command injection detection patterns
//!
//! Core detection functions for command injection attempts in paths.
//! These are pure functions with NO observe dependencies.
//!
//! ## Coverage
//!
//! - Command substitution: `$()`, backticks
//! - Variable expansion: `${}`, plain `$`
//! - Shell metacharacters: `;`, `|`, `&`, `&&`, `||`
//!
//! ## Design Principles
//!
//! 1. **Pure Functions**: No logging, no side effects
//! 2. **Detection Only**: Returns bool, no Result types
//! 3. **Reusable**: Used by validation and sanitization layers
//!
//! ## Security Standards
//!
//! - CWE-78: OS Command Injection
//! - OWASP: Command Injection Prevention

// ============================================================================
// Command Substitution Detection
// ============================================================================

/// Check if path contains command substitution patterns
///
/// Detects shell command substitution:
/// - `$()` - POSIX command substitution
/// - Backticks (`) - Legacy command substitution
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::injection;
///
/// assert!(injection::is_command_substitution_present("file$(whoami).txt"));
/// assert!(injection::is_command_substitution_present("path`ls`.txt"));
/// assert!(!injection::is_command_substitution_present("safe/path"));
/// ```
#[must_use]
pub fn is_command_substitution_present(path: &str) -> bool {
    path.contains("$(") || path.contains('`')
}

// ============================================================================
// Variable Expansion Detection
// ============================================================================

/// Check if path contains variable expansion patterns
///
/// Detects shell variable expansion:
/// - `${}` - Brace-delimited expansion
/// - `$VARIABLE` - Plain variable expansion
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::injection;
///
/// assert!(injection::is_variable_expansion_present("${HOME}/file"));
/// assert!(injection::is_variable_expansion_present("$USER/file"));
/// assert!(injection::is_variable_expansion_present("path/$PATH/bin"));
/// assert!(!injection::is_variable_expansion_present("safe/path"));
/// ```
#[must_use]
pub fn is_variable_expansion_present(path: &str) -> bool {
    path.contains("${") || path.contains('$')
}

// ============================================================================
// Shell Metacharacter Detection
// ============================================================================

/// Check if path contains shell metacharacters
///
/// Detects shell metacharacters that allow command chaining:
/// - `;` (command separator)
/// - `|` (pipe)
/// - `&` (background/AND)
/// - `&&` and `||` (logical operators - detected via `&` and `|`)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::injection;
///
/// assert!(injection::is_shell_metacharacters_present("file;ls"));
/// assert!(injection::is_shell_metacharacters_present("path|cat"));
/// assert!(injection::is_shell_metacharacters_present("file&whoami"));
/// assert!(injection::is_shell_metacharacters_present("cmd&&other"));
/// assert!(injection::is_shell_metacharacters_present("cmd||fallback"));
/// assert!(!injection::is_shell_metacharacters_present("safe/path"));
/// ```
#[must_use]
pub fn is_shell_metacharacters_present(path: &str) -> bool {
    path.contains(';') || path.contains('|') || path.contains('&')
}

/// Check if path contains redirection operators
///
/// Detects shell redirection:
/// - `>` (output redirection)
/// - `<` (input redirection)
/// - `>>` (append redirection)
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::injection;
///
/// assert!(injection::is_redirection_present("file>output"));
/// assert!(injection::is_redirection_present("path<input"));
/// assert!(injection::is_redirection_present("log>>append"));
/// assert!(!injection::is_redirection_present("safe/path"));
/// ```
#[must_use]
pub fn is_redirection_present(path: &str) -> bool {
    path.contains('>') || path.contains('<')
}

// ============================================================================
// Combined Detection
// ============================================================================

/// Check if path contains any command injection patterns
///
/// Comprehensive check combining:
/// - Command substitution (`$()`, backticks)
/// - Variable expansion (`${}`, `$VAR`)
/// - Shell metacharacters (`;`, `|`, `&`)
///
/// This is the primary command injection detection function.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::injection;
///
/// assert!(injection::is_any_injection_present("$(whoami)"));
/// assert!(injection::is_any_injection_present("${HOME}"));
/// assert!(injection::is_any_injection_present("$PATH"));
/// assert!(injection::is_any_injection_present("file;rm -rf"));
/// assert!(!injection::is_any_injection_present("safe/path/file.txt"));
/// ```
#[must_use]
pub fn is_any_injection_present(path: &str) -> bool {
    is_command_substitution_present(path)
        || is_variable_expansion_present(path)
        || is_shell_metacharacters_present(path)
}

/// Check if path contains any command injection including redirection
///
/// Like [`is_any_injection_present`] but also includes redirection operators.
/// Use this for stricter security contexts.
///
/// # Examples
///
/// ```ignore
/// use octarine::primitives::paths::common::patterns::injection;
///
/// assert!(injection::is_any_injection_present_strict("file>output"));
/// assert!(injection::is_any_injection_present_strict("$(whoami)"));
/// assert!(!injection::is_any_injection_present_strict("safe/path"));
/// ```
#[must_use]
pub fn is_any_injection_present_strict(path: &str) -> bool {
    is_any_injection_present(path) || is_redirection_present(path)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // Command substitution tests
    #[test]
    fn test_is_command_substitution_present_posix() {
        assert!(is_command_substitution_present("$(whoami)"));
        assert!(is_command_substitution_present("file$(id).txt"));
        assert!(is_command_substitution_present("$(cat /etc/passwd)"));
        assert!(is_command_substitution_present("prefix$(cmd)suffix"));
    }

    #[test]
    fn test_is_command_substitution_present_backticks() {
        assert!(is_command_substitution_present("`whoami`"));
        assert!(is_command_substitution_present("file`id`.txt"));
        assert!(is_command_substitution_present("`cat /etc/passwd`"));
    }

    #[test]
    fn test_is_command_substitution_present_safe() {
        assert!(!is_command_substitution_present("safe/path"));
        assert!(!is_command_substitution_present("file.txt"));
        assert!(!is_command_substitution_present("path/to/file"));
        assert!(!is_command_substitution_present("file$name")); // No ( after $
    }

    // Variable expansion tests
    #[test]
    fn test_is_variable_expansion_present_brace() {
        assert!(is_variable_expansion_present("${HOME}"));
        assert!(is_variable_expansion_present("${HOME}/file"));
        assert!(is_variable_expansion_present("path/${USER}/file"));
        assert!(is_variable_expansion_present("${VAR:-default}"));
    }

    #[test]
    fn test_is_variable_expansion_present_plain() {
        assert!(is_variable_expansion_present("$HOME"));
        assert!(is_variable_expansion_present("$USER/file"));
        assert!(is_variable_expansion_present("path/$PATH/bin"));
        assert!(is_variable_expansion_present("$1")); // Positional parameter
    }

    #[test]
    fn test_is_variable_expansion_present_safe() {
        assert!(!is_variable_expansion_present("safe/path"));
        assert!(!is_variable_expansion_present("file.txt"));
        assert!(!is_variable_expansion_present("path/to/file"));
    }

    // Shell metacharacter tests
    #[test]
    fn test_is_shell_metacharacters_present_semicolon() {
        assert!(is_shell_metacharacters_present("file;ls"));
        assert!(is_shell_metacharacters_present(";rm -rf /"));
        assert!(is_shell_metacharacters_present("cmd1;cmd2;cmd3"));
    }

    #[test]
    fn test_is_shell_metacharacters_present_pipe() {
        assert!(is_shell_metacharacters_present("file|cat"));
        assert!(is_shell_metacharacters_present("cat file|grep pattern"));
        assert!(is_shell_metacharacters_present("||fallback"));
    }

    #[test]
    fn test_is_shell_metacharacters_present_ampersand() {
        assert!(is_shell_metacharacters_present("file&"));
        assert!(is_shell_metacharacters_present("cmd1&cmd2"));
        assert!(is_shell_metacharacters_present("&&next"));
        assert!(is_shell_metacharacters_present("cmd1&&cmd2"));
    }

    #[test]
    fn test_is_shell_metacharacters_present_safe() {
        assert!(!is_shell_metacharacters_present("safe/path"));
        assert!(!is_shell_metacharacters_present("file.txt"));
        assert!(!is_shell_metacharacters_present("path/to/file"));
    }

    // Redirection tests
    #[test]
    fn test_is_redirection_present() {
        assert!(is_redirection_present("file>output"));
        assert!(is_redirection_present("file>>append"));
        assert!(is_redirection_present("cmd<input"));
        assert!(is_redirection_present("cmd>out<in"));
        assert!(is_redirection_present("2>&1"));
    }

    #[test]
    fn test_is_redirection_present_safe() {
        assert!(!is_redirection_present("safe/path"));
        assert!(!is_redirection_present("file.txt"));
        assert!(!is_redirection_present("path/to/file"));
    }

    // Combined detection tests
    #[test]
    fn test_is_any_injection_present() {
        // Command substitution
        assert!(is_any_injection_present("$(whoami)"));
        assert!(is_any_injection_present("`id`"));

        // Variable expansion
        assert!(is_any_injection_present("${HOME}"));
        assert!(is_any_injection_present("$PATH"));

        // Metacharacters
        assert!(is_any_injection_present("file;ls"));
        assert!(is_any_injection_present("cmd|cat"));
        assert!(is_any_injection_present("file&bg"));
    }

    #[test]
    fn test_is_any_injection_present_safe() {
        assert!(!is_any_injection_present("safe/path"));
        assert!(!is_any_injection_present("relative/path/file.txt"));
        assert!(!is_any_injection_present("file.txt"));
        assert!(!is_any_injection_present("path/to/dir/"));
    }

    #[test]
    fn test_is_any_injection_present_strict() {
        // All regular injections
        assert!(is_any_injection_present_strict("$(whoami)"));
        assert!(is_any_injection_present_strict("file;ls"));

        // Plus redirection
        assert!(is_any_injection_present_strict("file>output"));
        assert!(is_any_injection_present_strict("cmd<input"));

        // Safe
        assert!(!is_any_injection_present_strict("safe/path"));
    }

    // Edge cases
    #[test]
    fn test_empty_string() {
        assert!(!is_command_substitution_present(""));
        assert!(!is_variable_expansion_present(""));
        assert!(!is_shell_metacharacters_present(""));
        assert!(!is_redirection_present(""));
        assert!(!is_any_injection_present(""));
    }

    #[test]
    fn test_combined_attacks() {
        // Multiple attack vectors in one string
        assert!(is_any_injection_present("$(whoami);rm -rf /"));
        assert!(is_any_injection_present("${HOME}|cat /etc/passwd"));
        assert!(is_any_injection_present_strict("$(cmd)>output"));
    }

    #[test]
    fn test_nested_patterns() {
        assert!(is_command_substitution_present("$(echo $(whoami))"));
        assert!(is_variable_expansion_present("${${NESTED}}"));
    }
}
