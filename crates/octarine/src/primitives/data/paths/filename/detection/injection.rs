//! Command injection detection functions
//!
//! Functions to detect command substitution and variable expansion patterns.

// Allow arithmetic operations in this module - they are intentional and bounds-checked
#![allow(clippy::arithmetic_side_effects)]

use super::characters::is_dangerous_shell_chars_present;

// ============================================================================
// Command Injection Detection
// ============================================================================

/// Check if filename contains command substitution patterns
///
/// Detects `$(...)`, `${...}`, and backtick patterns.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::detection;
///
/// assert!(detection::is_command_substitution_present("$(whoami).txt"));
/// assert!(detection::is_command_substitution_present("${HOME}.txt"));
/// assert!(detection::is_command_substitution_present("`id`.txt"));
/// assert!(!detection::is_command_substitution_present("file.txt"));
/// ```
#[must_use]
pub fn is_command_substitution_present(filename: &str) -> bool {
    filename.contains("$(")
        || filename.contains("${")
        || filename.contains('`')
        || filename.contains("$((")
}

/// Check if filename contains variable expansion
///
/// Detects `$VAR` style variable expansion patterns.
///
/// ## Example
///
/// ```ignore
/// use octarine::primitives::paths::filename::detection;
///
/// assert!(detection::is_variable_expansion_present("$HOME.txt"));
/// assert!(detection::is_variable_expansion_present("file_$USER.txt"));
/// assert!(!detection::is_variable_expansion_present("file.txt"));
/// ```
#[must_use]
pub fn is_variable_expansion_present(filename: &str) -> bool {
    let chars: Vec<char> = filename.chars().collect();
    for i in 0..chars.len() {
        if chars.get(i).copied() == Some('$')
            && let Some(&next) = chars.get(i + 1)
        {
            // $VAR pattern (letter or underscore after $)
            if next.is_ascii_alphabetic() || next == '_' {
                return true;
            }
        }
    }
    false
}

/// Check if filename has any injection pattern
///
/// Comprehensive check for command substitution, variable expansion,
/// and dangerous shell characters.
#[must_use]
pub fn is_injection_pattern_present(filename: &str) -> bool {
    is_command_substitution_present(filename)
        || is_variable_expansion_present(filename)
        || is_dangerous_shell_chars_present(filename)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_command_substitution_present() {
        assert!(is_command_substitution_present("$(whoami).txt"));
        assert!(is_command_substitution_present("${HOME}.txt"));
        assert!(is_command_substitution_present("`id`.txt"));
        assert!(is_command_substitution_present("$((1+1)).txt"));
        assert!(!is_command_substitution_present("file.txt"));
        assert!(!is_command_substitution_present("file$123.txt")); // $ followed by digit
    }

    #[test]
    fn test_is_variable_expansion_present() {
        assert!(is_variable_expansion_present("$HOME.txt"));
        assert!(is_variable_expansion_present("file_$USER.txt"));
        assert!(is_variable_expansion_present("$_var.txt"));
        assert!(!is_variable_expansion_present("file.txt"));
        assert!(!is_variable_expansion_present("$123.txt")); // $ followed by digit
        assert!(!is_variable_expansion_present("file$.txt")); // $ at end
    }

    #[test]
    fn test_is_injection_pattern_present() {
        assert!(is_injection_pattern_present("$(cmd).txt"));
        assert!(is_injection_pattern_present("$VAR.txt"));
        assert!(is_injection_pattern_present("file;rm.txt"));
        assert!(!is_injection_pattern_present("file.txt"));
    }
}
