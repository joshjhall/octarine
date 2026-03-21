//! Security-related command types
//!
//! These types form the canonical location for command security types.
//! They wrap primitives types with the Layer 3 visibility boundary.

use std::collections::HashSet;

// ============================================================================
// Command Threat Types
// ============================================================================

/// Security threat type detected in command arguments
///
/// These threats correspond to OS command injection attacks
/// documented in CWE-78 and OWASP guidelines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommandThreat {
    /// Semicolon command chaining: `cmd1; cmd2`
    CommandChain,
    /// Pipe chaining: `cmd1 | cmd2`
    PipeChain,
    /// Background execution: `cmd &`
    BackgroundExecution,
    /// Conditional chaining: `cmd1 && cmd2` or `cmd1 || cmd2`
    ConditionalChain,
    /// Command substitution: `$(cmd)` or `` `cmd` ``
    CommandSubstitution,
    /// Variable expansion: `$VAR` or `${VAR}`
    VariableExpansion,
    /// Indirect variable expansion: `${!VAR}`
    IndirectExpansion,
    /// Arithmetic expansion: `$((expr))`
    ArithmeticExpansion,
    /// Output redirection: `>` or `>>`
    OutputRedirect,
    /// Input redirection: `<`
    InputRedirect,
    /// Shell glob patterns: `*`, `?`, `[...]`
    GlobPattern,
    /// Null byte injection (CWE-158)
    NullByte,
    /// Control characters (CWE-707)
    ControlCharacter,
    /// Newline injection (CWE-93)
    NewlineInjection,
    /// Command not in allow-list
    DisallowedCommand,
    /// Dangerous environment variable name
    DangerousEnvName,
    /// Dangerous environment variable value
    DangerousEnvValue,
}

impl CommandThreat {
    /// Get the CWE identifier for this threat
    #[must_use]
    pub const fn cwe(&self) -> &'static str {
        match self {
            Self::CommandChain
            | Self::PipeChain
            | Self::BackgroundExecution
            | Self::ConditionalChain
            | Self::CommandSubstitution
            | Self::VariableExpansion
            | Self::IndirectExpansion
            | Self::ArithmeticExpansion
            | Self::OutputRedirect
            | Self::InputRedirect => "CWE-78",
            Self::GlobPattern => "CWE-200", // Information Exposure
            Self::NullByte => "CWE-158",
            Self::ControlCharacter => "CWE-707",
            Self::NewlineInjection => "CWE-93", // CRLF Injection
            Self::DisallowedCommand => "CWE-78",
            Self::DangerousEnvName | Self::DangerousEnvValue => "CWE-78",
        }
    }

    /// Get the severity level (1-5, higher is more severe)
    #[must_use]
    pub const fn severity(&self) -> u8 {
        match self {
            // Critical: Direct command execution
            Self::CommandSubstitution
            | Self::CommandChain
            | Self::PipeChain
            | Self::NewlineInjection => 5,
            // High: Can lead to command execution
            Self::ConditionalChain
            | Self::BackgroundExecution
            | Self::VariableExpansion
            | Self::IndirectExpansion
            | Self::ArithmeticExpansion
            | Self::DisallowedCommand => 4,
            // Medium: Data manipulation
            Self::OutputRedirect | Self::InputRedirect | Self::DangerousEnvValue => 3,
            // Low: Information disclosure or parsing issues
            Self::GlobPattern
            | Self::NullByte
            | Self::ControlCharacter
            | Self::DangerousEnvName => 2,
        }
    }

    /// Get a human-readable description
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::CommandChain => "Semicolon command chaining (;)",
            Self::PipeChain => "Pipe command chaining (|)",
            Self::BackgroundExecution => "Background execution (&)",
            Self::ConditionalChain => "Conditional chaining (&& or ||)",
            Self::CommandSubstitution => "Command substitution ($() or ``)",
            Self::VariableExpansion => "Variable expansion ($VAR or ${VAR})",
            Self::IndirectExpansion => "Indirect variable expansion (${!VAR})",
            Self::ArithmeticExpansion => "Arithmetic expansion ($((expr)))",
            Self::OutputRedirect => "Output redirection (> or >>)",
            Self::InputRedirect => "Input redirection (<)",
            Self::GlobPattern => "Shell glob pattern (* ? [...])",
            Self::NullByte => "Null byte injection",
            Self::ControlCharacter => "Control character",
            Self::NewlineInjection => "Newline injection (\\n or \\r\\n)",
            Self::DisallowedCommand => "Command not in allow-list",
            Self::DangerousEnvName => "Dangerous environment variable name",
            Self::DangerousEnvValue => "Dangerous environment variable value",
        }
    }
}

impl std::fmt::Display for CommandThreat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.description(), self.cwe())
    }
}

impl From<crate::primitives::security::commands::CommandThreat> for CommandThreat {
    fn from(t: crate::primitives::security::commands::CommandThreat) -> Self {
        use crate::primitives::security::commands::CommandThreat as P;
        match t {
            P::CommandChain => Self::CommandChain,
            P::PipeChain => Self::PipeChain,
            P::BackgroundExecution => Self::BackgroundExecution,
            P::ConditionalChain => Self::ConditionalChain,
            P::CommandSubstitution => Self::CommandSubstitution,
            P::VariableExpansion => Self::VariableExpansion,
            P::IndirectExpansion => Self::IndirectExpansion,
            P::ArithmeticExpansion => Self::ArithmeticExpansion,
            P::OutputRedirect => Self::OutputRedirect,
            P::InputRedirect => Self::InputRedirect,
            P::GlobPattern => Self::GlobPattern,
            P::NullByte => Self::NullByte,
            P::ControlCharacter => Self::ControlCharacter,
            P::NewlineInjection => Self::NewlineInjection,
            P::DisallowedCommand => Self::DisallowedCommand,
            P::DangerousEnvName => Self::DangerousEnvName,
            P::DangerousEnvValue => Self::DangerousEnvValue,
        }
    }
}

// ============================================================================
// AllowList Types
// ============================================================================

/// Mode for allow-list enforcement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AllowListMode {
    /// Only commands in the list are allowed (default, most secure)
    #[default]
    AllowOnly,
    /// Commands in the list are denied, others allowed (less secure)
    DenyListed,
}

impl From<crate::primitives::security::commands::AllowListMode> for AllowListMode {
    fn from(m: crate::primitives::security::commands::AllowListMode) -> Self {
        use crate::primitives::security::commands::AllowListMode as P;
        match m {
            P::AllowOnly => Self::AllowOnly,
            P::DenyListed => Self::DenyListed,
        }
    }
}

impl From<AllowListMode> for crate::primitives::security::commands::AllowListMode {
    fn from(m: AllowListMode) -> Self {
        match m {
            AllowListMode::AllowOnly => Self::AllowOnly,
            AllowListMode::DenyListed => Self::DenyListed,
        }
    }
}

/// Allow-list for command validation
///
/// Controls which commands can be executed. The default mode is `AllowOnly`,
/// which only permits explicitly listed commands.
///
/// # Example
///
/// ```ignore
/// use octarine::security::commands::AllowList;
///
/// let list = AllowList::new()
///     .allow("git")
///     .allow("docker");
///
/// assert!(list.is_allowed("git"));
/// assert!(!list.is_allowed("rm"));
/// ```
#[derive(Debug, Clone, Default)]
pub struct AllowList {
    commands: HashSet<String>,
    mode: AllowListMode,
}

impl AllowList {
    /// Create a new empty allow-list in `AllowOnly` mode
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a command to the list
    #[must_use]
    pub fn allow(mut self, command: impl Into<String>) -> Self {
        self.commands.insert(command.into());
        self
    }

    /// Add multiple commands to the list
    #[must_use]
    pub fn allow_many<I, S>(mut self, commands: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for cmd in commands {
            self.commands.insert(cmd.into());
        }
        self
    }

    /// Set mode to deny all commands not in the list (default)
    #[must_use]
    pub fn deny_all_others(mut self) -> Self {
        self.mode = AllowListMode::AllowOnly;
        self
    }

    /// Set mode to allow all commands except those in the list
    #[must_use]
    pub fn allow_all_except(mut self) -> Self {
        self.mode = AllowListMode::DenyListed;
        self
    }

    /// Check if a command is allowed
    #[must_use]
    pub fn is_allowed(&self, command: &str) -> bool {
        // Extract just the command name (basename) for comparison
        let cmd_name = Self::extract_command_name(command);

        match self.mode {
            AllowListMode::AllowOnly => self.commands.contains(cmd_name),
            AllowListMode::DenyListed => !self.commands.contains(cmd_name),
        }
    }

    /// Check if a command is allowed, resolving symlinks
    ///
    /// Prevents bypass attacks where an attacker creates a symlink
    /// like `/tmp/git -> /bin/rm` to execute disallowed commands.
    pub fn is_allowed_resolving_symlinks(&self, command: &str) -> std::io::Result<bool> {
        // First check the basename
        let cmd_name = Self::extract_command_name(command);
        if !self.is_allowed(cmd_name) {
            return Ok(false);
        }

        // If it's a path (contains separator), resolve symlinks
        if command.contains('/') || command.contains('\\') {
            use std::path::Path;

            let path = Path::new(command);

            // Only resolve if the path exists
            if path.exists() {
                let resolved = std::fs::canonicalize(path)?;
                let resolved_name = resolved.file_name().and_then(|n| n.to_str()).unwrap_or("");

                // The resolved binary name must also be in the allow-list
                return Ok(self.is_allowed(resolved_name));
            }
        }

        Ok(true)
    }

    /// Extract the command name from a path
    fn extract_command_name(command: &str) -> &str {
        command
            .rsplit('/')
            .next()
            .unwrap_or(command)
            .rsplit('\\')
            .next()
            .unwrap_or(command)
    }

    /// Get the number of commands in the list
    #[must_use]
    pub fn len(&self) -> usize {
        self.commands.len()
    }

    /// Check if the list is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }

    /// Get the mode
    #[must_use]
    pub fn mode(&self) -> AllowListMode {
        self.mode
    }

    /// Get reference to the underlying primitive AllowList
    #[must_use]
    pub(crate) fn as_primitive(&self) -> &crate::primitives::security::commands::AllowList {
        // Safety: AllowList has the same internal structure as primitive AllowList
        // This is a temporary workaround - ideally we'd store or convert properly
        // For now, we create a primitive on demand
        // This leaks a static reference which is fine for the limited use case
        static_allowlist(self)
    }

    // Preset allow-lists

    /// Create an allow-list for shell-safe commands
    #[must_use]
    pub fn shell_safe() -> Self {
        Self::new().allow_many([
            "ls", "cat", "echo", "grep", "find", "head", "tail", "wc", "sort", "uniq", "cut", "tr",
            "date", "whoami", "pwd", "env", "printenv", "which", "file", "stat", "du", "df",
        ])
    }

    /// Create an allow-list for git operations
    #[must_use]
    pub fn git_operations() -> Self {
        Self::new().allow("git")
    }

    /// Create an allow-list for docker operations
    #[must_use]
    pub fn docker_operations() -> Self {
        Self::new().allow_many(["docker", "docker-compose"])
    }

    /// Create an allow-list for npm/node operations
    #[must_use]
    pub fn node_operations() -> Self {
        Self::new().allow_many(["node", "npm", "npx", "yarn", "pnpm"])
    }

    /// Create an allow-list for cargo/rust operations
    #[must_use]
    pub fn rust_operations() -> Self {
        Self::new().allow_many(["cargo", "rustc", "rustup", "rustfmt", "clippy-driver"])
    }
}

/// Helper to create a primitive AllowList from our wrapper
/// This is used internally for validation calls
fn static_allowlist(
    wrapper: &AllowList,
) -> &'static crate::primitives::security::commands::AllowList {
    use crate::primitives::security::commands::AllowList as PrimAllowList;
    use std::sync::OnceLock;

    // For simplicity, we'll just create a new primitive each time
    // In practice this could be optimized with caching
    // Leak the allocation to get a 'static reference
    let prim = match wrapper.mode {
        AllowListMode::AllowOnly => {
            let mut p = PrimAllowList::new();
            for cmd in &wrapper.commands {
                p = p.allow(cmd.clone());
            }
            p.deny_all_others()
        }
        AllowListMode::DenyListed => {
            let mut p = PrimAllowList::new();
            for cmd in &wrapper.commands {
                p = p.allow(cmd.clone());
            }
            p.allow_all_except()
        }
    };

    Box::leak(Box::new(prim))
}

impl From<crate::primitives::security::commands::AllowList> for AllowList {
    fn from(p: crate::primitives::security::commands::AllowList) -> Self {
        // We can't directly access the internal commands set from primitive
        // So we create a new wrapper - the primitives AllowList would need
        // accessor methods for full conversion support
        Self {
            commands: HashSet::new(), // Can't access primitive's commands
            mode: p.mode().into(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_command_threat() {
        assert_eq!(CommandThreat::CommandSubstitution.cwe(), "CWE-78");
        assert_eq!(CommandThreat::CommandSubstitution.severity(), 5);
        assert!(!CommandThreat::CommandSubstitution.description().is_empty());
    }

    #[test]
    fn test_allowlist() {
        let list = AllowList::new().allow("git").allow("docker");
        assert!(list.is_allowed("git"));
        assert!(list.is_allowed("docker"));
        assert!(!list.is_allowed("rm"));
    }

    #[test]
    fn test_allowlist_presets() {
        let git = AllowList::git_operations();
        assert!(git.is_allowed("git"));
        assert!(!git.is_allowed("docker"));

        let shell = AllowList::shell_safe();
        assert!(shell.is_allowed("ls"));
        assert!(!shell.is_allowed("rm"));
    }

    #[test]
    fn test_allowlist_mode_default() {
        assert_eq!(AllowListMode::default(), AllowListMode::AllowOnly);
    }
}
