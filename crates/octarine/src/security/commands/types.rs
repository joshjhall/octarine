//! Security-related command types
//!
//! These types form the canonical location for command security types.
//! They wrap primitives types with the Layer 3 visibility boundary.

use crate::primitives::security::commands::AllowList as PrimAllowList;

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
/// Internally wraps a [`PrimAllowList`] and delegates all operations to it,
/// so conversions to the primitive are zero-cost and lossless.
///
/// # Example
///
/// Pre-existing example - ignored at compile until adapted.
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
    inner: PrimAllowList,
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
        self.inner = self.inner.allow(command);
        self
    }

    /// Add multiple commands to the list
    #[must_use]
    pub fn allow_many<I, S>(mut self, commands: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.inner = self.inner.allow_many(commands);
        self
    }

    /// Set mode to deny all commands not in the list (default)
    #[must_use]
    pub fn deny_all_others(mut self) -> Self {
        self.inner = self.inner.deny_all_others();
        self
    }

    /// Set mode to allow all commands except those in the list
    #[must_use]
    pub fn allow_all_except(mut self) -> Self {
        self.inner = self.inner.allow_all_except();
        self
    }

    /// Check if a command is allowed
    #[must_use]
    pub fn is_allowed(&self, command: &str) -> bool {
        self.inner.is_allowed(command)
    }

    /// Check if a command is allowed, resolving symlinks
    ///
    /// Prevents bypass attacks where an attacker creates a symlink
    /// like `/tmp/git -> /bin/rm` to execute disallowed commands.
    pub fn is_allowed_resolving_symlinks(&self, command: &str) -> std::io::Result<bool> {
        self.inner.is_allowed_resolving_symlinks(command)
    }

    /// Get the number of commands in the list
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the list is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get the mode
    #[must_use]
    pub fn mode(&self) -> AllowListMode {
        self.inner.mode().into()
    }

    /// Get reference to the underlying primitive AllowList
    #[must_use]
    pub(crate) fn as_primitive(&self) -> &PrimAllowList {
        &self.inner
    }

    // Preset allow-lists

    /// Create an allow-list for shell-safe commands
    #[must_use]
    pub fn shell_safe() -> Self {
        Self {
            inner: PrimAllowList::shell_safe(),
        }
    }

    /// Create an allow-list for git operations
    #[must_use]
    pub fn git_operations() -> Self {
        Self {
            inner: PrimAllowList::git_operations(),
        }
    }

    /// Create an allow-list for docker operations
    #[must_use]
    pub fn docker_operations() -> Self {
        Self {
            inner: PrimAllowList::docker_operations(),
        }
    }

    /// Create an allow-list for npm/node operations
    #[must_use]
    pub fn node_operations() -> Self {
        Self {
            inner: PrimAllowList::node_operations(),
        }
    }

    /// Create an allow-list for cargo/rust operations
    #[must_use]
    pub fn rust_operations() -> Self {
        Self {
            inner: PrimAllowList::rust_operations(),
        }
    }
}

impl From<PrimAllowList> for AllowList {
    fn from(inner: PrimAllowList) -> Self {
        Self { inner }
    }
}

impl From<AllowList> for PrimAllowList {
    fn from(wrapper: AllowList) -> Self {
        wrapper.inner
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

    #[test]
    fn test_from_primitive_preserves_commands() {
        // Previously, From<PrimAllowList> for AllowList silently discarded the
        // commands set because the wrapper had no way to read primitive state.
        // After the wrap-and-delegate refactor it round-trips losslessly.
        let prim = PrimAllowList::new().allow("git").allow("docker");
        let wrapper: AllowList = prim.into();

        assert!(wrapper.is_allowed("git"));
        assert!(wrapper.is_allowed("docker"));
        assert!(!wrapper.is_allowed("rm"));
        assert_eq!(wrapper.len(), 2);
    }

    #[test]
    fn test_from_primitive_preserves_mode() {
        let prim = PrimAllowList::new().allow("rm").allow_all_except();
        let wrapper: AllowList = prim.into();

        // Mode preserved → "rm" is denied, everything else allowed.
        assert!(!wrapper.is_allowed("rm"));
        assert!(wrapper.is_allowed("ls"));
        assert_eq!(wrapper.mode(), AllowListMode::DenyListed);
    }

    #[test]
    fn test_repeated_validation_no_leak() {
        // Smoke test for the hot path. Previously every call to as_primitive()
        // leaked a Box; this loop would have leaked thousands of allocations.
        // The structural fix (no Box::leak in the source) is the real guarantee
        // — this test just exercises the call path heavily.
        let list = AllowList::git_operations();
        for _ in 0..1000 {
            assert!(list.as_primitive().is_allowed("git"));
        }
    }
}
