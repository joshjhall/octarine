//! Observable shell context

use once_cell::sync::Lazy;

use super::command::ObservableCmd;
use super::xshell_error;
use crate::observe::metrics::MetricName;
use crate::observe::{self, Problem, metrics};
use crate::security::commands::validate_command_name;
use crate::security::paths::is_secure;
use std::path::Path;
use xshell::Shell;

// Pre-validated metric names for shell context operations
static METRIC_CONTEXTS_CREATED: Lazy<MetricName> =
    Lazy::new(|| MetricName::from_static_str("shell.contexts_created"));
static METRIC_PATHS_BLOCKED: Lazy<MetricName> =
    Lazy::new(|| MetricName::from_static_str("shell.security.paths_blocked"));
static METRIC_PROGRAMS_BLOCKED: Lazy<MetricName> =
    Lazy::new(|| MetricName::from_static_str("shell.security.programs_blocked"));

/// Observable shell context - wraps xshell with observe logging
pub struct ObservableShell {
    inner: Shell,
}

impl ObservableShell {
    /// Create a new observable shell context
    pub fn new() -> Result<Self, Problem> {
        let _timer = metrics::timer("shell.init");
        observe::debug("shell.init", "Creating new shell context");

        let inner = Shell::new().map_err(xshell_error)?;

        metrics::increment(METRIC_CONTEXTS_CREATED.clone());
        observe::debug("shell.init.complete", "Shell context created");
        Ok(Self { inner })
    }

    /// Create a command builder for the given program
    pub fn cmd(&self, program: &str) -> ObservableCmd<'_> {
        ObservableCmd::new(&self.inner, program)
    }

    /// Create a validated command builder (rejects dangerous program names)
    ///
    /// # Errors
    ///
    /// Returns error if program name contains dangerous patterns like:
    /// - Command substitution: `$(whoami)`
    /// - Path traversal: `../../../bin/sh`
    /// - Empty string
    pub fn cmd_validated(&self, program: &str) -> Result<ObservableCmd<'_>, Problem> {
        validate_command_name(program).inspect_err(|_| {
            metrics::increment(METRIC_PROGRAMS_BLOCKED.clone());
            observe::warn(
                "shell.cmd.program_rejected",
                "Dangerous program name rejected: [REDACTED]",
            );
        })?;
        Ok(ObservableCmd::new(&self.inner, program))
    }

    /// Get the current working directory
    #[must_use]
    pub fn current_dir(&self) -> std::path::PathBuf {
        self.inner.current_dir()
    }

    /// Change the working directory (validates path security)
    ///
    /// # Errors
    ///
    /// Returns an error if the path contains security threats (traversal, injection, etc.)
    pub fn change_dir(&self, path: impl AsRef<Path>) -> Result<(), Problem> {
        let path = path.as_ref();
        let path_str = path.to_string_lossy();

        // Validate path is secure (no traversal attacks)
        if !is_secure(&path_str) {
            metrics::increment(METRIC_PATHS_BLOCKED.clone());
            observe::warn(
                "shell.change_dir.blocked",
                format!("Insecure path blocked: {}", path_str),
            );
            return Err(Problem::validation(format!("Insecure path: {}", path_str)));
        }

        observe::debug(
            "shell.change_dir",
            format!("Changing to: {}", path.display()),
        );
        self.inner.change_dir(path);
        Ok(())
    }

    /// Temporarily push a directory (validates path security)
    ///
    /// Returns a guard that restores the previous directory when dropped.
    /// This is xshell's RAII pattern for directory management.
    ///
    /// # Errors
    ///
    /// Returns an error if the path contains security threats
    ///
    /// # Example
    ///
    /// ```ignore
    /// let shell = ObservableShell::new()?;
    /// {
    ///     let _guard = shell.push_dir("/some/path")?;
    ///     // Commands here run in /some/path
    ///     shell.cmd("ls").run()?;
    /// }
    /// // Back to original directory when guard drops
    /// ```
    pub fn push_dir(&self, path: impl AsRef<Path>) -> Result<xshell::PushDir<'_>, Problem> {
        let path = path.as_ref();
        let path_str = path.to_string_lossy();

        if !is_secure(&path_str) {
            metrics::increment(METRIC_PATHS_BLOCKED.clone());
            observe::warn(
                "shell.push_dir.blocked",
                format!("Insecure path blocked: {}", path_str),
            );
            return Err(Problem::validation(format!("Insecure path: {}", path_str)));
        }

        observe::debug("shell.push_dir", format!("Pushing: {}", path.display()));
        Ok(self.inner.push_dir(path))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_change_dir_blocks_traversal() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let result = shell.change_dir("../../../etc/passwd");
        assert!(result.is_err());
    }

    #[test]
    fn test_push_dir_blocks_traversal() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let result = shell.push_dir("../../../etc");
        assert!(result.is_err());
    }

    #[test]
    fn test_change_dir_allows_safe_path() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let result = shell.change_dir("/tmp");
        assert!(result.is_ok());
    }

    #[test]
    fn test_push_dir_returns_guard() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let original = shell.current_dir();

        {
            let _guard = shell.push_dir("/tmp").expect("push_dir failed");
            // We're now in /tmp
            assert_eq!(shell.current_dir().to_string_lossy(), "/tmp");
        }
        // Guard dropped, back to original
        assert_eq!(shell.current_dir(), original);
    }

    #[test]
    fn test_current_dir_returns_path() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let cwd = shell.current_dir();
        assert!(!cwd.as_os_str().is_empty());
    }

    #[test]
    fn test_cmd_validated_accepts_safe_program() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let result = shell.cmd_validated("echo");
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_validated_rejects_command_substitution() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let result = shell.cmd_validated("$(whoami)");
        assert!(result.is_err());
    }

    #[test]
    fn test_cmd_validated_rejects_path_traversal() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let result = shell.cmd_validated("../../../bin/sh");
        assert!(result.is_err());
    }

    #[test]
    fn test_cmd_validated_accepts_absolute_path() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let result = shell.cmd_validated("/usr/bin/echo");
        assert!(result.is_ok());
    }
}
