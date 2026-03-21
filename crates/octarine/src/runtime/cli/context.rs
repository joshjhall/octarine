//! CLI execution context
//!
//! Provides context for command execution including output helpers,
//! progress indicators, and logging integration.

use super::output::{OutputFormat, OutputStyle, StyledOutput};
use super::progress::{ProgressBar, ProgressStyle, Spinner};
use super::{CliError, CliResult};
use crate::observe;

/// Execution context for CLI commands
///
/// Provides helpers for output, progress, and logging during command execution.
///
/// # Example
///
/// ```ignore
/// use octarine::runtime::cli::CliContext;
///
/// fn my_command(ctx: &CliContext) -> CliResult<()> {
///     ctx.info("Starting operation...");
///
///     let spinner = ctx.spinner("Processing");
///     // do work
///     spinner.finish_with_message("Done!");
///
///     ctx.success("Operation completed");
///     Ok(())
/// }
/// ```
#[derive(Debug)]
pub struct CliContext {
    /// Application name
    app_name: String,
    /// Command name (if running a subcommand)
    command_name: Option<String>,
    /// Output format
    format: OutputFormat,
    /// Output styling
    style: OutputStyle,
    /// Verbosity level (0 = quiet, 1 = normal, 2+ = verbose)
    verbosity: u8,
    /// Output helper
    output: StyledOutput,
}

impl CliContext {
    /// Create a new CLI context
    #[must_use]
    pub fn new(app_name: impl Into<String>) -> Self {
        let style = OutputStyle::detect();
        Self {
            app_name: app_name.into(),
            command_name: None,
            format: OutputFormat::Text,
            style,
            verbosity: 1,
            output: StyledOutput::new(style),
        }
    }

    /// Set the command name
    #[must_use]
    pub fn with_command(mut self, name: impl Into<String>) -> Self {
        self.command_name = Some(name.into());
        self
    }

    /// Set the output format
    #[must_use]
    pub fn with_format(mut self, format: OutputFormat) -> Self {
        self.format = format;
        self
    }

    /// Set the output style
    #[must_use]
    pub fn with_style(mut self, style: OutputStyle) -> Self {
        self.style = style;
        self.output = StyledOutput::new(style);
        self
    }

    /// Set verbosity level
    #[must_use]
    pub fn with_verbosity(mut self, level: u8) -> Self {
        self.verbosity = level;
        self
    }

    /// Get the application name
    #[must_use]
    pub fn app_name(&self) -> &str {
        &self.app_name
    }

    /// Get the command name
    #[must_use]
    pub fn command_name(&self) -> Option<&str> {
        self.command_name.as_deref()
    }

    /// Get the output format
    #[must_use]
    pub fn format(&self) -> OutputFormat {
        self.format
    }

    /// Get the output style
    #[must_use]
    pub fn style(&self) -> &OutputStyle {
        &self.style
    }

    /// Get verbosity level
    #[must_use]
    pub fn verbosity(&self) -> u8 {
        self.verbosity
    }

    /// Check if quiet mode
    #[must_use]
    pub fn is_quiet(&self) -> bool {
        self.verbosity == 0 || self.format == OutputFormat::Quiet
    }

    /// Check if verbose mode
    #[must_use]
    pub fn is_verbose(&self) -> bool {
        self.verbosity > 1
    }

    // ========================================================================
    // Output Methods
    // ========================================================================

    /// Print a success message
    pub fn success(&self, message: &str) {
        if !self.is_quiet() {
            let _ = self.output.success(message);
        }
        observe::info(self.log_target(), format!("success: {}", message));
    }

    /// Print an error message
    pub fn error(&self, message: &str) {
        // Always show errors
        let _ = self.output.error(message);
        observe::error(self.log_target(), message);
    }

    /// Print a warning message
    pub fn warning(&self, message: &str) {
        if !self.is_quiet() {
            let _ = self.output.warning(message);
        }
        observe::warn(self.log_target(), message);
    }

    /// Print an info message
    pub fn info(&self, message: &str) {
        if !self.is_quiet() {
            let _ = self.output.info(message);
        }
        observe::info(self.log_target(), message);
    }

    /// Print a debug message (only in verbose mode)
    pub fn debug(&self, message: &str) {
        if self.is_verbose() {
            let _ = self.output.print(&format!("  [debug] {}", message));
        }
        observe::debug(self.log_target(), message);
    }

    /// Print a plain message
    pub fn print(&self, message: &str) {
        if !self.is_quiet() {
            let _ = self.output.print(message);
        }
    }

    /// Print a header
    pub fn header(&self, title: &str) {
        if !self.is_quiet() {
            let _ = self.output.header(title);
        }
    }

    /// Print a list item
    pub fn list_item(&self, item: &str) {
        if !self.is_quiet() {
            let _ = self.output.list_item(item);
        }
    }

    /// Print a key-value pair
    pub fn key_value(&self, key: &str, value: &str) {
        if !self.is_quiet() {
            let _ = self.output.key_value(key, value);
        }
    }

    // ========================================================================
    // Progress Methods
    // ========================================================================

    /// Create a progress bar
    #[must_use]
    pub fn progress(&self, total: u64) -> ProgressBar {
        if self.is_quiet() {
            ProgressBar::hidden(total)
        } else {
            ProgressBar::new(total)
        }
    }

    /// Create a progress bar with a specific style
    #[must_use]
    pub fn progress_styled(&self, total: u64, style: ProgressStyle) -> ProgressBar {
        if self.is_quiet() {
            ProgressBar::hidden(total)
        } else {
            ProgressBar::with_style(total, style)
        }
    }

    /// Create a spinner
    #[must_use]
    pub fn spinner(&self, message: impl Into<std::borrow::Cow<'static, str>>) -> Spinner {
        if self.is_quiet() {
            Spinner::hidden()
        } else {
            Spinner::new(message)
        }
    }

    // ========================================================================
    // JSON Output
    // ========================================================================

    /// Output JSON data (respects format setting)
    pub fn json<T: serde::Serialize>(&self, data: &T) -> CliResult<()> {
        match self.format {
            OutputFormat::Json => {
                let json = serde_json::to_string_pretty(data)
                    .map_err(|e| CliError::new(format!("JSON serialization failed: {}", e)))?;
                let _ = self.output.print(&json);
            }
            OutputFormat::Text => {
                // For text format, we still output JSON but without pretty printing
                let json = serde_json::to_string(data)
                    .map_err(|e| CliError::new(format!("JSON serialization failed: {}", e)))?;
                let _ = self.output.print(&json);
            }
            OutputFormat::Quiet => {
                // No output in quiet mode
            }
        }
        Ok(())
    }

    // ========================================================================
    // Internal
    // ========================================================================

    /// Get the log target for observe
    fn log_target(&self) -> &str {
        match &self.command_name {
            Some(cmd) => cmd,
            None => &self.app_name,
        }
    }
}

impl Default for CliContext {
    fn default() -> Self {
        Self::new("cli")
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_context_creation() {
        let ctx = CliContext::new("myapp");
        assert_eq!(ctx.app_name(), "myapp");
        assert!(ctx.command_name().is_none());
        assert_eq!(ctx.verbosity(), 1);
    }

    #[test]
    fn test_context_with_command() {
        let ctx = CliContext::new("myapp").with_command("init");
        assert_eq!(ctx.command_name(), Some("init"));
    }

    #[test]
    fn test_context_quiet_mode() {
        let ctx = CliContext::new("myapp").with_verbosity(0);
        assert!(ctx.is_quiet());
        assert!(!ctx.is_verbose());
    }

    #[test]
    fn test_context_verbose_mode() {
        let ctx = CliContext::new("myapp").with_verbosity(2);
        assert!(!ctx.is_quiet());
        assert!(ctx.is_verbose());
    }

    #[test]
    fn test_context_format() {
        let ctx = CliContext::new("myapp").with_format(OutputFormat::Json);
        assert_eq!(ctx.format(), OutputFormat::Json);
    }

    #[test]
    fn test_context_quiet_format() {
        let ctx = CliContext::new("myapp").with_format(OutputFormat::Quiet);
        assert!(ctx.is_quiet());
    }

    #[test]
    fn test_progress_hidden_in_quiet() {
        let ctx = CliContext::new("myapp").with_verbosity(0);
        let pb = ctx.progress(100);
        // Just verify it doesn't panic
        pb.inc(10);
        pb.finish();
    }

    #[test]
    fn test_spinner_hidden_in_quiet() {
        let ctx = CliContext::new("myapp").with_verbosity(0);
        let spinner = ctx.spinner("Loading...");
        spinner.set_message("Still loading...");
        spinner.finish();
    }

    #[test]
    fn test_default() {
        let ctx = CliContext::default();
        assert_eq!(ctx.app_name(), "cli");
    }
}
