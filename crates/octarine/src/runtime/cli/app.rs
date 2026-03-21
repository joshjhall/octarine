//! CLI application builder
//!
//! Provides a builder for creating CLI applications with integrated
//! logging, error handling, and common argument patterns.

use std::time::Instant;

use crate::observe;

use super::context::CliContext;
use super::error::{CliError, CliResult};
use super::exit::ExitCode;
use super::output::OutputFormat;

/// CLI application builder
///
/// Wraps clap with observe integration and consistent error handling.
///
/// # Example
///
/// ```ignore
/// use octarine::runtime::cli::{CliApp, ExitCode};
///
/// fn main() -> ExitCode {
///     CliApp::new("myapp", "My application description")
///         .version(env!("CARGO_PKG_VERSION"))
///         .run(|ctx| {
///             ctx.info("Hello, world!");
///             Ok(())
///         })
/// }
/// ```
pub struct CliApp {
    /// Application name
    name: &'static str,
    /// Application description
    description: &'static str,
    /// Version string
    version: Option<&'static str>,
    /// Author string
    author: Option<&'static str>,
    /// Whether to add verbose flag
    with_verbose: bool,
    /// Whether to add quiet flag
    with_quiet: bool,
    /// Whether to add format flag
    with_format: bool,
    /// Whether to add color flag
    with_color: bool,
}

impl CliApp {
    /// Create a new CLI application
    #[must_use]
    pub fn new(name: &'static str, description: &'static str) -> Self {
        Self {
            name,
            description,
            version: None,
            author: None,
            with_verbose: true,
            with_quiet: true,
            with_format: false,
            with_color: true,
        }
    }

    /// Set the version string
    #[must_use]
    pub fn version(mut self, version: &'static str) -> Self {
        self.version = Some(version);
        self
    }

    /// Set the author string
    #[must_use]
    pub fn author(mut self, author: &'static str) -> Self {
        self.author = Some(author);
        self
    }

    /// Enable/disable verbose flag (-v, --verbose)
    #[must_use]
    pub fn with_verbose(mut self, enabled: bool) -> Self {
        self.with_verbose = enabled;
        self
    }

    /// Enable/disable quiet flag (-q, --quiet)
    #[must_use]
    pub fn with_quiet(mut self, enabled: bool) -> Self {
        self.with_quiet = enabled;
        self
    }

    /// Enable/disable format flag (--format)
    #[must_use]
    pub fn with_format(mut self, enabled: bool) -> Self {
        self.with_format = enabled;
        self
    }

    /// Enable/disable color flag (--color/--no-color)
    #[must_use]
    pub fn with_color(mut self, enabled: bool) -> Self {
        self.with_color = enabled;
        self
    }

    /// Build the clap command
    #[cfg(feature = "cli")]
    #[allow(clippy::too_many_arguments)]
    fn build_command(
        name: &'static str,
        description: &'static str,
        version: Option<&'static str>,
        author: Option<&'static str>,
        with_verbose: bool,
        with_quiet: bool,
        with_format: bool,
        with_color: bool,
    ) -> clap::Command {
        let mut cmd = clap::Command::new(name).about(description);

        if let Some(version) = version {
            cmd = cmd.version(version);
        }

        if let Some(author) = author {
            cmd = cmd.author(author);
        }

        // Add common flags
        if with_verbose {
            cmd = cmd.arg(
                clap::Arg::new("verbose")
                    .short('v')
                    .long("verbose")
                    .action(clap::ArgAction::Count)
                    .help("Increase verbosity (can be repeated)"),
            );
        }

        if with_quiet {
            cmd = cmd.arg(
                clap::Arg::new("quiet")
                    .short('q')
                    .long("quiet")
                    .action(clap::ArgAction::SetTrue)
                    .help("Suppress non-error output"),
            );
        }

        if with_format {
            cmd = cmd.arg(
                clap::Arg::new("format")
                    .long("format")
                    .value_name("FORMAT")
                    .value_parser(["text", "json", "quiet"])
                    .default_value("text")
                    .help("Output format"),
            );
        }

        if with_color {
            cmd = cmd
                .arg(
                    clap::Arg::new("color")
                        .long("color")
                        .action(clap::ArgAction::SetTrue)
                        .help("Force color output"),
                )
                .arg(
                    clap::Arg::new("no-color")
                        .long("no-color")
                        .action(clap::ArgAction::SetTrue)
                        .help("Disable color output"),
                );
        }

        cmd
    }

    /// Run the application with a handler function
    ///
    /// The handler receives a `CliContext` for output and logging.
    /// Returns an `ExitCode` suitable for use as `main()` return type.
    #[cfg(feature = "cli")]
    pub fn run<F>(self, handler: F) -> ExitCode
    where
        F: FnOnce(&CliContext) -> CliResult<()>,
    {
        let cmd = Self::build_command(
            self.name,
            self.description,
            self.version,
            self.author,
            self.with_verbose,
            self.with_quiet,
            self.with_format,
            self.with_color,
        );
        let matches = cmd.get_matches();

        // Parse common flags
        let verbosity = self.parse_verbosity(&matches);
        let format = self.parse_format(&matches);

        // Create context
        let ctx = CliContext::new(self.name)
            .with_verbosity(verbosity)
            .with_format(format);

        // Log command start
        observe::info(
            self.name,
            format!(
                "Starting {} v{}",
                self.name,
                self.version.unwrap_or("unknown")
            ),
        );

        let start = Instant::now();

        // Run handler
        let result = handler(&ctx);

        let duration = start.elapsed();

        // Handle result
        match result {
            Ok(()) => {
                observe::info(
                    self.name,
                    format!("Completed successfully in {:?}", duration),
                );
                ExitCode::SUCCESS
            }
            Err(err) => {
                ctx.error(&err.format_user());
                observe::error(self.name, format!("Failed: {}", err));
                err.exit_code()
            }
        }
    }

    /// Run the application (fallback without cli feature)
    #[cfg(not(feature = "cli"))]
    pub fn run<F>(self, handler: F) -> ExitCode
    where
        F: FnOnce(&CliContext) -> CliResult<()>,
    {
        let ctx = CliContext::new(self.name);

        observe::info(
            self.name,
            format!(
                "Starting {} v{}",
                self.name,
                self.version.unwrap_or("unknown")
            ),
        );

        let start = Instant::now();
        let result = handler(&ctx);
        let duration = start.elapsed();

        match result {
            Ok(()) => {
                observe::info(
                    self.name,
                    format!("Completed successfully in {:?}", duration),
                );
                ExitCode::SUCCESS
            }
            Err(err) => {
                ctx.error(&err.format_user());
                observe::error(self.name, format!("Failed: {}", err));
                err.exit_code()
            }
        }
    }

    /// Run with parsed arguments (for subcommand-style applications)
    #[cfg(feature = "cli")]
    pub fn run_with_args<F, A>(self, handler: F) -> ExitCode
    where
        F: FnOnce(&CliContext, A) -> CliResult<()>,
        A: clap::FromArgMatches + clap::Args,
    {
        let cmd = Self::build_command(
            self.name,
            self.description,
            self.version,
            self.author,
            self.with_verbose,
            self.with_quiet,
            self.with_format,
            self.with_color,
        );
        let cmd = A::augment_args(cmd);
        let matches = cmd.get_matches();

        // Parse custom args
        let args = match A::from_arg_matches(&matches) {
            Ok(args) => args,
            Err(e) => {
                observe::error(self.name, format!("Argument parsing failed: {}", e));
                return ExitCode::USAGE_ERROR;
            }
        };

        // Parse common flags
        let verbosity = self.parse_verbosity(&matches);
        let format = self.parse_format(&matches);

        // Create context
        let ctx = CliContext::new(self.name)
            .with_verbosity(verbosity)
            .with_format(format);

        observe::info(
            self.name,
            format!(
                "Starting {} v{}",
                self.name,
                self.version.unwrap_or("unknown")
            ),
        );

        let start = Instant::now();
        let result = handler(&ctx, args);
        let duration = start.elapsed();

        match result {
            Ok(()) => {
                observe::info(
                    self.name,
                    format!("Completed successfully in {:?}", duration),
                );
                ExitCode::SUCCESS
            }
            Err(err) => {
                ctx.error(&err.format_user());
                observe::error(self.name, format!("Failed: {}", err));
                err.exit_code()
            }
        }
    }

    /// Parse verbosity from matches
    #[cfg(feature = "cli")]
    fn parse_verbosity(&self, matches: &clap::ArgMatches) -> u8 {
        if self.with_quiet && matches.get_flag("quiet") {
            return 0;
        }

        if self.with_verbose {
            let verbose_count = matches.get_count("verbose");
            return verbose_count.saturating_add(1);
        }

        1 // Normal verbosity
    }

    /// Parse format from matches
    #[cfg(feature = "cli")]
    fn parse_format(&self, matches: &clap::ArgMatches) -> OutputFormat {
        if self.with_format
            && let Some(format) = matches.get_one::<String>("format")
        {
            return OutputFormat::from_str_opt(format).unwrap_or_default();
        }

        // Check quiet flag
        if self.with_quiet && matches.get_flag("quiet") {
            return OutputFormat::Quiet;
        }

        OutputFormat::Text
    }
}

/// Helper to run a simple CLI with just a handler
///
/// # Example
///
/// ```ignore
/// use octarine::runtime::cli::{run_cli, ExitCode};
///
/// fn main() -> ExitCode {
///     run_cli("myapp", "My app", |ctx| {
///         ctx.info("Hello!");
///         Ok(())
///     })
/// }
/// ```
pub fn run_cli<F>(name: &'static str, description: &'static str, handler: F) -> ExitCode
where
    F: FnOnce(&CliContext) -> CliResult<()>,
{
    CliApp::new(name, description).run(handler)
}

/// Handle a CLI error and return appropriate exit code
///
/// Useful for custom error handling in main functions.
pub fn handle_error(err: CliError) -> ExitCode {
    let ctx = CliContext::default();
    ctx.error(&err.format_user());
    err.exit_code()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_cli_app_builder() {
        let app = CliApp::new("myapp", "My application")
            .version("1.0.0")
            .author("Test Author")
            .with_verbose(true)
            .with_quiet(true);

        assert_eq!(app.name, "myapp");
        assert_eq!(app.description, "My application");
        assert_eq!(app.version, Some("1.0.0"));
        assert_eq!(app.author, Some("Test Author"));
        assert!(app.with_verbose);
        assert!(app.with_quiet);
    }

    #[test]
    fn test_cli_app_disable_flags() {
        let app = CliApp::new("myapp", "My application")
            .with_verbose(false)
            .with_quiet(false)
            .with_color(false);

        assert!(!app.with_verbose);
        assert!(!app.with_quiet);
        assert!(!app.with_color);
    }

    #[test]
    fn test_handle_error() {
        let err = CliError::config("Missing config file");
        let code = handle_error(err);
        assert_eq!(code, ExitCode::CONFIG_ERROR);
    }

    #[cfg(feature = "cli")]
    #[test]
    fn test_build_command() {
        let cmd = CliApp::build_command(
            "testapp",
            "Test application",
            Some("1.0.0"),
            None,
            true,
            true,
            true,
            true,
        );

        // Verify command was built
        assert_eq!(cmd.get_name(), "testapp");
    }
}
