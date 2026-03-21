//! Interactive CLI Testing
//!
//! Utilities for testing interactive CLI applications using expect-style
//! pattern matching with rexpect.

use std::io;
use std::time::Duration;

/// Configuration for interactive CLI sessions
#[derive(Clone)]
pub struct InteractiveConfig {
    /// Timeout for expect operations
    pub timeout: Duration,
    /// Echo input to stdout
    pub echo: bool,
}

impl Default for InteractiveConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            echo: false,
        }
    }
}

impl InteractiveConfig {
    /// Create a new config with custom timeout
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            timeout,
            ..Default::default()
        }
    }

    /// Set echo mode
    pub fn with_echo(mut self, echo: bool) -> Self {
        self.echo = echo;
        self
    }
}

/// Spawn an interactive CLI session
///
/// Uses rexpect to spawn a process and interact with it using
/// expect-style pattern matching.
///
/// # Arguments
///
/// * `program` - The program to run
/// * `args` - Command-line arguments
///
/// # Returns
///
/// A `Result` containing the interactive session or an error.
///
/// # Example
///
/// ```rust,ignore
/// use octarine::testing::cli::spawn_interactive;
///
/// let mut session = spawn_interactive("python3", &["-c", "print(input('Name: '))"])?;
/// session.expect("Name:")?;
/// session.send_line("Alice")?;
/// session.expect("Alice")?;
/// ```
///
/// # Note
///
/// This is a simplified wrapper. For complex interactive testing,
/// use rexpect directly:
///
/// ```rust,ignore
/// use rexpect::spawn;
///
/// let mut session = spawn("my-app --interactive", Some(30000))?;
/// ```
pub fn spawn_interactive(program: &str, args: &[&str]) -> io::Result<rexpect::session::PtySession> {
    let cmd = format!(
        "{} {}",
        program,
        args.iter()
            .map(|a| shell_escape::escape((*a).into()))
            .collect::<Vec<_>>()
            .join(" ")
    );

    rexpect::spawn(&cmd, Some(30000)).map_err(io::Error::other)
}

/// Spawn an interactive session with custom configuration
pub fn spawn_interactive_with_config(
    program: &str,
    args: &[&str],
    config: &InteractiveConfig,
) -> io::Result<rexpect::session::PtySession> {
    let cmd = format!(
        "{} {}",
        program,
        args.iter()
            .map(|a| shell_escape::escape((*a).into()))
            .collect::<Vec<_>>()
            .join(" ")
    );

    let timeout_ms = config.timeout.as_millis() as u64;
    rexpect::spawn(&cmd, Some(timeout_ms)).map_err(io::Error::other)
}

/// Spawn a cargo binary interactively
///
/// # Note
///
/// Uses deprecated `cargo_bin` function - see [`super::runner::cargo_bin`] for rationale.
///
/// # Example
///
/// ```rust,ignore
/// use octarine::testing::cli::spawn_cargo_bin;
///
/// let mut session = spawn_cargo_bin("my-cli", &["repl"])?;
/// session.expect(">")?;
/// session.send_line("help")?;
/// ```
#[allow(deprecated)]
pub fn spawn_cargo_bin(name: &str, args: &[&str]) -> io::Result<rexpect::session::PtySession> {
    // Get the path to the cargo binary
    let bin_path = assert_cmd::cargo::cargo_bin(name);

    spawn_interactive(bin_path.to_str().unwrap_or(name), args)
}

/// Helper trait for common interactive testing patterns
pub trait InteractiveTestExt {
    /// Expect a prompt and send a response
    fn prompt_response(
        &mut self,
        prompt: &str,
        response: &str,
    ) -> Result<(), rexpect::error::Error>;

    /// Wait for the session to complete
    fn wait_for_exit(&mut self) -> Result<(), rexpect::error::Error>;
}

impl InteractiveTestExt for rexpect::session::PtySession {
    fn prompt_response(
        &mut self,
        prompt: &str,
        response: &str,
    ) -> Result<(), rexpect::error::Error> {
        self.exp_string(prompt)?;
        self.send_line(response)?;
        Ok(())
    }

    fn wait_for_exit(&mut self) -> Result<(), rexpect::error::Error> {
        self.exp_eof()?;
        Ok(())
    }
}

/// Builder for interactive test scenarios
///
/// # Example
///
/// ```rust,ignore
/// use octarine::testing::cli::InteractiveTestBuilder;
///
/// InteractiveTestBuilder::new("my-app")
///     .with_args(&["--interactive"])
///     .expect("Welcome!")
///     .send("help")
///     .expect("Available commands:")
///     .send("quit")
///     .expect_eof()
///     .run();
/// ```
pub struct InteractiveTestBuilder {
    program: String,
    args: Vec<String>,
    config: InteractiveConfig,
    steps: Vec<InteractiveStep>,
}

enum InteractiveStep {
    Expect(String),
    ExpectRegex(String),
    Send(String),
    SendLine(String),
    ExpectEof,
    Wait(Duration),
}

impl InteractiveTestBuilder {
    /// Create a new interactive test builder
    pub fn new(program: &str) -> Self {
        Self {
            program: program.to_string(),
            args: Vec::new(),
            config: InteractiveConfig::default(),
            steps: Vec::new(),
        }
    }

    /// Create a builder for a cargo binary
    ///
    /// Uses deprecated `cargo_bin` function - see [`super::runner::cargo_bin`] for rationale.
    #[allow(deprecated)]
    pub fn cargo_bin(name: &str) -> Self {
        let bin_path = assert_cmd::cargo::cargo_bin(name);
        Self::new(bin_path.to_str().unwrap_or(name))
    }

    /// Add command-line arguments
    pub fn with_args(mut self, args: &[&str]) -> Self {
        self.args.extend(args.iter().map(|s| s.to_string()));
        self
    }

    /// Set the timeout
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = timeout;
        self
    }

    /// Expect a string in the output
    pub fn expect(mut self, s: &str) -> Self {
        self.steps.push(InteractiveStep::Expect(s.to_string()));
        self
    }

    /// Expect a regex pattern in the output
    pub fn expect_regex(mut self, pattern: &str) -> Self {
        self.steps
            .push(InteractiveStep::ExpectRegex(pattern.to_string()));
        self
    }

    /// Send text (without newline)
    pub fn send(mut self, s: &str) -> Self {
        self.steps.push(InteractiveStep::Send(s.to_string()));
        self
    }

    /// Send text with newline
    pub fn send_line(mut self, s: &str) -> Self {
        self.steps.push(InteractiveStep::SendLine(s.to_string()));
        self
    }

    /// Expect end of output (EOF)
    pub fn expect_eof(mut self) -> Self {
        self.steps.push(InteractiveStep::ExpectEof);
        self
    }

    /// Wait for a duration
    pub fn wait(mut self, duration: Duration) -> Self {
        self.steps.push(InteractiveStep::Wait(duration));
        self
    }

    /// Run the interactive test
    pub fn run(self) -> Result<(), rexpect::error::Error> {
        let args: Vec<&str> = self.args.iter().map(|s| s.as_str()).collect();
        let mut session = spawn_interactive_with_config(&self.program, &args, &self.config)?;

        for step in self.steps {
            match step {
                InteractiveStep::Expect(s) => {
                    session.exp_string(&s)?;
                }
                InteractiveStep::ExpectRegex(pattern) => {
                    session.exp_regex(&pattern)?;
                }
                InteractiveStep::Send(s) => {
                    session.send(&s)?;
                }
                InteractiveStep::SendLine(s) => {
                    session.send_line(&s)?;
                }
                InteractiveStep::ExpectEof => {
                    session.exp_eof()?;
                }
                InteractiveStep::Wait(duration) => {
                    std::thread::sleep(duration);
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_interactive_config_default() {
        let config = InteractiveConfig::default();
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert!(!config.echo);
    }

    #[test]
    fn test_interactive_config_with_timeout() {
        let config = InteractiveConfig::with_timeout(Duration::from_secs(60));
        assert_eq!(config.timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_builder_creation() {
        let builder = InteractiveTestBuilder::new("echo")
            .with_args(&["hello"])
            .with_timeout(Duration::from_secs(10))
            .expect("hello")
            .expect_eof();

        assert_eq!(builder.program, "echo");
        assert_eq!(builder.args, vec!["hello"]);
        assert_eq!(builder.steps.len(), 2);
    }

    #[test]
    #[ignore] // Requires actual terminal
    fn test_echo_interactive() {
        let result = InteractiveTestBuilder::new("echo")
            .with_args(&["hello", "world"])
            .expect("hello world")
            .expect_eof()
            .run();

        assert!(result.is_ok());
    }
}
