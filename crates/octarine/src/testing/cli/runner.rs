//! CLI Command Runner
//!
//! Utilities for running and testing CLI commands using assert_cmd.

use assert_cmd::Command;
use predicates::prelude::*;
use std::ffi::OsStr;
use std::path::Path;

/// Get a Command for a binary in the current package
///
/// # Note
///
/// This uses the deprecated `Command::cargo_bin` function because the replacement
/// macros (`cargo_bin!`, `cargo_bin_cmd!`) require compile-time environment variables
/// that are only available during `cargo test`. Since this is a library function
/// called at runtime, we must use the runtime lookup approach.
///
/// For integration tests where you have direct control, consider using:
/// ```rust,ignore
/// use assert_cmd::cargo::cargo_bin_cmd;
/// let mut cmd = cargo_bin_cmd!("my-tool");
/// ```
///
/// # Example
///
/// ```rust,ignore
/// use octarine::testing::cli::cargo_bin;
///
/// let cmd = cargo_bin("my-tool");
/// cmd.arg("--version")
///    .assert()
///    .success();
/// ```
#[allow(deprecated)]
pub fn cargo_bin(name: &str) -> Command {
    Command::cargo_bin(name).expect("Failed to find cargo binary")
}

/// Create a command from an arbitrary path
///
/// # Example
///
/// ```rust,ignore
/// use octarine::testing::cli::command;
///
/// let cmd = command("/usr/bin/ls");
/// cmd.arg("-la")
///    .assert()
///    .success();
/// ```
pub fn command<S: AsRef<OsStr>>(program: S) -> Command {
    Command::new(program)
}

/// Common predicates for CLI output testing
pub mod predicates_ext {
    use predicates::prelude::*;

    /// Match output containing a substring
    pub fn contains(s: &str) -> predicates::str::ContainsPredicate {
        predicate::str::contains(s)
    }

    /// Match output starting with a prefix
    pub fn starts_with(s: &str) -> predicates::str::StartsWithPredicate {
        predicate::str::starts_with(s)
    }

    /// Match output ending with a suffix
    pub fn ends_with(s: &str) -> predicates::str::EndsWithPredicate {
        predicate::str::ends_with(s)
    }

    /// Match empty output
    pub fn is_empty() -> predicates::str::IsEmptyPredicate {
        predicate::str::is_empty()
    }

    /// Match output against a regex pattern
    pub fn matches_regex(pattern: &str) -> predicates::str::RegexPredicate {
        predicate::str::is_match(pattern).expect("Invalid regex pattern")
    }
}

/// Builder for CLI test scenarios
///
/// Provides a fluent API for building complex CLI test cases.
/// Uses simple string matching for stdout/stderr assertions.
///
/// # Example
///
/// ```rust,ignore
/// use octarine::testing::cli::CliTestBuilder;
///
/// CliTestBuilder::new("my-app")
///     .with_args(&["--config", "test.toml"])
///     .with_env("LOG_LEVEL", "debug")
///     .with_stdin("input data")
///     .expect_success()
///     .expect_stdout_contains("Success")
///     .run();
/// ```
pub struct CliTestBuilder {
    program: String,
    args: Vec<String>,
    env_vars: Vec<(String, String)>,
    stdin: Option<String>,
    working_dir: Option<String>,
    expect_success: bool,
    expect_code: Option<i32>,
    stdout_contains: Vec<String>,
    stderr_contains: Vec<String>,
}

impl CliTestBuilder {
    /// Create a new CLI test builder for a cargo binary
    pub fn new(bin_name: &str) -> Self {
        Self {
            program: bin_name.to_string(),
            args: Vec::new(),
            env_vars: Vec::new(),
            stdin: None,
            working_dir: None,
            expect_success: true,
            expect_code: None,
            stdout_contains: Vec::new(),
            stderr_contains: Vec::new(),
        }
    }

    /// Add command-line arguments
    pub fn with_args(mut self, args: &[&str]) -> Self {
        self.args.extend(args.iter().map(|s| s.to_string()));
        self
    }

    /// Add a single argument
    pub fn with_arg(mut self, arg: &str) -> Self {
        self.args.push(arg.to_string());
        self
    }

    /// Set an environment variable
    pub fn with_env(mut self, key: &str, value: &str) -> Self {
        self.env_vars.push((key.to_string(), value.to_string()));
        self
    }

    /// Set stdin content
    pub fn with_stdin(mut self, input: &str) -> Self {
        self.stdin = Some(input.to_string());
        self
    }

    /// Set the working directory
    pub fn with_working_dir<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.working_dir = Some(path.as_ref().to_string_lossy().to_string());
        self
    }

    /// Expect the command to succeed (exit code 0)
    pub fn expect_success(mut self) -> Self {
        self.expect_success = true;
        self.expect_code = None;
        self
    }

    /// Expect the command to fail (non-zero exit code)
    pub fn expect_failure(mut self) -> Self {
        self.expect_success = false;
        self.expect_code = None;
        self
    }

    /// Expect a specific exit code
    pub fn expect_exit_code(mut self, code: i32) -> Self {
        self.expect_code = Some(code);
        self
    }

    /// Expect stdout to contain a substring
    pub fn expect_stdout_contains(mut self, s: &str) -> Self {
        self.stdout_contains.push(s.to_string());
        self
    }

    /// Expect stderr to contain a substring
    pub fn expect_stderr_contains(mut self, s: &str) -> Self {
        self.stderr_contains.push(s.to_string());
        self
    }

    /// Run the test and assert all expectations
    ///
    /// See [`cargo_bin`] for notes on the deprecated function usage.
    #[allow(deprecated)]
    pub fn run(self) -> assert_cmd::assert::Assert {
        let mut cmd = Command::cargo_bin(&self.program).expect("Failed to find cargo binary");

        // Add arguments
        for arg in &self.args {
            cmd.arg(arg);
        }

        // Add environment variables
        for (key, value) in &self.env_vars {
            cmd.env(key, value);
        }

        // Set working directory
        if let Some(ref dir) = self.working_dir {
            cmd.current_dir(dir);
        }

        // Set stdin
        if let Some(ref input) = self.stdin {
            cmd.write_stdin(input.as_bytes());
        }

        // Run and get assertion
        let mut assertion = cmd.assert();

        // Check exit code
        if let Some(code) = self.expect_code {
            assertion = assertion.code(code);
        } else if self.expect_success {
            assertion = assertion.success();
        } else {
            assertion = assertion.failure();
        }

        // Check stdout predicates
        for expected in self.stdout_contains {
            assertion = assertion.stdout(predicate::str::contains(expected));
        }

        // Check stderr predicates
        for expected in self.stderr_contains {
            assertion = assertion.stderr(predicate::str::contains(expected));
        }

        assertion
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_predicates_contains() {
        let pred = predicates_ext::contains("hello");
        assert!(pred.eval("hello world"));
        assert!(!pred.eval("goodbye world"));
    }

    #[test]
    fn test_predicates_starts_with() {
        let pred = predicates_ext::starts_with("hello");
        assert!(pred.eval("hello world"));
        assert!(!pred.eval("world hello"));
    }

    #[test]
    fn test_predicates_is_empty() {
        let pred = predicates_ext::is_empty();
        assert!(pred.eval(""));
        assert!(!pred.eval("not empty"));
    }

    #[test]
    fn test_cli_builder_creation() {
        let builder = CliTestBuilder::new("test-app")
            .with_args(&["--help"])
            .with_env("DEBUG", "1")
            .expect_success();

        assert_eq!(builder.program, "test-app");
        assert_eq!(builder.args, vec!["--help"]);
        assert!(builder.expect_success);
    }
}
