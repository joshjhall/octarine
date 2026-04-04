//! Observable command builder with security integration

use once_cell::sync::Lazy;

use serde::de::DeserializeOwned;

use super::xshell_error;
use crate::crypto::secrets::SecretString;
use crate::observe::metrics::MetricName;
use crate::observe::{self, Problem, metrics, pii};
use crate::security::commands::{is_dangerous_arg, validate_env, validate_safe_arg};
use std::ffi::OsStr;
use std::process::Output;
use xshell::{Cmd, Shell};

// Pre-validated metric names for shell command operations
static METRIC_DANGEROUS_ARGS: Lazy<MetricName> =
    Lazy::new(|| MetricName::from_static_str("shell.security.dangerous_args_detected"));
static METRIC_ARGS_REJECTED: Lazy<MetricName> =
    Lazy::new(|| MetricName::from_static_str("shell.security.args_rejected"));
static METRIC_ENVS_REJECTED: Lazy<MetricName> =
    Lazy::new(|| MetricName::from_static_str("shell.security.envs_rejected"));
static METRIC_EXECUTIONS: Lazy<MetricName> =
    Lazy::new(|| MetricName::from_static_str("shell.cmd.executions"));
static METRIC_FAILURES: Lazy<MetricName> =
    Lazy::new(|| MetricName::from_static_str("shell.cmd.failures"));

/// Observable command — wraps xshell `Cmd` with security auditing and metrics.
///
/// # Security Model
///
/// xshell passes arguments directly via `execvp` without shell interpretation,
/// so shell metacharacters (`$(...)`, backticks, pipes, semicolons) are never
/// executed — they are passed as literal strings.
///
/// This struct provides two argument APIs:
/// - [`arg()`](Self::arg) — logs a warning for dangerous patterns (audit trail)
///   but still adds the argument, since xshell does not interpret them.
/// - [`arg_validated()`](Self::arg_validated) — rejects dangerous patterns with
///   an error, for defense-in-depth with untrusted input.
pub struct ObservableCmd<'a> {
    inner: Cmd<'a>,
    program: String,
    /// Skip argument validation (for trusted internal use)
    skip_validation: bool,
}

impl<'a> ObservableCmd<'a> {
    /// Create a new observable command (internal)
    pub(crate) fn new(shell: &'a Shell, program: &str) -> Self {
        observe::debug("shell.cmd.new", format!("Creating command: {program}"));
        Self {
            inner: shell.cmd(program),
            program: program.to_string(),
            skip_validation: false,
        }
    }

    // ========== Security Configuration ==========

    /// Skip argument validation (use only for trusted internal commands)
    ///
    /// By default, all arguments are validated against command injection.
    /// Call this to bypass validation for performance with trusted input.
    #[must_use]
    pub fn trusted(mut self) -> Self {
        self.skip_validation = true;
        self
    }

    // ========== Argument Methods (with validation) ==========

    /// Add a single argument with audit logging for dangerous patterns.
    ///
    /// Checks the argument for shell metacharacters and logs a warning if found,
    /// but still adds the argument. This is safe because xshell uses direct
    /// `execvp` — shell metacharacters are never interpreted, just passed as
    /// literal strings. The warning exists for audit trail visibility.
    ///
    /// Use [`arg_validated()`](Self::arg_validated) instead if you want to
    /// reject dangerous patterns as an error (defense-in-depth).
    #[must_use]
    pub fn arg<P: AsRef<OsStr>>(mut self, arg: P) -> Self {
        let arg_str = arg.as_ref().to_string_lossy();

        if !self.skip_validation && is_dangerous_arg(&arg_str) {
            metrics::increment(METRIC_DANGEROUS_ARGS.clone());
            observe::warn(
                "shell.cmd.dangerous_arg",
                format!(
                    "Potentially dangerous argument detected for '{}': {}",
                    self.program,
                    pii::redact_pii(&arg_str)
                ),
            );
        }

        self.inner = self.inner.arg(arg);
        self
    }

    /// Add a validated argument (returns error if dangerous)
    ///
    /// # Errors
    ///
    /// Returns an error if the argument contains dangerous patterns
    pub fn arg_validated<P: AsRef<OsStr>>(mut self, arg: P) -> Result<Self, Problem> {
        let arg_str = arg.as_ref().to_string_lossy();

        validate_safe_arg(&arg_str).inspect_err(|_| {
            metrics::increment(METRIC_ARGS_REJECTED.clone());
            observe::warn(
                "shell.cmd.arg_rejected",
                format!(
                    "Unsafe argument rejected for '{}': [REDACTED]",
                    self.program
                ),
            );
        })?;

        self.inner = self.inner.arg(arg);
        Ok(self)
    }

    /// Add multiple arguments
    #[must_use]
    pub fn args<I, P>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<OsStr>,
    {
        for arg in args {
            self = self.arg(arg);
        }
        self
    }

    /// Add multiple validated arguments (returns error if any is dangerous)
    ///
    /// # Errors
    ///
    /// Returns error on first dangerous argument encountered
    pub fn args_validated<I, P>(mut self, args: I) -> Result<Self, Problem>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<OsStr>,
    {
        for arg in args {
            self = self.arg_validated(arg)?;
        }
        Ok(self)
    }

    // ========== Environment Methods ==========

    /// Set an environment variable
    #[must_use]
    pub fn env<K: AsRef<OsStr>, V: AsRef<OsStr>>(mut self, key: K, val: V) -> Self {
        self.inner = self.inner.env(key, val);
        self
    }

    /// Set multiple environment variables
    #[must_use]
    pub fn envs<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        self.inner = self.inner.envs(vars);
        self
    }

    /// Set an environment variable with validation
    ///
    /// # Errors
    ///
    /// Returns error if name or value contains dangerous patterns
    pub fn env_validated<K: AsRef<OsStr>, V: AsRef<OsStr>>(
        mut self,
        key: K,
        val: V,
    ) -> Result<Self, Problem> {
        let key_str = key.as_ref().to_string_lossy();
        let val_str = val.as_ref().to_string_lossy();

        validate_env(&key_str, &val_str).inspect_err(|_| {
            metrics::increment(METRIC_ENVS_REJECTED.clone());
            observe::warn(
                "shell.cmd.env_rejected",
                format!(
                    "Unsafe environment variable rejected for '{}': [REDACTED]",
                    self.program
                ),
            );
        })?;

        self.inner = self.inner.env(key, val);
        Ok(self)
    }

    /// Set multiple environment variables with validation
    ///
    /// # Errors
    ///
    /// Returns error if any name or value contains dangerous patterns
    pub fn envs_validated<I, K, V>(mut self, vars: I) -> Result<Self, Problem>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        for (key, val) in vars {
            self = self.env_validated(key, val)?;
        }
        Ok(self)
    }

    /// Remove an environment variable
    #[must_use]
    pub fn env_remove<K: AsRef<OsStr>>(mut self, key: K) -> Self {
        self.inner = self.inner.env_remove(key);
        self
    }

    /// Clear all environment variables
    #[must_use]
    pub fn env_clear(mut self) -> Self {
        observe::warn(
            "shell.cmd.env_clear",
            format!("Clearing all environment for: {}", self.program),
        );
        self.inner = self.inner.env_clear();
        self
    }

    // ========== Input/Output Control ==========

    /// Provide stdin data
    #[must_use]
    pub fn stdin<S: AsRef<[u8]>>(mut self, stdin: S) -> Self {
        self.inner = self.inner.stdin(stdin);
        self
    }

    /// Ignore stdout (redirect to /dev/null)
    #[must_use]
    pub fn ignore_stdout(mut self) -> Self {
        self.inner = self.inner.ignore_stdout();
        self
    }

    /// Ignore stderr (redirect to /dev/null)
    #[must_use]
    pub fn ignore_stderr(mut self) -> Self {
        self.inner = self.inner.ignore_stderr();
        self
    }

    /// Suppress echoing command to stderr
    #[must_use]
    pub fn quiet(mut self) -> Self {
        self.inner = self.inner.quiet();
        self
    }

    /// Mark command as secret (masked in output)
    #[must_use]
    pub fn secret(mut self) -> Self {
        self.inner = self.inner.secret();
        self
    }

    /// Ignore non-zero exit status
    #[must_use]
    pub fn ignore_status(mut self) -> Self {
        self.inner = self.inner.ignore_status();
        self
    }

    // ========== Execution Methods ==========

    /// Run the command, inheriting stdio
    ///
    /// # Errors
    ///
    /// Returns an error if the command fails to execute
    pub fn run(self) -> Result<(), Problem> {
        let _timer = metrics::timer(&format!("shell.cmd.{}.run", self.program));
        metrics::increment(METRIC_EXECUTIONS.clone());

        observe::info("shell.cmd.run", format!("Running: {}", self.program));

        let result = self.inner.run();

        match &result {
            Ok(()) => {
                observe::info(
                    "shell.cmd.run.complete",
                    format!("Command '{}' completed", self.program),
                );
            }
            Err(e) => {
                metrics::increment(METRIC_FAILURES.clone());
                observe::warn(
                    "shell.cmd.run.failed",
                    format!("Command '{}' failed: {}", self.program, e),
                );
            }
        }

        result.map_err(xshell_error)
    }

    /// Run and return stdout as trimmed string (output is PII-redacted in logs)
    ///
    /// # Errors
    ///
    /// Returns an error if the command fails to execute
    pub fn read(self) -> Result<String, Problem> {
        let _timer = metrics::timer(&format!("shell.cmd.{}.read", self.program));
        metrics::increment(METRIC_EXECUTIONS.clone());

        observe::info("shell.cmd.read", format!("Executing: {}", self.program));

        let result = self.inner.read();

        match &result {
            Ok(output) => {
                // Log output length, never raw content (may contain secrets)
                observe::info(
                    "shell.cmd.read.complete",
                    format!(
                        "Command '{}' completed ({} bytes)",
                        self.program,
                        output.len()
                    ),
                );
            }
            Err(e) => {
                metrics::increment(METRIC_FAILURES.clone());
                // Redact error message in case it contains secrets
                observe::warn(
                    "shell.cmd.read.failed",
                    format!(
                        "Command '{}' failed: {}",
                        self.program,
                        pii::redact_pii(&e.to_string())
                    ),
                );
            }
        }

        result.map_err(xshell_error)
    }

    /// Run and return stderr as trimmed string
    ///
    /// # Errors
    ///
    /// Returns an error if the command fails to execute
    pub fn read_stderr(self) -> Result<String, Problem> {
        let _timer = metrics::timer(&format!("shell.cmd.{}.read_stderr", self.program));
        metrics::increment(METRIC_EXECUTIONS.clone());

        observe::info(
            "shell.cmd.read_stderr",
            format!("Executing: {}", self.program),
        );

        let result = self.inner.read_stderr();

        match &result {
            Ok(_) => {
                observe::info(
                    "shell.cmd.read_stderr.complete",
                    format!("Command '{}' completed", self.program),
                );
            }
            Err(e) => {
                metrics::increment(METRIC_FAILURES.clone());
                observe::warn(
                    "shell.cmd.read_stderr.failed",
                    format!(
                        "Command '{}' failed: {}",
                        self.program,
                        pii::redact_pii(&e.to_string())
                    ),
                );
            }
        }

        result.map_err(xshell_error)
    }

    /// Run and return full output
    ///
    /// # Errors
    ///
    /// Returns an error if the command fails to execute
    pub fn output(self) -> Result<Output, Problem> {
        let _timer = metrics::timer(&format!("shell.cmd.{}.output", self.program));
        metrics::increment(METRIC_EXECUTIONS.clone());

        observe::info("shell.cmd.output", format!("Executing: {}", self.program));

        let result = self.inner.output();

        match &result {
            Ok(output) => {
                let exit_code = output.status.code().unwrap_or(-1);
                observe::info(
                    "shell.cmd.output.complete",
                    format!("Command '{}' exited {}", self.program, exit_code),
                );
            }
            Err(e) => {
                metrics::increment(METRIC_FAILURES.clone());
                observe::warn(
                    "shell.cmd.output.failed",
                    format!(
                        "Command '{}' failed: {}",
                        self.program,
                        pii::redact_pii(&e.to_string())
                    ),
                );
            }
        }

        result.map_err(xshell_error)
    }

    /// Run and parse stdout as JSON
    ///
    /// # Errors
    ///
    /// Returns an error if the command fails or JSON parsing fails
    pub fn read_json<T: DeserializeOwned>(self) -> Result<T, Problem> {
        let _timer = metrics::timer(&format!("shell.cmd.{}.read_json", self.program));
        metrics::increment(METRIC_EXECUTIONS.clone());

        observe::info(
            "shell.cmd.read_json",
            format!("Executing: {}", self.program),
        );

        let output = self.inner.read().map_err(xshell_error)?;

        observe::info(
            "shell.cmd.read_json.complete",
            format!(
                "Command '{}' completed ({} bytes)",
                self.program,
                output.len()
            ),
        );

        serde_json::from_str(&output).map_err(|e| {
            observe::warn(
                "shell.cmd.read_json.parse_failed",
                format!("JSON parse failed for '{}': {}", self.program, e),
            );
            Problem::validation(format!("Failed to parse JSON: {}", e))
        })
    }

    /// Run and return stdout as SecretString (output NOT logged)
    ///
    /// Use this for commands that return sensitive data like passwords or tokens.
    /// The output is never logged, only timing and byte count.
    ///
    /// # Errors
    ///
    /// Returns an error if the command fails
    pub fn read_secret(self) -> Result<SecretString, Problem> {
        let _timer = metrics::timer(&format!("shell.cmd.{}.read_secret", self.program));
        metrics::increment(METRIC_EXECUTIONS.clone());

        observe::info(
            "shell.cmd.read_secret",
            format!("Executing: {}", self.program),
        );

        let result = self.inner.read();

        match result {
            Ok(output) => {
                // Log timing and size, but NEVER the content
                observe::info(
                    "shell.cmd.read_secret.complete",
                    format!(
                        "Command '{}' completed ({} bytes)",
                        self.program,
                        output.len()
                    ),
                );
                Ok(SecretString::new(output))
            }
            Err(e) => {
                metrics::increment(METRIC_FAILURES.clone());
                observe::warn(
                    "shell.cmd.read_secret.failed",
                    format!(
                        "Command '{}' failed: {}",
                        self.program,
                        pii::redact_pii(&e.to_string())
                    ),
                );
                Err(xshell_error(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]

    use crate::runtime::shell::ObservableShell;

    #[test]
    fn test_shell_creation() {
        let shell = ObservableShell::new();
        assert!(shell.is_ok());
    }

    #[test]
    fn test_simple_command() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let result = shell.cmd("echo").arg("hello").read();
        assert!(result.is_ok());
        assert_eq!(result.expect("read failed"), "hello");
    }

    #[test]
    fn test_command_with_args() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let result = shell.cmd("echo").args(["one", "two", "three"]).read();
        assert!(result.is_ok());
        assert_eq!(result.expect("read failed"), "one two three");
    }

    #[test]
    fn test_trusted_skips_validation() {
        let shell = ObservableShell::new().expect("shell creation failed");
        // This would normally warn, but trusted() skips validation
        let result = shell.cmd("echo").trusted().arg("$(whoami)").read();
        // Note: echo doesn't execute the substitution, just prints it
        assert!(result.is_ok());
    }

    #[test]
    fn test_command_not_found() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let result = shell.cmd("nonexistent-command-12345").read();
        assert!(result.is_err());
    }

    #[test]
    fn test_arg_validated_rejects_dangerous() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let cmd = shell.cmd("echo");
        let result = cmd.arg_validated("$(rm -rf /)");
        assert!(result.is_err());
    }

    #[test]
    fn test_quiet_command() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let result = shell.cmd("echo").quiet().arg("hello").read();
        assert!(result.is_ok());
    }

    #[test]
    fn test_environment_variable() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let result = shell
            .cmd("sh")
            .args(["-c", "echo $TEST_VAR"])
            .env("TEST_VAR", "hello")
            .read();
        assert!(result.is_ok());
        assert_eq!(result.expect("read failed"), "hello");
    }

    #[test]
    fn test_stdin() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let result = shell.cmd("cat").stdin("hello from stdin").read();
        assert!(result.is_ok());
        assert_eq!(result.expect("read failed"), "hello from stdin");
    }

    #[test]
    fn test_ignore_status() {
        let shell = ObservableShell::new().expect("shell creation failed");
        // false command returns exit code 1
        let result = shell.cmd("false").ignore_status().run();
        assert!(result.is_ok());
    }

    #[test]
    fn test_output_captures_exit_code() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let output = shell
            .cmd("sh")
            .args(["-c", "exit 42"])
            .ignore_status()
            .output();
        assert!(output.is_ok());
        let output = output.expect("output failed");
        assert_eq!(output.status.code(), Some(42));
    }

    #[test]
    fn test_dangerous_arg_still_executes() {
        // Dangerous args warn but still execute (lenient mode)
        let shell = ObservableShell::new().expect("shell creation failed");
        let result = shell.cmd("echo").arg("$(whoami)").read();
        // echo doesn't interpret, just prints literal
        assert!(result.is_ok());
        assert_eq!(result.expect("read failed"), "$(whoami)");
    }

    #[test]
    fn test_args_validated_rejects_on_first_bad() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let result = shell
            .cmd("echo")
            .args_validated(["safe", "$(bad)", "also_safe"]);
        assert!(result.is_err());
    }

    #[test]
    fn test_args_validated_accepts_all_safe() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let result = shell.cmd("echo").args_validated(["one", "two", "three"]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_env_validated_accepts_safe() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let result = shell
            .cmd("sh")
            .args(["-c", "echo $MY_VAR"])
            .env_validated("MY_VAR", "safe_value");
        assert!(result.is_ok());
    }

    #[test]
    fn test_env_validated_rejects_dangerous_value() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let result = shell.cmd("sh").env_validated("MY_VAR", "$(whoami)");
        assert!(result.is_err());
    }

    #[test]
    fn test_env_validated_rejects_dangerous_name() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let result = shell.cmd("sh").env_validated("VAR;rm", "value");
        assert!(result.is_err());
    }

    #[test]
    fn test_envs_validated_accepts_all_safe() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let result = shell
            .cmd("sh")
            .envs_validated([("VAR1", "value1"), ("VAR2", "value2")]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_envs_validated_rejects_on_first_bad() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let result = shell
            .cmd("sh")
            .envs_validated([("SAFE", "value"), ("BAD", "$(whoami)")]);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_json_parses_valid() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let result: Result<serde_json::Value, _> =
            shell.cmd("echo").arg(r#"{"key": "value"}"#).read_json();
        assert!(result.is_ok());
        let json = result.expect("json parse failed");
        assert_eq!(json.get("key").expect("key not found"), "value");
    }

    #[test]
    fn test_read_json_fails_on_invalid() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let result: Result<serde_json::Value, _> = shell.cmd("echo").arg("not json").read_json();
        assert!(result.is_err());
    }

    #[test]
    fn test_read_secret_returns_secret_string() {
        use crate::crypto::secrets::ExposeSecret;
        let shell = ObservableShell::new().expect("shell creation failed");
        let result = shell.cmd("echo").arg("secret_value").read_secret();
        assert!(result.is_ok());
        let secret = result.expect("read_secret failed");
        // Must use expose_secret() to access value
        assert_eq!(secret.expose_secret().trim(), "secret_value");
    }

    #[test]
    fn test_read_secret_command_not_found() {
        let shell = ObservableShell::new().expect("shell creation failed");
        let result = shell.cmd("nonexistent-command-12345").read_secret();
        assert!(result.is_err());
    }
}
