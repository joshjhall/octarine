//! Secure command execution
//!
//! Builder and executor for secure subprocess execution.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::observe;
use crate::primitives::crypto::secrets::PrimitiveSecureEnvBuilder;
use crate::primitives::security::commands::types::AllowList;

use super::error::ProcessError;
use super::output::CommandOutput;
use super::validation::{ArgumentPolicy, ValidatedArg};

/// Default timeout for command execution (5 minutes)
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(300);

/// A secure command builder with input validation and audit trails
///
/// `SecureCommand` wraps `std::process::Command` with security features:
/// - Argument validation against injection patterns
/// - Environment sanitization (only safe vars inherited by default)
/// - Timeout enforcement
/// - Audit logging via observe
///
/// # Example
///
/// ```ignore
/// use octarine::runtime::process::SecureCommand;
/// use std::time::Duration;
///
/// let output = SecureCommand::new("git")
///     .arg("status")
///     .current_dir("/path/to/repo")
///     .timeout(Duration::from_secs(30))
///     .execute()?;
///
/// println!("Status: {}", output.stdout_string());
/// ```
///
/// # Security Model
///
/// By default:
/// - No arguments are validated (use `arg_validated` for untrusted input)
/// - Environment is sanitized (only PATH, HOME, etc. inherited)
/// - Commands time out after 5 minutes
///
/// For untrusted input, always use `arg_validated`:
///
/// ```ignore
/// SecureCommand::new("git")
///     .arg("clone")
///     .arg_validated(user_provided_url)?  // Validates against injection
///     .execute()?;
/// ```
pub struct SecureCommand {
    /// The program to execute
    program: String,
    /// Arguments (both validated and unvalidated)
    args: Vec<String>,
    /// Working directory
    current_dir: Option<PathBuf>,
    /// Environment variables to set
    env_vars: HashMap<String, String>,
    /// Whether to inherit safe environment variables
    inherit_safe_env: bool,
    /// Whether to inherit ALL environment variables (unsafe)
    inherit_all_env: bool,
    /// Execution timeout
    timeout: Duration,
    /// Capture stdout
    capture_stdout: bool,
    /// Capture stderr
    capture_stderr: bool,
    /// Stdin data to pipe
    stdin_data: Option<Vec<u8>>,
}

impl SecureCommand {
    /// Create a new SecureCommand for the given program
    ///
    /// # Arguments
    ///
    /// * `program` - The program to execute (e.g., "git", "docker", "/usr/bin/ls")
    ///
    /// # Example
    ///
    /// ```ignore
    /// let cmd = SecureCommand::new("git");
    /// ```
    #[must_use]
    pub fn new(program: impl Into<String>) -> Self {
        let program = program.into();
        observe::debug(
            "process.command.new",
            format!("Creating SecureCommand for: {}", program),
        );

        Self {
            program,
            args: Vec::new(),
            current_dir: None,
            env_vars: HashMap::new(),
            inherit_safe_env: true,
            inherit_all_env: false,
            timeout: DEFAULT_TIMEOUT,
            capture_stdout: true,
            capture_stderr: true,
            stdin_data: None,
        }
    }

    /// Add an argument (not validated)
    ///
    /// Use this for trusted arguments like flags and known values.
    /// For untrusted input, use [`arg_validated`](Self::arg_validated).
    ///
    /// # Example
    ///
    /// ```ignore
    /// SecureCommand::new("git")
    ///     .arg("--version")  // Trusted flag
    ///     .execute()?;
    /// ```
    #[must_use]
    pub fn arg(mut self, arg: impl AsRef<str>) -> Self {
        self.args.push(arg.as_ref().to_string());
        self
    }

    /// Add multiple arguments (not validated)
    ///
    /// Use this for trusted arguments. For untrusted input, validate each
    /// argument individually with [`arg_validated`](Self::arg_validated).
    #[must_use]
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for arg in args {
            self.args.push(arg.as_ref().to_string());
        }
        self
    }

    /// Add a validated argument (prevents injection)
    ///
    /// Validates the argument against command injection patterns using
    /// the strict policy. Use this for any untrusted input.
    ///
    /// # Errors
    ///
    /// Returns `ProcessError::InjectionDetected` if injection patterns are found.
    ///
    /// # Example
    ///
    /// ```ignore
    /// SecureCommand::new("git")
    ///     .arg("clone")
    ///     .arg_validated(user_provided_url)?  // Validated
    ///     .execute()?;
    /// ```
    pub fn arg_validated(mut self, arg: impl Into<String>) -> Result<Self, ProcessError> {
        let validated = ValidatedArg::new(arg)?;
        self.args.push(validated.into_inner());
        Ok(self)
    }

    /// Add a validated argument with a specific policy
    ///
    /// Different argument types may need different validation rules.
    /// See [`ArgumentPolicy`] for available policies.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use octarine::runtime::process::ArgumentPolicy;
    ///
    /// SecureCommand::new("curl")
    ///     .arg_with_policy(url, ArgumentPolicy::Url)?
    ///     .execute()?;
    /// ```
    pub fn arg_with_policy(
        mut self,
        arg: impl Into<String>,
        policy: ArgumentPolicy,
    ) -> Result<Self, ProcessError> {
        let validated = ValidatedArg::with_policy(arg, policy)?;
        self.args.push(validated.into_inner());
        Ok(self)
    }

    /// Add a pre-validated argument
    ///
    /// Use when you've already validated the argument elsewhere.
    #[must_use]
    pub fn arg_pre_validated(mut self, arg: ValidatedArg) -> Self {
        self.args.push(arg.into_inner());
        self
    }

    /// Set the working directory
    ///
    /// # Example
    ///
    /// ```ignore
    /// SecureCommand::new("ls")
    ///     .current_dir("/tmp")
    ///     .execute()?;
    /// ```
    #[must_use]
    pub fn current_dir(mut self, dir: impl AsRef<Path>) -> Self {
        self.current_dir = Some(dir.as_ref().to_path_buf());
        self
    }

    /// Set an environment variable
    ///
    /// This adds to (or overrides) the inherited environment.
    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env_vars.insert(key.into(), value.into());
        self
    }

    /// Set multiple environment variables
    #[must_use]
    pub fn envs<I, K, V>(mut self, vars: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        for (k, v) in vars {
            self.env_vars.insert(k.into(), v.into());
        }
        self
    }

    /// Disable safe environment inheritance
    ///
    /// By default, safe environment variables (PATH, HOME, etc.) are inherited.
    /// Call this to start with a completely empty environment.
    #[must_use]
    pub fn env_clear(mut self) -> Self {
        self.inherit_safe_env = false;
        self
    }

    /// Inherit ALL environment variables (unsafe)
    ///
    /// **Warning**: This inherits potentially dangerous variables like
    /// credentials and LD_PRELOAD. Only use when absolutely necessary.
    #[must_use]
    pub fn env_inherit_all(mut self) -> Self {
        observe::warn(
            "process.command.env",
            "Inheriting all environment variables (unsafe)",
        );
        self.inherit_all_env = true;
        self
    }

    /// Set the execution timeout
    ///
    /// Default is 5 minutes. Commands that exceed the timeout are killed.
    ///
    /// # Example
    ///
    /// ```ignore
    /// SecureCommand::new("slow-command")
    ///     .timeout(Duration::from_secs(60))
    ///     .execute()?;
    /// ```
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set stdin data to pipe to the command
    ///
    /// # Example
    ///
    /// ```ignore
    /// SecureCommand::new("cat")
    ///     .stdin(b"hello world")
    ///     .execute()?;
    /// ```
    #[must_use]
    pub fn stdin(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.stdin_data = Some(data.into());
        self
    }

    /// Set stdin data from a string
    #[must_use]
    pub fn stdin_string(self, data: impl AsRef<str>) -> Self {
        self.stdin(data.as_ref().as_bytes().to_vec())
    }

    /// Verify the command is in the allow-list
    ///
    /// Checks that the command name (basename) is in the provided allow-list.
    /// This provides defense-in-depth by restricting which commands can be executed.
    ///
    /// # Errors
    ///
    /// Returns `ProcessError::CommandNotAllowed` if the command is not in the allow-list.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use octarine::runtime::process::{SecureCommand, AllowList};
    ///
    /// let allowlist = AllowList::git_operations();
    /// let cmd = SecureCommand::new("git")
    ///     .with_allowlist(&allowlist)?  // Validates command
    ///     .arg("status")
    ///     .execute()?;
    /// ```
    pub fn with_allowlist(self, allowlist: &AllowList) -> Result<Self, ProcessError> {
        if !allowlist.is_allowed(&self.program) {
            observe::event::critical(format!("Command '{}' is not in allow-list", self.program));
            return Err(ProcessError::command_not_allowed(&self.program));
        }
        observe::debug(
            "process.command.allowlist",
            format!("Command '{}' is allowed", self.program),
        );
        Ok(self)
    }

    /// Verify the command is in the allow-list, resolving symlinks
    ///
    /// Stricter variant that also resolves symlinks to prevent bypass attacks
    /// where an attacker creates a symlink like `/tmp/git -> /bin/rm`.
    ///
    /// # Errors
    ///
    /// Returns `ProcessError::CommandNotAllowed` if:
    /// - The command basename is not in the allow-list
    /// - The resolved symlink target is not in the allow-list
    ///
    /// Returns `ProcessError::Io` if the path cannot be resolved.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use octarine::runtime::process::{SecureCommand, AllowList};
    ///
    /// let allowlist = AllowList::git_operations();
    /// // This will reject /tmp/git if it symlinks to /bin/rm
    /// let cmd = SecureCommand::new("/tmp/git")
    ///     .with_allowlist_strict(&allowlist)?
    ///     .arg("status")
    ///     .execute()?;
    /// ```
    pub fn with_allowlist_strict(self, allowlist: &AllowList) -> Result<Self, ProcessError> {
        match allowlist.is_allowed_resolving_symlinks(&self.program) {
            Ok(true) => {
                observe::debug(
                    "process.command.allowlist",
                    format!("Command '{}' is allowed (symlink-checked)", self.program),
                );
                Ok(self)
            }
            Ok(false) => {
                observe::event::critical(format!(
                    "Command '{}' is not in allow-list (symlink-checked)",
                    self.program
                ));
                Err(ProcessError::command_not_allowed(&self.program))
            }
            Err(e) => Err(ProcessError::io(
                e,
                format!("failed to resolve command path: {}", self.program),
            )),
        }
    }

    /// Don't capture stdout (discard it)
    #[must_use]
    pub fn stdout_null(mut self) -> Self {
        self.capture_stdout = false;
        self
    }

    /// Don't capture stderr (discard it)
    #[must_use]
    pub fn stderr_null(mut self) -> Self {
        self.capture_stderr = false;
        self
    }

    /// Execute the command and wait for it to complete
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The command cannot be spawned
    /// - The command times out
    /// - An I/O error occurs
    ///
    /// Note: A non-zero exit code is NOT an error. Check `output.success()`.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let output = SecureCommand::new("ls")
    ///     .arg("-la")
    ///     .execute()?;
    ///
    /// if output.success() {
    ///     println!("{}", output.stdout_string());
    /// }
    /// ```
    pub fn execute(self) -> Result<CommandOutput, ProcessError> {
        let start = Instant::now();
        let command_str = self.command_string();

        observe::info(
            "process.command.execute",
            format!("Executing: {}", command_str),
        );

        // Build the actual Command
        let mut cmd = Command::new(&self.program);

        // Add arguments
        for arg in &self.args {
            cmd.arg(arg);
        }

        // Set working directory
        if let Some(ref dir) = self.current_dir {
            cmd.current_dir(dir);
        }

        // Configure environment
        self.configure_environment(&mut cmd);

        // Configure stdio
        if self.stdin_data.is_some() {
            cmd.stdin(Stdio::piped());
        } else {
            cmd.stdin(Stdio::null());
        }
        cmd.stdout(if self.capture_stdout {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        cmd.stderr(if self.capture_stderr {
            Stdio::piped()
        } else {
            Stdio::null()
        });

        // Spawn the process
        let mut child = cmd.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ProcessError::not_found(&self.program)
            } else {
                ProcessError::io(e, format!("failed to spawn {}", self.program))
            }
        })?;

        // Write stdin if provided
        if let Some(ref stdin_data) = self.stdin_data {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                stdin
                    .write_all(stdin_data)
                    .map_err(|e| ProcessError::io(e, "failed to write to stdin"))?;
            }
        }

        // Wait with timeout
        let output = self.wait_with_timeout(&mut child, &command_str)?;
        let duration = start.elapsed();

        // Log completion
        let exit_code = output.status.code().unwrap_or(-1);
        if output.status.success() {
            observe::info(
                "process.command.complete",
                format!(
                    "Command completed: {} (exit: {}, duration: {:?})",
                    command_str, exit_code, duration
                ),
            );
        } else {
            observe::warn(
                "process.command.failed",
                format!(
                    "Command failed: {} (exit: {}, duration: {:?})",
                    command_str, exit_code, duration
                ),
            );
        }

        Ok(CommandOutput::new(
            output.status,
            output.stdout,
            output.stderr,
            duration,
            command_str,
        ))
    }

    /// Execute and require success (exit code 0)
    ///
    /// # Errors
    ///
    /// Returns `ProcessError::NonZeroExit` if the command exits with non-zero status.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let output = SecureCommand::new("test")
    ///     .arg("-f")
    ///     .arg("file.txt")
    ///     .execute_success()?;  // Returns error if file doesn't exist
    /// ```
    pub fn execute_success(self) -> Result<CommandOutput, ProcessError> {
        let command_str = self.command_string();
        let output = self.execute()?;

        if !output.success() {
            return Err(ProcessError::non_zero_exit(
                command_str,
                output.code().unwrap_or(-1),
                output.stderr_trimmed(),
            ));
        }

        Ok(output)
    }

    /// Get the command as a string for logging
    fn command_string(&self) -> String {
        let mut parts = vec![self.program.clone()];
        parts.extend(self.args.iter().cloned());
        parts.join(" ")
    }

    /// Configure the environment for the command
    fn configure_environment(&self, cmd: &mut Command) {
        if self.inherit_all_env {
            // Just add our vars on top
            for (key, value) in &self.env_vars {
                cmd.env(key, value);
            }
        } else {
            // Use PrimitiveSecureEnvBuilder for safe inheritance
            // (runtime has its own observe instrumentation, so we use the primitive)
            let mut builder = PrimitiveSecureEnvBuilder::new();

            if self.inherit_safe_env {
                builder = builder.inherit_safe();
            }

            // Add our explicit vars
            for (key, value) in &self.env_vars {
                builder = builder.with_var(key, value);
            }

            let env = builder.build_simple();

            // Clear and set
            cmd.env_clear();
            for (key, value) in env.iter() {
                cmd.env(key, value);
            }
        }
    }

    /// Wait for the child with timeout
    fn wait_with_timeout(
        &self,
        child: &mut std::process::Child,
        command_str: &str,
    ) -> Result<std::process::Output, ProcessError> {
        use std::thread;

        // For simplicity, we use try_wait in a loop with sleeps
        // A more sophisticated implementation could use platform-specific APIs
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .unwrap_or_else(Instant::now);
        let poll_interval = Duration::from_millis(100);

        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    // Process has exited, collect output
                    let stdout = child
                        .stdout
                        .take()
                        .map(|mut s| {
                            use std::io::Read;
                            let mut buf = Vec::new();
                            let _ = s.read_to_end(&mut buf);
                            buf
                        })
                        .unwrap_or_default();

                    let stderr = child
                        .stderr
                        .take()
                        .map(|mut s| {
                            use std::io::Read;
                            let mut buf = Vec::new();
                            let _ = s.read_to_end(&mut buf);
                            buf
                        })
                        .unwrap_or_default();

                    return Ok(std::process::Output {
                        status,
                        stdout,
                        stderr,
                    });
                }
                Ok(None) => {
                    // Still running, check timeout
                    if Instant::now() >= deadline {
                        observe::error(
                            "process.command.timeout",
                            format!(
                                "Command timed out after {:?}: {}",
                                self.timeout, command_str
                            ),
                        );

                        // Kill the process
                        let _ = child.kill();
                        let _ = child.wait(); // Reap the zombie

                        return Err(ProcessError::timeout(command_str, self.timeout.as_secs()));
                    }

                    thread::sleep(poll_interval);
                }
                Err(e) => {
                    return Err(ProcessError::io(e, "failed to wait for process"));
                }
            }
        }
    }
}

impl std::fmt::Debug for SecureCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureCommand")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("current_dir", &self.current_dir)
            .field("env_vars", &self.env_vars.keys().collect::<Vec<_>>())
            .field("inherit_safe_env", &self.inherit_safe_env)
            .field("timeout", &self.timeout)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_simple_command() {
        let output = SecureCommand::new("echo")
            .arg("hello")
            .execute()
            .expect("echo should succeed");

        assert!(output.success());
        assert_eq!(output.stdout_trimmed(), "hello");
    }

    #[test]
    fn test_multiple_args() {
        let output = SecureCommand::new("echo")
            .args(["one", "two", "three"])
            .execute()
            .expect("echo should succeed");

        assert!(output.success());
        assert_eq!(output.stdout_trimmed(), "one two three");
    }

    #[test]
    fn test_command_not_found() {
        let result = SecureCommand::new("nonexistent-command-12345").execute();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ProcessError::CommandNotFound { .. }));
    }

    #[test]
    fn test_non_zero_exit() {
        let output = SecureCommand::new("false")
            .execute()
            .expect("false should execute");

        assert!(!output.success());
        assert_eq!(output.code(), Some(1));
    }

    #[test]
    fn test_execute_success_fails_on_non_zero() {
        let result = SecureCommand::new("false").execute_success();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ProcessError::NonZeroExit { .. }));
    }

    #[test]
    fn test_validated_arg_rejects_injection() {
        let result = SecureCommand::new("echo").arg_validated("$(whoami)");

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ProcessError::InjectionDetected { .. }));
    }

    #[test]
    fn test_validated_arg_accepts_safe() {
        let result = SecureCommand::new("echo").arg_validated("hello-world");

        assert!(result.is_ok());
    }

    #[test]
    fn test_current_dir() {
        let output = SecureCommand::new("pwd")
            .current_dir("/tmp")
            .execute()
            .expect("pwd should succeed");

        assert!(output.success());
        assert!(
            output.stdout_trimmed().starts_with("/tmp")
                || output.stdout_trimmed().starts_with("/private/tmp")
        ); // macOS
    }

    #[test]
    fn test_environment_variable() {
        let output = SecureCommand::new("sh")
            .arg("-c")
            .arg("echo $TEST_VAR")
            .env("TEST_VAR", "test_value")
            .execute()
            .expect("sh should succeed");

        assert!(output.success());
        assert_eq!(output.stdout_trimmed(), "test_value");
    }

    #[test]
    fn test_stdin() {
        let output = SecureCommand::new("cat")
            .stdin_string("hello from stdin")
            .execute()
            .expect("cat should succeed");

        assert!(output.success());
        assert_eq!(output.stdout_trimmed(), "hello from stdin");
    }

    #[test]
    fn test_timeout() {
        let result = SecureCommand::new("sleep")
            .arg("10")
            .timeout(Duration::from_millis(100))
            .execute();

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ProcessError::Timeout { .. }));
    }

    #[test]
    fn test_stderr_capture() {
        let output = SecureCommand::new("sh")
            .arg("-c")
            .arg("echo error >&2")
            .execute()
            .expect("sh should succeed");

        assert!(output.success());
        assert_eq!(output.stderr_trimmed(), "error");
    }

    #[test]
    fn test_url_policy() {
        let result = SecureCommand::new("echo")
            .arg_with_policy("https://example.com/path?query=value", ArgumentPolicy::Url);

        assert!(result.is_ok());
    }

    #[test]
    fn test_debug_output() {
        let cmd = SecureCommand::new("test")
            .arg("--flag")
            .env("SECRET", "value")
            .timeout(Duration::from_secs(30));

        let debug = format!("{:?}", cmd);
        assert!(debug.contains("test"));
        assert!(debug.contains("--flag"));
        // Env var keys shown but not values
        assert!(debug.contains("SECRET"));
    }

    #[test]
    fn test_allowlist_allows_command() {
        let allowlist = AllowList::new().allow("echo");
        let result = SecureCommand::new("echo").with_allowlist(&allowlist);

        assert!(result.is_ok());
    }

    #[test]
    fn test_allowlist_rejects_command() {
        let allowlist = AllowList::git_operations();
        let result = SecureCommand::new("rm").with_allowlist(&allowlist);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ProcessError::CommandNotAllowed { .. }));
    }

    #[test]
    fn test_allowlist_with_path() {
        let allowlist = AllowList::new().allow("echo");
        // Should extract basename
        let result = SecureCommand::new("/bin/echo").with_allowlist(&allowlist);

        assert!(result.is_ok());
    }

    #[test]
    fn test_allowlist_strict_nonexistent() {
        let allowlist = AllowList::new().allow("echo");
        // Non-existent path should still pass if basename is allowed
        let result = SecureCommand::new("/nonexistent/path/echo").with_allowlist_strict(&allowlist);

        assert!(result.is_ok());
    }

    #[test]
    fn test_allowlist_strict_rejects_not_in_list() {
        let allowlist = AllowList::git_operations();
        let result = SecureCommand::new("rm").with_allowlist_strict(&allowlist);

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ProcessError::CommandNotAllowed { .. }));
    }

    #[test]
    fn test_allowlist_execute() {
        let allowlist = AllowList::shell_safe();
        let output = SecureCommand::new("echo")
            .with_allowlist(&allowlist)
            .expect("echo should be in shell_safe")
            .arg("hello")
            .execute()
            .expect("echo should succeed");

        assert!(output.success());
        assert_eq!(output.stdout_trimmed(), "hello");
    }

    #[test]
    fn test_allowlist_preset_git() {
        let allowlist = AllowList::git_operations();
        assert!(SecureCommand::new("git").with_allowlist(&allowlist).is_ok());
        assert!(
            SecureCommand::new("docker")
                .with_allowlist(&allowlist)
                .is_err()
        );
    }

    #[test]
    fn test_allowlist_preset_docker() {
        let allowlist = AllowList::docker_operations();
        assert!(
            SecureCommand::new("docker")
                .with_allowlist(&allowlist)
                .is_ok()
        );
        assert!(
            SecureCommand::new("docker-compose")
                .with_allowlist(&allowlist)
                .is_ok()
        );
        assert!(
            SecureCommand::new("git")
                .with_allowlist(&allowlist)
                .is_err()
        );
    }
}
