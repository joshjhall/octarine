//! Command output types
//!
//! Types for capturing and inspecting command execution results.

use std::process::ExitStatus;
use std::time::Duration;

/// Output from a secure command execution
///
/// Contains the exit status, stdout, stderr, and execution metadata.
///
/// # Example
///
/// ```ignore
/// let output = SecureCommand::new("ls")
///     .arg("-la")
///     .execute()?;
///
/// if output.success() {
///     println!("Files:\n{}", output.stdout_string());
/// } else {
///     eprintln!("Error: {}", output.stderr_string());
/// }
/// ```
#[derive(Debug, Clone)]
pub struct CommandOutput {
    /// The exit status of the command
    status: ExitStatus,
    /// Standard output (stdout)
    stdout: Vec<u8>,
    /// Standard error (stderr)
    stderr: Vec<u8>,
    /// How long the command took to execute
    duration: Duration,
    /// The command that was executed (for debugging)
    command: String,
}

impl CommandOutput {
    /// Create a new CommandOutput
    pub(crate) fn new(
        status: ExitStatus,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        duration: Duration,
        command: String,
    ) -> Self {
        Self {
            status,
            stdout,
            stderr,
            duration,
            command,
        }
    }

    /// Check if the command exited successfully (exit code 0)
    #[must_use]
    pub fn success(&self) -> bool {
        self.status.success()
    }

    /// Get the exit code, if available
    ///
    /// On Unix, this returns `None` if the process was terminated by a signal.
    #[must_use]
    pub fn code(&self) -> Option<i32> {
        self.status.code()
    }

    /// Get the exit status
    #[must_use]
    pub fn status(&self) -> ExitStatus {
        self.status
    }

    /// Get stdout as bytes
    #[must_use]
    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    /// Get stderr as bytes
    #[must_use]
    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    /// Get stdout as a UTF-8 string
    ///
    /// Invalid UTF-8 sequences are replaced with the replacement character.
    #[must_use]
    pub fn stdout_string(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// Get stderr as a UTF-8 string
    ///
    /// Invalid UTF-8 sequences are replaced with the replacement character.
    #[must_use]
    pub fn stderr_string(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    /// Get stdout as a trimmed UTF-8 string
    ///
    /// Removes leading and trailing whitespace.
    #[must_use]
    pub fn stdout_trimmed(&self) -> String {
        self.stdout_string().trim().to_string()
    }

    /// Get stderr as a trimmed UTF-8 string
    ///
    /// Removes leading and trailing whitespace.
    #[must_use]
    pub fn stderr_trimmed(&self) -> String {
        self.stderr_string().trim().to_string()
    }

    /// Get stdout lines as a vector of strings
    #[must_use]
    pub fn stdout_lines(&self) -> Vec<String> {
        self.stdout_string().lines().map(String::from).collect()
    }

    /// Get stderr lines as a vector of strings
    #[must_use]
    pub fn stderr_lines(&self) -> Vec<String> {
        self.stderr_string().lines().map(String::from).collect()
    }

    /// Get the execution duration
    #[must_use]
    pub fn duration(&self) -> Duration {
        self.duration
    }

    /// Get the command that was executed
    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }

    /// Check if stdout is empty
    #[must_use]
    pub fn stdout_is_empty(&self) -> bool {
        self.stdout.is_empty()
    }

    /// Check if stderr is empty
    #[must_use]
    pub fn stderr_is_empty(&self) -> bool {
        self.stderr.is_empty()
    }

    /// Check if stdout contains a substring
    ///
    /// Returns `true` if the given text appears anywhere in stdout.
    #[must_use]
    pub fn is_in_stdout(&self, s: &str) -> bool {
        self.stdout_string().contains(s)
    }

    /// Check if stderr contains a substring
    ///
    /// Returns `true` if the given text appears anywhere in stderr.
    #[must_use]
    pub fn is_in_stderr(&self, s: &str) -> bool {
        self.stderr_string().contains(s)
    }
}

#[cfg(test)]
#[cfg(any(unix, windows))]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[cfg(unix)]
    fn mock_status(code: i32) -> ExitStatus {
        use std::os::unix::process::ExitStatusExt;
        // Unix encodes the exit code in the high byte of the wait-status word
        ExitStatus::from_raw(code << 8)
    }

    #[cfg(windows)]
    fn mock_status(code: i32) -> ExitStatus {
        use std::os::windows::process::ExitStatusExt;
        #[allow(clippy::cast_sign_loss)] // Test-only helper: negative codes are not used
        ExitStatus::from_raw(code as u32)
    }

    #[test]
    fn test_success() {
        let output = CommandOutput::new(
            mock_status(0),
            b"output".to_vec(),
            vec![],
            Duration::from_millis(100),
            "test".to_string(),
        );
        assert!(output.success());
        assert_eq!(output.code(), Some(0));
    }

    #[test]
    fn test_failure() {
        let output = CommandOutput::new(
            mock_status(1),
            vec![],
            b"error".to_vec(),
            Duration::from_millis(50),
            "test".to_string(),
        );
        assert!(!output.success());
        assert_eq!(output.code(), Some(1));
    }

    #[test]
    fn test_stdout_string() {
        let output = CommandOutput::new(
            mock_status(0),
            b"hello world\n".to_vec(),
            vec![],
            Duration::from_millis(10),
            "echo".to_string(),
        );
        assert_eq!(output.stdout_string(), "hello world\n");
        assert_eq!(output.stdout_trimmed(), "hello world");
    }

    #[test]
    fn test_stdout_lines() {
        let output = CommandOutput::new(
            mock_status(0),
            b"line1\nline2\nline3".to_vec(),
            vec![],
            Duration::from_millis(10),
            "test".to_string(),
        );
        let lines = output.stdout_lines();
        assert_eq!(lines, vec!["line1", "line2", "line3"]);
    }

    #[test]
    fn test_is_in_stdout_stderr() {
        let output = CommandOutput::new(
            mock_status(0),
            b"success: operation completed".to_vec(),
            b"warning: deprecated".to_vec(),
            Duration::from_millis(10),
            "test".to_string(),
        );
        assert!(output.is_in_stdout("success"));
        assert!(output.is_in_stderr("warning"));
        assert!(!output.is_in_stdout("error"));
    }

    #[test]
    fn test_duration() {
        let output = CommandOutput::new(
            mock_status(0),
            vec![],
            vec![],
            Duration::from_secs(5),
            "slow".to_string(),
        );
        assert_eq!(output.duration(), Duration::from_secs(5));
    }

    #[test]
    fn test_invalid_utf8() {
        let output = CommandOutput::new(
            mock_status(0),
            vec![0xFF, 0xFE, b'h', b'i'],
            vec![],
            Duration::from_millis(10),
            "test".to_string(),
        );
        // Should not panic, invalid bytes replaced
        let s = output.stdout_string();
        assert!(s.contains("hi"));
    }
}
