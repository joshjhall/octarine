//! Observable shell execution with xshell
//!
//! Wraps xshell with full octarine integration:
//! - Input validation via security/commands primitives
//! - Output redaction via observe/pii
//! - Metrics via observe/metrics
//!
//! # Example
//!
//! ```ignore
//! use octarine::runtime::shell::ObservableShell;
//!
//! let shell = ObservableShell::new()?;
//! let output = shell.cmd("git").args(["status", "--short"]).read()?;
//! ```

mod command;
mod context;

pub use command::ObservableCmd;
pub use context::ObservableShell;

use crate::observe::Problem;

/// Convert xshell error to Problem
pub(crate) fn xshell_error(err: xshell::Error) -> Problem {
    Problem::operation_failed(format!("shell command failed: {err}"))
}
