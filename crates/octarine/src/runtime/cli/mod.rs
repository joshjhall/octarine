//! CLI framework integration with observability
//!
//! Provides a wrapper around clap with integrated logging, consistent error
//! handling, progress indicators, and interactive prompts.
//!
//! # Features
//!
//! - **Command Logging**: Automatic logging of command execution via observe
//! - **Error Handling**: Consistent error formatting with proper exit codes
//! - **Progress Indicators**: Spinners and progress bars for long operations
//! - **Interactive Prompts**: User input with validation
//!
//! # Example
//!
//! ```ignore
//! use octarine::runtime::cli::{CliApp, ExitCode};
//!
//! fn main() -> ExitCode {
//!     CliApp::new("myapp", "My application")
//!         .version(env!("CARGO_PKG_VERSION"))
//!         .run(|ctx| {
//!             ctx.info("Starting operation...");
//!             // ... do work ...
//!             Ok(())
//!         })
//! }
//! ```
//!
//! # Exit Codes
//!
//! The module follows standard Unix exit code conventions:
//! - 0: Success
//! - 1: General error
//! - 2: Usage/argument error
//! - 64-78: BSD sysexits.h conventions

mod app;
mod context;
mod error;
mod exit;
mod output;
mod progress;
mod prompt;

pub use app::{CliApp, handle_error, run_cli};
pub use context::CliContext;
pub use error::{CliError, CliResult};
pub use exit::ExitCode;
pub use output::{OutputFormat, OutputStyle, StyledOutput};
pub use progress::{ProgressBar, ProgressStyle, Spinner};
pub use prompt::{Confirm, Input, Password, Select};
