//! CLI Testing Utilities
//!
//! Provides utilities for testing command-line applications using
//! assert_cmd for command execution and rexpect for interactive sessions.
//!
//! ## Command Testing
//!
//! Test non-interactive CLI commands:
//!
//! ```rust,ignore
//! use octarine::testing::cli::*;
//!
//! #[test]
//! fn test_help_command() {
//!     cargo_bin("my-app")
//!         .arg("--help")
//!         .assert()
//!         .success()
//!         .stdout(contains("Usage:"));
//! }
//! ```
//!
//! ## Interactive Testing
//!
//! Test interactive CLI sessions:
//!
//! ```rust,ignore
//! use octarine::testing::cli::*;
//!
//! #[test]
//! fn test_interactive_prompt() {
//!     let mut session = spawn_interactive("my-app", &["--interactive"]).unwrap();
//!     session.expect("Enter name:").unwrap();
//!     session.send_line("Alice").unwrap();
//!     session.expect("Hello, Alice!").unwrap();
//! }
//! ```

mod interactive;
mod runner;

pub use interactive::*;
pub use runner::*;
