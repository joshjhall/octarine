//! Secure command execution with observability
//!
//! Provides secure wrappers for subprocess execution with:
//! - Input validation to prevent command injection
//! - Timeout enforcement
//! - Environment sanitization
//! - Audit trails via observe
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    process/ (Public API)                    │
//! │  - SecureCommand, CommandOutput                             │
//! │  - Argument validation, timeout, audit trails               │
//! ├─────────────────────────────────────────────────────────────┤
//! │                    std::process (Internal)                  │
//! │  - Command, Output, ExitStatus                              │
//! ├─────────────────────────────────────────────────────────────┤
//! │                crypto/secrets (Internal)                    │
//! │  - SecureEnvBuilder for environment sanitization            │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Security Model
//!
//! ## Input Validation
//!
//! All arguments are validated against command injection patterns:
//! - Shell metacharacters (`;`, `|`, `&`, etc.)
//! - Command substitution (`$()`, backticks)
//! - Variable expansion (`$VAR`, `${VAR}`)
//!
//! ## Command Allow-Lists
//!
//! Restrict which commands can be executed using [`AllowList`]:
//! - `with_allowlist()` - Check command against an allow-list
//! - `with_allowlist_strict()` - Also resolves symlinks to prevent bypass attacks
//!
//! ## Environment Sanitization
//!
//! By default, the subprocess environment is sanitized:
//! - Only safe variables inherited (PATH, HOME, etc.)
//! - Dangerous variables blocked (credentials, LD_PRELOAD, etc.)
//! - Secrets can be explicitly added with audit logging
//!
//! ## Audit Trails
//!
//! All command executions are logged via observe:
//! - Command and arguments (sanitized)
//! - Exit status
//! - Execution duration
//! - Timeout events
//!
//! # Example
//!
//! ```ignore
//! use octarine::runtime::process::SecureCommand;
//! use std::time::Duration;
//!
//! let output = SecureCommand::new("git")
//!     .arg("clone")
//!     .arg_validated("https://github.com/user/repo.git")?
//!     .current_dir("/tmp")
//!     .timeout(Duration::from_secs(60))
//!     .execute()?;
//!
//! if output.success() {
//!     println!("Clone successful");
//! }
//! ```
//!
//! # OWASP Compliance
//!
//! This module implements OWASP recommendations for:
//! - OS Command Injection Prevention (CWE-78)
//! - Input validation and sanitization
//! - Principle of least privilege (environment sanitization)

mod command;
mod error;
mod output;
mod validation;

pub use command::SecureCommand;
pub use error::ProcessError;
pub use output::CommandOutput;
pub use validation::{ArgumentPolicy, ValidatedArg};

// Re-export AllowList for convenience
pub use crate::primitives::security::commands::types::{AllowList, AllowListMode};
