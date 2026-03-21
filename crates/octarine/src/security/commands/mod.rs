// Allow unused imports: This module exports public API that may not be used within the crate
#![allow(unused_imports)]

//! OS Command security operations with built-in observability
//!
//! This module provides command argument detection, validation, and sanitization
//! with observe instrumentation for compliance-grade audit trails.
//!
//! # Architecture
//!
//! This is **Layer 3 (security)** - wraps primitives with observe instrumentation:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │           runtime/process/SecureCommand (Execution)         │
//! │  - Full command execution with observability                │
//! │  - Timeout, environment sanitization, audit trails          │
//! ├─────────────────────────────────────────────────────────────┤
//! │              security/commands (Detection/Validation)       │
//! │  - CommandSecurityBuilder                                   │
//! │  - Threat detection with logging                            │
//! │  - Argument validation with audit trails                    │
//! │  - Shell escaping for safe string building                  │
//! ├─────────────────────────────────────────────────────────────┤
//! │              primitives/security/commands (Internal)        │
//! │  - Pure detection, validation, sanitization functions       │
//! │  - No logging, no side effects                              │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # When to Use What
//!
//! | Task | Module | Example |
//! |------|--------|---------|
//! | Execute commands securely | `runtime::process` | `SecureCommand::new("git")` |
//! | Check if string is dangerous | `security::commands` | `is_dangerous_arg(input)` |
//! | Escape for shell string | `security::commands` | `escape_shell_arg(input)` |
//! | Validate safely | `security::commands` | `validate_safe_arg(input)?` |
//! | Restrict to allowed commands | `runtime::process` | `cmd.with_allowlist(&list)?` |
//!
//! # Features
//!
//! - **Threat Detection**: Detect command injection patterns (CWE-78)
//! - **Argument Validation**: Validate arguments are safe to use
//! - **Shell Escaping**: Platform-aware argument escaping
//! - **Environment Validation**: Validate env var names and values
//! - **Audit Logging**: All detections logged for compliance
//!
//! # Examples
//!
//! ## Threat Detection
//!
//! ```ignore
//! use octarine::security::commands::is_dangerous_arg;
//!
//! if is_dangerous_arg(user_input) {
//!     // Block dangerous input - already logged
//! }
//! # let user_input = "safe";
//! ```
//!
//! ## Builder Pattern
//!
//! ```ignore
//! use octarine::security::commands::CommandSecurityBuilder;
//!
//! let security = CommandSecurityBuilder::new();
//!
//! // Detection
//! if security.is_dangerous(user_input) {
//!     // Handle threat
//! }
//!
//! // Validation
//! security.validate_safe("safe-arg")?;
//!
//! // Sanitization
//! let escaped = security.escape_shell_arg("user's input")?;
//! # let user_input = "safe";
//! ```
//!
//! ## Shell Escaping
//!
//! ```ignore
//! use octarine::security::commands::escape_shell_arg;
//!
//! // Platform-aware escaping
//! let safe = escape_shell_arg(user_input)?;
//! // Unix: 'user'\\''s input'
//! // Windows: "user's input"
//! # let user_input = "safe";
//! ```
//!
//! ## Command Execution
//!
//! For command execution, use `runtime::process::SecureCommand`:
//!
//! ```ignore
//! use octarine::runtime::process::SecureCommand;
//!
//! let output = SecureCommand::new("git")
//!     .arg("status")
//!     .execute()?;
//! ```
//!
//! ## Command Allow-Lists
//!
//! Restrict which commands can be executed:
//!
//! ```ignore
//! use octarine::runtime::process::{SecureCommand, AllowList};
//!
//! // Only allow git commands
//! let allowlist = AllowList::git_operations();
//!
//! // This succeeds - git is allowed
//! SecureCommand::new("git")
//!     .with_allowlist(&allowlist)?
//!     .arg("status")
//!     .execute()?;
//!
//! // This fails - rm is not in the allow-list
//! SecureCommand::new("rm")
//!     .with_allowlist(&allowlist)?  // Returns CommandNotAllowed error
//!     .arg("-rf")
//!     .execute()?;
//! ```
//!
//! For symlink-aware checking (prevents `/tmp/git -> /bin/rm` attacks):
//!
//! ```ignore
//! use octarine::runtime::process::{SecureCommand, AllowList};
//!
//! let allowlist = AllowList::git_operations();
//!
//! // Resolves symlinks before checking
//! SecureCommand::new("/usr/local/bin/git")
//!     .with_allowlist_strict(&allowlist)?
//!     .arg("status")
//!     .execute()?;
//! ```

mod builder;
mod shortcuts;
mod types;

// Re-export the builder
pub use builder::CommandSecurityBuilder;

// Re-export types - canonical location for command security types
pub use types::{AllowList, AllowListMode, CommandThreat};

// Re-export shortcuts at module level
pub use shortcuts::*;
