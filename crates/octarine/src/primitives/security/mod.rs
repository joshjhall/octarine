// Allow dead code and unused imports - this module is being built incrementally
// and not all items are used yet. They will be used when public API layer consumes them.
#![allow(dead_code)]
#![allow(unused_imports)]

//! Security primitives for data validation and sanitization
//!
//! This module provides OWASP-compliant security detection, validation,
//! and sanitization for different data types.
//!
//! # Architecture
//!
//! This is **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns data only
//!
//! # Submodules
//!
//! | Module | Purpose | Examples |
//! |--------|---------|----------|
//! | [`paths`] | Path security | Traversal, injection, null bytes |
//! | [`network`] | Network security | SSRF, URL schemes, internal hosts |
//! | [`commands`] | Command security | Injection, allow-lists, escaping |
//!
//! # Security Coverage
//!
//! ## Path Security (CWE References)
//!
//! | Threat | CWE | Description |
//! |--------|-----|-------------|
//! | Traversal | CWE-22 | Directory traversal (`..`) |
//! | CommandInjection | CWE-78 | Shell command execution |
//! | NullByte | CWE-158 | String truncation (`\0`) |
//! | DoubleEncoding | CWE-175 | Bypass attacks (`%252e`) |
//!
//! ## Network Security (OWASP)
//!
//! | Check | OWASP | CWE | Notes |
//! |-------|-------|-----|-------|
//! | SSRF | A10:2021 | CWE-918 | Server-Side Request Forgery |
//! | Scheme validation | A10:2021 | CWE-918 | Dangerous protocol access |
//! | Internal access | A01:2021 | CWE-441 | Unintended proxy/intermediary |
//!
//! ## Command Security (CWE-78)
//!
//! | Threat | CWE | Description |
//! |--------|-----|-------------|
//! | CommandChain | CWE-78 | Semicolon chaining (`;`) |
//! | PipeChain | CWE-78 | Pipe chaining (`\|`) |
//! | CommandSubstitution | CWE-78 | Subshell execution (`$()`) |
//! | VariableExpansion | CWE-78 | Variable injection (`$VAR`) |
//! | GlobPattern | CWE-200 | Glob expansion (`*`) |
//!
//! # Usage
//!
//! ```ignore
//! use octarine::primitives::data::security::{paths, network};
//!
//! // Path security
//! let path_builder = paths::SecurityBuilder::new();
//! if path_builder.is_threat_present(user_path) {
//!     // Handle threat
//! }
//!
//! // Network security
//! let net_builder = network::NetworkSecurityBuilder::new();
//! if net_builder.is_potential_ssrf(url) {
//!     // Block request
//! }
//! ```

pub(crate) mod commands;
#[cfg(feature = "crypto-validation")]
pub(crate) mod crypto;
#[cfg(feature = "formats")]
pub(crate) mod formats;
pub(crate) mod network;
pub(crate) mod paths;
#[cfg(feature = "database")]
pub(crate) mod queries;

// Re-export builders for crate-internal convenience
#[cfg(feature = "crypto-validation")]
pub(crate) use crypto::CryptoSecurityBuilder;
#[cfg(feature = "formats")]
pub(crate) use formats::FormatSecurityBuilder;
pub(crate) use network::NetworkSecurityBuilder;
pub(crate) use paths::SecurityBuilder as PathSecurityBuilder;
#[cfg(feature = "database")]
pub(crate) use queries::QuerySecurityBuilder;
