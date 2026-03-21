//! Octarine - Foundation library for security and observability
//!
//! Provides battle-tested security primitives and observability tools
//! for Rust applications.
//!
//! # Quick Start
//!
//! ```rust
//! use octarine::{Problem, Result, info, warn};
//! use octarine::data::paths::{validate_path, is_path_traversal_present};
//! use octarine::identifiers::{is_pii_present, redact_pii};
//!
//! // Logging with automatic context capture
//! info("startup", "Application initialized");
//!
//! // Path security
//! if is_path_traversal_present("../etc/passwd") {
//!     warn("security", "Path traversal attempt detected");
//! }
//!
//! // PII protection
//! if is_pii_present("Contact: user@example.com") {
//!     let safe = redact_pii("Contact: user@example.com");
//! }
//! ```
//!
//! # Modules
//!
//! | Module | Purpose |
//! |--------|---------|
//! | [`observe`] | Logging, events, metrics, writers, tracing, compliance |
//! | [`data`] | Path/URL normalization, text formatting |
//! | [`security`] | SSRF protection, path traversal detection |
//! | [`identifiers`] | PII detection, redaction, identifier validation |
//! | [`runtime`] | Async primitives, channels, circuit breakers, shutdown |
//! | [`io`] | Secure file operations, magic bytes, temp files |
//! | [`crypto`] | Secret management (SecureMap, SecureEnvBuilder) |
//! | [`auth`] | Authentication with OWASP ASVS (feature: `auth`) |
//!
//! # Architecture
//!
//! Octarine uses a three-layer architecture:
//!
//! - **Layer 1 (primitives)**: Pure functions, no logging or side effects
//! - **Layer 2 (observe)**: Observability system, uses primitives only
//! - **Layer 3 (paths, identifiers, etc.)**: Full features with observe instrumentation

// ============================================================================
// Internal modules (not part of public API)
// ============================================================================

/// Layer 1: Foundation utilities (internal)
pub(crate) mod primitives;

/// Data formatting, normalization, and canonicalization (Layer 3)
///
/// This module handles FORMAT concerns - how data should be structured:
/// - `data::paths` - Path normalization and formatting
/// - `data::network` - URL normalization
/// - `data::text` - Text normalization
///
/// For THREATS (danger detection), see [`security`].
/// For CLASSIFICATION (what is it?), see [`identifiers`].
pub mod data;

/// Security threat detection and mitigation (Layer 3)
///
/// This module handles THREATS concerns - is this dangerous?:
/// - `security::paths` - Path traversal, command injection detection
/// - `security::network` - SSRF detection, internal host detection
///
/// For FORMAT (normalization), see [`data`].
/// For CLASSIFICATION (what is it?), see [`identifiers`].
pub mod security;

// ============================================================================
// Public namespaces
// ============================================================================

/// Logging, events, metrics, writers, tracing, and compliance
///
/// The observe module provides compliance-grade observability suitable for
/// SOC2, HIPAA, GDPR, and PCI-DSS requirements.
///
/// # Quick Start
///
/// ```rust
/// use octarine::observe::{info, warn, Problem, Result};
///
/// fn process(input: &str) -> Result<()> {
///     if input.is_empty() {
///         return Err(Problem::validation("input cannot be empty"));
///     }
///     info("process", "Processing input");
///     Ok(())
/// }
/// ```
pub mod observe;

/// Async operations, channels, circuit breakers, and shutdown coordination
///
/// # Quick Start
///
/// ```rust
/// use octarine::runtime::r#async::{retry, RetryPolicy, Channel};
/// ```
pub mod runtime;

/// Secure file I/O operations with audit trails
///
/// # Quick Start
///
/// ```rust,ignore
/// use octarine::io::{SecureTempFile, write_atomic, WriteOptions};
///
/// // Atomic file write
/// write_atomic("config.json", b"{}", WriteOptions::default()).await?;
///
/// // Secure temp file
/// let temp = SecureTempFile::new()?;
/// ```
pub mod io;

/// Secret management with secure memory handling
///
/// # Quick Start
///
/// ```rust,ignore
/// use octarine::crypto::{SecureMap, SecureEnvBuilder};
///
/// let mut secrets = SecureMap::new();
/// secrets.insert("API_KEY", "sk-secret");
/// ```
pub mod crypto;

// ============================================================================
// Identifier classification (promoted to root level)
// ============================================================================

/// PII detection, redaction, and identifier classification (Layer 3)
///
/// This module handles CLASSIFICATION concerns - what is it?:
/// - PII detection across 14+ domains (personal, financial, medical, etc.)
/// - Identifier validation (email, phone, SSN, credit cards, etc.)
/// - Automatic redaction for compliance
///
/// For FORMAT (normalization), see [`data`].
/// For THREATS (danger detection), see [`security`].
///
/// # Quick Start
///
/// ```rust
/// use octarine::identifiers::{is_pii_present, redact_pii, validate_email};
///
/// // Check for PII
/// if is_pii_present("Contact: user@example.com") {
///     let safe = redact_pii("Contact: user@example.com");
/// }
///
/// // Validate specific types
/// validate_email("user@example.com").unwrap();
/// ```
pub mod identifiers;

// ============================================================================
// Prelude - common imports for consuming applications
// ============================================================================

/// Common imports for consuming applications
///
/// Provides the three unified facades and commonly used types:
///
/// ```rust
/// use octarine::prelude::*;
///
/// let security = Security::new();
/// let data = Data::new();
/// let identifiers = Identifiers::new();
/// ```
pub mod prelude;

// ============================================================================
// Root-level exports (daily drivers)
// ============================================================================

// Core types
pub use observe::{Problem, Result};

// Logging shortcuts
pub use observe::{auth_success, success, validation_success};
pub use observe::{debug, error, info, trace, warn};

// Error handling shortcuts (return Problem)
pub use observe::{fail, fail_permission, fail_security, fail_validation, todo};

// ============================================================================
// Feature-gated modules
// ============================================================================

/// HTTP server middleware for Axum (feature-gated)
///
/// Provides Tower middleware and Axum extractors that integrate with
/// Octarine's observability and context management.
/// Enable with `features = ["http"]`.
///
/// # Quick Start
///
/// ```rust
/// use axum::{Router, routing::get};
/// use octarine::http::{RequestIdLayer, ContextLayer};
///
/// fn api_routes() -> Router {
///     Router::new().route("/api", get(|| async { "ok" }))
/// }
///
/// let app: Router = Router::new()
///     .merge(api_routes())
///     .layer(RequestIdLayer::new())
///     .layer(ContextLayer::new());
/// ```
#[cfg(feature = "http")]
pub mod http;

/// Authentication with OWASP ASVS compliance (feature-gated)
///
/// Provides comprehensive authentication functionality following OWASP
/// Application Security Verification Standard (ASVS) V2 and V3 controls.
/// Enable with `features = ["auth"]`.
///
/// # Features
///
/// - Password policy validation with zxcvbn strength checking
/// - Session management with binding and timeouts (coming soon)
/// - Account lockout with exponential backoff (coming soon)
/// - CSRF protection (coming soon)
/// - TOTP/MFA support (`auth-totp` feature, coming soon)
/// - HIBP breach checking (`auth-hibp` feature, coming soon)
///
/// # Quick Start
///
/// ```ignore
/// use octarine::auth::{PasswordPolicy, validate_password, estimate_strength};
///
/// let policy = PasswordPolicy::default();
/// validate_password("MySecure#Pass123!", &policy, Some("user@example.com"))?;
///
/// let strength = estimate_strength("MySecure#Pass123!");
/// assert!(strength.is_acceptable());
/// ```
#[cfg(feature = "auth")]
pub mod auth;

/// Testing infrastructure (feature-gated)
///
/// Provides test fixtures, generators, and assertions for security testing.
/// Enable with `features = ["testing"]`.
#[cfg(feature = "testing")]
pub mod testing;

// ============================================================================
// Derive macros
// ============================================================================

/// Configuration derive macro (feature-gated)
///
/// Provides `#[derive(Config)]` for generating type-safe configuration loading.
/// Enable with `features = ["derive"]` (included in default features).
///
/// # Quick Start
///
/// ```ignore
/// use octarine::Config;
///
/// #[derive(Config)]
/// #[config(prefix = "APP")]
/// struct AppConfig {
///     #[config(default = "8080")]
///     port: u16,
///
///     #[config(secret)]
///     database_url: String,
/// }
///
/// let config = AppConfig::load()?;
/// ```
#[cfg(feature = "derive")]
pub use octarine_derive::Config;
