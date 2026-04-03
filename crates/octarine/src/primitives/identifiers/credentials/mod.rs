//! Credential identifier primitives (Something You KNOW - NIST Factor 1)
//!
//! Pure detection and sanitization for knowledge-based authentication secrets.
//! No observe dependencies - used by Layer 2 and Layer 3 modules.
//!
//! # Supported Credentials
//!
//! - **Passwords**: Text-based secrets in various formats (key=value, JSON, YAML)
//! - **PINs**: Numeric secrets (4-8 digits typically)
//! - **Security Questions/Answers**: Challenge-response secrets
//! - **Passphrases**: Longer password-like secrets
//!
//! # Key Difference from Other Identifiers
//!
//! Unlike SSNs, emails, or credit cards, credentials are **opaque arbitrary strings**.
//! You cannot validate that "hunter2" is a valid password - any string could be one.
//!
//! Detection is therefore **context-based**, not pattern-based:
//! - `password: secret123` - detected by "password:" label
//! - `"pin": "1234"` - detected by JSON key name
//! - Direct redaction when caller knows the value is a credential
//!
//! # Security Considerations
//!
//! Credential identifiers are **CRITICAL security primitives**:
//! - **NIST 800-63B**: Knowledge-based authenticators (memorized secrets)
//! - **OWASP A07:2021**: Identification and Authentication Failures
//! - **PCI DSS 8.2**: Password/passphrase requirements
//! - **SOC2 CC6.1**: Logical access security
//! - **HIPAA §164.312(d)**: Person or entity authentication
//!
//! # Architecture
//!
//! This is **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns data only
//!
//! # Usage
//!
//! ## Primary API: Builder Pattern
//!
//! The `CredentialIdentifierBuilder` is the **primary interface**:
//!
//! ```ignore
//! use octarine::primitives::identifiers::credentials::{
//!     CredentialIdentifierBuilder, TextRedactionPolicy
//! };
//!
//! let builder = CredentialIdentifierBuilder::new();
//!
//! // Direct redaction (caller knows it's a password)
//! let safe = builder.redact_password("hunter2");
//! // Result: "[PASSWORD]"
//!
//! // Context-based detection and redaction in text
//! let text = "password: secret123";
//! let safe = builder.redact_passwords_in_text(text);
//! // Result: "password: [PASSWORD]"
//!
//! // JSON payload redaction
//! let json = r#"{"username": "alice", "password": "secret", "pin": "1234"}"#;
//! let safe = builder.redact_credentials_in_text(json);
//! // Result: r#"{"username": "alice", "password": "[PASSWORD]", "pin": "[PIN]"}"#
//! ```
//!
//! ## Detection vs Direct Redaction
//!
//! Since credentials are opaque, there are two usage patterns:
//!
//! 1. **Direct redaction**: Caller knows the value is a credential
//!    ```ignore
//!    let password = get_user_password();
//!    let safe = builder.redact_password(&password);
//!    ```
//!
//! 2. **Context-based detection**: Scan text for credential patterns
//!    ```ignore
//!    let log_line = "User login: password=secret123";
//!    let safe = builder.redact_passwords_in_text(&log_line);
//!    ```
//!
//! ## Compliance Coverage
//!
//! | Credential | NIST 800-63B | PCI DSS | SOC2 | HIPAA |
//! |------------|--------------|---------|------|-------|
//! | Password | Memorized Secret | 8.2.3 | CC6.1 | §164.312(d) |
//! | PIN | Memorized Secret | 8.2.3 | CC6.1 | §164.312(d) |
//! | Security Answer | Memorized Secret | N/A | CC6.1 | §164.312(d) |
//! | Passphrase | Memorized Secret | 8.2.3 | CC6.1 | §164.312(d) |
//!
//! # Performance Characteristics
//!
//! ## Computational Complexity
//!
//! | Operation | Time | Space | Notes |
//! |-----------|------|-------|-------|
//! | `is_credentials_present` | O(n) | O(1) | Quick keyword check + regex |
//! | `is_passwords_present` | O(n) | O(1) | Quick keyword check + regex |
//! | `is_pins_present` | O(n) | O(1) | Quick keyword check + regex |
//! | `detect_passwords` | O(n) | O(m) | n = text length, m = matches |
//! | `detect_pins` | O(n) | O(m) | n = text length, m = matches |
//! | `detect_credentials` | O(n) | O(m) | n = text length, m = matches |
//! | `redact_password` | O(1) | O(1) | Constant time replacement |
//! | `redact_pin` | O(1) | O(1) | Constant time replacement |
//! | `redact_passwords_in_text` | O(n) | O(n) | Detection + replacement |
//!
//! ## Memory Usage
//!
//! - **Regex patterns**: ~5KB lazily initialized (shared across calls)
//! - **Per-call overhead**: Minimal, typically < 1KB for single credentials
//! - **Text scanning**: Linear with text size plus detected matches
//! - **No caching**: Credentials are too sensitive to cache
//!
//! ## Recommendations
//!
//! - Use `Complete` or `Anonymous` policies in production (never `Partial`)
//! - Prefer direct redaction when caller knows the credential type
//! - Use `Cow<str>` returns to avoid allocation when no matches found
//! - For large documents (>1MB), process in chunks to limit memory

pub mod builder;
pub mod redaction;

// Internal modules - not directly accessible outside credentials/
mod detection;
mod sanitization;
mod validation;

// Re-export builder for convenient access
pub use builder::CredentialIdentifierBuilder;

// Export redaction strategies for type-safe redaction API
pub use redaction::{
    CredentialRedactionStrategy, PassphraseRedactionStrategy, PasswordRedactionStrategy,
    PinRedactionStrategy, SecurityAnswerRedactionStrategy, TextRedactionPolicy,
};

// Export types from shared types module
pub use super::types::{CredentialMatch, CredentialType};
