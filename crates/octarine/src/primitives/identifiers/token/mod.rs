//! Token identifier primitives
//!
//! Pure detection, validation, and sanitization for authentication and authorization tokens.
//! No observe dependencies - used by Layer 2 and Layer 3 modules.
//!
//! # Supported Tokens
//!
//! - **JWT**: JSON Web Tokens with algorithm validation
//! - **API Keys**: Generic and provider-specific (AWS, Azure, GCP, GitHub, GitLab, Stripe)
//! - **SSH Keys**: Public keys and fingerprints (MD5, SHA256 formats)
//! - **Session IDs**: Session identifiers with entropy validation
//!
//! # Security Considerations
//!
//! Token identifiers are **CRITICAL security primitives**:
//! - **PCI DSS 3.2.1 Requirement 3.4**: API keys and tokens require secure storage and redaction in logs
//! - **OWASP A01:2021**: Broken Access Control - Session hijacking via exposed session IDs
//! - **OWASP A02:2021**: Cryptographic Failures - Weak tokens and predictable session IDs
//! - **OWASP A07:2021**: Identification and Authentication Failures
//! - **SOC2 Trust Services Criteria CC7.2**: Token sanitization in logs
//! - **HIPAA §164.308(a)(1)(ii)(D)**: Session ID redaction in healthcare logs
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
//! The `TokenIdentifierBuilder` is the **primary interface** for all token operations:
//!
//! ```ignore
//! use octarine::primitives::identifiers::token::{
//!     TokenIdentifierBuilder, TextRedactionPolicy, JwtRedactionStrategy
//! };
//!
//! let builder = TokenIdentifierBuilder::new();
//!
//! // Detection
//! if builder.is_jwt("eyJhbGc...") {
//!     println!("Found JWT");
//! }
//!
//! // Validation
//! if builder.validate_jwt_algorithm("eyJhbGc...", false) {
//!     println!("Valid JWT algorithm");
//! }
//!
//! // Sanitization - default strategies
//! let jwt_safe = builder.redact_jwt("eyJhbGc...");  // Shows algorithm
//! let key_safe = builder.redact_api_key("sk_live_...");  // Shows prefix
//!
//! // Sanitization - custom strategies
//! let jwt_token = builder.redact_jwt_with_strategy("eyJhbGc...", JwtRedactionStrategy::Token);
//! let key_anon = builder.redact_api_key_with_strategy("sk_live_...", ApiKeyRedactionStrategy::Anonymous);
//!
//! // Text scanning
//! let text = "My API key is sk_live_abc123def456";
//! let safe = builder.redact_api_keys_in_text(text);  // Complete by default
//! let partial = builder.redact_api_keys_in_text_with_policy(text, TextRedactionPolicy::Partial);
//! ```
//!
//! ## Shortcut Functions (Internal Use)
//!
//! **For internal use only** (observe module). Convenience functions with sensible defaults:
//!
//! ```ignore
//! use octarine::primitives::identifiers::token::{mask_jwt, mask_api_key, mask_session_id};
//!
//! // Simple masking - no strategy required
//! let jwt_masked = mask_jwt("eyJhbGc...");      // "<JWT-RS256>"
//! let key_masked = mask_api_key("sk_live_...");  // "sk_live_****"
//! let session_masked = mask_session_id("sess_..."); // "sess_****"
//! ```
//!
//! ## Architecture Notes
//!
//! This module follows the **cascading visibility pattern**:
//!
//! 1. **Primitive layer (this module)**: Pure functions, no logging, internal use
//!    - Complete builder API with all detection/validation/sanitization methods
//!    - Shortcut functions for common defaults (used by observe module)
//!    - Strategy enums exported (needed for builder parameters)
//!
//! 2. **Observe layer**: Uses primitive shortcuts for consistent redaction
//!    - Calls `mask_*` functions for logging/events
//!    - No direct access to detection/validation (uses builder)
//!
//! 3. **Security layer (public API)**: Wraps primitive builder + adds logging/metrics
//!    - SecurityTokenBuilder wraps TokenIdentifierBuilder
//!    - Public shortcuts built with SecurityTokenBuilder (inherit logging/metrics)
//!    - External users should use security layer, NOT primitives directly
//!
//! ## Compliance Coverage
//!
//! Token identifiers have varying regulatory requirements:
//!
//! | Identifier | PCI DSS | SOC2 | HIPAA | OWASP | Notes |
//! |------------|---------|------|-------|-------|-------|
//! | JWT | Level 1 Data if contains PII | CC7.2 | §164.308 if healthcare | A01:2021 | Contains user claims and signatures |
//! | API Key | Level 1 Data (Requirement 3.4) | CC7.2 | §164.308 | A02:2021 | Unauthorized access risk |
//! | Session ID | Level 1 Data (Requirement 8.2.4) | CC7.2 | §164.312(d) | A01:2021 | Session hijacking risk |
//! | SSH Key | Infrastructure access | CC6.7 | §164.312(a)(2)(iv) | Critical | Server access compromise |
//! | SSH Fingerprint | Audit trail | CC7.2 | §164.312(b) | Informational | Key verification |
//!
//! ## Performance Characteristics
//!
//! ### Computational Complexity
//!
//! | Operation | Time | Space | Notes |
//! |-----------|------|-------|-------|
//! | `is_jwt` | O(n) | O(1) | Regex match with length check (max 1000 chars) |
//! | `is_api_key` | O(n) | O(1) | Multiple provider patterns checked |
//! | `is_ssh_public_key` | O(n) | O(1) | Regex match, supports multiple key types |
//! | `is_likely_session_id` | O(n) | O(m) | Heuristic check with entropy analysis, m = unique chars |
//! | `validate_jwt` | O(n) | O(1) | Uses detection layer + 3-part structure check |
//! | `validate_jwt_algorithm` | O(n) | O(n) | Includes base64 decode + JSON parse |
//! | `validate_api_key` | O(n) | O(1) | Length, character set, and pattern checks |
//! | `detect_jwt_algorithm` | O(n) | O(n) | Base64 decode + JSON parse of header |
//! | `detect_api_key_provider` | O(n) | O(1) | Prefix pattern matching |
//! | `redact_jwt` | O(n) | O(n) | Strategy-dependent, may extract algorithm |
//! | `redact_api_key` | O(n) | O(n) | Strategy-dependent, provider detection |
//! | `redact_jwts_in_text` | O(n) | O(m) | n = text length, m = matches found |
//! | `redact_api_keys_in_text` | O(n) | O(m) | Cow optimization: O(1) space if no matches |
//! | `mask_api_key` | O(n) | O(n) | Extracts prefix, adds asterisks |
//!
//! ### Memory Usage
//!
//! - **Regex patterns**: ~15KB lazily initialized (shared across calls)
//! - **Per-call overhead**: Minimal, typically < 500 bytes for single identifiers
//! - **Text scanning**: Linear with text size plus detected matches
//! - **Cow optimization**: Zero allocation when text contains no tokens
//! - **Base64 decoding**: Temporary allocation for JWT algorithm detection
//!
//! ### ReDoS Protection
//!
//! All detection functions include length limits:
//! - **JWT tokens**: Max 1,000 characters
//! - **API keys**: Max 1,000 characters (10,000 for Azure)
//! - **SSH keys**: Max 10,000 characters
//! - **Session IDs**: Max 1,000 characters
//! - Exceeding limits returns `false` or `None` immediately
//!
//! ## Recommendations
//!
//! - **For API logs**: Always use `redact_api_keys_in_text()` with `Complete` policy before logging
//! - **For JWT handling**: Use `validate_jwt_algorithm()` to reject insecure "none" algorithm
//! - **For session IDs**: Validate entropy with `validate_session_id()` to prevent weak IDs
//! - **For SSH keys**: Use `ShowType` or `ShowFingerprint` strategy for audit logs
//! - **For performance**: Use `Cow<str>` returns to avoid allocations when text is clean
//! - **For security**: Never use `None` redaction strategy in production logs
//! - **For compliance**: Document which redaction strategy meets your regulatory requirements

pub mod builder;
pub mod redaction;

// Internal modules - not directly accessible outside token/
mod conversion;
mod detection;
mod sanitization;
mod validation;

// Re-export builder for convenient access
pub use builder::TokenIdentifierBuilder;

// Export redaction strategies for type-safe redaction API
pub use redaction::{
    ApiKeyRedactionStrategy, JwtRedactionStrategy, SessionIdRedactionStrategy,
    SshFingerprintRedactionStrategy, SshKeyRedactionStrategy, TextRedactionPolicy,
};

// Export detection types (needed for builder return types)
pub use detection::{ApiKeyProvider, JwtAlgorithm, TokenType};

// Export conversion types (needed for builder return types)
pub use conversion::JwtMetadata;

// Export shortcut functions for internal use (observe module)
// These provide common defaults without requiring strategy knowledge
pub use sanitization::{
    mask_api_key, mask_aws_key, mask_aws_session_token, mask_azure_key, mask_gcp_key,
    mask_github_token, mask_jwt, mask_paypal_token, mask_session_id, mask_shopify_token,
    mask_square_token, mask_ssh_key, mask_stripe_key,
};

// Export test pattern detection functions (observe module testing)
pub use detection::{is_test_api_key, is_test_jwt, is_test_session_id, is_test_ssh_key};
