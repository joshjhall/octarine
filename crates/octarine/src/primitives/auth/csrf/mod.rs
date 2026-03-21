//! CSRF protection primitives (Layer 1)
//!
//! Cross-Site Request Forgery protection using secure token-based patterns.
//! Implements OWASP ASVS V3.4 controls.

mod token;

pub use token::{
    CsrfConfig, CsrfConfigBuilder, CsrfToken, SameSite, generate_csrf_token, tokens_match,
    validate_csrf_token,
};
