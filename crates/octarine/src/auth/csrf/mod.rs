//! CSRF protection with observe integration
//!
//! Cross-Site Request Forgery protection following OWASP ASVS V3.4 controls.
//!
//! # Patterns Supported
//!
//! ## Double-Submit Cookie
//!
//! The token is stored in a cookie and must also be submitted via header or form.
//! Simpler but relies on same-origin policy for cookie access.
//!
//! ```ignore
//! use octarine::auth::csrf::CsrfProtection;
//!
//! let csrf = CsrfProtection::new();
//!
//! // On page load, set cookie and embed token in form
//! let token = csrf.generate_token();
//! // Set cookie: __csrf={token.value()}
//! // Embed in form: <input type="hidden" name="_csrf" value="{token.value()}">
//!
//! // On form submit, validate
//! if csrf.validate_double_submit(&submitted_token, &cookie_token) {
//!     // Request is valid
//! }
//! ```
//!
//! ## Synchronizer Token
//!
//! The token is stored server-side (in session) and validated against submission.
//! More secure as it doesn't rely on cookie-based storage.
//!
//! # Audit Events
//!
//! - `auth.csrf.token_generated` - New token created
//! - `auth.csrf.validation_success` - Token validated successfully
//! - `auth.csrf.validation_failed` - Token validation failed

mod protection;

pub use protection::CsrfProtection;

// Re-export types from primitives
pub use crate::primitives::auth::csrf::{
    CsrfConfig, CsrfConfigBuilder, CsrfToken, SameSite, generate_csrf_token, validate_csrf_token,
};
