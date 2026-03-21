//! Remember-me token primitives (Layer 1)
//!
//! Provides secure persistent login tokens following OWASP ASVS V3.5 controls.
//!
//! # Security Model
//!
//! Remember-me tokens use a split-token approach for security:
//!
//! - **Selector**: A public identifier used for database lookup (like a primary key)
//! - **Validator**: A secret value that is hashed before storage
//!
//! The cookie contains `selector:validator`. On verification:
//! 1. Look up the token by selector
//! 2. Hash the submitted validator
//! 3. Compare with stored hash using constant-time comparison
//!
//! This approach means that even if the database is compromised, the attacker
//! cannot directly use the stored tokens.
//!
//! # Features
//!
//! - Split selector:validator token design
//! - Token rotation on use (prevent token fixation)
//! - Device binding support
//! - Configurable lifetime (default: 30 days)

mod token;

pub use token::{
    RememberConfig, RememberConfigBuilder, RememberToken, RememberTokenPair,
    generate_remember_token, parse_cookie_value, validate_remember_token,
};
