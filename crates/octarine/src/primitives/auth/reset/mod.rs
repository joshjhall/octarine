//! Password reset primitives (Layer 1)
//!
//! Provides secure password reset token generation and validation
//! following OWASP ASVS V2.5 controls.
//!
//! # Features
//!
//! - Secure token generation with 256 bits of entropy
//! - Time-limited tokens (default: 1 hour)
//! - Single-use token validation
//! - Rate limiting support

mod token;

pub use token::{
    ResetConfig, ResetConfigBuilder, ResetToken, generate_reset_token, validate_rate_limit,
    validate_reset_token,
};
