//! Token identifier validation (primitives layer)
//!
//! Pure validation functions for authentication and authorization tokens with NO logging.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns data only
//!
//! # Important Note
//!
//! This module validates **token formats** for authentication/authorization data.
//! It does not verify signatures, check expiration, or validate against external
//! services - those are Layer 3 responsibilities.

// Domain-specific validation modules
mod api_keys;
mod entropy;
mod jwt;
mod session;

// Re-export all validation functions
//
// Naming conventions:
// - `is_*` returns `bool` (detection layer only)
// - `validate_*` returns `Result<T, E>` (validation with error details)

// API Key validation
pub use api_keys::validate_api_key;

// JWT validation
pub use jwt::{validate_jwt, validate_jwt_algorithm};

// Session ID validation
pub use session::validate_session_id;

// Entropy analysis
pub use entropy::{
    analyze_key_strength, calculate_char_diversity, calculate_shannon_entropy, validate_key_entropy,
};
