//! Integration tests for the auth module
//!
//! These tests verify end-to-end authentication workflows:
//! - Account lockout after repeated failures
//! - Password reset with token expiration
//! - MFA enrollment and verification (auth-totp feature)
//! - Session binding and mismatch rejection
//! - Remember-me token rotation

#![cfg(feature = "auth")]

mod auth;
