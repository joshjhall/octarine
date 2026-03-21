//! Password policy primitives
//!
//! This module provides password validation against configurable policies,
//! following OWASP ASVS V2.1 requirements.
//!
//! # Features
//!
//! - Configurable password policy (min/max length, complexity)
//! - Password strength estimation using zxcvbn (Dropbox algorithm)
//! - Password history checking
//! - Username similarity detection
//!
//! # ASVS Coverage
//!
//! - V2.1.1: Minimum password length >= 8
//! - V2.1.2: Maximum password length >= 64
//! - V2.1.7: Common password blocklist (via zxcvbn)
//! - V2.3.1: Password history checking

mod policy;

pub use policy::{
    PasswordPolicy, PasswordPolicyBuilder, PasswordPolicyViolation, PasswordStrength,
    estimate_strength, validate_password,
};
