//! Personal identifier detection
//!
//! Detects personal identifiers (PII) including:
//! - **Email Addresses**: RFC-compliant email patterns
//! - **Phone Numbers**: E.164 and US formats with various delimiters
//! - **Personal Names**: Full names in various formats (First Last, Last, First)
//! - **Birthdates**: Date of birth in ISO, US, European, and month name formats
//! - **Usernames**: Alphanumeric identifiers with common special characters
//!
//! **Note**: SSN/Tax IDs are government-issued and handled in `government` module
//!
//! # Module Structure
//!
//! - `cache` - Shared caching infrastructure
//! - `email` - Email address detection
//! - `phone` - Phone number detection
//! - `name` - Personal name detection
//! - `birthdate` - Date of birth detection
//! - `username` - Username detection
//! - `common` - Aggregate functions and utilities
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.
//! Used by both observe/pii and security modules.

mod birthdate;
mod cache;
mod common;
mod email;
mod name;
mod phone;
mod username;

// Re-export cache utilities
pub use cache::{clear_personal_caches, email_cache_stats, phone_cache_stats};

// Re-export email functions
pub use email::{detect_emails_in_text, is_email, is_test_email};

// Re-export phone functions
pub use phone::{detect_phones_in_text, find_phone_region, is_phone_number, is_test_phone};

// Re-export name functions
pub use name::{detect_names_in_text, is_name};

// Re-export birthdate functions
pub use birthdate::{detect_birthdates_in_text, is_birthdate};

// Re-export username functions
pub use username::{detect_usernames_in_text, is_username};

// Re-export common/aggregate functions
pub use common::{
    detect_all_pii_in_text, find_personal_identifier, is_personal_identifier, is_pii,
    is_pii_present,
};

// Re-export deduplicate_matches for internal use by sibling modules
pub(super) use common::deduplicate_matches;
