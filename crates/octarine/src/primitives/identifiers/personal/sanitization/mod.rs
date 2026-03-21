//! Personal identifier sanitization primitives
//!
//! Pure sanitization functions for personal identifiers (PII) with ZERO
//! rust-core dependencies beyond the common utilities.
//!
//! ## Design Principles
//!
//! 1. **No Logging**: Pure functions, no trace/debug calls
//! 2. **No Side Effects**: Only string transformations
//! 3. **Reusable**: Used by observe/pii and security modules
//! 4. **Type-Safe API**: Domain-specific redaction strategies
//!
//! ## Module Structure
//!
//! - `email` - Email redaction and normalization
//! - `phone` - Phone redaction and normalization
//! - `name` - Name redaction and normalization
//! - `birthdate` - Birthdate redaction and normalization
//! - `username` - Username redaction
//! - `text` - Text scanning with find/replace
//!
//! ## Two-Tier Redaction API
//!
//! ### Domain-Specific Strategies (Single Identifiers)
//! Each identifier type has its own strategy enum with only valid options:
//! - `redact_email(email, EmailRedactionStrategy)` - ShowFirst, ShowDomain, Token, etc.
//! - `redact_phone(phone, PhoneRedactionStrategy)` - ShowLastFour (PCI-DSS), Token, etc.
//! - `redact_name(name, NameRedactionStrategy)` - ShowInitials, ShowFirst, Token, etc.
//! - `redact_birthdate(date, BirthdateRedactionStrategy)` - ShowYear, Token, etc.
//! - `redact_username(username, UsernameRedactionStrategy)` - ShowFirstAndLast, Token, etc.
//!
//! ### Generic Text Policy (Text Scanning)
//! For scanning text with multiple identifier types, use `TextRedactionPolicy`:
//! - `None` - No redaction
//! - `Partial` - Show some information (sensible defaults per type)
//! - `Complete` - Full token redaction ([EMAIL], [PHONE], etc.)
//! - `Anonymous` - Generic [REDACTED] for everything
//!
//! Environment-aware defaults and compliance-ready options (GDPR, HIPAA, PCI-DSS).

mod birthdate;
mod email;
mod name;
mod phone;
mod text;
mod username;

// Re-export email functions
pub use email::{redact_email_with_strategy, sanitize_email};

// Re-export phone functions
pub use phone::{redact_phone_with_strategy, sanitize_phone};

// Re-export name functions
pub use name::{redact_name_with_strategy, sanitize_name};

// Re-export birthdate functions
pub use birthdate::{redact_birthdate_with_strategy, sanitize_birthdate};

// Re-export username functions
pub use username::redact_username_with_strategy;

// Re-export text functions
pub use text::{
    redact_all_in_text, redact_birthdates_in_text, redact_emails_in_text,
    redact_emails_in_text_with_strategy, redact_names_in_text, redact_phones_in_text,
    redact_phones_in_text_with_strategy,
};
