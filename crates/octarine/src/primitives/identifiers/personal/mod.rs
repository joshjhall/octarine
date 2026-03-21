//! Personal identifier detection, validation, and sanitization
//!
//! This module provides pure functions for personal identifiers (PII):
//! - **Detection**: Find emails, phones, names, dates of birth in text
//! - **Validation**: Verify format and validity of emails, phones, usernames, birthdates
//! - **Sanitization**: Redact and mask PII with various strategies
//! - **Conversion**: Normalize formats (E.164 phones, lowercase emails, Gmail handling)
//!
//! **Note**: SSN/Tax IDs are in the `government` module (government-issued IDs)
//!
//! ## Compliance Coverage
//!
//! Personal identifiers handled by this module are protected under:
//!
//! | Identifier | GDPR | CCPA | HIPAA |
//! |------------|------|------|-------|
//! | Email | Art. 4(1) - Personal data | Personal information | PHI when linked to health |
//! | Phone | Art. 4(1) - Personal data | Personal information | PHI when linked to health |
//! | Name | Art. 4(1) - Personal data | Personal information | PHI identifier |
//! | Birthdate | Art. 9 - Special category | Personal information | PHI identifier |
//! | Username | Art. 4(1) when linkable | Personal information | PHI when linked |
//!
//! ## Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.
//! - No observe:: dependencies
//! - Returns data, no side effects
//! - Used by observe/pii and security modules
//!
//! ## Usage
//!
//! Access functionality through the builder:
//!
//! ```rust,ignore
//! use octarine::primitives::identifiers::personal::PersonalIdentifierBuilder;
//!
//! let builder = PersonalIdentifierBuilder::new();
//!
//! // Detection
//! let has_pii = builder.is_pii_present("user@example.com");
//! let emails = builder.find_emails_in_text("Contact: user@example.com");
//!
//! // Validation (returns Result with details)
//! assert!(builder.validate_email("user@example.com").is_ok());
//! assert!(builder.validate_phone("+14155552671").is_ok());
//!
//! // Sanitization
//! assert_eq!(builder.redact_email("user@example.com"), "u***@example.com");
//! assert_eq!(builder.redact_phone("+1-555-123-4567"), "***-***-4567");
//!
//! // Conversion
//! let normalized = builder.normalize_email("User.Name+tag@Gmail.com").unwrap();
//! assert_eq!(normalized, "username@gmail.com");
//! ```
//!
//! # Performance Characteristics
//!
//! ## Computational Complexity
//!
//! | Operation | Time | Space | Notes |
//! |-----------|------|-------|-------|
//! | `is_email` | O(n) | O(1) | LRU cached, regex match |
//! | `is_phone_number` | O(n) | O(1) | LRU cached, regex match |
//! | `is_name` | O(n) | O(1) | Pattern match, requires 2+ words |
//! | `is_birthdate` | O(n) | O(1) | Pattern match, multiple formats |
//! | `is_username` | O(n) | O(1) | Pattern match, heuristic-based |
//! | `find_emails_in_text` | O(n) | O(m) | n = text length, m = matches |
//! | `find_phones_in_text` | O(n) | O(m) | n = text length, m = matches |
//! | `find_names_in_text` | O(n) | O(m) | n = text length, m = matches |
//! | `find_birthdates_in_text` | O(n) | O(m) | n = text length, m = matches |
//! | `redact_email` | O(n) | O(n) | n = email length |
//! | `redact_phone` | O(n) | O(n) | n = phone length |
//! | `normalize_email` | O(n) | O(n) | n = email length |
//! | `normalize_phone_e164` | O(n) | O(n) | n = phone length |
//!
//! ## Memory Usage
//!
//! - **Regex patterns**: ~15KB lazily initialized (shared across calls)
//! - **LRU caches**: Up to 20,000 entries (10K emails + 10K phones), 1-hour TTL
//! - **Per-call overhead**: Minimal, typically < 1KB for single identifiers
//! - **Text scanning**: Linear with text size plus detected matches
//!
//! ## Caching
//!
//! Email and phone validation results are cached using LRU caches:
//! - Email cache: 10,000 entries, 1-hour TTL
//! - Phone cache: 10,000 entries, 1-hour TTL
//!
//! Use `email_cache_stats()` and `phone_cache_stats()` to monitor cache performance.
//! Use `clear_personal_caches()` to reset caches when needed.
//!
//! ## Recommendations
//!
//! - For large documents (>1MB), use `StreamingScanner` from Layer 1
//! - Use `Cow<str>` returns when possible to avoid allocations on clean text
//! - Cache builder instances for repeated operations
//! - Monitor cache hit rates with stats functions for performance tuning

pub mod builder;
pub mod redaction;

// Internal modules - not directly accessible outside personal/
mod conversion;
mod detection;
mod sanitization;
mod validation;

// Re-export the builder as primary API and redaction types
pub use builder::PersonalIdentifierBuilder;
pub use redaction::{
    BirthdateRedactionStrategy, EmailRedactionStrategy, NameRedactionStrategy,
    PhoneRedactionStrategy, TextRedactionPolicy, UsernameRedactionStrategy,
};

// Export cache stats functions for performance monitoring
pub use detection::{clear_personal_caches, email_cache_stats, phone_cache_stats};

// Export test pattern detection functions
pub use detection::{is_test_email, is_test_phone};
pub use validation::is_test_birthdate;

// Export phone region detection function
pub use detection::find_phone_region;

// Export PII detection functions for observe/context/compliance
pub use detection::is_pii_present;

// Export phone region type from common types module
pub use super::types::PhoneRegion;

// Export sanitization functions for normalization (in addition to redaction)
pub use sanitization::{
    redact_emails_in_text_with_strategy, redact_phones_in_text_with_strategy, sanitize_birthdate,
    sanitize_email, sanitize_name, sanitize_phone,
};

// Export phone format style for display formatting
pub use conversion::PhoneFormatStyle;
