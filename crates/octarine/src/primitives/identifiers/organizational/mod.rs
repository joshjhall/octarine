//! Organizational identifier detection, validation, and sanitization
//!
//! This module provides pure functions for organization-issued identifiers:
//! - **Detection**: Find employee IDs, student IDs, badge numbers in text
//! - **Validation**: Verify format and validity of organizational identifiers
//! - **Sanitization**: Redact and mask organizational IDs for privacy
//!
//! ## Identifiers Covered
//!
//! | Identifier | Examples | Privacy Risk |
//! |------------|----------|--------------|
//! | Employee ID | E123456, EMP00123, BADGE# 98765 | Moderate - Social engineering |
//! | Student ID | S12345678, STUDENT# 123456 | High - FERPA protected |
//! | Badge Number | ID-12345, 000123 | Moderate - Physical security |
//!
//! ## Compliance Coverage
//!
//! Organizational identifiers are protected under various regulations:
//!
//! | Identifier | FERPA | GDPR | CCPA |
//! |------------|-------|------|------|
//! | Employee ID | N/A | Art. 4(1) - Personal data | Personal information |
//! | Student ID | Yes - Directory information | Art. 4(1) - Personal data | Personal information |
//! | Badge Number | N/A | Art. 4(1) when linkable | Personal information |
//!
//! ## Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.
//! - No observe:: dependencies
//! - Returns data, no side effects
//! - Used by observe/pii and security modules
//!
//! ## Design Notes
//!
//! Unlike government-issued IDs (SSN, passport) which have strict format rules,
//! organizational IDs vary widely by institution. Validation focuses on:
//! - Common format patterns (E-numbers, prefixed codes)
//! - Length constraints (prevent buffer overflows)
//! - Character set validation (alphanumeric + separators only)
//! - Injection pattern detection (SQL, command, path traversal)
//!
//! ## Architectural Decisions
//!
//! This module intentionally omits certain features present in the personal module:
//!
//! ### No Conversion Module
//!
//! Unlike the personal module (which includes phone/email conversion for E.164 and
//! canonicalization), organizational identifiers have simpler, institution-specific
//! formats that don't require standardized conversion. Employee IDs, student IDs, and
//! badge numbers are used as-is by their issuing organizations.
//!
//! ### No LRU Caching
//!
//! The personal module uses LRU caches because email/phone regex validation is
//! computationally expensive (complex patterns with lookaheads, TLD validation, etc.).
//! Organizational ID patterns are significantly simpler (e.g., `\b[Ee]\d{5,8}\b` for
//! E-numbers) and don't benefit meaningfully from caching. Benchmark testing showed
//! cache overhead exceeded any performance gain for these lightweight patterns.
//!
//! ### Rationale
//!
//! These omissions follow the principle of "don't add for the sake of adding" -
//! each module includes only the features necessary for its domain. The simpler
//! nature of organizational identifiers means they need less supporting infrastructure
//! than the more complex personal identifiers (email/phone).
//!
//! ## Usage
//!
//! Access functionality through the builder:
//!
//! ```rust,ignore
//! use octarine::primitives::identifiers::organizational::OrganizationalIdentifierBuilder;
//!
//! let builder = OrganizationalIdentifierBuilder::new();
//!
//! // Detection
//! assert!(builder.is_employee_id("E123456"));
//! assert!(builder.is_student_id("S12345678"));
//! let ids = builder.find_all_in_text("Employee: E123456, Student: S98765432");
//!
//! // Validation
//! assert!(builder.validate_employee_id("E123456").is_ok());
//!
//! // Sanitization
//! assert_eq!(builder.redact_employee_id("E123456"), "[EMPLOYEE_ID]");
//! assert_eq!(builder.redact_student_id("S12345678"), "[STUDENT_ID]");
//!
//! // Text redaction
//! let safe = builder.redact_all_in_text("Employee: E123456");
//! assert!(safe.contains("[EMPLOYEE_ID]"));
//! ```
//!
//! # Performance Characteristics
//!
//! ## Computational Complexity
//!
//! | Operation | Time | Space | Notes |
//! |-----------|------|-------|-------|
//! | `is_employee_id` | O(n) | O(1) | Regex match |
//! | `is_student_id` | O(n) | O(1) | Regex match |
//! | `find_employee_ids_in_text` | O(n) | O(m) | n = text length, m = matches |
//! | `find_student_ids_in_text` | O(n) | O(m) | Context checking adds overhead |
//! | `validate_employee_id_strict` | O(n) | O(1) | Format + injection checks |
//! | `redact_employee_ids_in_text` | O(n) | O(n) | Cow optimization for clean text |
//!
//! ## Memory Usage
//!
//! - **Regex patterns**: ~5KB lazily initialized (shared across calls)
//! - **Per-call overhead**: Minimal, typically < 1KB for single identifiers
//! - **Text scanning**: Linear with text size plus detected matches
//!
//! ## Recommendations
//!
//! - For large documents (>1MB), use `StreamingScanner` from Layer 1
//! - Use `Cow<str>` returns when possible to avoid allocations on clean text
//! - Cache builder instances for repeated operations
//! - Student ID scanning uses context checking - may have false negatives for safety

pub(crate) mod builder;
pub(crate) mod redaction;

// Internal modules - not directly accessible outside organizational/
mod detection;
mod sanitization;
mod validation;

// Re-export the builder as primary API and redaction types
pub use builder::OrganizationalIdentifierBuilder;
pub use redaction::{
    BadgeRedactionStrategy, EmployeeIdRedactionStrategy, StudentIdRedactionStrategy,
    TextRedactionPolicy,
};

// Re-export detection functions
pub use detection::is_organizational_present;
pub use detection::{is_test_badge_number, is_test_employee_id, is_test_student_id};

// Re-export validation functions
pub use validation::{validate_badge_number, validate_employee_id, validate_student_id};
