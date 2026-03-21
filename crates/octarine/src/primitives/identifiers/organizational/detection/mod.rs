//! Organizationally-issued identifier detection
//!
//! Detects identifiers issued by private organizations with custom formats:
//! - **Employee ID**: Corporate HR systems
//! - **Student ID**: Educational institutions
//! - **Badge Number**: Security/access control
//!
//! # Future Extensions
//!
//! This module can easily be extended for additional organizational IDs:
//! - Patient ID (healthcare providers)
//! - Member ID (clubs, gyms, associations)
//! - Customer ID (banks, retailers)
//! - Account Number (service providers)
//!
//! # Architecture
//!
//! Two types of detection:
//! 1. **Single-value detection** (`is_*`, `detect_*`): Validate one identifier
//! 2. **Text scanning** (`find_*_in_text`): Find all matches in documents
//!
//! # Module Organization
//!
//! - [`constants`] - Length limits and utility functions for ReDoS protection
//! - [`single_value`] - Individual identifier validation
//! - [`text_scanning`] - Document scanning for identifiers
//! - [`test_patterns`] - Test/sample pattern detection
//!
//! # Design Principles
//!
//! - **No logging**: Pure detection functions
//! - **No external dependencies**: Only uses primitives module
//! - **Pattern-based**: Relies on regex patterns from common/patterns
//!
//! # Usage
//!
//! ```ignore
//! use crate::primitives::identifiers::organizational;
//!
//! // Single-value detection
//! if organizational::is_employee_id("E123456") {
//!     println!("Valid employee ID format");
//! }
//!
//! // Detailed detection
//! if let Some(id_type) = organizational::detect_organizational_id("E123456") {
//!     println!("Detected: {:?}", id_type);
//! }
//!
//! // Text scanning
//! let text = "Employee: E123456, Badge# 98765";
//! let matches = organizational::find_employee_ids_in_text(text);
//! ```

mod constants;
mod single_value;
mod test_patterns;
mod text_scanning;

// Re-export constants
pub use constants::{MAX_IDENTIFIER_LENGTH, MAX_INPUT_LENGTH, exceeds_safe_length};

// Re-export single-value detection
pub use single_value::{
    detect_organizational_id, is_badge_number, is_employee_id, is_organizational_id, is_student_id,
};

// Re-export text scanning
pub use text_scanning::{
    find_all_organizational_ids_in_text, find_badge_numbers_in_text, find_employee_ids_in_text,
    find_student_ids_in_text, is_organizational_present,
};

// Re-export test pattern detection
pub use test_patterns::{is_test_badge_number, is_test_employee_id, is_test_student_id};
