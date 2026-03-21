//! Test Data Generators
//!
//! Provides generators for property-based testing using proptest.
//! These generators produce both valid and invalid inputs for testing
//! security functions.
//!
//! ## Generator Categories
//!
//! - Attack pattern generators (injection, traversal, SSRF)
//! - Fake PII data generators (SSN, email, credit cards)
//! - Identifier generators (valid and invalid)
//!
//! ## Usage with Proptest
//!
//! ```rust,ignore
//! use octarine::testing::prelude::*;
//!
//! proptest! {
//!     #[test]
//!     fn rejects_path_traversal(attack in arb_path_traversal()) {
//!         assert!(validate_path(&attack).is_err());
//!     }
//!
//!     #[test]
//!     fn redacts_all_ssns(ssn in arb_ssn()) {
//!         let text = format!("SSN: {}", ssn);
//!         let redacted = redact_pii(&text);
//!         assert!(!redacted.contains(&ssn));
//!     }
//! }
//! ```

mod attacks;
mod identifiers;
mod pii;

pub use attacks::*;
pub use identifiers::*;
pub use pii::*;
