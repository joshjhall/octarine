//! Identifier operation shortcuts
//!
//! Convenience functions for common identifier operations. These are the recommended
//! entry points for most use cases.
//!
//! # Examples
//!
//! ```
//! use octarine::identifiers::{is_pii_present, redact_pii, detect_identifier, validate_email};
//!
//! // PII Detection
//! if is_pii_present("Contact: user@example.com") {
//!     let redacted = redact_pii("Contact: user@example.com");
//! }
//!
//! // Type Detection
//! let id_type = detect_identifier("user@example.com");
//!
//! // Validation
//! validate_email("user@example.com").unwrap();
//! ```
//!
//! # Module organization
//!
//! Functions are split across submodules by PII domain. Each submodule wraps a
//! single Layer 3 builder (e.g., [`PersonalBuilder`](super::PersonalBuilder),
//! [`FinancialBuilder`](super::FinancialBuilder)) plus closely related cross-cutting
//! helpers. All functions are re-exported at this level so callers can simply use
//! `octarine::identifiers::*` without caring which file a shortcut lives in.

mod biometric;
mod bulk;
mod correlation;
mod credentials;
mod detection;
mod financial;
mod government;
mod location;
mod medical;
mod network;
mod organizational;
mod personal;
mod sensitive;
mod token;

pub use biometric::*;
pub use bulk::*;
pub use correlation::*;
pub use credentials::*;
pub use detection::*;
pub use financial::*;
pub use government::*;
pub use location::*;
pub use medical::*;
pub use network::*;
pub use organizational::*;
pub use personal::*;
pub use sensitive::*;
pub use token::*;
