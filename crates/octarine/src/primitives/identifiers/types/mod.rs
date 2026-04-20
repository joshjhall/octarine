//! Type definitions for identifier detection
//!
//! Pure type definitions with no dependencies on other rust-core modules.
//! Split into per-concern files mirroring the Layer 3 `identifiers/types/`
//! layout.

mod core;
mod financial;
mod personal;

pub use core::{DetectionConfidence, DetectionResult, IdentifierMatch, IdentifierType};
pub use financial::CreditCardType;
pub use personal::{CredentialMatch, CredentialType, PhoneRegion};
