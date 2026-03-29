//! Credential pair correlation detection.
//!
//! Detects related credentials that appear near each other in text
//! (e.g., AWS access key + secret key within a few lines). Pair matching
//! dramatically reduces false positives: a random 20-character alphanumeric
//! string is noise, but the same string next to `AKIA...` is almost
//! certainly an AWS secret key.
//!
//! # Architecture
//!
//! This module provides the foundational types for correlation detection.
//! Detection logic, proximity scanning, and pair recognition rules are
//! added by subsequent modules.

pub(crate) mod builder;
pub(crate) mod detection;
pub(crate) mod proximity;
pub(crate) mod rules;
mod types;

pub(crate) use builder::CorrelationBuilder;
pub(crate) use detection::{detect_credential_pairs, detect_credential_pairs_with_config};
pub(crate) use rules::is_credential_pair;
pub use types::{CorrelationConfig, CorrelationMatch, CredentialPairType};
