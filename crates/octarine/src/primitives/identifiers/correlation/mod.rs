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

mod types;

pub(crate) use types::{CorrelationConfig, CorrelationMatch, CredentialPairType};
