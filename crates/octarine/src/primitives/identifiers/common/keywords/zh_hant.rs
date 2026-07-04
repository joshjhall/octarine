//! Chinese Traditional (`zh-Hant`) context keywords for identifier confidence
//! scoring.
//!
//! Relocated from the previously flat `ApiKey` keyword list. Additional
//! identifier translations are added by the follow-up translation PRs.

use crate::primitives::identifiers::IdentifierType;

/// Chinese Traditional context keyword table, keyed by identifier type.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] =
    &[(IdentifierType::ApiKey, &["api密鑰", "認證", "密鑰"])];
