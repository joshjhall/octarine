//! Turkish (`tr`) context keywords for identifier confidence scoring.
//!
//! Placeholder for the follow-up translation PRs (Step 3 of #432). The file
//! exists so the per-language layout is complete; keyword data is sourced from
//! Presidio's MIT-licensed `country_specific/tr` files with attribution.

use crate::primitives::identifiers::IdentifierType;

/// Turkish (`tr`) context keyword table, keyed by identifier type.
///
/// Empty until the translation PR populates it.
pub(super) static KEYWORDS: &[(IdentifierType, &[&str])] = &[];
