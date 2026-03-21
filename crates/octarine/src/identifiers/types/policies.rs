//! Text redaction policies
//!
//! Policy enums for redacting various identifier types in text:
//! - `MedicalTextPolicy` - Medical/HIPAA identifiers
//! - `GovernmentTextPolicy` - Government identifiers (SSN, etc.)
//! - `OrganizationalTextPolicy` - Organizational identifiers

// ============================================================================
// Medical Text Policy
// ============================================================================

/// Policy for redacting medical identifiers in text
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MedicalTextPolicy {
    /// Skip redaction - pass through unchanged
    Skip,
    /// Partial redaction with sensible defaults (show some information)
    Partial,
    /// Complete redaction with type-specific tokens
    #[default]
    Complete,
    /// Anonymous redaction with generic `[REDACTED]` for all types
    Anonymous,
}

impl From<crate::primitives::identifiers::MedicalTextPolicy> for MedicalTextPolicy {
    fn from(p: crate::primitives::identifiers::MedicalTextPolicy) -> Self {
        use crate::primitives::identifiers::MedicalTextPolicy as P;
        match p {
            P::Skip => Self::Skip,
            P::Partial => Self::Partial,
            P::Complete => Self::Complete,
            P::Anonymous => Self::Anonymous,
        }
    }
}

impl From<MedicalTextPolicy> for crate::primitives::identifiers::MedicalTextPolicy {
    fn from(p: MedicalTextPolicy) -> Self {
        match p {
            MedicalTextPolicy::Skip => Self::Skip,
            MedicalTextPolicy::Partial => Self::Partial,
            MedicalTextPolicy::Complete => Self::Complete,
            MedicalTextPolicy::Anonymous => Self::Anonymous,
        }
    }
}

// ============================================================================
// Government Text Policy
// ============================================================================

/// Government identifier text redaction policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GovernmentTextPolicy {
    /// Skip redaction
    Skip,
    /// Partial redaction (show last 4 for SSN, etc.)
    Partial,
    /// Complete redaction with type tokens
    #[default]
    Complete,
    /// Anonymous redaction with generic `[REDACTED]`
    Anonymous,
}

impl From<crate::primitives::identifiers::GovernmentTextPolicy> for GovernmentTextPolicy {
    fn from(p: crate::primitives::identifiers::GovernmentTextPolicy) -> Self {
        use crate::primitives::identifiers::GovernmentTextPolicy as P;
        match p {
            P::Skip => Self::Skip,
            P::Partial => Self::Partial,
            P::Complete => Self::Complete,
            P::Anonymous => Self::Anonymous,
        }
    }
}

impl From<GovernmentTextPolicy> for crate::primitives::identifiers::GovernmentTextPolicy {
    fn from(p: GovernmentTextPolicy) -> Self {
        match p {
            GovernmentTextPolicy::Skip => Self::Skip,
            GovernmentTextPolicy::Partial => Self::Partial,
            GovernmentTextPolicy::Complete => Self::Complete,
            GovernmentTextPolicy::Anonymous => Self::Anonymous,
        }
    }
}

// ============================================================================
// Organizational Text Policy
// ============================================================================

/// Organizational identifier text redaction policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OrganizationalTextPolicy {
    /// Skip redaction
    Skip,
    /// Partial redaction (show prefix/year)
    Partial,
    /// Complete redaction with type tokens
    #[default]
    Complete,
    /// Anonymous redaction with generic `[REDACTED]`
    Anonymous,
}

impl From<crate::primitives::identifiers::OrganizationalTextPolicy> for OrganizationalTextPolicy {
    fn from(p: crate::primitives::identifiers::OrganizationalTextPolicy) -> Self {
        use crate::primitives::identifiers::OrganizationalTextPolicy as P;
        match p {
            P::Skip => Self::Skip,
            P::Partial => Self::Partial,
            P::Complete => Self::Complete,
            P::Anonymous => Self::Anonymous,
        }
    }
}

impl From<OrganizationalTextPolicy> for crate::primitives::identifiers::OrganizationalTextPolicy {
    fn from(p: OrganizationalTextPolicy) -> Self {
        match p {
            OrganizationalTextPolicy::Skip => Self::Skip,
            OrganizationalTextPolicy::Partial => Self::Partial,
            OrganizationalTextPolicy::Complete => Self::Complete,
            OrganizationalTextPolicy::Anonymous => Self::Anonymous,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_medical_text_policy_default() {
        assert_eq!(MedicalTextPolicy::default(), MedicalTextPolicy::Complete);
    }

    #[test]
    fn test_government_text_policy_default() {
        assert_eq!(
            GovernmentTextPolicy::default(),
            GovernmentTextPolicy::Complete
        );
    }

    #[test]
    fn test_organizational_text_policy_default() {
        assert_eq!(
            OrganizationalTextPolicy::default(),
            OrganizationalTextPolicy::Complete
        );
    }

    #[test]
    fn test_policy_conversion() {
        let public = MedicalTextPolicy::Partial;
        let primitive: crate::primitives::identifiers::MedicalTextPolicy = public.into();
        let back: MedicalTextPolicy = primitive.into();
        assert_eq!(back, MedicalTextPolicy::Partial);
    }
}
