//! Financial identifier types
//!
//! Types related to financial identifiers:
//! - `CreditCardType` - Credit card brands
//! - `FinancialTextPolicy` - Redaction policy for financial data

// ============================================================================
// Credit Card Type
// ============================================================================

/// Credit card brand/type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreditCardType {
    /// Visa card
    Visa,
    /// Mastercard
    Mastercard,
    /// American Express
    AmericanExpress,
    /// Discover card
    Discover,
    /// JCB card
    Jcb,
    /// Diners Club card
    DinersClub,
    /// Unknown card type
    Unknown,
}

impl std::fmt::Display for CreditCardType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Visa => write!(f, "Visa"),
            Self::Mastercard => write!(f, "Mastercard"),
            Self::AmericanExpress => write!(f, "American Express"),
            Self::Discover => write!(f, "Discover"),
            Self::Jcb => write!(f, "JCB"),
            Self::DinersClub => write!(f, "Diners Club"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

impl From<crate::primitives::identifiers::CreditCardType> for CreditCardType {
    fn from(c: crate::primitives::identifiers::CreditCardType) -> Self {
        use crate::primitives::identifiers::CreditCardType as P;
        match c {
            P::Visa => Self::Visa,
            P::Mastercard => Self::Mastercard,
            P::AmericanExpress => Self::AmericanExpress,
            P::Discover => Self::Discover,
            P::Jcb => Self::Jcb,
            P::DinersClub => Self::DinersClub,
            P::Unknown => Self::Unknown,
        }
    }
}

impl From<CreditCardType> for crate::primitives::identifiers::CreditCardType {
    fn from(c: CreditCardType) -> Self {
        match c {
            CreditCardType::Visa => Self::Visa,
            CreditCardType::Mastercard => Self::Mastercard,
            CreditCardType::AmericanExpress => Self::AmericanExpress,
            CreditCardType::Discover => Self::Discover,
            CreditCardType::Jcb => Self::Jcb,
            CreditCardType::DinersClub => Self::DinersClub,
            CreditCardType::Unknown => Self::Unknown,
        }
    }
}

// ============================================================================
// Financial Text Policy
// ============================================================================

/// Financial identifier text redaction policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FinancialTextPolicy {
    /// Skip redaction
    Skip,
    /// Partial redaction (show last 4 digits for cards/accounts)
    Partial,
    /// Complete redaction with type tokens
    #[default]
    Complete,
    /// Anonymous redaction with generic `[REDACTED]`
    Anonymous,
}

impl From<crate::primitives::identifiers::FinancialTextPolicy> for FinancialTextPolicy {
    fn from(p: crate::primitives::identifiers::FinancialTextPolicy) -> Self {
        use crate::primitives::identifiers::FinancialTextPolicy as P;
        match p {
            P::Skip => Self::Skip,
            P::Partial => Self::Partial,
            P::Complete => Self::Complete,
            P::Anonymous => Self::Anonymous,
        }
    }
}

impl From<FinancialTextPolicy> for crate::primitives::identifiers::FinancialTextPolicy {
    fn from(p: FinancialTextPolicy) -> Self {
        match p {
            FinancialTextPolicy::Skip => Self::Skip,
            FinancialTextPolicy::Partial => Self::Partial,
            FinancialTextPolicy::Complete => Self::Complete,
            FinancialTextPolicy::Anonymous => Self::Anonymous,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_credit_card_type_display() {
        assert_eq!(CreditCardType::Visa.to_string(), "Visa");
        assert_eq!(
            CreditCardType::AmericanExpress.to_string(),
            "American Express"
        );
    }

    #[test]
    fn test_financial_text_policy_default() {
        assert_eq!(
            FinancialTextPolicy::default(),
            FinancialTextPolicy::Complete
        );
    }
}
