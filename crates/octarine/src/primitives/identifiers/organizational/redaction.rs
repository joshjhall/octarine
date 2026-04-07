//! Redaction strategy types for organizational identifiers
//!
//! This module provides type-safe redaction strategies with two tiers:
//! 1. **Domain-specific enums** - Strict, type-safe strategies for single identifiers
//! 2. **Generic policy enum** - Simple, consistent policy for text scanning
//!
//! # Domain-Specific Strategies
//!
//! Each identifier type has its own strategy enum with only valid options:
//! - `EmployeeIdRedactionStrategy` - ShowPrefix, ShowDepartment, Token, etc.
//! - `StudentIdRedactionStrategy` - ShowYear, Token, etc.
//! - `BadgeRedactionStrategy` - ShowFacility, Token, etc.
//!
//! # Text Redaction Policy
//!
//! For scanning text with multiple identifier types, use `TextRedactionPolicy`:
//! - `None` - Skip redaction
//! - `Partial` - Show some information (sensible defaults per type)
//! - `Complete` - Full token redaction ([EMPLOYEE_ID], [STUDENT_ID], etc.)
//! - `Anonymous` - Generic [REDACTED] for everything
//!
//! Each `*_in_text()` function internally maps the policy to appropriate domain strategies.

/// Employee ID redaction strategies
///
/// Organizational identifiers for employees in corporate HR systems.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmployeeIdRedactionStrategy {
    /// Skip redaction - return as-is
    Skip,
    /// Show prefix only: EMP-****
    ShowPrefix,
    /// Show department: [EMP-Engineering-****]
    ShowDepartment,
    /// Replace with [EMPLOYEE_ID] token
    Token,
    /// Replace with generic [REDACTED]
    Anonymous,
    /// Replace with asterisks matching length
    Asterisks,
    /// Replace with hashes matching length
    Hashes,
}

/// Student ID redaction strategies
///
/// Educational institution identifiers protected under FERPA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StudentIdRedactionStrategy {
    /// Skip redaction - return as-is
    Skip,
    /// Show year only: 2024-****
    ShowYear,
    /// Replace with [STUDENT_ID] token
    Token,
    /// Replace with generic [REDACTED]
    Anonymous,
    /// Replace with asterisks matching length
    Asterisks,
    /// Replace with hashes matching length
    Hashes,
}

/// Badge number redaction strategies
///
/// Physical security badges granting facility access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadgeRedactionStrategy {
    /// Skip redaction - return as-is
    Skip,
    /// Show facility: [BADGE-Building5-****]
    ShowFacility,
    /// Replace with [BADGE] token
    Token,
    /// Replace with generic [REDACTED]
    Anonymous,
    /// Replace with asterisks matching length
    Asterisks,
    /// Replace with hashes matching length
    Hashes,
}

/// Generic redaction policy for text scanning across multiple identifier types
///
/// This simple enum provides a consistent policy when scanning text that may contain
/// multiple types of identifiers. Each `*_in_text()` function maps the policy to
/// appropriate domain-specific strategies.
///
/// # Policy Mappings
///
/// - `Partial` maps to sensible defaults per identifier:
///   - Employee ID: `ShowPrefix` (EMP-****)
///   - Student ID: `ShowYear` (2024-****)
///   - Badge: `Token` ([BADGE])
///
/// - `Complete` maps to token variants:
///   - [EMPLOYEE_ID], [STUDENT_ID], [BADGE]
///
/// - `Anonymous` maps to generic [REDACTED] for all types
///
/// - `None` passes through unchanged
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TextRedactionPolicy {
    /// Skip redaction - pass through unchanged
    Skip,
    /// Partial redaction with sensible defaults (show some information)
    Partial,
    /// Complete redaction with type-specific tokens (`[EMPLOYEE_ID]`, `[STUDENT_ID]`, etc.)
    #[default]
    Complete,
    /// Anonymous redaction with generic `[REDACTED]` for all types
    Anonymous,
}

impl TextRedactionPolicy {
    /// Map text policy to employee ID strategy
    #[must_use]
    pub const fn to_employee_id_strategy(self) -> EmployeeIdRedactionStrategy {
        match self {
            Self::Skip => EmployeeIdRedactionStrategy::Skip,
            Self::Partial => EmployeeIdRedactionStrategy::ShowPrefix,
            Self::Complete => EmployeeIdRedactionStrategy::Token,
            Self::Anonymous => EmployeeIdRedactionStrategy::Anonymous,
        }
    }

    /// Map text policy to student ID strategy
    #[must_use]
    pub const fn to_student_id_strategy(self) -> StudentIdRedactionStrategy {
        match self {
            Self::Skip => StudentIdRedactionStrategy::Skip,
            Self::Partial => StudentIdRedactionStrategy::ShowYear,
            Self::Complete => StudentIdRedactionStrategy::Token,
            Self::Anonymous => StudentIdRedactionStrategy::Anonymous,
        }
    }

    /// Map text policy to badge strategy
    #[must_use]
    pub const fn to_badge_strategy(self) -> BadgeRedactionStrategy {
        match self {
            Self::Skip => BadgeRedactionStrategy::Skip,
            Self::Partial => BadgeRedactionStrategy::Token,
            Self::Complete => BadgeRedactionStrategy::Token,
            Self::Anonymous => BadgeRedactionStrategy::Anonymous,
        }
    }
}
