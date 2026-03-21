//! Severity filtering for writers
//!
//! Filter configuration for controlling which events writers process.

use crate::observe::types::Severity;

/// Filter for event severity levels
///
/// Used to configure which events a writer should process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeverityFilter {
    /// Minimum severity level to accept
    min_severity: Severity,
    /// Whether to include debug events
    include_debug: bool,
    /// Whether to include trace events
    include_trace: bool,
}

impl SeverityFilter {
    /// Accept all severity levels
    pub fn all() -> Self {
        Self {
            min_severity: Severity::Debug,
            include_debug: true,
            include_trace: true,
        }
    }

    /// Production filter - Info and above, no debug/trace
    pub fn production() -> Self {
        Self {
            min_severity: Severity::Info,
            include_debug: false,
            include_trace: false,
        }
    }

    /// Errors only - Error and Critical
    pub fn errors_only() -> Self {
        Self {
            min_severity: Severity::Error,
            include_debug: false,
            include_trace: false,
        }
    }

    /// Create a filter with minimum severity
    pub fn with_min_severity(severity: Severity) -> Self {
        Self {
            min_severity: severity,
            include_debug: matches!(severity, Severity::Debug),
            include_trace: false,
        }
    }

    /// Check if a severity level passes the filter
    pub fn accepts(&self, severity: Severity) -> bool {
        match severity {
            Severity::Debug => self.include_debug,
            Severity::Info => {
                self.min_severity == Severity::Debug || self.min_severity == Severity::Info
            }
            Severity::Warning => {
                matches!(
                    self.min_severity,
                    Severity::Debug | Severity::Info | Severity::Warning
                )
            }
            Severity::Error => {
                matches!(
                    self.min_severity,
                    Severity::Debug | Severity::Info | Severity::Warning | Severity::Error
                )
            }
            Severity::Critical => true, // Always accept critical
        }
    }
}

impl Default for SeverityFilter {
    fn default() -> Self {
        Self::production()
    }
}
