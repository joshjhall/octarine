//! Government identifier builder with observability
//!
//! Wraps `primitives::identifiers::GovernmentIdentifierBuilder` with observe instrumentation.
//!
//! This is the **public API** (Layer 3) that wraps the primitive builder
//! with observe instrumentation for compliance-grade audit trails.
//!
//! # Why Wrapper Types?
//!
//! Wrapper types are necessary for two reasons:
//! 1. **Visibility bridging**: Primitives are `pub(crate)`, so we can't directly
//!    re-export them as `pub`. Wrapper types provide the public API surface.
//! 2. **API stability**: Wrappers allow the public API to evolve independently
//!    from internal primitives.
//!
//! # Module Structure
//!
//! `GovernmentBuilder`'s methods are split across per-country/domain
//! submodules that mirror the underlying primitive layout in
//! `primitives/identifiers/government/detection/`. Each submodule contains
//! one or more `impl GovernmentBuilder` blocks holding that country/domain's
//! methods. The struct itself, the metric-name constants, and constructors
//! stay in this `mod.rs`.

use std::time::Instant;

use crate::observe::metrics::{MetricName, increment_by, record};
use crate::observe::{self, Problem};
use crate::primitives::identifiers::{
    DriverLicenseRedactionStrategy, GovernmentIdentifierBuilder, NationalIdRedactionStrategy,
    PassportRedactionStrategy, SsnRedactionStrategy, TaxIdRedactionStrategy,
    VehicleIdRedactionStrategy,
};

use super::super::types::IdentifierMatch;

mod aggregate;
mod australia;
mod brazil;
mod cache;
mod driver_license;
mod europe;
mod india;
mod korea;
mod mexico;
mod national_id;
mod nigeria;
mod passport;
mod singapore;
mod ssn;
mod tax_id;
mod test_patterns;
mod thailand;
mod uk_ni;
mod vehicle_id;

#[allow(clippy::expect_used)]
pub(super) mod metric_names {
    use super::MetricName;

    pub fn detect_ms() -> MetricName {
        MetricName::new("data.identifiers.government.detect_ms").expect("valid metric name")
    }

    pub fn validate_ms() -> MetricName {
        MetricName::new("data.identifiers.government.validate_ms").expect("valid metric name")
    }

    pub fn redact_ms() -> MetricName {
        MetricName::new("data.identifiers.government.redact_ms").expect("valid metric name")
    }

    pub fn detected() -> MetricName {
        MetricName::new("data.identifiers.government.detected").expect("valid metric name")
    }

    pub fn government_data_found() -> MetricName {
        MetricName::new("data.identifiers.government.government_data_found")
            .expect("valid metric name")
    }
}

/// Government identifier builder with observability
///
/// Provides detection, validation, and sanitization for government identifiers
/// (SSNs, EINs, driver's licenses, passports, VINs) with full audit trail via observe.
///
/// # Example
///
/// ```ignore
/// use octarine::data::identifiers::GovernmentBuilder;
///
/// let builder = GovernmentBuilder::new();
///
/// // Detection
/// if builder.is_ssn("123-45-6789") {
///     println!("Found SSN");
/// }
///
/// // Silent mode (no events)
/// let silent = GovernmentBuilder::silent();
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct GovernmentBuilder {
    /// The underlying primitive builder
    pub(super) inner: GovernmentIdentifierBuilder,
    /// Whether to emit observe events
    pub(super) emit_events: bool,
}

impl GovernmentBuilder {
    /// Create a new GovernmentBuilder with observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: GovernmentIdentifierBuilder::new(),
            emit_events: true,
        }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self {
            inner: GovernmentIdentifierBuilder::new(),
            emit_events: false,
        }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = GovernmentBuilder::new();
        assert!(builder.emit_events);

        let silent = GovernmentBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = GovernmentBuilder::new().with_events(false);
        assert!(!builder.emit_events);

        let builder = GovernmentBuilder::silent().with_events(true);
        assert!(builder.emit_events);
    }

    #[test]
    fn test_ssn_detection() {
        let builder = GovernmentBuilder::silent();
        assert!(builder.is_ssn("517-29-8346"));
    }

    #[test]
    fn test_ssn_redaction_with_strategy() {
        let builder = GovernmentBuilder::silent();
        assert_eq!(
            builder.redact_ssn_with_strategy("517-29-8346", SsnRedactionStrategy::Token),
            "[SSN]"
        );
        assert_eq!(
            builder.redact_ssn_with_strategy("517-29-8346", SsnRedactionStrategy::LastFour),
            "***-**-8346"
        );
    }
}
