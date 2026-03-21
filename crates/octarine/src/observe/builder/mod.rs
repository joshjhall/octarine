//! Unified observe builder - facade for all observability operations
//!
//! This builder provides a single, unified API that composes:
//! - Context building (who/what/where/when)
//! - Event logging (debug/info/warn/error/success)
//! - Problem creation (validation/security/permission errors)
//! - Metrics tracking (counters/gauges/histograms)
//!
//! Users interact with ObserveBuilder, which internally delegates to
//! specialized sub-builders (ContextBuilder, EventBuilder, etc.) that
//! remain private implementation details.

// Extension modules that add methods to ObserveBuilder
mod aggregate;
mod compliance;
mod context;
mod event;
mod metrics;
mod problem;
mod writers; // Documentation only

// Shortcuts (pub(super) so observe/shortcuts.rs can use them)
pub(super) mod aggregate_shortcuts;
pub(super) mod event_shortcuts;
pub(super) mod metrics_shortcuts;
pub(super) mod problem_shortcuts;

// Import ContextBuilder for build_context() helper
use crate::observe::compliance::ComplianceTags;
use crate::observe::context::ContextBuilder;
use crate::observe::metrics::MetricName;
use std::collections::HashMap;

/// Unified observe builder - single API for all observability operations
///
/// This is the main builder users interact with. It provides a facade over
/// the internal builder hierarchy (context, event, problem, metrics).
#[derive(Debug, Clone)]
pub struct ObserveBuilder {
    // Context configuration
    pub(super) operation: String,
    pub(super) tenant_id: Option<String>,
    pub(super) user_id: Option<String>,
    pub(super) session_id: Option<String>,

    // Event/Problem message
    pub(super) message: String,

    // Event metadata (arbitrary key-value pairs)
    pub(super) metadata: HashMap<String, serde_json::Value>,

    // Metrics configuration
    pub(super) metric_name: Option<MetricName>,

    // Compliance flags
    pub(super) security_relevant: bool,
    pub(super) contains_pii: bool,
    pub(super) contains_phi: bool,

    // Compliance framework tags
    pub(super) compliance_tags: ComplianceTags,
}

impl ObserveBuilder {
    /// Create a new observe builder
    pub fn new() -> Self {
        Self {
            operation: String::new(),
            tenant_id: None,
            user_id: None,
            session_id: None,
            message: String::new(),
            metadata: HashMap::new(),
            metric_name: None,
            security_relevant: false,
            contains_pii: false,
            contains_phi: false,
            compliance_tags: ComplianceTags::default(),
        }
    }

    /// Create builder for a specific operation
    pub fn for_operation(operation: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            ..Self::new()
        }
    }

    /// Set the operation name
    pub fn operation(mut self, operation: impl Into<String>) -> Self {
        self.operation = operation.into();
        self
    }

    /// Set the message
    pub fn message(mut self, message: impl Into<String>) -> Self {
        self.message = message.into();
        self
    }

    /// Set tenant ID
    pub fn tenant(mut self, tenant_id: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant_id.into());
        self
    }

    /// Set user ID
    pub fn user(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Set session ID
    pub fn session(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Mark as security relevant
    pub fn security_relevant(mut self) -> Self {
        self.security_relevant = true;
        self
    }

    /// Mark as containing PII
    pub fn with_pii(mut self) -> Self {
        self.contains_pii = true;
        self
    }

    /// Mark as containing PHI
    pub fn with_phi(mut self) -> Self {
        self.contains_phi = true;
        self
    }

    /// Add metadata to the event
    ///
    /// Metadata is arbitrary key-value data attached to events for
    /// structured logging and analysis. Values are stored as JSON.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use octarine::observe::ObserveBuilder;
    ///
    /// ObserveBuilder::for_operation("path_validation")
    ///     .message("Path validation failed")
    ///     .with_metadata("path_length", 256)
    ///     .with_metadata("threat_type", "traversal")
    ///     .warn();
    /// ```
    ///
    /// # Note
    ///
    /// Metadata values are automatically scanned for PII and redacted
    /// according to the current redaction profile.
    pub fn with_metadata(
        mut self,
        key: impl Into<String>,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Set metric name for metrics operations (validates metric name)
    ///
    /// Returns self unchanged if metric name is invalid (lenient).
    pub fn metric(mut self, name: impl AsRef<str>) -> Self {
        self.metric_name = MetricName::new(name).ok();
        self
    }

    // Internal helper: Build context from current state
    pub(super) fn build_context(&self) -> super::EventContext {
        let mut builder = ContextBuilder::new();

        if !self.operation.is_empty() {
            builder = builder.with_operation(&self.operation);
        }
        if let Some(ref tenant) = self.tenant_id {
            builder = builder.with_tenant(tenant);
        }
        if let Some(ref user) = self.user_id {
            builder = builder.with_user(user);
        }
        if let Some(ref session) = self.session_id {
            builder = builder.with_session(session);
        }
        if self.security_relevant {
            builder = builder.security_relevant(true);
        }
        if self.contains_pii {
            builder = builder.with_pii_detected();
        }
        if self.contains_phi {
            builder = builder.with_phi_detected();
        }

        let mut ctx = builder.build();

        // Add compliance tags if any are set
        if !self.compliance_tags.is_empty() {
            ctx.compliance = self.compliance_tags.clone();
        }

        ctx
    }

    /// Get the metadata for this event
    pub(super) fn get_metadata(&self) -> &HashMap<String, serde_json::Value> {
        &self.metadata
    }
}

impl Default for ObserveBuilder {
    fn default() -> Self {
        Self::new()
    }
}
