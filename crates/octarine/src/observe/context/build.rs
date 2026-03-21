//! Context building implementation
//!
//! Contains the business logic for constructing EventContext from builder state.
//! This is separate from the builder itself to keep the builder pure.

use super::capture::capture_context;
use crate::observe::EventContext;
use crate::observe::compliance::ComplianceTags;
use crate::observe::types::{TenantId, UserId};
use uuid::Uuid;

/// Configuration for building context (mirrors ContextBuilder fields)
#[derive(Debug, Clone)]
pub(super) struct ContextConfig {
    // Identity fields
    pub tenant_id: Option<TenantId>,
    pub user_id: Option<UserId>,
    pub session_id: Option<String>,

    // Operation fields
    pub operation: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,

    // Correlation
    pub correlation_id: Option<Uuid>,
    pub parent_span_id: Option<Uuid>,

    // Compliance flags
    pub contains_pii: bool,
    pub contains_phi: bool,
    pub security_relevant: bool,

    // Control flags
    pub auto_capture: bool,
}

/// Build EventContext from configuration
///
/// This is the actual business logic for context construction.
/// The builder delegates to this function.
pub(super) fn build_context(config: ContextConfig) -> EventContext {
    // Start with base context - either auto-captured or empty
    let mut context = if config.auto_capture {
        // Delegate to capture implementation
        capture_context()
    } else {
        // Start with empty context
        EventContext {
            tenant_id: None,
            user_id: None,
            session_id: None,
            operation: String::new(),
            resource_type: None,
            resource_id: None,
            module_path: String::new(),
            file: String::new(),
            line: 0,
            local_ip: None,
            source_ip: None,
            source_ip_chain: Vec::new(),
            correlation_id: Uuid::new_v4(),
            parent_span_id: None,
            contains_pii: false,
            contains_phi: false,
            security_relevant: true,
            pii_types: Vec::new(),
            compliance: ComplianceTags::default(),
        }
    };

    // Override with builder values if provided
    if let Some(id) = config.tenant_id {
        context.tenant_id = Some(id);
    }
    if let Some(id) = config.user_id {
        context.user_id = Some(id);
    }
    if let Some(id) = config.session_id {
        context.session_id = Some(id);
    }
    if !config.operation.is_empty() {
        context.operation = config.operation;
    }
    if let Some(rt) = config.resource_type {
        context.resource_type = Some(rt);
    }
    if let Some(id) = config.resource_id {
        context.resource_id = Some(id);
    }
    if let Some(id) = config.correlation_id {
        context.correlation_id = id;
    }
    if let Some(span) = config.parent_span_id {
        context.parent_span_id = Some(span);
    }

    // Set compliance flags
    context.contains_pii = config.contains_pii;
    context.contains_phi = config.contains_phi;
    context.security_relevant = config.security_relevant;

    context
}
