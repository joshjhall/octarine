//! Dispatch extensions for EventBuilder
//!
//! Extends EventBuilder with methods that delegate to dispatch implementation.
//! NO business logic here - only delegation to implementation.

use super::EventBuilder;
use std::cell::Cell;

// Import the dispatch functions we're delegating to
use crate::observe::event::dispatch::{
    dispatch_auth_failure_from_message, dispatch_auth_success_from_message, dispatch_critical,
    dispatch_debug, dispatch_error, dispatch_error_with_problem, dispatch_info, dispatch_success,
    dispatch_trace, dispatch_warning,
};

// Import PII redaction
use crate::observe::pii::{PiiScanResult, RedactionProfile, scan_and_redact};

// Thread-local flag to prevent recursive PII redaction
// This prevents infinite recursion when PII redaction code calls trace/debug/etc
thread_local! {
    static IN_PII_REDACTION: Cell<bool> = const { Cell::new(false) };
}

/// Update context with PII metadata from scan results
fn update_context_with_pii(
    context: &mut crate::observe::EventContext,
    pii_result: &Option<PiiScanResult>,
) {
    if let Some(result) = pii_result {
        context.contains_pii = result.contains_pii;
        context.contains_phi = result.contains_phi;
        context.pii_types = result
            .pii_types
            .iter()
            .map(|t| t.name().to_string())
            .collect();
    }
}

/// Extensions for EventBuilder related to event dispatch
impl EventBuilder {
    /// Process message for PII redaction if enabled
    ///
    /// Returns a tuple of (redacted_message, pii_scan_result).
    /// Uses a thread-local guard to prevent recursive calls from security/detection code.
    fn process_message(&self) -> (String, Option<PiiScanResult>) {
        // Skip redaction if explicitly requested
        if self.skip_pii_redaction {
            return (self.message.clone(), None);
        }

        // Check if we're already in a PII redaction call (prevent recursion)
        let already_redacting = IN_PII_REDACTION.with(|flag| flag.get());
        if already_redacting {
            return (self.message.clone(), None);
        }

        // Set flag and perform redaction with metadata tracking
        IN_PII_REDACTION.with(|flag| flag.set(true));
        let profile = RedactionProfile::from_environment();
        let scan_result = scan_and_redact(&self.message, profile);
        let redacted = scan_result.redacted.clone();
        IN_PII_REDACTION.with(|flag| flag.set(false));

        (redacted, Some(scan_result))
    }

    /// Returns a builder configured for debug event (customizable)
    pub fn debug_builder(self) -> Self {
        self // Just return self for further configuration
    }

    /// Build and dispatch as debug event immediately
    pub fn debug(self) {
        let (message, pii_result) = self.process_message();
        let mut context = self
            .context
            .unwrap_or_else(crate::observe::context::shortcuts::full);
        update_context_with_pii(&mut context, &pii_result);
        dispatch_debug(message, context, self.metadata);
    }

    /// Returns a builder configured for info event (customizable)
    pub fn info_builder(self) -> Self {
        self
    }

    /// Build and dispatch as info event immediately
    pub fn info(self) {
        let (message, pii_result) = self.process_message();
        let mut context = self
            .context
            .unwrap_or_else(crate::observe::context::shortcuts::full);
        update_context_with_pii(&mut context, &pii_result);
        dispatch_info(message, context, self.metadata);
    }

    /// Returns a builder configured for warning event (customizable)
    pub fn warn_builder(self) -> Self {
        self
    }

    /// Build and dispatch as warning event immediately
    pub fn warn(self) {
        let (message, pii_result) = self.process_message();
        let mut context = self
            .context
            .unwrap_or_else(crate::observe::context::shortcuts::full);
        update_context_with_pii(&mut context, &pii_result);
        dispatch_warning(message, context, self.metadata);
    }

    /// Returns a builder configured for error event (customizable)
    pub fn error_builder(self) -> Self {
        self
    }

    /// Build and dispatch as error event immediately (just logs, no Problem)
    pub fn error(self) {
        let (message, pii_result) = self.process_message();
        let mut context = self
            .context
            .unwrap_or_else(crate::observe::context::shortcuts::full);
        update_context_with_pii(&mut context, &pii_result);
        dispatch_error(message, context, self.metadata);
    }

    /// Build and dispatch as error event immediately, returning Problem
    pub fn error_with_problem(self) -> crate::observe::problem::Problem {
        let (message, pii_result) = self.process_message();
        let mut context = self
            .context
            .unwrap_or_else(crate::observe::context::shortcuts::full);
        update_context_with_pii(&mut context, &pii_result);
        dispatch_error_with_problem(message, context, self.metadata)
    }

    /// Returns a builder configured for critical event (customizable)
    pub fn critical_builder(self) -> Self {
        self
    }

    /// Build and dispatch as critical event immediately
    pub fn critical(self) {
        let (message, pii_result) = self.process_message();
        let mut context = self
            .context
            .unwrap_or_else(crate::observe::context::shortcuts::security);
        update_context_with_pii(&mut context, &pii_result);
        dispatch_critical(message, context, self.metadata);
    }

    /// Returns a builder configured for success event (customizable)
    pub fn success_builder(self) -> Self {
        self
    }

    /// Build and dispatch as success event immediately
    pub fn success(self) {
        let (message, pii_result) = self.process_message();
        let mut context = self
            .context
            .unwrap_or_else(crate::observe::context::shortcuts::full);
        update_context_with_pii(&mut context, &pii_result);
        dispatch_success(message, context, self.metadata);
    }

    /// Returns a builder configured for trace event (customizable)
    pub fn trace_builder(self) -> Self {
        self
    }

    /// Build and dispatch as trace event immediately
    pub fn trace(self) {
        let (message, pii_result) = self.process_message();
        let mut context = self
            .context
            .unwrap_or_else(crate::observe::context::shortcuts::full);
        update_context_with_pii(&mut context, &pii_result);
        dispatch_trace(message, context, self.metadata);
    }

    /// Build and dispatch as authentication success event
    pub fn auth_success(self) {
        let (message, pii_result) = self.process_message();
        let mut context = self
            .context
            .unwrap_or_else(|| crate::observe::context::shortcuts::authentication(""));
        update_context_with_pii(&mut context, &pii_result);
        // Delegate to dispatch function that handles message parsing
        dispatch_auth_success_from_message(message, context);
    }

    /// Build and dispatch as authentication failure event
    pub fn auth_failure(self) {
        let (message, pii_result) = self.process_message();
        let mut context = self
            .context
            .unwrap_or_else(|| crate::observe::context::shortcuts::authentication(""));
        update_context_with_pii(&mut context, &pii_result);
        // Delegate to dispatch function that handles message parsing
        dispatch_auth_failure_from_message(message, context);
    }
}
