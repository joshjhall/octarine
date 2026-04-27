//! Format security builder with observe instrumentation
//!
//! Wraps the primitives FormatSecurityBuilder with audit trails.

use std::time::Instant;

use crate::observe::metrics::{increment_by, record};
use crate::observe::{debug, warn};
use crate::primitives::data::formats::FormatType;
use crate::primitives::security::formats::{
    FormatSecurityBuilder as PrimBuilder, FormatThreat, JsonPolicy, XmlPolicy, YamlPolicy,
};
use crate::primitives::types::Result;

crate::define_metrics! {
    validate_ms => "security.formats.validate_ms",
    detect_ms => "security.formats.detect_ms",
    threats_detected => "security.formats.threats_detected",
}

/// Builder for format security detection and validation with observability
///
/// This is the Layer 3 wrapper that adds observe instrumentation
/// to the primitives FormatSecurityBuilder.
#[derive(Debug, Clone, Copy)]
pub struct FormatSecurityBuilder {
    inner: PrimBuilder,
    emit_events: bool,
}

impl Default for FormatSecurityBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FormatSecurityBuilder {
    /// Create a new format security builder with observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: PrimBuilder::new(),
            emit_events: true,
        }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self {
            inner: PrimBuilder::new(),
            emit_events: false,
        }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    // ========================================================================
    // XML Security
    // ========================================================================

    /// Check if XML input contains XXE patterns
    ///
    /// Returns true if any XXE-related patterns are detected.
    #[must_use]
    pub fn is_xxe_present(&self, input: &str) -> bool {
        let result = self.inner.is_xxe_present(input);
        if self.emit_events {
            if result {
                warn("security.format", "XXE pattern detected in XML input");
                increment_by(metric_names::threats_detected(), 1);
            } else {
                debug("security.format", "No XXE patterns found");
            }
        }
        result
    }

    /// Check if XML input contains a DOCTYPE declaration
    #[must_use]
    pub fn is_dtd_present(&self, input: &str) -> bool {
        let result = self.inner.is_dtd_present(input);
        if self.emit_events && result {
            debug("security.format", "DTD declaration found in XML");
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check if XML input contains external entity declarations
    #[must_use]
    pub fn is_external_entity_present(&self, input: &str) -> bool {
        let result = self.inner.is_external_entity_present(input);
        if self.emit_events && result {
            warn("security.format", "External entity declaration detected");
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Detect all XML threats in input
    #[must_use]
    pub fn detect_xml_threats(&self, input: &str) -> Vec<FormatThreat> {
        let start = Instant::now();
        let threats = self.inner.detect_xml_threats(input);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !threats.is_empty() {
                warn(
                    "security.format",
                    format!("Detected {} XML threat(s)", threats.len()),
                );
                increment_by(metric_names::threats_detected(), threats.len() as u64);
            }
        }
        threats
    }

    /// Validate XML input against policy
    pub fn validate_xml(&self, input: &str, policy: &XmlPolicy) -> Result<()> {
        let start = Instant::now();
        debug("security.format", "Validating XML against policy");
        let result = self.inner.validate_xml(input, policy);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }
        if result.is_err() {
            warn("security.format", "XML validation failed");
        }
        result
    }

    // ========================================================================
    // JSON Security
    // ========================================================================

    /// Check if JSON input exceeds depth limit
    #[must_use]
    pub fn is_json_depth_exceeded(&self, input: &str, max_depth: usize) -> bool {
        let result = self.inner.is_json_depth_exceeded(input, max_depth);
        if self.emit_events && result {
            warn(
                "security.format",
                format!("JSON exceeds depth limit of {}", max_depth),
            );
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check if JSON input exceeds size limit
    #[must_use]
    pub fn is_json_size_exceeded(&self, input: &str, max_size: usize) -> bool {
        let result = self.inner.is_json_size_exceeded(input, max_size);
        if self.emit_events && result {
            warn(
                "security.format",
                format!("JSON exceeds size limit of {} bytes", max_size),
            );
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Detect all JSON threats according to policy
    #[must_use]
    pub fn detect_json_threats(&self, input: &str, policy: &JsonPolicy) -> Vec<FormatThreat> {
        let start = Instant::now();
        let threats = self.inner.detect_json_threats(input, policy);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !threats.is_empty() {
                warn(
                    "security.format",
                    format!("Detected {} JSON threat(s)", threats.len()),
                );
                increment_by(metric_names::threats_detected(), threats.len() as u64);
            }
        }
        threats
    }

    /// Validate JSON input against policy
    pub fn validate_json(&self, input: &str, policy: &JsonPolicy) -> Result<()> {
        let start = Instant::now();
        debug("security.format", "Validating JSON against policy");
        let result = self.inner.validate_json(input, policy);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }
        if result.is_err() {
            warn("security.format", "JSON validation failed");
        }
        result
    }

    // ========================================================================
    // YAML Security
    // ========================================================================

    /// Check if YAML input contains unsafe patterns
    #[must_use]
    pub fn is_yaml_unsafe(&self, input: &str) -> bool {
        let result = self.inner.is_yaml_unsafe(input);
        if self.emit_events {
            if result {
                warn("security.format", "Unsafe pattern detected in YAML input");
                increment_by(metric_names::threats_detected(), 1);
            } else {
                debug("security.format", "No unsafe patterns found in YAML");
            }
        }
        result
    }

    /// Check if YAML input contains unsafe tags
    #[must_use]
    pub fn is_unsafe_yaml_tag_present(&self, input: &str) -> bool {
        let result = self.inner.is_unsafe_yaml_tag_present(input);
        if self.emit_events && result {
            warn(
                "security.format",
                "Unsafe YAML tag detected (code execution risk)",
            );
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Check if YAML input shows anchor bomb patterns
    #[must_use]
    pub fn is_yaml_anchor_bomb_present(&self, input: &str) -> bool {
        let result = self.inner.is_yaml_anchor_bomb_present(input);
        if self.emit_events && result {
            warn(
                "security.format",
                "YAML anchor bomb pattern detected (DoS risk)",
            );
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Detect all YAML threats according to policy
    #[must_use]
    pub fn detect_yaml_threats(&self, input: &str, policy: &YamlPolicy) -> Vec<FormatThreat> {
        let start = Instant::now();
        let threats = self.inner.detect_yaml_threats(input, policy);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !threats.is_empty() {
                warn(
                    "security.format",
                    format!("Detected {} YAML threat(s)", threats.len()),
                );
                increment_by(metric_names::threats_detected(), threats.len() as u64);
            }
        }
        threats
    }

    /// Validate YAML input against policy
    pub fn validate_yaml(&self, input: &str, policy: &YamlPolicy) -> Result<()> {
        let start = Instant::now();
        debug("security.format", "Validating YAML against policy");
        let result = self.inner.validate_yaml(input, policy);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }
        if result.is_err() {
            warn("security.format", "YAML validation failed");
        }
        result
    }

    // ========================================================================
    // Generic Operations
    // ========================================================================

    /// Detect threats for a specific format type
    #[must_use]
    pub fn detect_threats(&self, input: &str, format: FormatType) -> Vec<FormatThreat> {
        let start = Instant::now();
        debug("security.format", "Detecting format threats");
        let threats = self.inner.detect_threats(input, format);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            if !threats.is_empty() {
                increment_by(metric_names::threats_detected(), threats.len() as u64);
            }
        }
        threats
    }

    /// Check if input contains any threats for the specified format
    #[must_use]
    pub fn is_dangerous(&self, input: &str, format: FormatType) -> bool {
        let result = self.inner.is_dangerous(input, format);
        if self.emit_events && result {
            warn("security.format", "Dangerous content detected");
            increment_by(metric_names::threats_detected(), 1);
        }
        result
    }

    /// Validate input with default strict policies
    pub fn validate_strict(&self, input: &str, format: FormatType) -> Result<()> {
        let start = Instant::now();
        debug("security.format", "Validating with strict policy");
        let result = self.inner.validate_strict(input, format);
        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }
        result
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use crate::observe::metrics::{flush_for_testing, snapshot};
    use std::sync::Mutex;

    /// Serializes metrics-touching tests within this file so they don't race
    /// each other on the shared global registry.
    static METRICS_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_builder_creation() {
        let builder = FormatSecurityBuilder::new();
        assert!(builder.emit_events);

        let silent = FormatSecurityBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events_toggle() {
        let builder = FormatSecurityBuilder::new().with_events(false);
        assert!(!builder.emit_events);
    }

    #[test]
    fn test_builder_xxe_detection() {
        let builder = FormatSecurityBuilder::silent();

        let xxe = r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#;
        assert!(builder.is_xxe_present(xxe));
        assert!(!builder.is_xxe_present("<root/>"));
    }

    #[test]
    fn test_builder_yaml_unsafe() {
        let builder = FormatSecurityBuilder::silent();

        assert!(builder.is_yaml_unsafe("!!python/exec 'import os'"));
        assert!(!builder.is_yaml_unsafe("key: value"));
    }

    #[test]
    fn test_builder_json_depth() {
        let builder = FormatSecurityBuilder::silent();

        assert!(builder.is_json_depth_exceeded(r#"{"a":{"b":{"c":1}}}"#, 2));
        assert!(!builder.is_json_depth_exceeded(r#"{"a":{"b":1}}"#, 2));
    }

    #[test]
    fn test_metrics_validate_ms_recorded() {
        let _guard = METRICS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let builder = FormatSecurityBuilder::new();
        flush_for_testing();
        let before = snapshot()
            .histograms
            .get("security.formats.validate_ms")
            .map_or(0, |h| h.count);

        let _ = builder.validate_xml("<root/>", &XmlPolicy::default());
        flush_for_testing();

        let after = snapshot()
            .histograms
            .get("security.formats.validate_ms")
            .map_or(0, |h| h.count);
        assert!(after > before, "validate_ms should record");
    }

    #[test]
    fn test_metrics_threats_detected_counter() {
        let _guard = METRICS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let builder = FormatSecurityBuilder::new();
        flush_for_testing();
        let before = snapshot()
            .counters
            .get("security.formats.threats_detected")
            .map_or(0, |c| c.value);

        let xxe = r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#;
        assert!(builder.is_xxe_present(xxe));
        flush_for_testing();

        let after = snapshot()
            .counters
            .get("security.formats.threats_detected")
            .map_or(0, |c| c.value);
        assert!(after > before, "threats_detected should increment");
    }

    #[test]
    fn test_silent_mode_emits_no_metrics() {
        // Structural test: `silent()` returns a builder with emit_events=false,
        // and every metric call site in this module is gated by `if self.emit_events`.
        // A behavioral delta-assertion would race with concurrent tests across the
        // workspace that hit these same global metric names via shortcuts/facade.
        let builder = FormatSecurityBuilder::silent();
        assert!(!builder.emit_events);

        // Sanity: invoking through the silent builder still works functionally.
        let xxe = r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#;
        assert!(builder.is_xxe_present(xxe));
        assert!(
            builder
                .validate_xml("<root/>", &XmlPolicy::default())
                .is_ok()
        );
    }
}
