//! Format builder with observe instrumentation
//!
//! Wraps the primitives FormatBuilder with audit trails.

use std::time::Instant;

use serde::Serialize;
use serde_json::Value as JsonValue;

use crate::observe::metrics::record;
use crate::observe::{debug, warn};
use crate::primitives::data::formats::{FormatBuilder as PrimBuilder, FormatType, XmlDocument};
use crate::primitives::types::Result;

crate::define_metrics! {
    parse_ms => "data.formats.parse_ms",
    serialize_ms => "data.formats.serialize_ms",
    detect_ms => "data.formats.detect_ms",
}

/// Builder for format parsing and serialization with observability
///
/// This is the Layer 3 wrapper that adds observe instrumentation
/// to the primitives FormatBuilder.
#[derive(Debug, Clone, Copy)]
pub struct FormatBuilder {
    inner: PrimBuilder,
    emit_events: bool,
}

impl Default for FormatBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FormatBuilder {
    /// Create a new format builder with observe events enabled
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
    // JSON Operations
    // ========================================================================

    /// Parse JSON content
    pub fn parse_json(&self, input: &str) -> Result<JsonValue> {
        let start = Instant::now();
        debug("format.parse", "Parsing JSON content");
        let result = self.inner.parse_json(input);
        if self.emit_events {
            record(
                metric_names::parse_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }
        if result.is_err() {
            warn("format.parse", "JSON parsing failed");
        }
        result
    }

    /// Serialize value to JSON
    pub fn serialize_json<T: Serialize>(&self, value: &T) -> Result<String> {
        let start = Instant::now();
        debug("format.serialize", "Serializing to JSON");
        let result = self.inner.serialize_json(value);
        if self.emit_events {
            record(
                metric_names::serialize_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }
        result
    }

    /// Serialize value to pretty JSON
    pub fn serialize_json_pretty<T: Serialize>(&self, value: &T) -> Result<String> {
        let start = Instant::now();
        debug("format.serialize", "Serializing to pretty JSON");
        let result = self.inner.serialize_json_pretty(value);
        if self.emit_events {
            record(
                metric_names::serialize_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }
        result
    }

    // ========================================================================
    // XML Operations
    // ========================================================================

    /// Parse XML content
    pub fn parse_xml(&self, input: &str) -> Result<XmlDocument> {
        let start = Instant::now();
        debug("format.parse", "Parsing XML content");
        let result = self.inner.parse_xml(input);
        if self.emit_events {
            record(
                metric_names::parse_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }
        if result.is_err() {
            warn("format.parse", "XML parsing failed");
        }
        result
    }

    /// Serialize XML document to string
    pub fn serialize_xml(&self, doc: &XmlDocument) -> Result<String> {
        let start = Instant::now();
        debug("format.serialize", "Serializing to XML");
        let result = self.inner.serialize_xml(doc);
        if self.emit_events {
            record(
                metric_names::serialize_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }
        result
    }

    // ========================================================================
    // YAML Operations
    // ========================================================================

    /// Parse YAML content
    pub fn parse_yaml(&self, input: &str) -> Result<serde_yaml::Value> {
        let start = Instant::now();
        debug("format.parse", "Parsing YAML content");
        let result = self.inner.parse_yaml(input);
        if self.emit_events {
            record(
                metric_names::parse_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }
        if result.is_err() {
            warn("format.parse", "YAML parsing failed");
        }
        result
    }

    /// Serialize value to YAML
    pub fn serialize_yaml<T: Serialize>(&self, value: &T) -> Result<String> {
        let start = Instant::now();
        debug("format.serialize", "Serializing to YAML");
        let result = self.inner.serialize_yaml(value);
        if self.emit_events {
            record(
                metric_names::serialize_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }
        result
    }

    // ========================================================================
    // Format Detection
    // ========================================================================

    /// Detect format from content
    #[must_use]
    pub fn detect_format(&self, input: &str) -> Option<FormatType> {
        let start = Instant::now();
        debug("format.detect", "Detecting format from content");
        let format = self.inner.detect_from_content(input);
        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }
        if format.is_none() {
            debug("format.detect", "Could not detect format");
        }
        format
    }

    /// Detect format from file extension
    #[must_use]
    pub fn detect_from_extension(&self, ext: &str) -> Option<FormatType> {
        self.inner.detect_from_extension(ext)
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

    static METRICS_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_builder_creation() {
        let builder = FormatBuilder::new();
        assert!(builder.emit_events);

        let silent = FormatBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events_toggle() {
        let builder = FormatBuilder::new().with_events(false);
        assert!(!builder.emit_events);

        let builder = FormatBuilder::silent().with_events(true);
        assert!(builder.emit_events);
    }

    #[test]
    fn test_builder_parse_json() {
        let builder = FormatBuilder::new();
        let result = builder.parse_json(r#"{"key": "value"}"#);
        assert!(result.is_ok());
    }

    #[test]
    fn test_builder_parse_xml() {
        let builder = FormatBuilder::new();
        let result = builder.parse_xml("<root><child/></root>");
        assert!(result.is_ok());
    }

    #[test]
    fn test_builder_parse_yaml() {
        let builder = FormatBuilder::new();
        let result = builder.parse_yaml("key: value");
        assert!(result.is_ok());
    }

    #[test]
    fn test_builder_detect_format() {
        let builder = FormatBuilder::new();

        assert!(matches!(
            builder.detect_format(r#"{"key": "value"}"#),
            Some(FormatType::Json)
        ));
        assert!(matches!(
            builder.detect_format("<root/>"),
            Some(FormatType::Xml)
        ));
        assert!(matches!(
            builder.detect_format("key: value"),
            Some(FormatType::Yaml)
        ));
    }

    #[test]
    fn test_metrics_parse_ms_recorded() {
        let _guard = METRICS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let builder = FormatBuilder::new();
        flush_for_testing();
        let before = snapshot()
            .histograms
            .get("data.formats.parse_ms")
            .map_or(0, |h| h.count);

        let _ = builder.parse_json(r#"{"key": "value"}"#);
        flush_for_testing();

        let after = snapshot()
            .histograms
            .get("data.formats.parse_ms")
            .map_or(0, |h| h.count);
        assert!(
            after > before,
            "parse_ms histogram should record at least one sample"
        );
    }

    #[test]
    fn test_metrics_serialize_ms_recorded() {
        let _guard = METRICS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let builder = FormatBuilder::new();
        flush_for_testing();
        let before = snapshot()
            .histograms
            .get("data.formats.serialize_ms")
            .map_or(0, |h| h.count);

        let _ = builder.serialize_json(&serde_json::json!({"k": "v"}));
        flush_for_testing();

        let after = snapshot()
            .histograms
            .get("data.formats.serialize_ms")
            .map_or(0, |h| h.count);
        assert!(after > before, "serialize_ms histogram should record");
    }

    #[test]
    fn test_metrics_detect_ms_recorded() {
        let _guard = METRICS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let builder = FormatBuilder::new();
        flush_for_testing();
        let before = snapshot()
            .histograms
            .get("data.formats.detect_ms")
            .map_or(0, |h| h.count);

        let _ = builder.detect_format(r#"{"k": "v"}"#);
        flush_for_testing();

        let after = snapshot()
            .histograms
            .get("data.formats.detect_ms")
            .map_or(0, |h| h.count);
        assert!(after > before, "detect_ms histogram should record");
    }

    #[test]
    fn test_silent_mode_emits_no_metrics() {
        // Structural test: `silent()` returns a builder with emit_events=false,
        // and every metric call site in this module is gated by `if self.emit_events`.
        // A behavioral delta-assertion would race with concurrent tests across the
        // workspace that hit these same global metric names.
        let builder = FormatBuilder::silent();
        assert!(!builder.emit_events);

        // Sanity: invoking through the silent builder still works functionally.
        let _ = builder.parse_json(r#"{"k": "v"}"#);
        assert!(matches!(
            builder.detect_format(r#"{"k": "v"}"#),
            Some(FormatType::Json)
        ));
    }
}
