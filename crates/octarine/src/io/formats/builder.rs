//! Format I/O builder with observe instrumentation
//!
//! Wraps the primitives FormatIoBuilder with audit trails.

use std::path::Path;
use std::time::Instant;

use crate::observe::Result;
use crate::observe::metrics::{increment_by, record};
use crate::observe::{debug, warn};
use crate::primitives::data::formats::FormatType;
use crate::primitives::io::formats::{
    FormatIoBuilder as PrimBuilder, FormatReadOptions, FormatWriteOptions, ReadResult,
};

crate::define_metrics! {
    read_ms => "io.formats.read_ms",
    write_ms => "io.formats.write_ms",
    files_read => "io.formats.files_read",
    files_written => "io.formats.files_written",
}

/// Builder for format-aware I/O operations with observability
///
/// This is the Layer 3 wrapper that adds observe instrumentation
/// to the primitives FormatIoBuilder.
///
/// # Observability
///
/// Read and write operations record timing (`io.formats.read_ms`,
/// `io.formats.write_ms`) and success counts (`io.formats.files_read`,
/// `io.formats.files_written`).
///
/// Events embed the caller-supplied path, so bulk or untrusted-path workloads
/// should use [`silent()`](Self::silent) or
/// [`with_events(false)`](Self::with_events) to suppress both events and
/// metrics.
#[derive(Debug, Clone, Copy)]
pub struct FormatIoBuilder {
    inner: PrimBuilder,
    /// Whether to emit events and record metrics.
    emit_events: bool,
}

impl Default for FormatIoBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl FormatIoBuilder {
    /// Create a new format I/O builder with observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: PrimBuilder::new(),
            emit_events: true,
        }
    }

    /// Create a builder that emits no events and records no metrics
    ///
    /// Use for bulk operations, or when paths are untrusted and must not
    /// reach the audit trail.
    #[must_use]
    pub fn silent() -> Self {
        Self {
            inner: PrimBuilder::new(),
            emit_events: false,
        }
    }

    /// Enable or disable observe events and metrics
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    // ========================================================================
    // Reading Operations
    // ========================================================================

    /// Instrument a read operation: time it, count successes, log failures.
    ///
    /// Centralizes the `emit_events` gate so every read entry point is
    /// instrumented identically and no path string reaches the audit trail
    /// when events are disabled.
    fn instrument_read<F>(&self, path: &Path, what: &str, read: F) -> Result<ReadResult>
    where
        F: FnOnce() -> Result<ReadResult>,
    {
        if self.emit_events {
            debug("io.format", format!("Reading {what}: {}", path.display()));
        }

        let start = Instant::now();
        let result = read();

        if self.emit_events {
            record(
                metric_names::read_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            match result {
                Ok(_) => increment_by(metric_names::files_read(), 1),
                Err(_) => warn(
                    "io.format",
                    format!("Failed to read {what}: {}", path.display()),
                ),
            }
        }

        result
    }

    /// Instrument a write operation: time it, count successes, log failures.
    fn instrument_write<F>(&self, path: &Path, what: &str, write: F) -> Result<()>
    where
        F: FnOnce() -> Result<()>,
    {
        if self.emit_events {
            debug("io.format", format!("Writing {what}: {}", path.display()));
        }

        let start = Instant::now();
        let result = write();

        if self.emit_events {
            record(
                metric_names::write_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
            match result {
                Ok(()) => increment_by(metric_names::files_written(), 1),
                Err(_) => warn(
                    "io.format",
                    format!("Failed to write {what}: {}", path.display()),
                ),
            }
        }

        result
    }

    /// Read a file with automatic format detection
    pub fn read_file(&self, path: &Path) -> Result<ReadResult> {
        self.instrument_read(path, "file", || self.inner.read_file(path))
    }

    /// Read a file with specific options
    pub fn read_file_with_options(
        &self,
        path: &Path,
        options: &FormatReadOptions,
    ) -> Result<ReadResult> {
        self.instrument_read(path, "file with options", || {
            self.inner.read_file_with_options(path, options)
        })
    }

    /// Read a JSON file
    pub fn read_json_file(&self, path: &Path) -> Result<ReadResult> {
        self.instrument_read(path, "JSON file", || self.inner.read_json_file(path))
    }

    /// Read an XML file
    pub fn read_xml_file(&self, path: &Path) -> Result<ReadResult> {
        self.instrument_read(path, "XML file", || self.inner.read_xml_file(path))
    }

    /// Read a YAML file
    pub fn read_yaml_file(&self, path: &Path) -> Result<ReadResult> {
        self.instrument_read(path, "YAML file", || self.inner.read_yaml_file(path))
    }

    // ========================================================================
    // Writing Operations
    // ========================================================================

    /// Write content to a file
    pub fn write_file(&self, path: &Path, content: &str, format: FormatType) -> Result<()> {
        self.instrument_write(path, &format!("{format:?} file"), || {
            self.inner.write_file(path, content, format)
        })
    }

    /// Write content with specific options
    pub fn write_file_with_options(
        &self,
        path: &Path,
        content: &str,
        options: &FormatWriteOptions,
    ) -> Result<()> {
        self.instrument_write(path, "file with options", || {
            self.inner.write_file_with_options(path, content, options)
        })
    }

    /// Write JSON content to a file
    pub fn write_json_file(&self, path: &Path, content: &str) -> Result<()> {
        self.instrument_write(path, "JSON file", || {
            self.inner.write_json_file(path, content)
        })
    }

    /// Write XML content to a file
    pub fn write_xml_file(&self, path: &Path, content: &str) -> Result<()> {
        self.instrument_write(path, "XML file", || {
            self.inner.write_xml_file(path, content)
        })
    }

    /// Write YAML content to a file
    pub fn write_yaml_file(&self, path: &Path, content: &str) -> Result<()> {
        self.instrument_write(path, "YAML file", || {
            self.inner.write_yaml_file(path, content)
        })
    }

    // ========================================================================
    // Format Detection
    // ========================================================================

    /// Detect format from file path
    #[must_use]
    pub fn detect_format_from_path(&self, path: &Path) -> Option<FormatType> {
        self.inner.detect_format_from_path(path)
    }

    /// Detect format from content
    #[must_use]
    pub fn detect_format_from_content(&self, content: &str) -> Option<FormatType> {
        self.inner.detect_format_from_content(content)
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
    use tempfile::tempdir;

    /// Serializes metrics-touching tests within this file so they don't race
    /// each other on the shared global registry.
    static METRICS_LOCK: Mutex<()> = Mutex::new(());

    fn histogram_count(name: &str) -> u64 {
        snapshot().histograms.get(name).map_or(0, |h| h.count)
    }

    fn counter_value(name: &str) -> u64 {
        snapshot().counters.get(name).map_or(0, |c| c.value)
    }

    #[test]
    fn test_builder_creation_event_flags() {
        assert!(FormatIoBuilder::new().emit_events);
        assert!(!FormatIoBuilder::silent().emit_events);
        assert!(!FormatIoBuilder::new().with_events(false).emit_events);
        assert!(FormatIoBuilder::silent().with_events(true).emit_events);
        // Default must match new(), not the derive's `false`.
        assert!(FormatIoBuilder::default().emit_events);
    }

    #[test]
    fn test_metrics_read_write_recorded() {
        let _guard = METRICS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let builder = FormatIoBuilder::new();
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("metrics.json");

        flush_for_testing();
        let reads_before = histogram_count("io.formats.read_ms");
        let writes_before = histogram_count("io.formats.write_ms");
        let written_before = counter_value("io.formats.files_written");

        builder.write_json_file(&path, r#"{"a":1}"#).expect("write");
        builder.read_json_file(&path).expect("read");
        flush_for_testing();

        assert!(
            histogram_count("io.formats.write_ms") > writes_before,
            "write_ms should record on an instrumented write",
        );
        assert!(
            histogram_count("io.formats.read_ms") > reads_before,
            "read_ms should record on an instrumented read",
        );
        assert_eq!(
            counter_value("io.formats.files_written"),
            written_before.saturating_add(1),
            "a successful write must increment files_written exactly once",
        );
    }

    #[test]
    fn test_silent_builder_records_no_metrics() {
        let _guard = METRICS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let builder = FormatIoBuilder::silent();
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("silent.json");

        flush_for_testing();
        let reads_before = histogram_count("io.formats.read_ms");
        let writes_before = histogram_count("io.formats.write_ms");

        // Exercise both a success and a failure path: neither may record.
        builder.write_json_file(&path, r#"{"a":1}"#).expect("write");
        builder.read_json_file(&path).expect("read");
        assert!(
            builder
                .read_json_file(&dir.path().join("missing.json"))
                .is_err()
        );
        flush_for_testing();

        assert_eq!(
            histogram_count("io.formats.write_ms"),
            writes_before,
            "silent() must not record write_ms",
        );
        assert_eq!(
            histogram_count("io.formats.read_ms"),
            reads_before,
            "silent() must not record read_ms",
        );
    }

    #[test]
    fn test_failed_read_does_not_count_as_success() {
        let _guard = METRICS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let builder = FormatIoBuilder::new();

        flush_for_testing();
        let files_read_before = counter_value("io.formats.files_read");
        let read_ms_before = histogram_count("io.formats.read_ms");

        assert!(
            builder
                .read_json_file(Path::new("/nonexistent/definitely/missing.json"))
                .is_err()
        );
        flush_for_testing();

        assert_eq!(
            counter_value("io.formats.files_read"),
            files_read_before,
            "a failed read must not increment the success counter",
        );
        assert!(
            histogram_count("io.formats.read_ms") > read_ms_before,
            "a failed read is still timed",
        );
    }

    #[test]
    fn test_silent_builder_still_reads_and_writes() {
        // Disabling events must not disable the underlying operation.
        let builder = FormatIoBuilder::silent();
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("works.yaml");

        builder.write_yaml_file(&path, "key: value").expect("write");
        let result = builder.read_yaml_file(&path).expect("read");
        assert_eq!(result.content, "key: value");
    }

    #[test]
    fn test_builder_read_write_json() {
        let builder = FormatIoBuilder::new();
        let dir = tempdir().expect("create temp dir");
        let path = dir.path().join("test.json");

        let content = r#"{"key": "value"}"#;
        builder.write_json_file(&path, content).expect("write");

        let result = builder.read_json_file(&path).expect("read");
        assert!(matches!(result.format, FormatType::Json));
    }

    #[test]
    fn test_builder_detect_format() {
        let builder = FormatIoBuilder::new();

        assert!(matches!(
            builder.detect_format_from_path(Path::new("data.json")),
            Some(FormatType::Json)
        ));
        assert!(matches!(
            builder.detect_format_from_content("<root/>"),
            Some(FormatType::Xml)
        ));
    }

    #[test]
    fn test_builder_read_write_xml_roundtrip() {
        let builder = FormatIoBuilder::new();
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("doc.xml");
        let content = "<root><child/></root>";

        builder.write_xml_file(&path, content).expect("write xml");
        let result = builder.read_xml_file(&path).expect("read xml");
        assert!(matches!(result.format, FormatType::Xml));
        // Content round-trips byte-for-byte.
        assert_eq!(result.content, content);
    }

    #[test]
    fn test_builder_read_write_yaml_roundtrip() {
        let builder = FormatIoBuilder::new();
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("cfg.yaml");
        let content = "key: value";

        builder.write_yaml_file(&path, content).expect("write yaml");
        let result = builder.read_yaml_file(&path).expect("read yaml");
        assert!(matches!(result.format, FormatType::Yaml));
        assert_eq!(result.content, content);
    }

    #[test]
    fn test_write_file_dispatches_on_format() {
        let builder = FormatIoBuilder::new();
        let dir = tempdir().expect("temp dir");

        // write_file with an explicit format, then auto-detected read back.
        let path = dir.path().join("auto.yaml");
        builder
            .write_file(&path, "a: 1", FormatType::Yaml)
            .expect("write");
        let result = builder.read_file(&path).expect("read");
        assert!(matches!(result.format, FormatType::Yaml));
    }

    #[test]
    fn test_read_file_auto_detects_by_extension() {
        let builder = FormatIoBuilder::new();
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("data.json");
        builder.write_json_file(&path, r#"{"a":1}"#).expect("write");
        let result = builder.read_file(&path).expect("read");
        assert!(matches!(result.format, FormatType::Json));
    }

    #[test]
    fn test_read_missing_file_is_err() {
        // The Layer 3 wrapper must surface the primitive read error (and it
        // logs a warning on the failure path).
        let builder = FormatIoBuilder::new();
        let result = builder.read_file(Path::new("/nonexistent/definitely/missing.json"));
        assert!(result.is_err());
    }

    #[test]
    fn test_read_json_file_missing_is_err() {
        let builder = FormatIoBuilder::new();
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("nope.json");
        assert!(builder.read_json_file(&path).is_err());
    }

    #[test]
    fn test_write_to_unwritable_path_is_err() {
        // Writing into a directory that does not exist must error and trip the
        // warn() branch in write_file.
        let builder = FormatIoBuilder::new();
        let path = Path::new("/nonexistent/dir/out.json");
        let result = builder.write_file(path, r#"{"k":1}"#, FormatType::Json);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_file_with_options() {
        use crate::primitives::io::formats::FormatReadOptions;
        let builder = FormatIoBuilder::new();
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("data.json");
        builder
            .write_json_file(&path, r#"{"ok":true}"#)
            .expect("write");

        let opts = FormatReadOptions::json();
        let result = builder
            .read_file_with_options(&path, &opts)
            .expect("read w/ options");
        assert!(matches!(result.format, FormatType::Json));
    }

    #[test]
    fn test_write_file_with_options() {
        use crate::primitives::io::formats::FormatWriteOptions;
        let builder = FormatIoBuilder::new();
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join("out.json");

        let opts = FormatWriteOptions::json();
        builder
            .write_file_with_options(&path, r#"{"k":1}"#, &opts)
            .expect("write w/ options");
        assert!(path.exists());
        let result = builder.read_json_file(&path).expect("read");
        assert!(matches!(result.format, FormatType::Json));
    }

    #[test]
    fn test_detect_format_from_path_variants() {
        let builder = FormatIoBuilder::new();
        assert!(matches!(
            builder.detect_format_from_path(Path::new("a.yaml")),
            Some(FormatType::Yaml)
        ));
        assert!(matches!(
            builder.detect_format_from_path(Path::new("a.yml")),
            Some(FormatType::Yaml)
        ));
        assert!(matches!(
            builder.detect_format_from_path(Path::new("a.xml")),
            Some(FormatType::Xml)
        ));
        // Unknown extension yields None.
        assert!(
            builder
                .detect_format_from_path(Path::new("a.bin"))
                .is_none()
        );
        // No extension yields None.
        assert!(
            builder
                .detect_format_from_path(Path::new("noext"))
                .is_none()
        );
    }

    #[test]
    fn test_detect_format_from_content_variants() {
        let builder = FormatIoBuilder::new();
        // JSON object and array.
        assert!(matches!(
            builder.detect_format_from_content(r#"{"a":1}"#),
            Some(FormatType::Json)
        ));
        assert!(matches!(
            builder.detect_format_from_content("[1,2,3]"),
            Some(FormatType::Json)
        ));
        // XML.
        assert!(matches!(
            builder.detect_format_from_content("<a/>"),
            Some(FormatType::Xml)
        ));
        // YAML document marker and key: value form.
        assert!(matches!(
            builder.detect_format_from_content("---\nk: v"),
            Some(FormatType::Yaml)
        ));
        assert!(matches!(
            builder.detect_format_from_content("- item"),
            Some(FormatType::Yaml)
        ));
        // Unrecognized content yields None.
        assert!(builder.detect_format_from_content("plain text").is_none());
    }
}
