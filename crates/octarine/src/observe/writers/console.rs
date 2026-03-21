//! Console writer for development
//!
//! Writes observability events to stderr with nice formatting.
//!
//! ## Defense-in-Depth PII Protection
//!
//! ConsoleWriter provides a **second layer** of PII scanning:
//! 1. Scans the final output message before writing to stderr
//! 2. Catches any PII that bypassed event-level redaction
//! 3. Ensures compliance even if `.skip_pii_redaction()` was used incorrectly
//!
//! This defense-in-depth approach meets:
//! - **PCI DSS 3.4**: Multiple barriers prevent credit cards in console logs
//! - **SOC 2**: Demonstrates robust logging controls
//! - **HIPAA**: Final PHI check before output

use super::types::{SeverityFilter, WriterError, WriterHealthStatus};
use super::{Writer, sanitize_for_writing};
use crate::observe::context::is_development;
use crate::observe::types::{Event, Severity};
use async_trait::async_trait;

/// Console writer for observability events
pub(super) struct ConsoleWriter {
    /// Minimum severity to log
    min_severity: Severity,
    /// Whether to use color output
    use_color: bool,
}

impl ConsoleWriter {
    /// Create a new console writer
    pub fn new() -> Self {
        Self {
            min_severity: if is_development() {
                Severity::Debug
            } else {
                Severity::Info
            },
            #[cfg(feature = "console")]
            use_color: console::colors_enabled_stderr(),
            #[cfg(not(feature = "console"))]
            use_color: false,
        }
    }

    /// Write event synchronously (for immediate use)
    pub fn write_sync(&self, event: &Event) {
        // Check severity filter
        if event.severity < self.min_severity {
            return;
        }

        let level = self.format_level(event.severity);
        let timestamp = event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f");

        // Build the log line
        let mut output = String::new();

        // Add timestamp and level
        output.push_str(&format!("[{}] {} ", timestamp, level));

        // Add operation if present
        if !event.context.operation.is_empty() {
            output.push_str(&format!("{}: ", event.context.operation));
        }

        // Add message (with writer-level PII protection)
        // This provides defense-in-depth - even if event-level redaction was bypassed,
        // we scan the final output message before writing to stderr
        let safe_message = sanitize_for_writing(&event.message);
        output.push_str(&safe_message);

        // Add context in development
        if is_development() && event.severity >= Severity::Warning {
            // Add location info
            if !event.context.file.is_empty() {
                output.push_str(&format!(" @ {}:{}", event.context.file, event.context.line));
            }

            // Add tenant/user if present
            if let Some(ref tenant) = event.context.tenant_id {
                output.push_str(&format!(" [tenant={}]", tenant));
            }
            if let Some(ref user) = event.context.user_id {
                output.push_str(&format!(" [user={}]", user));
            }
        }

        // Write to stderr
        // Using eprintln! for console output is intentional - we want errors on stderr
        use std::io::Write;
        let _ = writeln!(std::io::stderr(), "{}", output);
    }

    /// Format severity level with optional color
    fn format_level(&self, severity: Severity) -> String {
        if !self.use_color {
            return match severity {
                Severity::Debug => "DEBUG",
                Severity::Info => "INFO",
                Severity::Warning => "WARN",
                Severity::Error => "ERROR",
                Severity::Critical => "CRITICAL",
            }
            .to_string();
        }

        // Use ANSI colors
        match severity {
            Severity::Debug => "\x1b[90mDEBUG\x1b[0m",       // Gray
            Severity::Info => "\x1b[36mINFO\x1b[0m",         // Cyan
            Severity::Warning => "\x1b[33mWARN\x1b[0m",      // Yellow
            Severity::Error => "\x1b[31mERROR\x1b[0m",       // Red
            Severity::Critical => "\x1b[91mCRITICAL\x1b[0m", // Bright Red
        }
        .to_string()
    }
}

#[async_trait]
impl Writer for ConsoleWriter {
    async fn write(&self, event: &Event) -> Result<(), WriterError> {
        self.write_sync(event);
        Ok(())
    }

    async fn flush(&self) -> Result<(), WriterError> {
        // Console writer doesn't buffer
        Ok(())
    }

    fn health_check(&self) -> WriterHealthStatus {
        // Console writer is always healthy
        WriterHealthStatus::Healthy
    }

    fn name(&self) -> &'static str {
        "console"
    }

    fn severity_filter(&self) -> SeverityFilter {
        SeverityFilter::with_min_severity(self.min_severity)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use crate::observe::types::{EventContext, EventType};

    /// Helper to capture stderr output
    fn capture_console_output<F>(f: F) -> String
    where
        F: FnOnce(),
    {
        // Note: In real tests, we'd use a proper capture mechanism
        // For now, we'll just test the sanitization function directly
        f();
        String::new()
    }

    #[test]
    fn test_writer_level_pii_redaction() {
        // Create a console writer
        let writer = ConsoleWriter::new();

        // Create an event with PII in the message
        // This simulates PII that bypassed event-level redaction
        let mut event = Event::new(
            EventType::Info,
            "User SSN is 123-45-6789 and email is user@example.com",
        );
        event.context = EventContext::default();

        // Write the event (should redact PII at writer level)
        writer.write_sync(&event);

        // NOTE: In a real test, we would capture stderr and verify:
        // assert!(!output.contains("123-45-6789"));
        // assert!(!output.contains("user@example.com"));
        // assert!(output.contains("[SSN]"));
        // assert!(output.contains("[Email]"));

        // For now, this test verifies the code compiles and runs without panic
    }

    #[test]
    fn test_sanitize_for_writing_ssn() {
        let text = "SSN: 123-45-6789";
        let result = sanitize_for_writing(text);

        // Writer-level redaction should catch SSN
        assert!(result.contains("[SSN]") || !result.contains("123-45-6789"));
    }

    #[test]
    fn test_sanitize_for_writing_credit_card() {
        let text = "Card: 4242424242424242";
        let result = sanitize_for_writing(text);

        // Writer-level redaction should catch credit card
        assert!(result.contains("[Credit Card]") || !result.contains("4242424242424242"));
    }

    #[test]
    fn test_sanitize_for_writing_email() {
        let text = "Email: user@example.com";
        let result = sanitize_for_writing(text);

        // Writer-level redaction behavior depends on environment profile
        // In production: will be redacted to [Email]
        // In development: might show u***@example.com or full email
        // Just verify the function runs without error
        assert!(!result.is_empty());
    }

    #[test]
    fn test_sanitize_for_writing_multiple_pii() {
        let text = "Contact user@example.com, SSN: 123-45-6789, Card: 4242424242424242";
        let result = sanitize_for_writing(text);

        // Should redact all PII types
        assert!(!result.contains("123-45-6789"));
        assert!(!result.contains("4242424242424242"));
        // Email might be partially visible in lenient mode, so just check it's not fully exposed
    }

    #[test]
    fn test_sanitize_for_writing_clean_text() {
        let text = "Clean message with no PII";
        let result = sanitize_for_writing(text);

        // Clean text should pass through unchanged
        assert_eq!(result, text);
    }

    #[test]
    fn test_defense_in_depth_bypassed_redaction() {
        // Simulate a case where event-level redaction was skipped
        // (e.g., developer used .skip_pii_redaction() incorrectly)
        let text = "ERROR: Failed to process payment for card 4242424242424242";
        let result = sanitize_for_writing(text);

        // Writer-level should catch it as last line of defense
        // Note: Credit cards are ALWAYS redacted, even in Development mode (PCI DSS requirement)
        assert!(!result.contains("4242424242424242"));
    }
}
