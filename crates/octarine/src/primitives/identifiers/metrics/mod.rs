//! Metrics identifier validation, sanitization, and detection
//!
//! Pure functions for validating and sanitizing metric names and labels.
//! Compatible with Prometheus, StatsD, and OpenMetrics naming conventions.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.
//! - No observe:: dependencies (uses Problem type from primitives::types)
//! - Returns data, no side effects
//! - Used by observe/metrics and security modules
//!
//! # Security Threats Addressed
//!
//! 1. **Cardinality Explosion**: Unbounded labels can exhaust memory
//! 2. **Injection Attacks**: Metric names in queries could enable injection
//! 3. **Template Injection**: `${}` or `{{}}` patterns in names
//! 4. **Path Traversal**: `../` in hierarchical metric names
//!
//! # Usage
//!
//! ```ignore
//! use octarine::primitives::identifiers::metrics::MetricsBuilder;
//!
//! let mb = MetricsBuilder::new();
//!
//! // Lenient validation (bool)
//! if mb.validate_name("api.requests") {
//!     println!("Valid metric name");
//! }
//!
//! // Strict validation (Result)
//! mb.validate_name_strict("api.requests")?;
//!
//! // Sanitization
//! let safe_name = mb.sanitize_name("API-Requests");
//! assert_eq!(safe_name, "api_requests");
//! ```

// Internal modules - not directly accessible outside metrics/
mod detection;
mod sanitization;
mod validation;

pub(crate) mod builder;

// Re-export builder and types for convenience
pub use builder::MetricsBuilder;
pub use detection::MetricViolation;

/// Default maximum length for metric names (prevents DoS)
pub const MAX_METRIC_NAME_LENGTH: usize = 200;

/// Default maximum number of labels per metric (prevents cardinality explosion)
pub const MAX_LABELS_PER_METRIC: usize = 20;

/// Default maximum length for label keys
pub const MAX_LABEL_KEY_LENGTH: usize = 100;

/// Default maximum length for label values
pub const MAX_LABEL_VALUE_LENGTH: usize = 200;

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_module_integration() {
        // Detection
        assert!(detection::is_valid_name("api_requests"));
        assert!(detection::is_valid_name("api.requests.total"));
        assert!(!detection::is_valid_name("123metric"));
        assert!(!detection::is_valid_name("api-requests"));

        // Validation
        assert!(validation::validate_name("api_requests").is_ok());
        assert!(validation::validate_name("").is_err());
        assert!(validation::validate_label_key("method").is_ok());
        assert!(validation::validate_label_value("GET").is_ok());

        // Sanitization
        assert_eq!(sanitization::sanitize_name("API-Requests"), "api_requests");
        assert_eq!(sanitization::sanitize_name(""), "metric");
    }

    #[test]
    fn test_builder_integration() {
        let mb = MetricsBuilder::new();

        // Detection via builder (bool)
        assert!(mb.is_name("api_requests"));
        assert!(!mb.is_name("123metric"));

        // Validation via builder (Result)
        assert!(mb.validate_name("api_requests").is_ok());

        // Normalization via builder (String - always succeeds)
        assert_eq!(mb.normalize_name("API-Requests"), "api_requests");

        // Sanitization via builder (Result - can fail)
        assert!(mb.sanitize_name("api_requests").is_ok());
    }

    #[test]
    fn test_security_patterns() {
        let mb = MetricsBuilder::new();

        // Injection patterns rejected
        assert!(!mb.is_name("$(whoami)"));
        assert!(!mb.is_name("${HOME}"));
        assert!(!mb.is_name("metric;drop"));

        // Path traversal rejected
        assert!(!mb.is_name("../etc/passwd"));

        // Template injection rejected
        assert!(!mb.is_name("api${test}"));
    }

    #[test]
    fn test_cardinality_protection() {
        let mb = MetricsBuilder::new();
        assert!(mb.validate_label_count(10).is_ok());
        assert!(mb.validate_label_count(MAX_LABELS_PER_METRIC).is_ok());
        assert!(mb.validate_label_count(MAX_LABELS_PER_METRIC + 1).is_err());
    }
}
