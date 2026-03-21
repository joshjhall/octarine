//! Metrics export for Prometheus and StatsD
//!
//! This module provides exporters for metrics in standard formats:
//! - **Prometheus**: Text exposition format for scraping
//! - **StatsD**: UDP push format for metrics aggregation
//!
//! # Prometheus Export
//!
//! The Prometheus exporter generates metrics in the standard text exposition format.
//! ```text
//! # TYPE api_requests counter
//! api_requests{tenant="acme",env="prod"} 12345
//!
//! # TYPE queue_depth gauge
//! queue_depth{tenant="acme",env="prod"} 42
//!
//! # TYPE response_time histogram
//! response_time_bucket{le="0.005"} 500
//! response_time_bucket{le="0.01"} 1000
//! response_time_bucket{le="+Inf"} 1500
//! response_time_sum 75.5
//! response_time_count 1500
//! ```
//!
//! # StatsD Export
//!
//! The StatsD writer sends metrics via UDP in DogStatsD-compatible format:
//! ```text
//! api.requests:1|c|#tenant:acme,env:prod
//! queue.depth:42|g|#tenant:acme,env:prod
//! response.time:45.2|h|#tenant:acme,env:prod
//! ```
//!
//! # Examples
//!
//! ```rust,no_run
//! use octarine::observe::metrics::{
//!     PrometheusExporter, PrometheusConfig,
//!     StatsDWriter, StatsDConfig,
//! };
//!
//! // Prometheus exporter
//! let prometheus = PrometheusExporter::new(PrometheusConfig::default());
//! let output = prometheus.render();
//!
//! // StatsD writer
//! let statsd = StatsDWriter::new(StatsDConfig::default());
//! statsd.counter("api.requests", 1, &[("tenant", "acme")]);
//! ```

mod prometheus;
mod statsd;

pub use prometheus::{PrometheusConfig, PrometheusExporter};
pub use statsd::{StatsDConfig, StatsDWriter};

use std::collections::HashMap;

/// Default labels applied to all exported metrics
///
/// These labels provide context for multi-tenant and multi-environment deployments.
#[derive(Debug, Clone, Default)]
pub struct DefaultLabels {
    /// Tenant identifier (from thread-local context)
    pub tenant_id: Option<String>,
    /// Environment (dev, staging, prod)
    pub environment: Option<String>,
    /// Service name
    pub service: Option<String>,
    /// Application version
    pub version: Option<String>,
    /// Additional custom labels
    pub custom: HashMap<String, String>,
}

impl DefaultLabels {
    /// Create a new DefaultLabels instance
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the tenant ID
    pub fn tenant(mut self, tenant: impl Into<String>) -> Self {
        self.tenant_id = Some(tenant.into());
        self
    }

    /// Set the environment
    pub fn environment(mut self, env: impl Into<String>) -> Self {
        self.environment = Some(env.into());
        self
    }

    /// Set the service name
    pub fn service(mut self, service: impl Into<String>) -> Self {
        self.service = Some(service.into());
        self
    }

    /// Set the version
    pub fn version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Add a custom label
    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.custom.insert(key.into(), value.into());
        self
    }

    /// Format labels for Prometheus (key="value",key2="value2")
    pub fn format_prometheus(&self) -> String {
        let mut parts = Vec::new();

        if let Some(ref tenant) = self.tenant_id {
            parts.push(format!("tenant=\"{}\"", escape_prometheus_value(tenant)));
        }
        if let Some(ref env) = self.environment {
            parts.push(format!("env=\"{}\"", escape_prometheus_value(env)));
        }
        if let Some(ref service) = self.service {
            parts.push(format!("service=\"{}\"", escape_prometheus_value(service)));
        }
        if let Some(ref version) = self.version {
            parts.push(format!("version=\"{}\"", escape_prometheus_value(version)));
        }
        for (key, value) in &self.custom {
            parts.push(format!(
                "{}=\"{}\"",
                escape_prometheus_name(key),
                escape_prometheus_value(value)
            ));
        }

        parts.join(",")
    }

    /// Format labels for StatsD (#key:value,key2:value2)
    pub fn format_statsd(&self) -> String {
        let mut parts = Vec::new();

        if let Some(ref tenant) = self.tenant_id {
            parts.push(format!("tenant:{}", escape_statsd_value(tenant)));
        }
        if let Some(ref env) = self.environment {
            parts.push(format!("env:{}", escape_statsd_value(env)));
        }
        if let Some(ref service) = self.service {
            parts.push(format!("service:{}", escape_statsd_value(service)));
        }
        if let Some(ref version) = self.version {
            parts.push(format!("version:{}", escape_statsd_value(version)));
        }
        for (key, value) in &self.custom {
            parts.push(format!(
                "{}:{}",
                escape_statsd_value(key),
                escape_statsd_value(value)
            ));
        }

        if parts.is_empty() {
            String::new()
        } else {
            format!("|#{}", parts.join(","))
        }
    }

    /// Check if any labels are set
    pub fn is_empty(&self) -> bool {
        self.tenant_id.is_none()
            && self.environment.is_none()
            && self.service.is_none()
            && self.version.is_none()
            && self.custom.is_empty()
    }
}

/// Escape a metric name for Prometheus (replace invalid chars with _)
fn escape_prometheus_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Escape a label value for Prometheus (escape \, ", newline)
fn escape_prometheus_value(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Escape a value for StatsD tags (remove special chars)
fn escape_statsd_value(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-' || *c == '.')
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_default_labels_builder() {
        let labels = DefaultLabels::new()
            .tenant("acme")
            .environment("prod")
            .service("api")
            .version("1.0.0")
            .label("region", "us-east-1");

        assert_eq!(labels.tenant_id, Some("acme".to_string()));
        assert_eq!(labels.environment, Some("prod".to_string()));
        assert_eq!(labels.service, Some("api".to_string()));
        assert_eq!(labels.version, Some("1.0.0".to_string()));
        assert_eq!(labels.custom.get("region"), Some(&"us-east-1".to_string()));
    }

    #[test]
    fn test_format_prometheus() {
        let labels = DefaultLabels::new().tenant("acme").environment("prod");

        let formatted = labels.format_prometheus();
        assert!(formatted.contains("tenant=\"acme\""));
        assert!(formatted.contains("env=\"prod\""));
    }

    #[test]
    fn test_format_prometheus_escaping() {
        let labels = DefaultLabels::new().tenant("test\"value\nwith\\escapes");

        let formatted = labels.format_prometheus();
        assert!(formatted.contains("tenant=\"test\\\"value\\nwith\\\\escapes\""));
    }

    #[test]
    fn test_format_statsd() {
        let labels = DefaultLabels::new().tenant("acme").environment("prod");

        let formatted = labels.format_statsd();
        assert!(formatted.starts_with("|#"));
        assert!(formatted.contains("tenant:acme"));
        assert!(formatted.contains("env:prod"));
    }

    #[test]
    fn test_format_statsd_empty() {
        let labels = DefaultLabels::new();
        assert_eq!(labels.format_statsd(), "");
    }

    #[test]
    fn test_escape_prometheus_name() {
        assert_eq!(escape_prometheus_name("metric.name"), "metric_name");
        assert_eq!(escape_prometheus_name("metric-name"), "metric_name");
        assert_eq!(escape_prometheus_name("metric_name_123"), "metric_name_123");
    }

    #[test]
    fn test_is_empty() {
        assert!(DefaultLabels::new().is_empty());
        assert!(!DefaultLabels::new().tenant("acme").is_empty());
    }
}
