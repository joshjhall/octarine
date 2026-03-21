//! SIEM integration example
//!
//! This example demonstrates:
//! - Custom writer implementation for SIEM systems
//! - Event formatting for log aggregation
//! - Syslog-compatible output
//! - Webhook/HTTP Event Collector patterns

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::print_stdout,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use chrono::Utc;
use octarine::observe::{Event, EventContext, EventType, Severity};
use octarine::{debug, error, fail_permission, fail_security, info, success, warn};
use serde_json::json;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Simulated SIEM event buffer (in production, this would be an HTTP client)
#[derive(Default)]
struct MockSiemBuffer {
    events: Mutex<VecDeque<String>>,
}

impl MockSiemBuffer {
    fn new() -> Self {
        Self::default()
    }

    fn push(&self, event: String) {
        if let Ok(mut events) = self.events.lock() {
            events.push_back(event);
        }
    }

    fn drain(&self) -> Vec<String> {
        if let Ok(mut events) = self.events.lock() {
            events.drain(..).collect()
        } else {
            Vec::new()
        }
    }
}

/// Format event for Splunk HTTP Event Collector (HEC)
fn format_for_splunk(event: &Event) -> String {
    let payload = json!({
        "time": event.timestamp.timestamp(),
        "sourcetype": "octarine_audit",
        "source": format!("{}:{}", event.context.file, event.context.line),
        "host": "application-server",
        "event": {
            "id": event.id.to_string(),
            "type": format!("{:?}", event.event_type),
            "severity": format!("{:?}", event.severity),
            "message": event.message,
            "operation": event.context.operation,
            "context": {
                "tenant_id": event.context.tenant_id.as_ref().map(|t| t.as_str()),
                "user_id": event.context.user_id.as_ref().map(|u| u.as_str()),
                "correlation_id": event.context.correlation_id.to_string(),
                "session_id": event.context.session_id,
            },
            "compliance": {
                "contains_pii": event.context.contains_pii,
                "contains_phi": event.context.contains_phi,
                "security_relevant": event.context.security_relevant,
            }
        }
    });

    serde_json::to_string(&payload).unwrap_or_default()
}

/// Format event for Elasticsearch/OpenSearch
fn format_for_elasticsearch(event: &Event) -> String {
    let payload = json!({
        "@timestamp": event.timestamp.to_rfc3339(),
        "event": {
            "id": event.id.to_string(),
            "kind": "event",
            "category": [match event.event_type {
                EventType::AuthenticationError | EventType::AuthorizationError => "authentication",
                EventType::LoginSuccess | EventType::LoginFailure => "authentication",
                _ => "process"
            }],
            "type": [match event.severity {
                Severity::Error | Severity::Critical => "error",
                Severity::Warning => "info",
                _ => "info"
            }],
            "outcome": match event.event_type {
                EventType::ValidationError | EventType::AuthenticationError |
                EventType::AuthorizationError | EventType::LoginFailure => "failure",
                _ => "success"
            }
        },
        "message": event.message,
        "log": {
            "level": format!("{:?}", event.severity).to_lowercase(),
            "logger": event.context.module_path,
        },
        "service": {
            "name": "rust-core-app",
            "type": "application"
        },
        "user": {
            "id": event.context.user_id.as_ref().map(|u| u.as_str()),
        },
        "organization": {
            "id": event.context.tenant_id.as_ref().map(|t| t.as_str()),
        },
        "trace": {
            "id": event.context.correlation_id.to_string(),
        },
        "octarine": {
            "operation": event.context.operation,
            "contains_pii": event.context.contains_pii,
            "contains_phi": event.context.contains_phi,
            "security_relevant": event.context.security_relevant,
        }
    });

    serde_json::to_string(&payload).unwrap_or_default()
}

/// Format event as syslog RFC 5424
fn format_as_syslog(event: &Event) -> String {
    let facility = 1; // user-level
    let severity = match event.severity {
        Severity::Critical => 2, // critical
        Severity::Error => 3,    // error
        Severity::Warning => 4,  // warning
        Severity::Info => 6,     // informational
        Severity::Debug => 7,    // debug
    };
    let priority = facility * 8 + severity;

    let hostname = "app-server";
    let app_name = "octarine";
    let proc_id = std::process::id();
    let msg_id = event.context.operation.replace(' ', "_");

    // Structured data for compliance
    let sd = format!(
        "[meta correlation_id=\"{}\" tenant_id=\"{}\" pii=\"{}\" security=\"{}\"]",
        event.context.correlation_id,
        event
            .context
            .tenant_id
            .as_ref()
            .map(|t| t.as_str())
            .unwrap_or("-"),
        event.context.contains_pii,
        event.context.security_relevant
    );

    format!(
        "<{}>{} {} {} {} {} {} {} {}",
        priority,
        1, // version
        event.timestamp.to_rfc3339(),
        hostname,
        app_name,
        proc_id,
        msg_id,
        sd,
        event.message
    )
}

/// Format event for Grafana Loki
fn format_for_loki(event: &Event) -> String {
    let labels = json!({
        "job": "octarine_audit",
        "level": format!("{:?}", event.severity).to_lowercase(),
        "operation": event.context.operation,
        "security_relevant": event.context.security_relevant.to_string(),
    });

    let entry = json!({
        "streams": [{
            "stream": labels,
            "values": [[
                format!("{}", event.timestamp.timestamp_nanos_opt().unwrap_or(0)),
                json!({
                    "id": event.id.to_string(),
                    "message": event.message,
                    "correlation_id": event.context.correlation_id.to_string(),
                    "tenant_id": event.context.tenant_id.as_ref().map(|t| t.as_str()),
                    "user_id": event.context.user_id.as_ref().map(|u| u.as_str()),
                    "contains_pii": event.context.contains_pii,
                }).to_string()
            ]]
        }]
    });

    serde_json::to_string(&entry).unwrap_or_default()
}

/// Create a sample event for demonstration
fn create_sample_event(
    event_type: EventType,
    severity: Severity,
    operation: &str,
    message: &str,
) -> Event {
    Event {
        id: Uuid::new_v4(),
        timestamp: Utc::now(),
        event_type,
        severity,
        message: message.to_string(),
        context: EventContext {
            tenant_id: None,
            user_id: None,
            session_id: Some("sess-12345".to_string()),
            operation: operation.to_string(),
            resource_type: None,
            resource_id: None,
            module_path: "example::observe_siem".to_string(),
            file: "observe_siem.rs".to_string(),
            line: 42,
            local_ip: None,
            source_ip: None,
            source_ip_chain: Vec::new(),
            correlation_id: Uuid::new_v4(),
            parent_span_id: None,
            contains_pii: false,
            contains_phi: false,
            security_relevant: matches!(
                event_type,
                EventType::AuthenticationError
                    | EventType::AuthorizationError
                    | EventType::LoginFailure
            ),
            pii_types: Vec::new(),
            compliance: Default::default(),
        },
        metadata: Default::default(),
    }
}

/// Demonstrate buffered SIEM sending pattern
fn demonstrate_buffered_sending() {
    println!("--- Buffered SIEM Sending ---\n");

    let buffer = Arc::new(MockSiemBuffer::new());

    // Simulate collecting events
    let events = vec![
        create_sample_event(
            EventType::Info,
            Severity::Info,
            "startup",
            "Application started",
        ),
        create_sample_event(
            EventType::LoginSuccess,
            Severity::Info,
            "auth",
            "User login successful",
        ),
        create_sample_event(
            EventType::AuthorizationError,
            Severity::Error,
            "access",
            "Permission denied for resource",
        ),
    ];

    // Buffer events for batch sending
    for event in &events {
        let formatted = format_for_splunk(event);
        buffer.push(formatted);
    }

    println!("Buffered {} events for batch sending", events.len());

    // Simulate batch send
    let batch = buffer.drain();
    println!("Sending batch of {} events to SIEM\n", batch.len());

    for (i, event_json) in batch.iter().enumerate() {
        let parsed: serde_json::Value = serde_json::from_str(event_json).unwrap();
        println!(
            "Event {}: {} - {}",
            i + 1,
            parsed["event"]["type"],
            parsed["event"]["message"]
        );
    }
}

/// Demonstrate filtering for security events
fn filter_security_events(events: &[Event]) -> Vec<&Event> {
    events
        .iter()
        .filter(|e| {
            e.context.security_relevant
                || matches!(e.severity, Severity::Error | Severity::Critical)
                || matches!(
                    e.event_type,
                    EventType::AuthenticationError
                        | EventType::AuthorizationError
                        | EventType::LoginFailure
                )
        })
        .collect()
}

fn main() {
    println!("=== Observe Module SIEM Integration Example ===\n");

    // 1. Create sample events
    println!("--- Sample Event Formatting ---\n");

    let info_event = create_sample_event(
        EventType::Info,
        Severity::Info,
        "user_action",
        "User updated profile settings",
    );

    let security_event = create_sample_event(
        EventType::AuthorizationError,
        Severity::Error,
        "resource_access",
        "Unauthorized access attempt to admin panel",
    );

    // 2. Splunk HEC format
    println!("Splunk HEC Format:");
    println!("{}\n", format_for_splunk(&info_event));

    // 3. Elasticsearch format (ECS compliant)
    println!("Elasticsearch/OpenSearch Format (ECS):");
    println!("{}\n", format_for_elasticsearch(&security_event));

    // 4. Syslog RFC 5424 format
    println!("Syslog RFC 5424 Format:");
    println!("{}\n", format_as_syslog(&info_event));

    // 5. Grafana Loki format
    println!("Grafana Loki Format:");
    println!("{}\n", format_for_loki(&security_event));

    // 6. Buffered sending demonstration
    demonstrate_buffered_sending();

    // 7. Security event filtering
    println!("\n--- Security Event Filtering ---\n");

    let all_events = vec![
        create_sample_event(EventType::Debug, Severity::Debug, "cache", "Cache hit"),
        create_sample_event(EventType::Info, Severity::Info, "api", "Request processed"),
        create_sample_event(
            EventType::LoginFailure,
            Severity::Warning,
            "auth",
            "Invalid password attempt",
        ),
        create_sample_event(
            EventType::AuthorizationError,
            Severity::Error,
            "access",
            "Permission denied",
        ),
    ];

    let security_only = filter_security_events(&all_events);
    println!(
        "Total events: {}, Security-relevant: {}",
        all_events.len(),
        security_only.len()
    );

    for event in security_only {
        println!("  - [{:?}] {}", event.event_type, event.message);
    }

    // 8. Generate events using observe API
    println!("\n--- Using Observe API ---\n");

    info("siem_demo", "Standard informational event");
    warn("siem_demo", "Warning condition detected");
    error("siem_demo", "Error occurred during processing");
    success("siem_demo", "Operation completed successfully");
    debug("siem_demo", "Debug-level diagnostic information");

    // Security events
    println!("\nSecurity events (would be routed to SIEM):");

    let _ = fail_security("siem_demo", "Suspicious activity detected");
    let _ = fail_permission("siem_demo", "user-123", "/admin/settings");

    // 9. SIEM integration best practices
    println!("\n--- SIEM Integration Best Practices ---\n");
    println!("1. Use structured logging (JSON) for easy parsing");
    println!("2. Include correlation IDs for cross-service tracing");
    println!("3. Tag security-relevant events for priority routing");
    println!("4. Buffer events for batch sending to reduce overhead");
    println!("5. Implement retry logic with exponential backoff");
    println!("6. Use circuit breakers to handle SIEM unavailability");
    println!("7. Ensure PII is redacted before sending to SIEM");
    println!("8. Include compliance flags (PII, PHI) for filtering");

    println!("\n=== Example Complete ===");
}
