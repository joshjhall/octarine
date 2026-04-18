# Observe Module - Integration Guide

This guide covers integrating the observe module with external systems including SIEM platforms, monitoring tools, and custom backends.

## Overview

The observe module supports multiple integration patterns:

- **Direct Writers**: Console, file (JSONL), SQLite, PostgreSQL
- **Custom Backends**: Implement `Writer` or `DatabaseBackend` traits
- **Export Formats**: JSONL for SIEM ingestion, structured events for APIs
- **Metrics Export**: Prometheus-compatible metrics

## Writer Configuration

### Console Writer (Development)

```rust
use octarine::observe::writers::{Writer, HealthStatus};
use octarine::observe::Event;
use async_trait::async_trait;

// Console writer is built-in and enabled by default in development
// Events automatically formatted with colors and timestamps
```

### File Writer (JSONL)

JSONL format enables:

- Log aggregation tool ingestion (Splunk, Elastic, etc.)
- Query capabilities via the Queryable trait
- Gzip compression for rotated files

```rust
use octarine::observe::writers::{
    LogDirectory, LogFilename, LogFormat, RotationConfig
};
use octarine::observe::writers::builder::FileWriterBuilder;

async fn setup_file_writer() -> Result<impl Writer, WriterError> {
    let writer = FileWriterBuilder::new()
        .directory(LogDirectory::new("/var/log/myapp")?)
        .filename(LogFilename::new("audit.jsonl")?)
        .with_format(LogFormat::JsonLines)
        .with_rotation(RotationConfig::builder()
            .max_size_mb(100)
            .max_age_days(90)
            .compress_rotated(true)
            .build())
        .build()
        .await?;

    Ok(writer)
}
```

### Database Writers

#### SQLite (Development/Testing)

```rust
#[cfg(feature = "database")]
use octarine::observe::writers::database::{SqliteBackend, DatabaseBackend};

async fn setup_sqlite() -> Result<SqliteBackend, WriterError> {
    let backend = SqliteBackend::new("audit.db").await?;
    backend.migrate().await?;  // Auto-create tables
    Ok(backend)
}
```

#### PostgreSQL (Production)

```rust
#[cfg(feature = "database")]
use octarine::observe::writers::database::{PostgresBackend, DatabaseBackend};

async fn setup_postgres() -> Result<PostgresBackend, WriterError> {
    let backend = PostgresBackend::new(
        "postgresql://user:pass@localhost/myapp"
    ).await?;
    backend.migrate().await?;
    Ok(backend)
}
```

## Custom Writer Implementation

Implement the `Writer` trait for custom destinations.

**Runtime contract.** `Writer::write` is invoked from inside the observe
dispatcher's tokio runtime (a dedicated background thread). Implementations
may freely `.await` tokio I/O — HTTP clients, file handles, database
drivers, async channels — and do not need to spawn their own runtime.
A failure returned from `write` is logged to stderr and does not block
dispatch to other registered writers.


```rust
use octarine::observe::writers::{Writer, WriterError, HealthStatus};
use octarine::observe::Event;
use async_trait::async_trait;

struct SplunkWriter {
    endpoint: String,
    token: String,
    client: reqwest::Client,
}

#[async_trait]
impl Writer for SplunkWriter {
    async fn write(&self, event: &Event) -> Result<(), WriterError> {
        // Convert event to Splunk HEC format
        let payload = serde_json::json!({
            "time": event.timestamp.timestamp(),
            "sourcetype": "octarine_audit",
            "event": {
                "id": event.id.to_string(),
                "type": format!("{:?}", event.event_type),
                "severity": format!("{:?}", event.severity),
                "message": &event.message,
                "context": {
                    "tenant_id": event.context.tenant_id.as_ref().map(|t| t.as_str()),
                    "user_id": event.context.user_id.as_ref().map(|u| u.as_str()),
                    "correlation_id": event.context.correlation_id.to_string(),
                }
            }
        });

        self.client
            .post(&self.endpoint)
            .header("Authorization", format!("Splunk {}", self.token))
            .json(&payload)
            .send()
            .await
            .map_err(|e| WriterError::Other(e.to_string()))?;

        Ok(())
    }

    async fn flush(&self) -> Result<(), WriterError> {
        // HTTP client handles its own flushing
        Ok(())
    }

    fn health_check(&self) -> HealthStatus {
        HealthStatus::Healthy
    }

    fn name(&self) -> &'static str {
        "splunk"
    }
}
```

## SIEM Integration

### Splunk

JSONL format is directly ingestible by Splunk:

```ini
# props.conf
[octarine_audit]
TIME_PREFIX = "timestamp":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S%.fZ
SHOULD_LINEMERGE = false
KV_MODE = json

# inputs.conf
[monitor:///var/log/myapp/*.jsonl]
sourcetype = octarine_audit
```

### Elasticsearch / OpenSearch

```yaml
# Filebeat configuration
filebeat.inputs:
  - type: log
    paths:
      - /var/log/myapp/*.jsonl
    json.keys_under_root: true
    json.add_error_key: true

output.elasticsearch:
  hosts: ["localhost:9200"]
  index: "octarine-audit-%{+yyyy.MM.dd}"
```

### Grafana Loki

```yaml
# Promtail configuration
scrape_configs:
  - job_name: octarine_audit
    static_configs:
      - targets:
          - localhost
        labels:
          job: octarine_audit
          __path__: /var/log/myapp/*.jsonl
    pipeline_stages:
      - json:
          expressions:
            timestamp: timestamp
            severity: severity
            event_type: event_type
            tenant_id: context.tenant_id
      - labels:
          severity:
          event_type:
          tenant_id:
```

## Prometheus Metrics

The metrics submodule provides Prometheus-compatible export:

```rust
use octarine::observe::metrics::{Counter, Gauge, Histogram};

// Define metrics
static REQUEST_COUNTER: Counter = Counter::new(
    "http_requests_total",
    "Total HTTP requests"
);

static ACTIVE_CONNECTIONS: Gauge = Gauge::new(
    "active_connections",
    "Current active connections"
);

static REQUEST_DURATION: Histogram = Histogram::new(
    "http_request_duration_seconds",
    "HTTP request duration"
);

// Use metrics
REQUEST_COUNTER.inc();
ACTIVE_CONNECTIONS.set(42.0);
REQUEST_DURATION.observe(0.123);
```

## OpenTelemetry Integration

For distributed tracing, propagate correlation IDs:

```rust
use octarine::observe::{set_tenant, TenantContext, TenantId};
use uuid::Uuid;

// Extract trace context from incoming request
fn extract_trace_context(headers: &HeaderMap) -> Option<Uuid> {
    headers
        .get("x-correlation-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| Uuid::parse_str(s).ok())
}

// Set context at request boundary
async fn handle_request(req: Request) -> Response {
    let correlation_id = extract_trace_context(req.headers())
        .unwrap_or_else(Uuid::new_v4);

    // Set tenant context with correlation ID
    // Events will include correlation_id automatically

    // Process request...
}

// Propagate to outgoing requests
fn inject_trace_context(headers: &mut HeaderMap, correlation_id: Uuid) {
    headers.insert(
        "x-correlation-id",
        correlation_id.to_string().parse().unwrap()
    );
}
```

## Multi-Tenant Configuration

### Request-Scoped Context

```rust
use octarine::observe::{set_tenant, clear_tenant, with_tenant, TenantContext, TenantId};

// Middleware pattern
async fn tenant_middleware<F, R>(
    tenant_id: &str,
    user_id: Option<&str>,
    f: F
) -> R
where
    F: FnOnce() -> R
{
    let tenant = TenantId::new(tenant_id).expect("valid tenant");
    let ctx = TenantContext {
        tenant_id: tenant,
        tenant_name: None,
        tenant_tier: None,
    };

    // All events within f() include tenant context
    with_tenant(ctx, f)
}
```

### Tenant-Specific Writers

```rust
use std::collections::HashMap;
use octarine::observe::writers::Writer;

struct TenantRouter {
    writers: HashMap<String, Box<dyn Writer + Send + Sync>>,
    default: Box<dyn Writer + Send + Sync>,
}

impl TenantRouter {
    async fn route(&self, event: &Event) -> Result<(), WriterError> {
        let writer = event.context.tenant_id
            .as_ref()
            .and_then(|tid| self.writers.get(tid.as_str()))
            .unwrap_or(&self.default);

        writer.write(event).await
    }
}
```

## Health Monitoring

### Writer Health Checks

```rust
use octarine::observe::writers::{Writer, HealthStatus};

async fn check_writer_health(writer: &impl Writer) -> HealthStatus {
    let status = writer.health_check();

    match status {
        HealthStatus::Healthy => {
            // All good
        }
        HealthStatus::Degraded(reason) => {
            warn("observability", format!("Writer degraded: {}", reason));
        }
        HealthStatus::Unhealthy(reason) => {
            error("observability", format!("Writer unhealthy: {}", reason));
        }
    }

    status
}
```

### PII Scanner Health

```rust
use octarine::observe::pii::{scanner_stats, scanner_health_score, scanner_is_healthy};

fn monitor_pii_scanner() {
    let stats = scanner_stats();

    // Expose as Prometheus metrics
    pii_cache_hit_rate.set(stats.cache_hit_rate);
    pii_avg_scan_time_us.set(stats.avg_scan_time_us);

    if !scanner_is_healthy() {
        alert("PII scanner degraded - check performance");
    }
}
```

## Buffering and Batching

### Async Dispatch

Events are dispatched asynchronously to avoid blocking:

```rust
use octarine::observe::writers::register_writer;

// Register writer - events dispatched async
register_writer(my_writer);

// Events are queued and processed by background task
info("operation", "This returns immediately");
```

### Batch Configuration

```rust
#[cfg(feature = "database")]
use octarine::observe::writers::database::DatabaseBackend;

// Database backends support batching
// Events are batched and written periodically
```

## Error Handling

### Writer Failures

```rust
use octarine::observe::writers::{Writer, WriterError};

async fn write_with_fallback(
    primary: &impl Writer,
    fallback: &impl Writer,
    event: &Event
) -> Result<(), WriterError> {
    match primary.write(event).await {
        Ok(()) => Ok(()),
        Err(e) => {
            warn("observability", format!("Primary writer failed: {}", e));
            fallback.write(event).await
        }
    }
}
```

### Circuit Breaker Pattern

```rust
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

struct CircuitBreaker {
    failures: AtomicUsize,
    last_failure: std::sync::Mutex<Option<Instant>>,
    threshold: usize,
    reset_after: Duration,
}

impl CircuitBreaker {
    fn is_open(&self) -> bool {
        let failures = self.failures.load(Ordering::Relaxed);
        if failures >= self.threshold {
            if let Ok(guard) = self.last_failure.lock() {
                if let Some(last) = *guard {
                    return last.elapsed() < self.reset_after;
                }
            }
        }
        false
    }

    fn record_failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut guard) = self.last_failure.lock() {
            *guard = Some(Instant::now());
        }
    }

    fn record_success(&self) {
        self.failures.store(0, Ordering::Relaxed);
    }
}
```

## Testing

### Mock Writers

```rust
use octarine::observe::writers::MemoryWriter;

#[tokio::test]
async fn test_event_logging() {
    let writer = MemoryWriter::new();

    // Perform operations that log events
    info("test", "Test event");

    // Verify events were captured
    let events = writer.events();
    assert!(!events.is_empty());
    assert!(events.iter().any(|e| e.message.contains("Test event")));
}
```

### Integration Tests

```rust
#[cfg(feature = "database")]
#[tokio::test]
async fn test_database_roundtrip() {
    use octarine::observe::writers::database::{SqliteBackend, DatabaseBackend};
    use octarine::observe::writers::{AuditQuery, Queryable};

    let backend = SqliteBackend::new(":memory:").await.unwrap();
    backend.migrate().await.unwrap();

    // Store event
    let event = Event::new(EventType::Info, "Test");
    backend.store_events(&[event.clone()]).await.unwrap();

    // Query back
    let result = backend.query_events(&AuditQuery::default()).await.unwrap();
    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0].id, event.id);
}
```

## Best Practices

1. **Use appropriate writers**: Console for dev, JSONL files for production, database for compliance
1. **Enable rotation**: Prevent disk space exhaustion with rotation policies
1. **Monitor health**: Check writer health in readiness probes
1. **Handle failures gracefully**: Implement fallback writers for critical systems
1. **Batch database writes**: Reduce I/O overhead for high-volume logging
1. **Use correlation IDs**: Enable distributed tracing across services
1. **Test PII redaction**: Verify sensitive data is never logged in clear text

## Related Documentation

- [Compliance Guide](compliance.md) - SOC2/HIPAA/GDPR mapping
- [API Guide](api-guide.md) - Detailed API reference
- [Writers Module](../../src/observe/writers/mod.rs) - Writer implementations
- [PII Module](../../src/observe/pii/mod.rs) - PII detection API
