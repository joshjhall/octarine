# Audit Logging and Event System

## Overview

The octarine observe module provides a comprehensive event system for audit logging, compliance, and observability. Events are automatically generated for security-relevant operations, errors, and business activities.

## Event Categories

### Business Events

Track business operations and user activities:

```rust
use octarine::observe::event::{Event, EventSeverity};

Event::business("user_created")
    .with_entity("user", user_id)
    .with_metadata("email", email)
    .emit();

Event::business("payment_processed")
    .with_entity("order", order_id)
    .with_metadata("amount", amount.to_string())
    .with_severity(EventSeverity::Info)
    .emit();
```

### Security Events

Automatically generated for security-relevant operations:

```rust
Event::security("authentication_failed")
    .with_metadata("username", username)
    .with_metadata("ip_address", ip)
    .with_severity(EventSeverity::Warning)
    .emit();

Event::security("permission_denied")
    .with_entity("resource", resource_id)
    .with_metadata("required_permission", permission)
    .emit();
```

### System Events

Track system health and operations:

```rust
Event::system("database_connection_lost")
    .with_severity(EventSeverity::Critical)
    .with_metadata("host", db_host)
    .emit();

Event::system("cache_cleared")
    .with_metadata("reason", "scheduled")
    .emit();
```

## Automatic Event Generation

### From Problems

Every Problem automatically generates an event:

```rust
// This code:
let problem = Problem::validation("Invalid email");

// Automatically emits:
// Event::problem()
//     .with_kind("validation")
//     .with_message("Invalid email")
//     .with_context(...)
//     .emit()
```

### From Security Operations

Security module operations generate events:

```rust
// Path sanitization
let safe_path = sanitize_path(user_input);
// Automatically emits security event if path traversal detected

// Rate limiting
rate_limiter.check_rate(user_id)?;
// Automatically emits event if rate limit exceeded
```

## Context Propagation

Events automatically capture context from the observe module:

```rust
use octarine::observe::context::Context;

// Set context at request boundary
Context::set()
    .tenant_id("acme-corp")
    .user_id("user-123")
    .correlation_id(request_id)
    .apply();

// All events within this context automatically include:
// - tenant_id: "acme-corp"
// - user_id: "user-123"
// - correlation_id: <request_id>
// - timestamp: <current_time>
```

## Event Metadata

### Standard Fields

All events include:

- `timestamp` - When the event occurred
- `correlation_id` - Request tracing ID
- `module_path` - Where in code it originated
- `severity` - Info, Warning, Error, Critical

### Context Fields (when available)

- `tenant_id` - Multi-tenant isolation
- `user_id` - User attribution
- `session_id` - Session tracking
- `environment` - dev/staging/prod

### Custom Metadata

Add domain-specific data:

```rust
Event::business("order_shipped")
    .with_entity("order", order_id)
    .with_metadata("carrier", "FedEx")
    .with_metadata("tracking_number", tracking)
    .with_metadata("estimated_delivery", date.to_string())
    .emit();
```

## Event Writers

Events can be sent to multiple destinations:

### Console Writer (Development)

```rust
use octarine::observe::writers::ConsoleWriter;

// Colored output for development
let writer = ConsoleWriter::builder()
    .with_colors(true)
    .with_timestamps(true)
    .build();
```

### File Writer (Production)

```rust
use octarine::observe::writers::FileWriter;

let writer = FileWriter::builder()
    .directory("/var/log/app")
    .rotation_size("100MB")
    .retention_days(90)
    .build();
```

### Database Writer (Compliance)

```rust
use octarine::observe::writers::DatabaseWriter;

let writer = DatabaseWriter::builder()
    .connection_string(db_url)
    .table_name("audit_logs")
    .batch_size(100)
    .build();
```

## Compliance Features

### SOC2 Requirements

- **Who**: User ID captured in context
- **What**: Event type and metadata
- **When**: Timestamp with microsecond precision
- **Where**: Module path and correlation ID
- **Result**: Success/failure in event severity

### HIPAA Requirements

- PHI access logging via business events
- Automatic PII redaction in messages
- Configurable retention policies
- Encryption at rest (database writer)

### GDPR Requirements

- Right to erasure support
- Data minimization (configurable fields)
- Audit log of data access
- Export capabilities

## Event Filtering

Control what gets logged:

```rust
use octarine::observe::filters::EventFilter;

let filter = EventFilter::builder()
    .min_severity(EventSeverity::Warning)  // Only Warning and above
    .include_security(true)                // Always include security
    .include_business(true)                // Include business events
    .exclude_system(false)                 // Include system events
    .build();
```

## Performance Optimization

### Asynchronous Emission

Events are emitted asynchronously to avoid blocking:

```rust
// Events are queued and processed by background thread
Event::business("heavy_operation")
    .emit();  // Returns immediately
```

### Batching

Writers can batch events for efficiency:

```rust
let writer = DatabaseWriter::builder()
    .batch_size(1000)        // Write 1000 events at once
    .flush_interval("5s")    // Or every 5 seconds
    .build();
```

### Sampling

High-volume events can be sampled:

```rust
Event::system("cache_hit")
    .sample_rate(0.01)  // Log 1% of cache hits
    .emit();
```

## Usage Examples

### Web Request Handler

```rust
async fn handle_request(req: Request) -> Response {
    // Set context for this request
    Context::set()
        .correlation_id(Uuid::new_v4())
        .user_id(req.user_id())
        .apply();

    // Log request
    Event::business("api_request")
        .with_metadata("method", req.method())
        .with_metadata("path", req.path())
        .emit();

    // Process request (events emitted automatically)
    let result = process(req).await;

    // Log response
    Event::business("api_response")
        .with_metadata("status", result.status())
        .with_metadata("duration_ms", duration.as_millis())
        .emit();

    result
}
```

### Security Operation

```rust
pub fn validate_admin_action(user: &User, action: &str) -> Result<()> {
    // Security check emits event automatically
    if !user.is_admin() {
        Event::security("admin_action_denied")
            .with_metadata("user_role", user.role())
            .with_metadata("attempted_action", action)
            .with_severity(EventSeverity::Warning)
            .emit();

        return Err(Problem::permission_denied("Admin access required"));
    }

    Event::security("admin_action_allowed")
        .with_metadata("action", action)
        .emit();

    Ok(())
}
```

## Configuration

Configure the event system via builder:

```rust
use octarine::observe::ObserveBuilder;

let observe = ObserveBuilder::new()
    .add_writer(console_writer)
    .add_writer(file_writer)
    .add_filter(security_filter)
    .buffer_size(10000)
    .worker_threads(2)
    .build();
```

## Best Practices

1. **Set context early** - At request/operation boundaries
1. **Use appropriate severity** - Critical for data loss, Info for routine
1. **Include entities** - Always identify what was affected
1. **Add relevant metadata** - But avoid PII in messages
1. **Use consistent event names** - Follow naming conventions
1. **Let the system handle emission** - Don't manually write to logs

## Related Documentation

- [Event System Architecture](../architecture/event-system.md)
- [Problem Type](../api/error-architecture.md)
- [Security Patterns](../security/patterns/)
- [Compliance Guide](../reference/compliance.md)
