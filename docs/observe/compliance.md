# Observe Module - Compliance Guide

This guide provides detailed compliance control mapping for the observe module, covering SOC2, HIPAA, GDPR, PCI-DSS, and ISO 27001 requirements.

## Overview

The observe module is designed with compliance-first principles:

- **Defense in Depth**: Multiple layers of PII protection
- **Audit Trail**: Automatic WHO/WHAT/WHEN/WHERE context capture
- **Data Minimization**: Configurable redaction profiles
- **Retention Control**: Time-based event retention policies
- **Query Capabilities**: Compliance reporting and data subject access requests

## SOC2 Trust Service Criteria

### CC6.1 - Logical Access Controls

The observe module captures user identity and access context:

```rust
use octarine::observe::{set_tenant, TenantContext, TenantId, info};

// Set user context at authentication boundary
let tenant_id = TenantId::new("acme-corp").expect("valid");
let ctx = TenantContext {
    tenant_id,
    tenant_name: Some("ACME Corp".to_string()),
    tenant_tier: Some("enterprise".to_string()),
};
set_tenant(ctx);

// All subsequent events include user identity
info("resource_access", "User accessed customer record");
// Event includes: user_id, tenant_id, timestamp, correlation_id
```

**Control Mapping:**

| Requirement | Feature |
|-------------|---------|
| User identification | `TenantContext.user_id` captured in events |
| Access logging | Every event includes context metadata |
| Session tracking | Correlation ID propagation |
| Multi-tenant isolation | Thread-local tenant context |

### CC7.2 - System Operations Monitoring

```rust
use octarine::observe::{info, warn, error, Severity};

// Operational events with appropriate severity
info("system", "Service started successfully");
warn("system", "Memory usage approaching threshold");
error("system", "Database connection timeout");
```

**Control Mapping:**

| Requirement | Feature |
|-------------|---------|
| Operational monitoring | Console/File/Database writers |
| Alert generation | Severity levels for filtering |
| Performance tracking | Timestamp precision to microseconds |
| Anomaly detection | Event correlation via correlation_id |

### CC6.6 - Data Classification

The PII scanner automatically classifies sensitive data:

```rust
use octarine::observe::pii::{scan_for_pii, PiiType};

let text = "Contact: john@example.com, SSN: 123-45-6789";
let pii_types = scan_for_pii(text);

// Detected: PiiType::Email, PiiType::Ssn
// Event metadata includes: contains_pii: true, pii_types: [...]
```

**Control Mapping:**

| Requirement | Feature |
|-------------|---------|
| Data classification | 30+ PII type detection |
| Sensitivity labels | `contains_pii`, `contains_phi` flags |
| Access restrictions | PII redaction before logging |

## HIPAA Technical Safeguards

### §164.312(a)(1) - Access Control

```rust
use octarine::observe::{fail_permission, Result};

fn access_phi_record(user: &str, record_id: &str) -> Result<PhiRecord> {
    if !has_phi_access(user) {
        // Creates security audit event automatically
        return Err(fail_permission("phi_access", user, record_id));
    }

    info("phi_access", format!("User {} accessed record {}", user, record_id));
    // Event automatically flagged with contains_phi: true

    fetch_record(record_id)
}
```

**Control Mapping:**

| HIPAA Requirement | Feature |
|-------------------|---------|
| Unique user identification | `user_id` in event context |
| Emergency access procedure | Severity::Critical events |
| Automatic logoff | Session timeout via correlation_id expiry |
| Encryption | Writer encryption at rest (database backend) |

### §164.312(b) - Audit Controls

```rust
use octarine::observe::writers::{AuditQuery, Queryable};

// Query PHI access events for audit
let query = AuditQuery::builder()
    .since(audit_period_start)
    .until(audit_period_end)
    .contains_phi_only(true)
    .build();

let result = writer.query(&query).await?;

// Generate HIPAA audit report
for event in result.events {
    println!(
        "{}: User {} accessed PHI - {}",
        event.timestamp,
        event.context.user_id.unwrap_or_default(),
        event.message
    );
}
```

**Control Mapping:**

| HIPAA Requirement | Feature |
|-------------------|---------|
| Hardware/software activity | Event source tracking |
| User activity | Complete audit trail |
| PHI access logging | `contains_phi` filter |
| Audit log protection | Immutable log storage (JSONL/database) |

### §164.312(c) - Integrity Controls

Defense-in-depth PII scanning ensures PHI is never logged in clear text:

```rust
use octarine::observe::pii::RedactionProfile;

// Production: Strict redaction - no PII in logs
// Development: Partial redaction for debugging

// Layer 1: Event builder redaction
// Layer 2: Writer redaction (defense-in-depth)
```

**Control Mapping:**

| HIPAA Requirement | Feature |
|-------------------|---------|
| Data integrity | Event ID uniqueness (UUID) |
| Alteration detection | Timestamp immutability |
| Transmission security | Async dispatch with buffering |

## GDPR Compliance

### Article 5 - Data Minimization

```rust
use octarine::observe::pii::{redact_pii, RedactionProfile};

// Strict profile: Maximum redaction for production
let safe = redact_pii(user_input, RedactionProfile::ProductionStrict);
// All PII types redacted with minimal context preserved

// Balanced profile: Partial redaction preserving some context
let balanced = redact_pii(user_input, RedactionProfile::ProductionBalanced);
// SSN fully redacted, emails partially masked
```

**Control Mapping:**

| GDPR Requirement | Feature |
|------------------|---------|
| Data minimization | Configurable redaction profiles |
| Purpose limitation | Operation context in events |
| Storage limitation | Retention policies in writers |
| Accuracy | Timestamp precision |

### Article 15 - Right of Access

The Queryable trait enables data subject access requests (DSAR):

```rust
use octarine::observe::writers::{AuditQuery, Queryable};

async fn handle_dsar(user_id: &str) -> Result<Vec<Event>> {
    let query = AuditQuery::builder()
        .user_id(user_id.to_string())
        .build();

    let result = writer.query(&query).await?;
    Ok(result.events)
}
```

### Article 17 - Right to Erasure

Database backends support event deletion for right to erasure:

```rust
#[cfg(feature = "database")]
use octarine::observe::writers::database::DatabaseBackend;

async fn erase_user_data(backend: &impl DatabaseBackend, retention_days: u32) {
    // Delete events older than retention period
    let deleted = backend.delete_before(retention_days).await?;
    info("gdpr", format!("Erased {} events for GDPR compliance", deleted));
}
```

### Article 32 - Security of Processing

| GDPR Requirement | Feature |
|------------------|---------|
| Pseudonymization | PII redaction with type markers |
| Encryption | Database writer encryption |
| Confidentiality | Multi-tenant isolation |
| Integrity | Event ID uniqueness |
| Availability | Multiple writer failover |
| Resilience | Async dispatch with buffering |

## PCI-DSS Requirements

### Requirement 3.4 - Primary Account Number (PAN) Protection

Credit card numbers are automatically detected and masked:

```rust
use octarine::observe::pii::{scan_for_pii, redact_pii, PiiType};

let input = "Card: 4111-1111-1111-1111";
let pii = scan_for_pii(input);
assert!(pii.contains(&PiiType::CreditCard));

let safe = redact_pii(input, RedactionProfile::ProductionStrict);
// Output: "Card: [CC:****1111]"
// Last 4 digits preserved per PCI-DSS display requirements
```

### Requirement 10.2 - Audit Trails

| PCI-DSS Requirement | Feature |
|---------------------|---------|
| 10.2.1 User access | `user_id` in context |
| 10.2.2 Actions by admin | Operation logging |
| 10.2.3 Access to audit trails | Writer access control |
| 10.2.4 Invalid access attempts | `fail_permission` events |
| 10.2.5 Auth mechanism use | `auth_success` events |
| 10.2.6 Initialization of audit logs | System startup events |
| 10.2.7 Object creation/deletion | Business events |

### Requirement 10.3 - Audit Trail Entries

Each event automatically includes:

```rust
// Event structure satisfies PCI-DSS 10.3.x
Event {
    id: Uuid,                    // 10.3.6 - Event ID
    timestamp: DateTime<Utc>,     // 10.3.3 - Date and time
    event_type: EventType,        // 10.3.4 - Type of event
    severity: Severity,           // 10.3.5 - Success/failure
    message: String,              // 10.3.1 - User identification
    context: EventContext {
        user_id: Option<UserId>,  // 10.3.1 - User identification
        tenant_id: Option<TenantId>,
        correlation_id: Uuid,     // 10.3.2 - Event origin
        // ...
    },
}
```

## ISO 27001 Controls

### A.12.4 - Logging and Monitoring

| ISO Control | Feature |
|-------------|---------|
| A.12.4.1 Event logging | Multi-destination writers |
| A.12.4.2 Protection of log info | Immutable storage backends |
| A.12.4.3 Admin/operator logs | Severity filtering |
| A.12.4.4 Clock synchronization | UTC timestamps |

### A.18.1 - Compliance with Legal Requirements

| ISO Control | Feature |
|-------------|---------|
| A.18.1.3 Protection of records | Retention policies |
| A.18.1.4 Privacy/PII protection | 30+ PII type redaction |

## Compliance Configuration Examples

### Production Configuration (Maximum Security)

```rust
use octarine::observe::pii::RedactionProfile;
use octarine::observe::writers::{Writer, WriterConfig, RotationConfig};

// PII: Strict redaction
let profile = RedactionProfile::ProductionStrict;

// File writer: JSONL with rotation and retention
let config = WriterConfig::builder()
    .rotation(RotationConfig::builder()
        .max_size_mb(100)
        .max_age_days(90)  // PCI-DSS: 90 days minimum
        .build())
    .build();
```

### Development Configuration (Debugging)

```rust
use octarine::observe::pii::RedactionProfile;

// PII: Balanced redaction for debugging
let profile = RedactionProfile::DevelopmentVisible;

// Console writer for immediate feedback
let writer = ConsoleWriter::colored();
```

### Audit Report Generation

```rust
use octarine::observe::writers::{AuditQuery, Queryable, QueryResult};
use chrono::{Duration, Utc};

async fn generate_compliance_report(
    writer: &impl Queryable,
    days: i64
) -> Result<ComplianceReport> {
    let since = Utc::now() - Duration::days(days);

    // Security events
    let security_query = AuditQuery::builder()
        .since(since)
        .security_relevant_only(true)
        .build();
    let security_events = writer.query(&security_query).await?;

    // PII access events
    let pii_query = AuditQuery::builder()
        .since(since)
        .contains_pii_only(true)
        .build();
    let pii_events = writer.query(&pii_query).await?;

    // PHI access events (HIPAA)
    let phi_query = AuditQuery::builder()
        .since(since)
        .contains_phi_only(true)
        .build();
    let phi_events = writer.query(&phi_query).await?;

    Ok(ComplianceReport {
        period_start: since,
        period_end: Utc::now(),
        security_event_count: security_events.events.len(),
        pii_access_count: pii_events.events.len(),
        phi_access_count: phi_events.events.len(),
        // ... additional metrics
    })
}
```

## Best Practices

1. **Set context early**: Establish tenant/user context at authentication boundary
1. **Use appropriate severity**: Critical for data loss, Error for failures, Warn for anomalies
1. **Enable defense-in-depth**: Don't rely solely on event builder redaction
1. **Query regularly**: Generate compliance reports on schedule
1. **Retain appropriately**: Balance compliance requirements with storage costs
1. **Test PII detection**: Include compliance tests in CI/CD pipeline
1. **Monitor scanner health**: Use `scanner_is_healthy()` for operational monitoring

## Related Documentation

- [API Guide](api-guide.md) - Detailed API usage
- [Integration Guide](integration.md) - SIEM and monitoring integration
- [PII Module](../../crates/octarine/src/observe/pii/mod.rs) - Scanner API reference
- [Writers Module](../../crates/octarine/src/observe/writers/mod.rs) - Output destinations
