# Metrics Implementation: Best Practices Gap Analysis

## Current Implementation Review

### ✅ What We're Doing Right

1. **Thread Safety**: Using atomic operations and RwLock appropriately
1. **Memory Bounds**: Histograms limit samples to prevent unbounded growth
1. **Global Registry**: Single source of truth for metrics
1. **RAII Pattern**: Timer auto-records on drop
1. **Minimal API Surface**: Clean public API with internal implementation hidden

### ⚠️ Missing Best Practices We Should Implement

## 1. **Metric Naming Conventions**

**Issue**: No validation or standardization of metric names

**Best Practice**:

```rust
// Should enforce naming conventions
pub fn validate_metric_name(name: &str) -> Result<(), MetricError> {
    // Enforce: lowercase, dots/underscores only, no spaces
    // e.g., "api.requests.total" or "db_query_duration_ms"

    // Reject: "API Requests", "api-requests", "api/requests"
}
```

**Implementation**:

- Add name validation in Registry
- Support hierarchical namespaces (e.g., "app.subsystem.metric")
- Consider automatic prefixing with service name

## 2. **Metric Labels/Tags**

**Issue**: No support for dimensional metrics

**Best Practice**:

```rust
// Current (flat metrics)
increment("api.requests");

// Should support (dimensional metrics)
increment("api.requests")
    .with_label("method", "GET")
    .with_label("endpoint", "/users")
    .with_label("status", "200");
```

**Benefits**:

- Better aggregation and filtering
- Industry standard (Prometheus, StatsD)
- Essential for microservices

## 3. **Units of Measurement**

**Issue**: No explicit units, leading to confusion

**Best Practice**:

```rust
pub enum MetricUnit {
    Count,
    Bytes,
    Milliseconds,
    Seconds,
    Percent,
    // ... more units
}

// Timer should record in consistent units
timer.record_as(MetricUnit::Milliseconds);
```

**Implementation**:

- Embed units in metric metadata
- Automatic unit conversion
- Include units in metric names (e.g., "response_time_ms")

## 4. **Metric Documentation**

**Issue**: No way to document what metrics mean

**Best Practice**:

```rust
pub struct MetricMetadata {
    pub name: String,
    pub description: String,
    pub unit: MetricUnit,
    pub metric_type: MetricType,
}

// Register with documentation
registry.register_counter(
    "api.requests",
    "Total number of API requests received",
    MetricUnit::Count,
);
```

## 5. **Cardinality Protection**

**Issue**: No protection against label explosion

**Best Practice**:

```rust
pub struct CardinalityLimits {
    max_metrics: usize,           // e.g., 10,000
    max_labels_per_metric: usize, // e.g., 100
    max_unique_label_values: usize, // e.g., 1,000
}

// Reject new metrics/labels when limits exceeded
```

**Why Important**:

- Prevents memory exhaustion
- Protects monitoring systems
- Common issue in production

## 6. **Export Format Standards**

**Issue**: Incomplete export implementations

**Best Practice**:

```rust
impl MetricsSnapshot {
    pub fn to_prometheus(&self) -> String {
        // Full Prometheus text format
        // # HELP api_requests_total Total API requests
        // # TYPE api_requests_total counter
        // api_requests_total{method="GET"} 1234
    }

    pub fn to_openmetrics(&self) -> String { }
    pub fn to_statsd(&self) -> Vec<String> { }
    pub fn to_json(&self) -> serde_json::Value { }
}
```

## 7. **Metric Expiry/Cleanup**

**Issue**: Metrics accumulate forever

**Best Practice**:

```rust
impl Registry {
    pub fn cleanup_stale_metrics(&self, max_age: Duration) {
        // Remove metrics not updated in max_age
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        // Auto-cleanup old metrics
    }
}
```

## 8. **Percentile Accuracy**

**Issue**: Current percentile calculation is approximate

**Best Practice**:

```rust
// Use T-Digest or HDRHistogram for accurate percentiles
pub struct TDigest {
    // Streaming percentile algorithm
    // Better accuracy with bounded memory
}
```

## 9. **Rate Calculation Windows**

**Issue**: Rate calculations from creation time only

**Best Practice**:

```rust
pub struct RateWindow {
    window_1m: f64,  // Rate over last minute
    window_5m: f64,  // Rate over last 5 minutes
    window_15m: f64, // Rate over last 15 minutes
}
```

## 10. **Atomic Snapshots**

**Issue**: Potential inconsistency during snapshot

**Best Practice**:

```rust
impl Registry {
    pub fn atomic_snapshot(&self) -> MetricsSnapshot {
        // Use RCU or versioning for consistent snapshots
        // All metrics from same point in time
    }
}
```

## 11. **Zero-Overhead When Disabled**

**Issue**: Metrics always active even if not needed

**Best Practice**:

```rust
#[cfg(feature = "metrics")]
pub fn increment(name: &str) { /* real implementation */ }

#[cfg(not(feature = "metrics"))]
pub fn increment(_name: &str) { /* no-op */ }
```

## 12. **Exemplars** (Advanced)

**Issue**: No tracing correlation

**Best Practice**:

```rust
pub struct Exemplar {
    value: f64,
    timestamp: Instant,
    trace_id: Option<String>, // Link to distributed trace
    labels: HashMap<String, String>,
}
```

## Priority Implementation Order

### High Priority (Should Do Now)

1. **Metric Labels/Tags** - Essential for production use
1. **Export Formats** - Needed for integration
1. **Cardinality Protection** - Prevents production issues
1. **Name Validation** - Prevents future breaking changes

### Medium Priority (Next Phase)

5. **Units of Measurement** - Improves clarity
1. **Metric Documentation** - Helps users
1. **Stale Metric Cleanup** - Prevents memory leaks
1. **Rate Windows** - Better monitoring

### Low Priority (Nice to Have)

9. **Percentile Accuracy** - Current approximation probably OK
1. **Zero-Overhead** - Only if performance critical
1. **Exemplars** - Advanced feature

## Example Implementation: Labels

```rust
// Quick implementation for labels
pub struct LabeledMetric<'a> {
    name: &'a str,
    labels: Vec<(&'a str, &'a str)>,
}

impl<'a> LabeledMetric<'a> {
    pub fn with_label(mut self, key: &'a str, value: &'a str) -> Self {
        self.labels.push((key, value));
        self
    }

    pub fn increment(self) {
        let full_name = self.to_full_name();
        global().counter(&full_name).increment();
    }

    fn to_full_name(&self) -> String {
        if self.labels.is_empty() {
            self.name.to_string()
        } else {
            let labels = self.labels.iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join(",");
            format!("{}[{}]", self.name, labels)
        }
    }
}

pub fn metric(name: &str) -> LabeledMetric {
    LabeledMetric {
        name,
        labels: Vec::new(),
    }
}

// Usage:
metric("api.requests")
    .with_label("method", "GET")
    .with_label("status", "200")
    .increment();
```

## Conclusion

The current implementation is solid for basic use cases but lacks several production-critical features:

1. **Labels/Tags** are essential for modern observability
1. **Export formats** needed for integration with monitoring systems
1. **Cardinality protection** prevents production outages
1. **Name validation** ensures consistency

These should be prioritized based on the library's intended use cases.
