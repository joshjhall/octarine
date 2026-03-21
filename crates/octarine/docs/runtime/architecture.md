# Async Observability Architecture

## Design Philosophy

**Critical Principle**: Observability must never block application code.

The observe system provides a **synchronous API** with a **fully async backend**. This ensures:

- Zero blocking on the hot path (application code)
- Robust async infrastructure for reliability under load
- Support for everything from CLI tools to high-scale services (MCP servers)

## User API (Synchronous - Must Stay Simple)

```rust
use octarine::observe::{debug, info, warn, incr, histogram};

// Events - no async/await required
debug("Processing request");
info("User logged in");
warn("Rate limit approaching");

// Metrics - no async/await required
incr("requests_total");
histogram("request_duration_ms", 142.5);
```

**Key Requirement**: These functions return immediately. No `.await`, no blocking, no ceremony.

## Backend Architecture (Fully Async)

```text
┌─────────────────────────────────────────────────────────────────┐
│ Application Code (Synchronous)                                  │
├─────────────────────────────────────────────────────────────────┤
│ debug("msg")  │  incr("counter")  │  histogram("latency", val) │
└────────┬──────┴─────────┬──────────┴─────────────┬──────────────┘
         │                │                        │
         │ try_send       │ try_send               │ try_send
         │ (non-blocking) │ (non-blocking)         │ (non-blocking)
         ↓                ↓                        ↓
┌────────────────┐ ┌──────────────┐ ┌─────────────────────┐
│ Event Channel  │ │ Metrics      │ │ Context Enrichment  │
│ (10k capacity) │ │ Channel      │ │ Queue               │
│                │ │ (100k cap)   │ │ (1k capacity)       │
└────────┬───────┘ └──────┬───────┘ └──────────┬──────────┘
         │                │                     │
         │                │                     │
    tokio::spawn     tokio::spawn          tokio::spawn
         │                │                     │
         ↓                ↓                     ↓
┌────────────────┐ ┌──────────────┐ ┌─────────────────────┐
│ Event          │ │ Metrics      │ │ Context             │
│ Processor      │ │ Aggregator   │ │ Enrichment          │
│                │ │              │ │ Worker              │
└────────┬───────┘ └──────┬───────┘ └──────────┬──────────┘
         │                │                     │
         │ Batching       │ Aggregation         │ Async capture
         ↓                ↓                     ↓
┌────────────────┐ ┌──────────────┐ ┌─────────────────────┐
│ AsyncWriter    │ │ AsyncWriter  │ │ Event metadata      │
│ (batched)      │ │ (periodic)   │ │ enrichment          │
└────────┬───────┘ └──────┬───────┘ └──────────┬──────────┘
         │                │                     │
    Circuit Breakers  Retry Logic          Merges back
    Retry Logic       Circuit Breakers     to event stream
         │                │                     │
         ↓                ↓                     ↓
┌────────────────────────────────────────────────────────────┐
│ Output Writers (Parallel, Fault-Tolerant)                  │
├────────────────────────────────────────────────────────────┤
│  Console  │  File  │  Database  │  SIEM  │  Prometheus    │
└────────────────────────────────────────────────────────────┘
```

## Runtime Components

### 1. Channel (Bounded, Non-blocking)

```rust
use octarine::runtime::{Channel, OverflowPolicy};

// Event channel with DropOldest policy
Channel::with_config(
    10_000,                      // Capacity
    OverflowPolicy::DropOldest,  // Drop old events under load
    "observe_events"             // Name for observability
)

// Metrics channel with higher capacity
Channel::with_config(
    100_000,                     // Higher capacity for metrics
    OverflowPolicy::DropNewest,  // Drop new metrics under extreme load
    "observe_metrics"
)
```

### 2. BatchProcessor (Batching)

```rust
use octarine::runtime::BatchProcessor;

AsyncWriter::with_config(WriterConfig {
    batch_size: 100,                        // Batch 100 events
    flush_interval: Duration::from_secs(1), // Or flush every 1s
    channel_capacity: 10_000,
    buffer_capacity: 1_000,
    write_timeout: Duration::from_secs(5),
    drop_on_overflow: true,
})
```

### 3. CircuitBreaker (Protect Writers)

```rust
use octarine::runtime::{CircuitBreaker, CircuitBreakerConfig};

CircuitBreaker::with_config(CircuitBreakerConfig {
    failure_threshold: 5,          // Open after 5 failures
    success_threshold: 0.5,        // Close after 50% success in half-open
    window_duration: Duration::from_secs(60),
    reset_timeout: Duration::from_secs(30),
    min_requests: 10,
})
```

### 4. Retry (Handle Transient Failures)

```rust
use octarine::runtime::{retry, RetryPolicy, BackoffStrategy};

Retry::with_policy(RetryPolicy {
    max_attempts: 3,
    backoff: BackoffStrategy::Exponential {
        base: Duration::from_millis(100),
        max: Duration::from_secs(30),
    },
})
```

### 5. Executor (Runtime Management)

```rust
use octarine::runtime::{executor, Executor};

// Detects existing tokio runtime or creates one
let executor = executor();

// Spawns async task (handles both async and sync contexts)
executor.spawn(async {
    process_events().await
})?;
```

## Initialization Flow

### Lazy Initialization (First Call)

```rust
static EVENT_DISPATCHER: Lazy<EventDispatcher> = Lazy::new(|| {
    EventDispatcher::new()
});

impl EventDispatcher {
    fn new() -> Self {
        // 1. Create channels
        let event_channel = Channel::with_config(...);
        let metrics_channel = Channel::with_config(...);

        // 2. Initialize async runtime (if needed)
        let executor = AdaptiveExecutor::new();

        // 3. Spawn background processors
        executor.spawn(async {
            Self::process_events(event_channel).await
        });

        executor.spawn(async {
            Self::process_metrics(metrics_channel).await
        });

        Self { event_channel, metrics_channel, executor }
    }
}
```

### Graceful Degradation (No Tokio Runtime)

```rust
pub fn dispatch_event(event: Event) {
    // Try async path first
    if let Some(dispatcher) = EVENT_DISPATCHER.try_get() {
        // Non-blocking queue to async backend
        let _ = dispatcher.event_channel.try_send(event);
    } else {
        // Fallback: Direct synchronous write
        // (Only happens if tokio initialization failed)
        ConsoleWriter::new().write_sync(&event);
    }
}
```

## Backpressure Management

### Overflow Policies

**Events** (DropOldest):

- Prioritize recent events
- Old debug logs less important than recent errors
- Ensures latest system state is captured

**Metrics** (DropNewest):

- Preserve historical trend data
- Better to have old counts than lose them entirely
- Aggregation smooths out gaps

**Context Enrichment** (Reject):

- Fast operations, should never overflow
- If full, something is seriously wrong
- Reject and log the backpressure issue

### Capacity Planning

| Queue | Capacity | Overflow | Rationale |
|-------|----------|----------|-----------|
| Events | 10,000 | DropOldest | Recent events more valuable |
| Metrics | 100,000 | DropNewest | High volume, preserve trends |
| Context | 1,000 | Reject | Should be fast, reject if slow |

## Batching Strategy

### Events

- **Batch size**: 100 events
- **Flush interval**: 1 second
- **Rationale**: Balance latency vs throughput

### Metrics

- **Batch size**: 1000 metrics
- **Flush interval**: 10 seconds
- **Rationale**: Metrics can tolerate higher latency for better aggregation

## Fault Tolerance

### Writer Failures

Each writer (Console, File, SIEM, etc.) is protected:

```rust
// Per-writer circuit breaker
let writer = CircuitBreakerWrapper::new(
    ConsoleWriter::new(),
    CircuitBreaker::with_config(...)
);

// Retry transient failures
let writer = RetryWrapper::new(
    writer,
    Retry::with_policy(...)
);
```

### Failure Isolation

If one writer fails (e.g., database down):

- Circuit breaker opens for that writer
- Other writers continue unaffected
- Events still logged to console/file
- Automatic recovery when database returns

### Observability of Observability

The observe system observes itself:

```rust
// Queue depths
metrics::gauge("observe_event_queue_depth", queue.len());
metrics::gauge("observe_metrics_queue_depth", queue.len());

// Writer health
metrics::gauge("observe_writer_console_healthy", 1.0);
metrics::gauge("observe_writer_siem_healthy", 0.0); // Circuit open

// Dropped events (backpressure)
metrics::incr("observe_events_dropped_oldest");
metrics::incr("observe_metrics_dropped_newest");
```

## Performance Characteristics

### Hot Path (Synchronous API)

- **Time**: O(1) - just a channel try_send
- **Allocations**: Minimal (event struct)
- **Blocking**: Zero - never blocks
- **Failure**: Silent drop on overflow (by design)

### Background Processing

- **Batching**: Reduces syscalls, improves throughput
- **Async I/O**: Non-blocking writes to files/network
- **Parallel writers**: Multiple destinations simultaneously
- **Circuit breakers**: Fail fast on unhealthy writers

## Use Cases

### CLI Tools

- Simple: Just call `debug()`, `info()`, etc.
- No runtime overhead: Events written directly if no tokio
- Graceful: Works even in constrained environments

### Services (MCP, APIs, etc.)

- High throughput: Batching handles 100k+ events/sec
- Reliable: Circuit breakers and retries
- Observable: Queue depths, writer health, drop rates
- Compliant: Full audit trail to SIEM systems

### Mixed Environments

- Same API everywhere
- Adapts to runtime availability
- No conditional compilation needed

## Runtime Status

The runtime module is complete with:

- ✅ Channel with observability
- ✅ Batch processor
- ✅ Circuit breakers with health monitoring
- ✅ Retry with metrics
- ✅ Executor with statistics
- ✅ Worker pools with monitoring
- ✅ Context management (correlation IDs, user context)

## Observability Features

All runtime components are observable:

- **Health monitoring**: `runtime_health()` aggregates component health
- **Statistics**: `runtime_stats()` provides detailed metrics
- **Queue depths**: Current size vs capacity
- **Drop rates**: Events/metrics lost due to overflow
- **Circuit breaker states**: Current state and transition history
- **Batch sizes**: Events per flush
- **Processing latency**: Queue time + write time

## References

- Runtime module: `src/runtime/`
- Primitives: `src/primitives/runtime/`
- Event types: `src/observe/types.rs`
- Writer trait: `src/observe/writers/mod.rs`
- Problem types: `src/observe/problem/mod.rs`
