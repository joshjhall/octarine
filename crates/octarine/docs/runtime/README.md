# Runtime Documentation

The `runtime` module provides resilient async infrastructure with built-in observability, built on tokio.

## Quick Links

- **[Architecture](./architecture.md)** - Design principles and module structure
- **[Observability Integration](./observability-integration.md)** - How runtime integrates with observe module
- **[Metrics Reference](./metrics-reference.md)** - Complete metrics emitted by runtime components

## Overview

The runtime module provides:

- **Adaptive Executor**: Automatically handles both sync and async contexts
- **Bounded Channels**: Channels with configurable overflow policies (block, reject, drop)
- **Retry with Backoff**: Configurable retry logic with exponential/fixed backoff
- **Circuit Breaker**: Automatic failure detection and circuit breaking
- **Worker Pools**: Task distribution across worker threads
- **Batch Processor**: Efficient batching with size/time thresholds
- **Context Management**: Correlation IDs, user context, and tenant context

## Architecture

The runtime follows a two-layer architecture:

```text
┌─────────────────────────────────────────────┐
│ Public API: runtime/ (Layer 3)              │
│ - Full observability (events, metrics)      │
│ - Health monitoring and diagnostics         │
│ - Shortcut functions                        │
└─────────────────────────────────────────────┘
         ↓ wraps
┌─────────────────────────────────────────────┐
│ Primitives: primitives/runtime/ (Layer 1)   │
│ - Pure implementations, no observe deps     │
│ - Core algorithms                           │
└─────────────────────────────────────────────┘
```

## Key Features

### 🔄 Context Awareness

The executor automatically detects whether it's running in a sync or async context and adapts accordingly.

### 🔒 Security by Default

- All channels are bounded to prevent memory exhaustion
- Configurable overflow policies for backpressure handling
- Rate limiting built into worker pools

### 📊 Comprehensive Observability

All runtime components emit detailed metrics and events:

- Queue sizes and utilization
- Operation timing and throughput
- Error rates and retry attempts
- Circuit breaker states
- Health monitoring via `runtime_health()`

### 🏥 Health Monitoring

```rust
use octarine::runtime::{runtime_health, runtime_stats};

let health = runtime_health();
if health.is_degraded() {
    eprintln!("Warning: {}", health.summary());
}

let stats = runtime_stats();
println!("Total retries: {}", stats.retry.total_attempts);
```

## Module Structure

```text
runtime/
├── mod.rs            # Public API exports and shortcuts
├── batch.rs          # Batch processor with metrics
├── builder.rs        # RuntimeBuilder configuration
├── channel.rs        # Bounded channels with logging
├── circuit_breaker.rs # Circuit breaker with events
├── executor.rs       # Adaptive executor with stats
├── retry.rs          # Retry with observability
└── worker.rs         # Worker pool with monitoring

primitives/runtime/
├── mod.rs            # Internal exports
├── async_utils.rs    # sleep, interval, timeout
├── backoff.rs        # Backoff strategies
├── broadcast.rs      # Broadcast channels
├── channel.rs        # Core channel implementation
├── circuit_breaker.rs # Circuit breaker state machine
├── config.rs         # Configuration types
├── context.rs        # Task context management
├── executor.rs       # Core executor
└── worker.rs         # Core worker pool
```

## Usage Examples

### Channels

```rust
use octarine::runtime::bounded_channel;

let (tx, mut rx) = bounded_channel::<String>("events", 1000);
tx.send("hello".to_string()).await?;
```

### Circuit Breaker

```rust
use octarine::runtime::circuit_breaker;

let breaker = circuit_breaker("database");
let result = breaker.execute("query", || async {
    database.query("SELECT * FROM users").await
}).await?;
```

### Worker Pool

```rust
use octarine::runtime::worker_pool;

let pool = worker_pool("processors", 4);
pool.spawn(|| heavy_computation())?;
pool.shutdown().await;
```

### Context Management

```rust
use octarine::{task_context, TaskContextBuilder, correlation_id_get};

let ctx = TaskContextBuilder::new()
    .correlation_id("req-123")
    .user_id("user-456")
    .build();

task_context(ctx, async {
    println!("Correlation: {:?}", correlation_id_get());
}).await;
```

## Related Documentation

- [Observe Module](../observe/) - Event system and metrics
- [Security Module](../security/) - Security primitives
- [Visibility Refactor Summary](../architecture/visibility-refactor-summary.md) - Architecture details

## Examples

See the test modules in each file for comprehensive usage examples.
