//! Async runtime operations with built-in observability
//!
//! This module provides resilient async runtime primitives that wrap the core primitives
//! with comprehensive logging, metrics, and error context.

mod backoff;
mod batch;
mod builder;
mod channel;
mod circuit_breaker;
mod context;
mod executor;
mod retry;
mod shortcuts;
mod worker;

// Re-export public API
pub use batch::{BatchProcessor, BatchResult, BatchStatistics, batch_stats};
pub use builder::RuntimeBuilder;
pub use circuit_breaker::{
    CircuitBreaker, CircuitBreakerConfig, CircuitBreakerStatistics, CircuitState,
    circuit_breaker_stats, circuit_breakers_healthy, circuit_breakers_is_degraded,
};
pub use retry::{
    RetryResult, RetryStatistics, retry, retry_is_degraded, retry_is_healthy, retry_stats,
    retry_with_context,
};

// Channel exports
pub use channel::{
    Channel, ChannelConfig, ChannelReceiver, ChannelSender, ChannelStatistics, DropReason,
    GlobalChannelStatistics, SendOutcome, channel_stats, channels_healthy, channels_is_degraded,
};

// Executor exports
pub use executor::{
    Executor, ExecutorConfig, ExecutorStatistics, GlobalExecutorStatistics, executor_stats,
    executors_healthy, executors_is_degraded,
};

// Worker pool exports
pub use worker::{
    GlobalWorkerStatistics, WorkerConfig, WorkerPool, WorkerPoolStatistics, worker_stats,
    workers_healthy, workers_is_degraded,
};

// Re-export backoff and retry policy types (public API)
pub use backoff::{BackoffStrategy, RetryPolicy};

// Shortcut functions and health monitoring
pub use shortcuts::{
    RuntimeHealth, RuntimeStats, SpawnBlockingStatistics, bounded_channel, circuit_breaker,
    executor, runtime_health, runtime_stats, spawn, spawn_blocking, spawn_blocking_stats,
    worker_pool,
};

// Context management (correlation ID, user, tenant, session)
pub use context::{
    TaskContextBuilder, clear_context, clear_correlation_id, clear_session_id, clear_tenant_id,
    clear_user_id, correlation_id, session_id, set_correlation_id, set_session_id, set_tenant_id,
    set_user_id, tenant_id, try_correlation_id, user_id, with_correlation_id,
    with_sync_correlation_id,
};
