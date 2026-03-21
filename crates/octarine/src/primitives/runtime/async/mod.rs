//! Async runtime primitives
//!
//! Pure async utilities with no observe dependencies. These provide the core
//! functionality that is wrapped by the public `runtime` module with observability.
//!
//! ## Features
//!
//! - **Async Utilities**: Sleep, interval, yield for async operations
//! - **Blocking Operations**: Run blocking I/O with context propagation
//! - **Configuration**: Runtime configuration types and builders
//! - **Context**: Task-local and thread-local context storage
//! - **Backoff**: Retry strategies and backoff algorithms
//! - **Circuit Breaker**: Circuit breaker configuration and state
//! - **Channel**: Channel statistics and health monitoring
//!
//! ## Architecture Note
//!
//! This is a **primitive** module - it has NO dependencies on observe or other
//! internal modules. The public `runtime` module wraps these primitives and adds
//! logging, metrics, and event dispatching.

pub(crate) mod async_utils;
pub(crate) mod backoff;
pub(crate) mod batch;
pub(crate) mod broadcast;
pub(crate) mod channel;
pub(crate) mod circuit_breaker;
pub(crate) mod config;
pub(crate) mod context;
pub(crate) mod executor;
pub(crate) mod worker;

// Re-export async utilities
#[allow(unused_imports, dead_code)] // Some reserved for future use
pub use async_utils::{
    interval, interval_ms, sleep, sleep_ms, spawn_blocking, spawn_blocking_result, timeout,
    yield_now,
};

// Re-export JoinError for spawn_blocking users
#[allow(unused_imports)] // Will be used by primitives/io
pub use tokio::task::JoinError;

// Re-export backoff/retry types (some items reserved for future use)
pub(crate) use backoff::BackoffStrategyCore;
#[allow(unused_imports)]
pub use backoff::{RetryOutcome, RetryPolicy, RetryStats};

// Re-export batch processor
pub use batch::BatchProcessor;

// Re-export circuit breaker types (some items reserved for future use)
#[allow(unused_imports)]
pub use circuit_breaker::{
    CircuitBreaker, CircuitBreakerConfig, CircuitBreakerStats, CircuitState,
};

// Re-export configuration types
#[allow(unused_imports, dead_code)] // Some reserved for future use
pub use config::{OverflowPolicy, RuntimeConfig};

// Re-export channel types
pub use channel::{
    BoundedChannel, ChannelConfig, ChannelReceiver, ChannelSender, ChannelStats, DropReason,
    SendOutcome,
};

// Re-export broadcast types (reserved for future use)
#[allow(unused_imports)]
pub use broadcast::{Broadcast, BroadcastConfig, BroadcastReceiver, BroadcastStats, RecvOutcome};

// Re-export executor types (some items reserved for future use)
#[allow(unused_imports)]
pub use executor::{AdaptiveExecutor, ExecutionOutcome, ExecutorConfig, ExecutorStats};

// Re-export worker types (some items reserved for future use)
#[allow(unused_imports)]
pub use worker::{SubmitOutcome, Task, WorkerConfig, WorkerPool, WorkerStats};

// Re-export context types for parent module
pub use context::{TaskContext, TaskLocal};

// Re-export context internal functions for parent module shortcut functions
pub(crate) use context::{
    clear_thread_context, clear_thread_correlation_id, clear_thread_session_id,
    clear_thread_tenant_id, clear_thread_user_id, get_thread_correlation_id, get_thread_session_id,
    get_thread_tenant_id, get_thread_user_id, set_thread_correlation_id, set_thread_session_id,
    set_thread_tenant_id, set_thread_user_id,
};
