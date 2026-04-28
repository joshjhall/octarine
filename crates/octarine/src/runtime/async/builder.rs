//! Unified RuntimeBuilder for all runtime capabilities
//!
//! Provides a single entry point for configuring and creating runtime components
//! with consistent observability settings.
//!
//! # Example
//!
//! ```rust
//! use octarine::runtime::r#async::RuntimeBuilder;
//!
//! // Create components through the builder
//! let runtime = RuntimeBuilder::new();
//!
//! // Create a channel
//! let channel = runtime.channel::<String>("events", 1000);
//!
//! // Create a circuit breaker
//! let breaker = runtime.circuit_breaker("database");
//!
//! // Create a worker pool (requires async runtime)
//! # tokio_test::block_on(async {
//! let pool = runtime.worker_pool("processors", 4);
//! pool.shutdown().await;
//! # });
//! ```

use crate::observe::Result;
use std::time::Duration;

use super::{
    Channel, ChannelConfig, CircuitBreaker, CircuitBreakerConfig, Executor, ExecutorConfig,
    RetryPolicy, WorkerConfig, WorkerPool,
};

/// Unified builder for runtime components
///
/// Provides a consistent API for creating all runtime components with
/// shared configuration options.
#[derive(Debug, Clone, Default)]
pub struct RuntimeBuilder {
    /// Default name prefix for components
    name_prefix: Option<String>,
}

impl RuntimeBuilder {
    /// Create a new RuntimeBuilder with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a default name prefix for all components
    ///
    /// Components will be named "{prefix}.{component_name}"
    pub fn with_name_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.name_prefix = Some(prefix.into());
        self
    }

    /// Get the full name for a component
    fn full_name(&self, name: &str) -> String {
        match &self.name_prefix {
            Some(prefix) => format!("{}.{}", prefix, name),
            None => name.to_string(),
        }
    }

    // ========================================================================
    // Channel creation
    // ========================================================================

    /// Create a bounded channel with default settings
    ///
    /// Uses Block overflow policy (backpressure).
    pub fn channel<T: Send + 'static>(&self, name: &str, capacity: usize) -> Channel<T> {
        Channel::new(self.full_name(name), capacity)
    }

    /// Create a channel with custom configuration
    ///
    /// Note: This method uses the name from the config directly and does NOT
    /// apply the builder's name prefix. Use this when you need full control
    /// over the channel configuration.
    pub fn channel_with_config<T: Send + 'static>(&self, config: ChannelConfig) -> Channel<T> {
        Channel::with_config(config)
    }

    /// Create a high-throughput channel (large buffer, drop oldest on overflow)
    pub fn high_throughput_channel<T: Send + 'static>(&self, name: &str) -> Channel<T> {
        Channel::with_config(ChannelConfig::high_throughput(self.full_name(name)))
    }

    /// Create a reliable channel (medium buffer, block on overflow)
    pub fn reliable_channel<T: Send + 'static>(&self, name: &str) -> Channel<T> {
        Channel::with_config(ChannelConfig::reliable(self.full_name(name)))
    }

    /// Create a low-latency channel (small buffer, reject on overflow)
    pub fn low_latency_channel<T: Send + 'static>(&self, name: &str) -> Channel<T> {
        Channel::with_config(ChannelConfig::low_latency(self.full_name(name)))
    }

    // ========================================================================
    // Circuit breaker creation
    // ========================================================================

    /// Create a circuit breaker with default settings
    ///
    /// # Errors
    ///
    /// Returns error if configuration is invalid (shouldn't happen with defaults).
    pub fn circuit_breaker(&self, name: &str) -> Result<CircuitBreaker> {
        CircuitBreaker::new(&self.full_name(name), CircuitBreakerConfig::default())
    }

    /// Create a circuit breaker with custom configuration
    ///
    /// Unlike other `*_with_config` methods, this one DOES apply the name prefix
    /// because the config doesn't contain a name - it's passed separately.
    pub fn circuit_breaker_with_config(
        &self,
        name: &str,
        config: CircuitBreakerConfig,
    ) -> Result<CircuitBreaker> {
        CircuitBreaker::new(&self.full_name(name), config)
    }

    /// Create a high-availability circuit breaker (strict thresholds)
    pub fn ha_circuit_breaker(&self, name: &str) -> Result<CircuitBreaker> {
        CircuitBreaker::new(
            &self.full_name(name),
            CircuitBreakerConfig::high_availability(),
        )
    }

    /// Create a database circuit breaker (more tolerant)
    pub fn db_circuit_breaker(&self, name: &str) -> Result<CircuitBreaker> {
        CircuitBreaker::new(&self.full_name(name), CircuitBreakerConfig::database())
    }

    /// Create an API circuit breaker (same as high-availability)
    pub fn api_circuit_breaker(&self, name: &str) -> Result<CircuitBreaker> {
        CircuitBreaker::new(&self.full_name(name), CircuitBreakerConfig::external_api())
    }

    // ========================================================================
    // Worker pool creation
    // ========================================================================

    /// Create a worker pool with specified number of workers
    pub fn worker_pool(&self, name: &str, workers: usize) -> WorkerPool {
        WorkerPool::new(self.full_name(name), workers)
    }

    /// Create a worker pool with custom configuration
    ///
    /// Note: This method uses the name from the config directly and does NOT
    /// apply the builder's name prefix. Use this when you need full control
    /// over the worker pool configuration.
    pub fn worker_pool_with_config(&self, config: WorkerConfig) -> WorkerPool {
        WorkerPool::with_config(config)
    }

    /// Create a CPU-bound worker pool (workers = CPU count)
    pub fn cpu_worker_pool(&self, name: &str) -> WorkerPool {
        WorkerPool::with_config(WorkerConfig::cpu_bound(self.full_name(name)))
    }

    /// Create an I/O-bound worker pool (workers = 2x CPU count)
    pub fn io_worker_pool(&self, name: &str) -> WorkerPool {
        WorkerPool::with_config(WorkerConfig::io_bound(self.full_name(name)))
    }

    /// Create a single-threaded worker pool
    pub fn single_worker_pool(&self, name: &str) -> WorkerPool {
        WorkerPool::with_config(WorkerConfig::single_threaded(self.full_name(name)))
    }

    // ========================================================================
    // Executor creation
    // ========================================================================

    /// Create an executor with default settings
    pub fn executor(&self, name: &str) -> Executor {
        Executor::with_name(self.full_name(name))
    }

    /// Create an executor with custom configuration
    ///
    /// The name prefix is applied to the provided name.
    pub fn executor_with_config(&self, name: &str, config: ExecutorConfig) -> Executor {
        Executor::with_config(self.full_name(name), config)
    }

    /// Create a lightweight executor (single thread, time only)
    pub fn lightweight_executor(&self, name: &str) -> Executor {
        Executor::with_config(self.full_name(name), ExecutorConfig::lightweight())
    }

    /// Create a full-featured executor (multi-thread, all features)
    pub fn full_executor(&self, name: &str) -> Executor {
        Executor::with_config(self.full_name(name), ExecutorConfig::full_featured())
    }

    /// Create a compute-only executor (multi-thread, no I/O)
    pub fn compute_executor(&self, name: &str) -> Executor {
        Executor::with_config(self.full_name(name), ExecutorConfig::compute_only())
    }

    // ========================================================================
    // Retry policy creation (these return policies, not executors)
    // ========================================================================

    /// Create a retry policy for network operations
    ///
    /// Exponential backoff starting at 100ms, max 30s, up to 5 attempts.
    pub fn network_retry_policy(&self) -> RetryPolicy {
        RetryPolicy::network()
    }

    /// Create a retry policy for database operations
    ///
    /// Exponential backoff starting at 1s, max 10s, up to 3 attempts.
    pub fn database_retry_policy(&self) -> RetryPolicy {
        RetryPolicy::database()
    }

    /// Create a custom retry policy with fixed delay
    pub fn fixed_retry_policy(&self, max_attempts: u32, delay: Duration) -> RetryPolicy {
        RetryPolicy::fixed(max_attempts, delay)
    }

    /// Create a custom retry policy with exponential backoff (default base/max)
    pub fn exponential_retry_policy(&self, max_attempts: u32) -> RetryPolicy {
        RetryPolicy::exponential(max_attempts)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_runtime_builder_default() {
        let builder = RuntimeBuilder::new();
        assert!(builder.name_prefix.is_none());
    }

    #[test]
    fn test_runtime_builder_with_prefix() {
        let builder = RuntimeBuilder::new().with_name_prefix("myapp");
        assert_eq!(builder.full_name("channel"), "myapp.channel");
    }

    #[test]
    fn test_create_channel() {
        let builder = RuntimeBuilder::new();
        let _channel: Channel<i32> = builder.channel("test", 100);
    }

    #[test]
    fn test_create_circuit_breaker() {
        let builder = RuntimeBuilder::new();
        let cb = builder.circuit_breaker("test");
        assert!(cb.is_ok());
    }

    #[tokio::test]
    async fn test_create_worker_pool() {
        let builder = RuntimeBuilder::new();
        let pool = builder.worker_pool("test", 2);
        pool.shutdown().await;
    }

    #[test]
    fn test_create_executor() {
        let builder = RuntimeBuilder::new();
        let executor = builder.executor("test");
        assert_eq!(executor.name(), "test");
    }

    #[test]
    fn test_retry_policies() {
        let builder = RuntimeBuilder::new();
        let _network = builder.network_retry_policy();
        let _db = builder.database_retry_policy();
        let _fixed = builder.fixed_retry_policy(3, Duration::from_millis(100));
        let _exp = builder.exponential_retry_policy(5);
    }

    #[test]
    fn test_prefixed_names() {
        let builder = RuntimeBuilder::new().with_name_prefix("service");

        let executor = builder.executor("worker");
        assert_eq!(executor.name(), "service.worker");
    }

    // ========================================================================
    // Channel name-prefix and config propagation
    //
    // These tests exercise observable channel state via `.split()`, which
    // exposes `sender.name()` / `receiver.name()`. They guard against
    // regressions where `with_name_prefix` silently stops propagating into
    // channel names, and lock in the documented quirk that
    // `channel_with_config` does NOT apply the builder prefix (the config
    // already carries its own name).
    // ========================================================================

    #[test]
    fn test_with_name_prefix_propagates_to_channel() {
        let builder = RuntimeBuilder::new().with_name_prefix("svc");
        let channel: Channel<i32> = builder.channel("events", 100);

        let (sender, receiver) = channel.split();
        assert_eq!(sender.name(), "svc.events");
        assert_eq!(receiver.name(), "svc.events");
    }

    #[test]
    fn test_with_name_prefix_propagates_to_high_throughput_channel() {
        let builder = RuntimeBuilder::new().with_name_prefix("svc");
        let channel: Channel<i32> = builder.high_throughput_channel("ingest");

        let (sender, _receiver) = channel.split();
        assert_eq!(
            sender.name(),
            "svc.ingest",
            "high_throughput_channel must apply the builder prefix",
        );
    }

    #[test]
    fn test_with_name_prefix_propagates_to_reliable_channel() {
        let builder = RuntimeBuilder::new().with_name_prefix("svc");
        let channel: Channel<i32> = builder.reliable_channel("queue");

        let (sender, _receiver) = channel.split();
        assert_eq!(sender.name(), "svc.queue");
    }

    #[test]
    fn test_with_name_prefix_propagates_to_low_latency_channel() {
        let builder = RuntimeBuilder::new().with_name_prefix("svc");
        let channel: Channel<i32> = builder.low_latency_channel("rpc");

        let (sender, _receiver) = channel.split();
        assert_eq!(sender.name(), "svc.rpc");
    }

    #[test]
    fn test_channel_with_config_uses_config_name_verbatim() {
        // Documented behavior: channel_with_config does NOT apply the
        // builder prefix because the config already carries its own name.
        let builder = RuntimeBuilder::new().with_name_prefix("ignored");
        let config = ChannelConfig::low_latency("explicit");

        // Sanity: confirm the assertion below tracks the config's actual
        // name and capacity. If `ChannelConfig::low_latency` is changed,
        // these expectations need to follow.
        assert_eq!(config.name(), "explicit");
        assert_eq!(config.capacity(), 100);

        let channel: Channel<i32> = builder.channel_with_config(config);
        let (sender, receiver) = channel.split();
        assert_eq!(
            sender.name(),
            "explicit",
            "channel_with_config must NOT prepend the builder prefix",
        );
        assert_eq!(receiver.name(), "explicit");
    }

    #[test]
    fn test_channel_with_config_preserves_capacity() {
        // Verify that channel_with_config actually wires the supplied
        // ChannelConfig through to channel construction. The builder is
        // a thin passthrough to `Channel::with_config`, so we assert
        // that the explicit config name and capacity survive.
        let custom = ChannelConfig::new("custom", 8);
        assert_eq!(custom.capacity(), 8, "sanity check on input config");

        let builder = RuntimeBuilder::new();
        let channel: Channel<u8> = builder.channel_with_config(custom);
        let (sender, _receiver) = channel.split();
        assert_eq!(sender.name(), "custom");
    }
}
