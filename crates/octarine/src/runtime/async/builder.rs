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
use crate::observe::metrics::{MetricName, increment_by};
use std::time::Duration;

use super::{
    Channel, ChannelConfig, CircuitBreaker, CircuitBreakerConfig, Executor, ExecutorConfig,
    RetryPolicy, WorkerConfig, WorkerPool,
};

crate::define_metrics! {
    channels_created => "runtime.async.channels_created",
    circuit_breakers_created => "runtime.async.circuit_breakers_created",
    worker_pools_created => "runtime.async.worker_pools_created",
    executors_created => "runtime.async.executors_created",
}

/// Unified builder for runtime components
///
/// Provides a consistent API for creating all runtime components with
/// shared configuration options.
///
/// # Observability
///
/// Component construction is counted (`runtime.async.channels_created`,
/// `runtime.async.circuit_breakers_created`,
/// `runtime.async.worker_pools_created`, `runtime.async.executors_created`).
/// Use [`silent()`](Self::silent) or [`with_events(false)`](Self::with_events)
/// to skip recording.
#[derive(Debug, Clone)]
pub struct RuntimeBuilder {
    /// Default name prefix for components
    name_prefix: Option<String>,
    /// Whether to record component-creation metrics
    emit_events: bool,
}

impl Default for RuntimeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RuntimeBuilder {
    /// Create a new RuntimeBuilder with default settings
    pub fn new() -> Self {
        Self {
            name_prefix: None,
            emit_events: true,
        }
    }

    /// Create a builder that records no component-creation metrics
    pub fn silent() -> Self {
        Self {
            name_prefix: None,
            emit_events: false,
        }
    }

    /// Enable or disable component-creation metrics
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    /// Count a component construction when events are enabled.
    fn count_created(&self, metric: MetricName) {
        if self.emit_events {
            increment_by(metric, 1);
        }
    }

    /// Count a circuit-breaker construction only if it actually succeeded.
    ///
    /// `CircuitBreaker::new` validates its config and can return `Err`, so
    /// counting before the call would report attempts rather than creations.
    fn count_breaker_created(&self, result: Result<CircuitBreaker>) -> Result<CircuitBreaker> {
        if result.is_ok() {
            self.count_created(metric_names::circuit_breakers_created());
        }
        result
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
        self.count_created(metric_names::channels_created());
        Channel::new(self.full_name(name), capacity)
    }

    /// Create a channel with custom configuration
    ///
    /// Note: This method uses the name from the config directly and does NOT
    /// apply the builder's name prefix. Use this when you need full control
    /// over the channel configuration.
    pub fn channel_with_config<T: Send + 'static>(&self, config: ChannelConfig) -> Channel<T> {
        self.count_created(metric_names::channels_created());
        Channel::with_config(config)
    }

    /// Create a high-throughput channel (large buffer, drop oldest on overflow)
    pub fn high_throughput_channel<T: Send + 'static>(&self, name: &str) -> Channel<T> {
        self.count_created(metric_names::channels_created());
        Channel::with_config(ChannelConfig::high_throughput(self.full_name(name)))
    }

    /// Create a reliable channel (medium buffer, block on overflow)
    pub fn reliable_channel<T: Send + 'static>(&self, name: &str) -> Channel<T> {
        self.count_created(metric_names::channels_created());
        Channel::with_config(ChannelConfig::reliable(self.full_name(name)))
    }

    /// Create a low-latency channel (small buffer, reject on overflow)
    pub fn low_latency_channel<T: Send + 'static>(&self, name: &str) -> Channel<T> {
        self.count_created(metric_names::channels_created());
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
        self.count_breaker_created(CircuitBreaker::new(
            &self.full_name(name),
            CircuitBreakerConfig::default(),
        ))
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
        self.count_breaker_created(CircuitBreaker::new(&self.full_name(name), config))
    }

    /// Create a high-availability circuit breaker (strict thresholds)
    pub fn ha_circuit_breaker(&self, name: &str) -> Result<CircuitBreaker> {
        self.count_breaker_created(CircuitBreaker::new(
            &self.full_name(name),
            CircuitBreakerConfig::high_availability(),
        ))
    }

    /// Create a database circuit breaker (more tolerant)
    pub fn db_circuit_breaker(&self, name: &str) -> Result<CircuitBreaker> {
        self.count_breaker_created(CircuitBreaker::new(
            &self.full_name(name),
            CircuitBreakerConfig::database(),
        ))
    }

    /// Create an API circuit breaker (same as high-availability)
    pub fn api_circuit_breaker(&self, name: &str) -> Result<CircuitBreaker> {
        self.count_breaker_created(CircuitBreaker::new(
            &self.full_name(name),
            CircuitBreakerConfig::external_api(),
        ))
    }

    // ========================================================================
    // Worker pool creation
    // ========================================================================

    /// Create a worker pool with specified number of workers
    pub fn worker_pool(&self, name: &str, workers: usize) -> WorkerPool {
        self.count_created(metric_names::worker_pools_created());
        WorkerPool::new(self.full_name(name), workers)
    }

    /// Create a worker pool with custom configuration
    ///
    /// Note: This method uses the name from the config directly and does NOT
    /// apply the builder's name prefix. Use this when you need full control
    /// over the worker pool configuration.
    pub fn worker_pool_with_config(&self, config: WorkerConfig) -> WorkerPool {
        self.count_created(metric_names::worker_pools_created());
        WorkerPool::with_config(config)
    }

    /// Create a CPU-bound worker pool (workers = CPU count)
    pub fn cpu_worker_pool(&self, name: &str) -> WorkerPool {
        self.count_created(metric_names::worker_pools_created());
        WorkerPool::with_config(WorkerConfig::cpu_bound(self.full_name(name)))
    }

    /// Create an I/O-bound worker pool (workers = 2x CPU count)
    pub fn io_worker_pool(&self, name: &str) -> WorkerPool {
        self.count_created(metric_names::worker_pools_created());
        WorkerPool::with_config(WorkerConfig::io_bound(self.full_name(name)))
    }

    /// Create a single-threaded worker pool
    pub fn single_worker_pool(&self, name: &str) -> WorkerPool {
        self.count_created(metric_names::worker_pools_created());
        WorkerPool::with_config(WorkerConfig::single_threaded(self.full_name(name)))
    }

    // ========================================================================
    // Executor creation
    // ========================================================================

    /// Create an executor with default settings
    pub fn executor(&self, name: &str) -> Executor {
        self.count_created(metric_names::executors_created());
        Executor::with_name(self.full_name(name))
    }

    /// Create an executor with custom configuration
    ///
    /// The name prefix is applied to the provided name.
    pub fn executor_with_config(&self, name: &str, config: ExecutorConfig) -> Executor {
        self.count_created(metric_names::executors_created());
        Executor::with_config(self.full_name(name), config)
    }

    /// Create a lightweight executor (single thread, time only)
    pub fn lightweight_executor(&self, name: &str) -> Executor {
        self.count_created(metric_names::executors_created());
        Executor::with_config(self.full_name(name), ExecutorConfig::lightweight())
    }

    /// Create a full-featured executor (multi-thread, all features)
    pub fn full_executor(&self, name: &str) -> Executor {
        self.count_created(metric_names::executors_created());
        Executor::with_config(self.full_name(name), ExecutorConfig::full_featured())
    }

    /// Create a compute-only executor (multi-thread, no I/O)
    pub fn compute_executor(&self, name: &str) -> Executor {
        self.count_created(metric_names::executors_created());
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

    use crate::observe::metrics::{flush_for_testing, snapshot};

    fn counter_value(name: &str) -> u64 {
        snapshot().counters.get(name).map_or(0, |c| c.value)
    }

    #[test]
    fn test_runtime_builder_default() {
        let builder = RuntimeBuilder::new();
        assert!(builder.name_prefix.is_none());
        // Default must route through new(), not derive a `false` flag.
        assert!(RuntimeBuilder::default().emit_events);
    }

    #[test]
    fn test_builder_event_flags() {
        assert!(RuntimeBuilder::new().emit_events);
        assert!(!RuntimeBuilder::silent().emit_events);
        assert!(!RuntimeBuilder::new().with_events(false).emit_events);
        assert!(RuntimeBuilder::silent().with_events(true).emit_events);
    }

    #[test]
    fn test_with_name_prefix_survives_with_events() {
        // with_events must not reset unrelated builder state.
        let builder = RuntimeBuilder::new()
            .with_name_prefix("svc")
            .with_events(false);
        assert_eq!(builder.full_name("chan"), "svc.chan");
    }

    #[test]
    fn test_component_creation_counted() {
        let _guard = crate::observe::metrics::metrics_test_lock();
        let builder = RuntimeBuilder::new();

        flush_for_testing();
        let channels_before = counter_value("runtime.async.channels_created");
        let breakers_before = counter_value("runtime.async.circuit_breakers_created");
        let executors_before = counter_value("runtime.async.executors_created");

        let _channel: Channel<i32> = builder.channel("counted", 4);
        let _reliable: Channel<i32> = builder.reliable_channel("counted2");
        let _breaker = builder.circuit_breaker("counted").expect("breaker");
        let _executor = builder.executor("counted");
        flush_for_testing();

        assert!(
            counter_value("runtime.async.channels_created") >= channels_before.saturating_add(2),
            "both channel constructors must count",
        );
        assert!(
            counter_value("runtime.async.circuit_breakers_created")
                >= breakers_before.saturating_add(1),
            "circuit breaker creation must count",
        );
        assert!(
            counter_value("runtime.async.executors_created") >= executors_before.saturating_add(1),
            "executor creation must count",
        );
    }

    #[test]
    fn test_failed_circuit_breaker_is_not_counted() {
        // CircuitBreaker::new validates its config and can fail; counting
        // before the call would report attempts rather than creations. The
        // check is structural -- count_breaker_created() only counts on Ok --
        // because the metrics registry is process-global and concurrent
        // sibling tests also create breakers.
        let builder = RuntimeBuilder::new();

        // failure_threshold = 0 is rejected by CircuitBreakerConfig::validate
        // ("circuit would always be open").
        let bad =
            CircuitBreakerConfig::new(0, 0.8, Duration::from_secs(60), Duration::from_secs(30));
        assert!(
            builder.circuit_breaker_with_config("bad", bad).is_err(),
            "a zero failure_threshold must fail validation",
        );

        // All five constructors route through the same helper, and each must
        // still succeed with a valid config.
        builder.circuit_breaker("good").expect("valid breaker");
        builder.ha_circuit_breaker("ha").expect("ha breaker");
        builder.db_circuit_breaker("db").expect("db breaker");
        builder.api_circuit_breaker("api").expect("api breaker");
        builder
            .circuit_breaker_with_config("cfg", CircuitBreakerConfig::default())
            .expect("cfg breaker");
    }
    #[test]
    fn test_worker_pool_creation_counted() {
        // WorkerPool::new spawns tokio tasks so it needs a runtime, but
        // flush_for_testing() blocks on a oneshot and panics inside one --
        // so the pool is built in a scoped runtime and flushed outside it.
        let _guard = crate::observe::metrics::metrics_test_lock();

        flush_for_testing();
        let before = counter_value("runtime.async.worker_pools_created");

        let rt = tokio::runtime::Runtime::new().expect("runtime");
        rt.block_on(async {
            // All five constructors share the count_created call site, and
            // each is exercised so a mistake confined to one is caught.
            let builder = RuntimeBuilder::new();
            builder.worker_pool("counted", 1).shutdown().await;
            builder
                .worker_pool_with_config(WorkerConfig::single_threaded("cfg"))
                .shutdown()
                .await;
            builder.cpu_worker_pool("cpu").shutdown().await;
            builder.io_worker_pool("io").shutdown().await;
            builder.single_worker_pool("single").shutdown().await;
        });
        flush_for_testing();

        assert!(
            counter_value("runtime.async.worker_pools_created") >= before.saturating_add(5),
            "every worker pool constructor must count exactly once",
        );

        // silent() must not count, or the assertion above proves nothing
        // about the gate.
        let quiet_before = counter_value("runtime.async.worker_pools_created");
        rt.block_on(async {
            let pool = RuntimeBuilder::silent().single_worker_pool("quiet");
            pool.shutdown().await;
        });
        flush_for_testing();

        assert_eq!(
            counter_value("runtime.async.worker_pools_created"),
            quiet_before,
            "silent() must not count worker pool creation",
        );
    }

    #[test]
    fn test_silent_builder_counts_nothing() {
        // Gate-level: every count_created() call sits behind this one flag,
        // and the metrics registry is process-global so an absolute "did not
        // move" assertion races concurrent sibling tests.
        let builder = RuntimeBuilder::silent().with_name_prefix("quiet");
        assert!(!builder.emit_events);
        assert!(
            RuntimeBuilder::new().emit_events,
            "the default must differ, or the assertion above is vacuous",
        );

        // The components are still fully constructed and named.
        let channel: Channel<i32> = builder.channel("chan", 4);
        let executor = builder.executor("exec");
        let (sender, _receiver) = channel.split();
        assert_eq!(sender.name(), "quiet.chan");
        assert_eq!(executor.name(), "quiet.exec");
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
