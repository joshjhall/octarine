//! Runtime operations with built-in observability
//!
//! This module provides resilient runtime primitives that wrap the core primitives
//! with comprehensive logging, metrics, and error context. It is the public API
//! for async operations, retry policies, circuit breakers, and batch processing.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │ Public API (this module)                                │
//! │ - Full observability (events, metrics, logging)         │
//! │ - Rich error context with Problem type                  │
//! │ - Health monitoring and diagnostics                     │
//! └─────────────────────────────────────────────────────────┘
//!          ↓ wraps
//! ┌─────────────────────────────────────────────────────────┐
//! │ Primitives (primitives/runtime)                         │
//! │ - Pure implementations, no dependencies                 │
//! │ - Core algorithms (backoff, circuit breaker state)      │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! # Features
//!
//! - **Retry**: Execute operations with configurable retry policies and full observability
//! - **Circuit Breaker**: Protect services with automatic failure detection and recovery
//! - **Batch Processor**: Efficient batching with size/time thresholds
//! - **Async Utilities**: Sleep, interval, timeout with timing metrics
//! - **Graceful Shutdown**: Coordinated service shutdown with signal handling and cleanup hooks
//! - **Rate Limiting**: Keyed rate limiting with GCRA algorithm and automatic logging
//!
//! # Usage
//!
//! ## Retry with Observability
//!
//! ```rust
//! use octarine::runtime::r#async::{retry, RetryPolicy};
//! use octarine::Problem;
//!
//! async fn fetch_data() -> Result<String, Problem> {
//!     Ok("data".to_string())
//! }
//!
//! # tokio_test::block_on(async {
//! // Retry with default exponential backoff
//! let result = retry("fetch_data", RetryPolicy::default(), fetch_data).await;
//! assert!(result.is_ok());
//! # });
//! ```
//!
//! ## Circuit Breaker with Observability
//!
//! ```rust
//! use octarine::runtime::r#async::{CircuitBreaker, CircuitBreakerConfig};
//! use octarine::Problem;
//!
//! let breaker = CircuitBreaker::new("database", CircuitBreakerConfig::default()).unwrap();
//!
//! # tokio_test::block_on(async {
//! // Execute with circuit breaker protection
//! let result = breaker.execute("query", || async {
//!     Ok::<_, Problem>("query result".to_string())
//! }).await;
//! assert!(result.is_ok());
//! # });
//! ```
//!
//! ## Batch Processor with Observability
//!
//! ```rust
//! use octarine::runtime::r#async::BatchProcessor;
//! use std::time::Duration;
//!
//! let mut batch: BatchProcessor<String> = BatchProcessor::new("events", 100, Duration::from_secs(1));
//!
//! // Add items with automatic flush detection
//! let result = batch.add("event1".to_string());
//! if result.should_flush() {
//!     let items = batch.take();
//!     // process_batch(items);
//! }
//! ```
//!
//! ## Channel with Observability
//!
//! ```rust
//! use octarine::runtime::r#async::bounded_channel;
//!
//! # tokio_test::block_on(async {
//! // Create a reliable channel (backpressure)
//! let (tx, mut rx) = bounded_channel::<String>("events", 1000);
//!
//! // Send with automatic logging
//! tx.send("hello".to_string()).await.unwrap();
//!
//! // Receive
//! let msg = rx.recv().await;
//! assert_eq!(msg, Some("hello".to_string()));
//! # });
//! ```
//!
//! ## Worker Pool with Observability
//!
//! ```rust
//! use octarine::runtime::r#async::worker_pool;
//!
//! # tokio_test::block_on(async {
//! // Create a worker pool
//! let pool = worker_pool("processors", 2);
//!
//! // Spawn tasks
//! pool.spawn(|| { /* task */ }).unwrap();
//!
//! // Graceful shutdown
//! pool.shutdown().await;
//! # });
//! ```
//!
//! ## Executor with Observability
//!
//! ```rust
//! use octarine::runtime::r#async::executor;
//!
//! // Works in both sync and async contexts
//! let exec = executor();
//!
//! // Execute a future (creates runtime if needed)
//! let result = exec.block_on(async {
//!     42
//! });
//! assert!(result.is_ok());
//! ```
//!
//! # Health Monitoring
//!
//! All components provide health status and statistics:
//!
//! ```rust
//! use octarine::runtime::r#async::{runtime_health, runtime_stats};
//!
//! // Get overall runtime health
//! let health = runtime_health();
//! let summary = health.summary();
//!
//! // Get detailed statistics
//! let stats = runtime_stats();
//! let _ = stats.retry.total_operations;
//! ```
//!
//! # Module Structure
//!
//! - `async/` - Async runtime operations (channels, retry, circuit breaker, etc.)
//! - `cli/` - CLI framework integration (feature-gated)
//! - `config/` - Configuration management
//! - `process/` - Secure subprocess execution
//! - `rate_limiter/` - Keyed rate limiting with observability
//! - `shutdown/` - Graceful shutdown coordination

// ============================================================================
// Public Submodules (Layer 3 - no cross-dependencies allowed)
// Each subdomain has different verbs, so exposed as separate modules
// ============================================================================

// Async runtime submodule - uses path attribute because "async" is a reserved keyword
// Mirrors primitives::runtime::r#async structure
#[path = "async/mod.rs"]
pub mod r#async;

// Graceful shutdown coordination
pub mod shutdown;

// Configuration management
pub mod config;

// CLI framework (feature-gated)
#[cfg(feature = "cli")]
pub mod cli;

// Secure process execution
pub mod process;

// Rate limiting with observability
pub mod rate_limiter;

// Database pool management (feature-gated)
#[cfg(feature = "postgres")]
pub mod database;

// HTTP client with observability
pub mod http;

// Secure format handling (JSON, XML, YAML)
#[cfg(feature = "formats")]
pub mod formats;

// Observable shell execution (feature-gated)
#[cfg(feature = "shell")]
pub mod shell;
