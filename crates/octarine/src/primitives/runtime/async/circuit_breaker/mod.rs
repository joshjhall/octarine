//! Circuit breaker types and configuration
//!
//! Pure types for the circuit breaker pattern with no dependencies on observe
//! or other internal modules. The actual circuit breaker implementation with
//! observability is in `runtime::CircuitBreaker`.
#![allow(dead_code)] // Public API primitives - not all items used internally yet
//!
//! ## Overview
//!
//! The circuit breaker pattern prevents cascading failures by:
//! 1. Monitoring failure rates
//! 2. Opening the circuit when failures exceed threshold
//! 3. Periodically testing if the service recovered
//! 4. Closing the circuit when service is healthy
//!
//! ## State Machine
//!
//! ```text
//!                    ┌─────────────────────────────────────────────┐
//!                    │           Circuit Breaker States            │
//!                    └─────────────────────────────────────────────┘
//!
//!    ┌─────────┐  failures >= threshold   ┌──────────┐
//!    │ CLOSED  │ ───────────────────────► │   OPEN   │
//!    │(normal) │                          │ (reject) │
//!    └────┬────┘                          └────┬─────┘
//!         ▲                                    │
//!         │                                    │ reset_timeout
//!         │                                    │ elapsed
//!         │                                    ▼
//!         │   success_rate >= threshold  ┌──────────┐
//!         └───────────────────────────── │ HALFOPEN │
//!                                        │  (test)  │
//!                                        └────┬─────┘
//!                                             │
//!                           failure ──────────┘
//!                             │
//!                             └──────► back to OPEN
//!
//! State Descriptions:
//! - CLOSED: Normal operation, requests flow through
//! - OPEN: Circuit tripped, all requests rejected immediately
//! - HALFOPEN: Testing recovery, limited requests allowed
//! ```
//!
//! ## Usage Examples
//!
//! ### Configuration
//!
//! ```rust,ignore
//! use octarine::primitives::runtime::circuit_breaker::{CircuitBreakerConfig, CircuitState};
//! use std::time::Duration;
//!
//! let config = CircuitBreakerConfig::default()
//!     .with_failure_threshold(5)
//!     .with_reset_timeout(Duration::from_secs(30))
//!     .with_success_threshold(0.5);
//!
//! assert_eq!(config.failure_threshold, 5);
//! ```
//!
//! ### Custom Configuration
//!
//! ```rust,ignore
//! use octarine::primitives::runtime::circuit_breaker::CircuitBreakerConfig;
//! use std::time::Duration;
//!
//! // High-availability configuration: quick to open, slow to recover
//! let ha_config = CircuitBreakerConfig {
//!     failure_threshold: 3,      // Open after 3 failures
//!     success_threshold: 0.8,    // Need 80% success to close
//!     window_duration: Duration::from_secs(30),
//!     reset_timeout: Duration::from_secs(60),
//!     min_requests: 5,
//! };
//! ```
//!
//! ## Design Notes
//!
//! This is a **primitive** module - it has NO dependencies on observe or other
//! internal modules. The actual circuit breaker with metrics and logging is in
//! `runtime::CircuitBreaker`.
//!
//! ## Module Structure
//!
//! - `state` - Circuit breaker state enum
//! - `config` - Configuration options and presets
//! - `stats` - Statistics and health metrics
//! - `breaker` - Core circuit breaker implementation

mod breaker;
mod config;
mod state;
mod stats;

// Re-export public API
pub use breaker::CircuitBreaker;
pub use config::CircuitBreakerConfig;
pub use state::CircuitState;
pub use stats::CircuitBreakerStats;
