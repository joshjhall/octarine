//! Backoff strategies for retry operations
//!
//! Provides configurable backoff algorithms for resilient operation execution.
//! These are pure algorithms with no dependencies on observe or other internal modules.
#![allow(dead_code)] // Public API primitives - not all items used internally yet
//!
//! ## Strategies
//!
//! - **Fixed**: Constant delay between retries
//! - **Linear**: Delay increases linearly (base * attempt)
//! - **Exponential**: Delay doubles each attempt (base * 2^attempt)
//! - **Fibonacci**: Delay follows fibonacci sequence
//! - **DecorrelatedJitter**: AWS-recommended jitter for distributed systems
//! - **Custom**: User-provided delay function
//!
//! ## Retry Flow
//!
//! ```text
//!     ┌────────────────────────────────────────────────┐
//!     │               Retry Operation Flow              │
//!     └────────────────────────────────────────────────┘
//!
//!     ┌─────────┐
//!     │  Start  │
//!     └────┬────┘
//!          │
//!          ▼
//!     ┌─────────────┐
//!     │ Execute Op  │◄──────────────────┐
//!     └──────┬──────┘                   │
//!            │                          │
//!        ┌───┴───┐                      │
//!        │Result?│                      │
//!        └───┬───┘                      │
//!            │                          │
//!     ┌──────┴──────┐                   │
//!     │             │                   │
//!   Success       Failure               │
//!     │             │                   │
//!     ▼             ▼                   │
//! ┌───────┐   ┌───────────────┐         │
//! │Return │   │ More attempts │         │
//! │  Ok   │   │   remaining?  │         │
//! └───────┘   └───────┬───────┘         │
//!                     │                 │
//!              ┌──────┴──────┐          │
//!              │             │          │
//!             Yes            No         │
//!              │             │          │
//!              ▼             ▼          │
//!        ┌──────────┐   ┌────────┐      │
//!        │  Sleep   │   │ Return │      │
//!        │(backoff) │   │  Err   │      │
//!        └─────┬────┘   └────────┘      │
//!              │                        │
//!              └────────────────────────┘
//! ```
//!
//! ## Usage Examples
//!
//! ### Basic Usage
//!
//! ```rust,ignore
//! use octarine::primitives::runtime::backoff::{BackoffStrategy, RetryPolicy};
//! use std::time::Duration;
//!
//! // Fixed delay of 100ms
//! let fixed = BackoffStrategy::Fixed(Duration::from_millis(100));
//! assert_eq!(fixed.delay(0), Duration::from_millis(100));
//! assert_eq!(fixed.delay(5), Duration::from_millis(100));
//!
//! // Exponential backoff with cap
//! let exp = BackoffStrategy::Exponential {
//!     base: Duration::from_millis(100),
//!     max: Duration::from_secs(10),
//! };
//! assert_eq!(exp.delay(0), Duration::from_millis(100));
//! assert_eq!(exp.delay(3), Duration::from_millis(800));
//! ```
//!
//! ### Retry Policy
//!
//! ```rust,ignore
//! use octarine::primitives::runtime::backoff::{BackoffStrategy, RetryPolicy};
//! use std::time::Duration;
//!
//! let policy = RetryPolicy::fixed(3, Duration::from_millis(100));
//! assert_eq!(policy.max_attempts, 3);
//!
//! // Or use builder pattern
//! let policy = RetryPolicy::default()
//!     .with_max_attempts(5)
//!     .with_backoff(BackoffStrategy::Linear {
//!         base: Duration::from_millis(50),
//!     })
//!     .with_jitter(true);
//! ```
//!
//! ## Design Notes
//!
//! This is a **primitive** module - it has NO dependencies on observe or other
//! internal modules. The actual retry execution with observability is in
//! `runtime::retry`.
//!
//! ## Module Structure
//!
//! - `strategy` - Backoff strategy algorithms
//! - `policy` - Retry policy configuration
//! - `stats` - Retry operation statistics
//! - `outcome` - Retry operation outcome types

mod outcome;
mod policy;
mod stats;
mod strategy;

// Re-export public API
pub use outcome::RetryOutcome;
pub use policy::RetryPolicy;
pub use stats::RetryStats;
pub use strategy::BackoffStrategyCore;
