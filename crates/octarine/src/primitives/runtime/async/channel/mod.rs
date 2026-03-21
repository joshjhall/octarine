//! Bounded channels with configurable overflow policies
//!
//! Pure channel implementation with no dependencies on observe or other internal
//! modules. The `runtime` module wraps these primitives and adds observability.
#![allow(dead_code)] // Public API primitives - not all items used internally yet
//!
//! ## Features
//!
//! - **Bounded capacity**: Prevents memory exhaustion (CWE-400)
//! - **Overflow policies**: DropOldest, DropNewest, Block, Reject
//! - **Statistics tracking**: Monitor channel health
//! - **Split API**: Separate sender and receiver for flexible ownership
//!
//! ## Usage Examples
//!
//! ### Basic Channel
//!
//! ```rust,ignore
//! use octarine::primitives::runtime::channel::{BoundedChannel, ChannelConfig};
//!
//! let config = ChannelConfig::new("events", 1000);
//! let channel = BoundedChannel::new(config);
//! let (tx, mut rx) = channel.split();
//!
//! tx.send("hello").await?;
//! let msg = rx.recv().await;
//! ```
//!
//! ### With Overflow Policy
//!
//! ```rust,ignore
//! use octarine::primitives::runtime::channel::{BoundedChannel, ChannelConfig};
//! use octarine::primitives::runtime::config::OverflowPolicy;
//!
//! let config = ChannelConfig::new("metrics", 100)
//!     .with_overflow_policy(OverflowPolicy::DropNewest);
//!
//! let channel = BoundedChannel::new(config);
//! ```
//!
//! ## Design Notes
//!
//! This is a **primitive** module - it has NO dependencies on observe or other
//! internal modules. The `runtime/channel.rs` wrapper adds logging, metrics,
//! and event dispatching.
//!
//! ## Module Structure
//!
//! - `config` - Channel configuration options
//! - `types` - Send outcome and drop reason types
//! - `stats` - Channel statistics and health metrics
//! - `bounded` - Core bounded channel implementation
//! - `sender` - Channel sender half
//! - `receiver` - Channel receiver half
//! - `ring_buffer` - Internal ring buffer for DropOldest policy
//! - `metrics` - Internal metrics tracking

mod bounded;
mod config;
mod metrics;
mod receiver;
mod ring_buffer;
mod sender;
mod stats;
mod types;

// Re-export public API
pub use bounded::BoundedChannel;
pub use config::ChannelConfig;
pub use receiver::ChannelReceiver;
pub use sender::ChannelSender;
pub use stats::ChannelStats;
pub use types::{DropReason, SendOutcome};
