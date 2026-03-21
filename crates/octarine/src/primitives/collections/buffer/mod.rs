//! Buffer primitives for bounded data storage
//!
//! Thread-safe buffer implementations with automatic overflow handling.
//!
//! ## Available Buffers
//!
//! - `RingBuffer` - Fixed-size circular buffer that drops oldest items when full
//!
//! ## Shared Types
//!
//! - `BufferError` - Error types for buffer operations
//! - `BufferStats` - Statistics for monitoring buffer usage
//!
//! ## Usage Examples
//!
//! ### Basic Ring Buffer
//!
//! ```rust,ignore
//! use crate::primitives::collections::RingBuffer;
//!
//! let buffer = RingBuffer::new(3);
//!
//! buffer.push(1).unwrap();
//! buffer.push(2).unwrap();
//! buffer.push(3).unwrap();
//!
//! assert_eq!(buffer.pop().unwrap(), Some(1));
//! assert_eq!(buffer.len().unwrap(), 2);
//! ```
//!
//! ### Overflow Handling
//!
//! ```rust,ignore
//! use crate::primitives::collections::RingBuffer;
//!
//! let buffer = RingBuffer::new(2);
//!
//! buffer.push("first").unwrap();
//! buffer.push("second").unwrap();
//! buffer.push("third").unwrap();  // Drops "first"
//!
//! let snapshot = buffer.snapshot().unwrap();
//! assert_eq!(snapshot, vec!["second", "third"]);
//!
//! let stats = buffer.stats().unwrap();
//! assert_eq!(stats.total_written, 3);
//! assert_eq!(stats.total_dropped, 1);
//! ```

mod error;
mod ring;
mod stats;

pub use error::BufferError;
pub use ring::RingBuffer;
pub use stats::BufferStats;
