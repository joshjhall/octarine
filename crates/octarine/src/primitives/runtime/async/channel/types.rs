//! Channel result types
//!
//! Types representing the outcome of send operations.

use std::fmt;

/// Result of a send operation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendOutcome {
    /// Item was successfully sent
    Sent,
    /// Item was dropped due to overflow policy
    Dropped(DropReason),
    /// Channel is closed, item could not be sent
    Closed,
}

/// Reason why an item was dropped
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// Channel was full, newest item (the one being sent) was dropped
    ChannelFullDropNewest,
    /// Channel was full, oldest item was dropped to make room
    ChannelFullDropOldest,
}

impl fmt::Display for DropReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChannelFullDropNewest => write!(f, "channel full, dropped newest"),
            Self::ChannelFullDropOldest => write!(f, "channel full, dropped oldest"),
        }
    }
}

impl fmt::Display for SendOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sent => write!(f, "Sent"),
            Self::Dropped(reason) => write!(f, "Dropped({})", reason),
            Self::Closed => write!(f, "Closed"),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_send_outcome_display() {
        assert_eq!(format!("{}", SendOutcome::Sent), "Sent");
        assert_eq!(
            format!(
                "{}",
                SendOutcome::Dropped(DropReason::ChannelFullDropNewest)
            ),
            "Dropped(channel full, dropped newest)"
        );
        assert_eq!(format!("{}", SendOutcome::Closed), "Closed");
    }

    #[test]
    fn test_drop_reason_display() {
        assert_eq!(
            format!("{}", DropReason::ChannelFullDropNewest),
            "channel full, dropped newest"
        );
        assert_eq!(
            format!("{}", DropReason::ChannelFullDropOldest),
            "channel full, dropped oldest"
        );
    }
}
