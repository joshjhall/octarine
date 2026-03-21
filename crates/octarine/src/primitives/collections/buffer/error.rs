//! Buffer error types
//!
//! Shared error types for all buffer implementations.

use thiserror::Error;

/// Errors that can occur with buffer operations
#[derive(Debug, Error)]
#[allow(dead_code)] // Used by higher layers
pub enum BufferError {
    /// Buffer is empty
    #[error("Buffer is empty")]
    Empty,

    /// Lock poisoned (thread panicked while holding lock)
    #[error("Buffer lock poisoned")]
    LockPoisoned,
}

impl From<BufferError> for crate::primitives::types::Problem {
    fn from(err: BufferError) -> Self {
        match err {
            BufferError::Empty => Self::OperationFailed("buffer is empty".into()),
            BufferError::LockPoisoned => Self::OperationFailed("buffer lock poisoned".into()),
        }
    }
}
