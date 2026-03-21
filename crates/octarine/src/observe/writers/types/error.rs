//! Writer error types
//!
//! Error types for writer operations with structured error information.

use std::time::Duration;

use thiserror::Error;

use crate::observe::Problem;

/// Error type for writer operations
///
/// Provides structured error information for writer failures,
/// enabling proper error handling and retry logic.
#[derive(Debug, Error)]
pub enum WriterError {
    /// I/O error (file, network, etc.)
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error (JSON, etc.)
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Connection error (database, network)
    #[error("Connection error: {0}")]
    Connection(String),

    /// Rate limited - should retry after duration
    #[error("Rate limited, retry after {retry_after:?}")]
    RateLimited {
        /// Time to wait before retrying
        retry_after: Duration,
    },

    /// Writer is closed and cannot accept events
    #[error("Writer is closed")]
    Closed,

    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Circuit breaker is open
    #[error("Circuit breaker is open")]
    CircuitOpen,

    /// Operation timed out
    #[error("Operation timed out after {0:?}")]
    Timeout(Duration),

    /// Batch operation partially failed
    #[error("Partial failure: {succeeded} succeeded, {failed} failed: {message}")]
    PartialFailure {
        /// Number of events successfully written
        succeeded: usize,
        /// Number of events that failed
        failed: usize,
        /// Error message
        message: String,
    },

    /// Other error
    #[error("{0}")]
    Other(String),
}

impl From<Problem> for WriterError {
    fn from(problem: Problem) -> Self {
        Self::Other(problem.to_string())
    }
}

impl From<WriterError> for Problem {
    fn from(err: WriterError) -> Self {
        match err {
            WriterError::Io(e) => Self::Io(e),
            WriterError::Serialization(msg) => Self::parse(msg),
            WriterError::Connection(msg) => Self::network(msg),
            WriterError::RateLimited { retry_after } => Self::RateLimited(retry_after),
            WriterError::Closed => Self::operation_failed("writer is closed"),
            WriterError::Configuration(msg) => Self::config(msg),
            WriterError::CircuitOpen => Self::operation_failed("circuit breaker is open"),
            WriterError::Timeout(duration) => {
                Self::timeout(format!("writer timed out after {duration:?}"))
            }
            WriterError::PartialFailure {
                succeeded,
                failed,
                message,
            } => Self::operation_failed(format!(
                "partial failure: {succeeded} succeeded, {failed} failed: {message}"
            )),
            WriterError::Other(msg) => Self::other(msg),
        }
    }
}
