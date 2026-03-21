//! Event writers for observability
//!
//! This module handles writing observability events to various destinations
//! (console, files, databases, SIEM systems).
//!
//! # Public API
//!
//! The [`Writer`] trait is the primary interface for implementing custom writers.
//! Use the provided types and configuration to build writers:
//!
//! ```rust
//! use octarine::observe::{Event, writers::{Writer, WriterError, WriterHealthStatus}};
//! use async_trait::async_trait;
//!
//! struct MyWriter;
//!
//! #[async_trait]
//! impl Writer for MyWriter {
//!     async fn write(&self, event: &Event) -> Result<(), WriterError> {
//!         // Write event to destination
//!         Ok(())
//!     }
//!
//!     async fn flush(&self) -> Result<(), WriterError> {
//!         // Flush buffered events
//!         Ok(())
//!     }
//!
//!     fn health_check(&self) -> WriterHealthStatus {
//!         WriterHealthStatus::Healthy
//!     }
//!
//!     fn name(&self) -> &'static str {
//!         "my_writer"
//!     }
//! }
//! ```
//!
//! # Defense-in-Depth PII Protection
//!
//! Writers provide a **second layer** of PII protection:
//! - First layer: Event builder redacts PII at creation time
//! - Second layer (here): Writers scan output before writing to destination
//!
//! ## Why Two Layers?
//! - **PCI DSS 3.4**: Multiple barriers prevent credit card numbers in logs
//! - **SOC 2**: Defense in depth demonstrates robust controls
//! - **HIPAA**: Final check before PHI reaches persistent storage
//!
//! ## What Writers Scan
//! - Event message (already redacted, but verify)
//! - Event metadata (may contain unredacted PII from raw `.with_metadata()`)
//! - Context fields (tenant_id, user_id, etc. - usually not PII but scan anyway)

mod async_dispatch;
mod builder;
mod console;
mod file;
mod memory;
mod protected;
mod query;
mod types;

// Private submodule - re-export types at writers level (three-layer API)
#[cfg(feature = "database")]
mod database;

// Re-export public types
pub use types::{
    DurabilityMode, FilenamePattern, LogDirectory, LogFilename, LogFormat, RotationConfig,
    RotationSchedule, SeverityFilter, WriterConfig, WriterError, WriterHealthStatus,
};

// Internal use - not re-exported from crate root
#[allow(unused_imports)]
pub(crate) use types::RotationConfigBuilder;

// Re-export async dispatch monitoring and configuration
pub use async_dispatch::{
    DispatcherConfig, DispatcherStats, OverflowStrategy, configure_dispatcher, dispatcher_capacity,
    dispatcher_health_score, dispatcher_is_degraded, dispatcher_is_healthy,
    dispatcher_overflow_strategy, dispatcher_stats, dispatcher_stats_extended,
};

// Internal use - callback type not exposed publicly
#[allow(unused_imports)]
pub(crate) use async_dispatch::OverflowCallback;

// Re-export query types and traits
pub use memory::MemoryWriter;
pub use query::{AuditQuery, QueryResult, Queryable, filter_events, paginate_events};

// Re-export database types at writers level (three-layer API)
#[cfg(feature = "database")]
pub use database::{
    DatabaseBackend, DatabaseWriter, DatabaseWriterConfig, InMemoryBackend, NoOpBackend,
};

#[cfg(feature = "postgres")]
pub use database::PostgresBackend;

#[cfg(feature = "sqlite")]
pub use database::SqliteBackend;

// Internal use - FileWriterBuilder is kept for future public file writer API
#[allow(unused_imports)]
use builder::FileWriterBuilder;

use crate::observe::pii::{RedactionProfile, redact_pii_with_profile};
use crate::observe::types::Event;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::RwLock;

// =============================================================================
// Writer Trait - Public API for implementing writers
// =============================================================================

/// Trait for event writers
///
/// Implement this trait to create custom writers for observability events.
/// Writers can be registered globally using [`register_writer`] and will
/// receive all dispatched events.
///
/// # Example
///
/// ```rust
/// use octarine::observe::{Event, writers::{Writer, WriterError, WriterHealthStatus}};
/// use async_trait::async_trait;
///
/// struct SlackWriter {
///     webhook_url: String,
/// }
///
/// #[async_trait]
/// impl Writer for SlackWriter {
///     async fn write(&self, event: &Event) -> Result<(), WriterError> {
///         // Send event to Slack
///         Ok(())
///     }
///
///     async fn flush(&self) -> Result<(), WriterError> {
///         Ok(()) // No buffering
///     }
///
///     fn health_check(&self) -> WriterHealthStatus {
///         WriterHealthStatus::Healthy
///     }
///
///     fn name(&self) -> &'static str {
///         "slack"
///     }
/// }
/// ```
#[async_trait]
pub trait Writer: Send + Sync {
    /// Write a single event to the destination
    ///
    /// Implementations should handle PII protection if needed,
    /// though defense-in-depth scanning is provided by the framework.
    async fn write(&self, event: &Event) -> Result<(), WriterError>;

    /// Write a batch of events to the destination
    ///
    /// Default implementation iterates over events and calls `write()`.
    /// Override for more efficient batch operations (e.g., bulk insert).
    ///
    /// # Returns
    ///
    /// The number of events successfully written.
    async fn write_batch(&self, events: &[Event]) -> Result<usize, WriterError> {
        for event in events {
            self.write(event).await?;
        }
        Ok(events.len())
    }

    /// Flush any buffered events to the destination
    ///
    /// Called periodically and on shutdown to ensure events are persisted.
    async fn flush(&self) -> Result<(), WriterError>;

    /// Check if the writer is healthy
    ///
    /// Called periodically for health monitoring.
    fn health_check(&self) -> WriterHealthStatus;

    /// Get the writer's name for identification and debugging
    fn name(&self) -> &'static str;

    /// Get the severity filter for this writer
    ///
    /// Default returns `SeverityFilter::production()` (Info and above).
    /// Override to customize which events this writer receives.
    fn severity_filter(&self) -> SeverityFilter {
        SeverityFilter::production()
    }

    /// Check if this writer should receive an event based on severity
    fn should_write(&self, event: &Event) -> bool {
        self.severity_filter().accepts(event.severity)
    }
}

// =============================================================================
// Writer Registry - Global writer management
// =============================================================================

/// Named writer for registration
struct RegisteredWriter {
    writer: Box<dyn Writer>,
    enabled: bool,
}

/// Global writer registry with names
static WRITER_REGISTRY: RwLock<Option<HashMap<&'static str, RegisteredWriter>>> = RwLock::new(None);

/// Initialize the registry if needed
fn ensure_registry() {
    let mut registry = WRITER_REGISTRY.write().unwrap_or_else(|e| e.into_inner());
    if registry.is_none() {
        *registry = Some(HashMap::new());
    }
}

/// Register a new writer
///
/// Registers a writer that will receive all dispatched events (filtered by severity).
/// Writers are identified by their name (from `Writer::name()`).
///
/// # Example
///
/// ```rust
/// use octarine::observe::{Event, writers::{Writer, WriterError, WriterHealthStatus, register_writer}};
/// use async_trait::async_trait;
///
/// struct MyWriter;
///
/// #[async_trait]
/// impl Writer for MyWriter {
///     async fn write(&self, _event: &Event) -> Result<(), WriterError> { Ok(()) }
///     async fn flush(&self) -> Result<(), WriterError> { Ok(()) }
///     fn health_check(&self) -> WriterHealthStatus { WriterHealthStatus::Healthy }
///     fn name(&self) -> &'static str { "my_writer" }
/// }
///
/// register_writer(Box::new(MyWriter));
/// ```
pub fn register_writer(writer: Box<dyn Writer>) {
    ensure_registry();
    let name = writer.name();
    let mut registry = WRITER_REGISTRY.write().unwrap_or_else(|e| e.into_inner());
    if let Some(ref mut map) = *registry {
        map.insert(
            name,
            RegisteredWriter {
                writer,
                enabled: true,
            },
        );
    }
}

/// Unregister a writer by name
///
/// Removes the writer from the registry. The writer will no longer receive events.
pub fn unregister_writer(name: &str) {
    let mut registry = WRITER_REGISTRY.write().unwrap_or_else(|e| e.into_inner());
    if let Some(ref mut map) = *registry {
        map.remove(name);
    }
}

/// List all registered writer names
pub fn list_writers() -> Vec<&'static str> {
    let registry = WRITER_REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    match *registry {
        Some(ref map) => map.keys().copied().collect(),
        None => Vec::new(),
    }
}

/// Get health status of all writers
pub fn writer_health() -> HashMap<&'static str, WriterHealthStatus> {
    let registry = WRITER_REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    match *registry {
        Some(ref map) => map
            .iter()
            .map(|(name, rw)| (*name, rw.writer.health_check()))
            .collect(),
        None => HashMap::new(),
    }
}

/// Enable a writer by name
pub fn enable_writer(name: &str) {
    let mut registry = WRITER_REGISTRY.write().unwrap_or_else(|e| e.into_inner());
    if let Some(ref mut map) = *registry
        && let Some(rw) = map.get_mut(name)
    {
        rw.enabled = true;
    }
}

/// Disable a writer by name (writer remains registered but won't receive events)
pub fn disable_writer(name: &str) {
    let mut registry = WRITER_REGISTRY.write().unwrap_or_else(|e| e.into_inner());
    if let Some(ref mut map) = *registry
        && let Some(rw) = map.get_mut(name)
    {
        rw.enabled = false;
    }
}

/// Check if a writer is enabled
pub fn is_writer_enabled(name: &str) -> bool {
    let registry = WRITER_REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    match *registry {
        Some(ref map) => map.get(name).map(|rw| rw.enabled).unwrap_or(false),
        None => false,
    }
}

/// Dispatch an event to all enabled registered writers (sync version)
///
/// This is called by the async dispatch background thread.
/// Writers that fail are logged but don't stop other writers.
pub(super) fn dispatch_to_writers_sync(event: &Event) {
    let registry = WRITER_REGISTRY.read().unwrap_or_else(|e| e.into_inner());
    if let Some(ref map) = *registry {
        for rw in map.values() {
            if rw.enabled && rw.writer.should_write(event) {
                // Use tokio's blocking runtime to call async write
                // This is safe because we're already in a dedicated dispatch thread
                let writer = &rw.writer;
                let event_clone = event.clone();

                // Create a minimal runtime for the async call
                // This is acceptable overhead since writes are batched
                if let Ok(rt) = tokio::runtime::Builder::new_current_thread().build() {
                    let _ = rt.block_on(async { writer.write(&event_clone).await });
                }
            }
        }
    }
}

// =============================================================================
// Event Dispatch
// =============================================================================

/// Dispatch an event to all registered writers
///
/// Events are queued asynchronously for non-blocking operation.
pub fn dispatch(event: Event) {
    // Queue event for async processing
    async_dispatch::queue_event(event);
}

/// Sanitize a string for writing (writer-level PII protection)
///
/// This provides **defense-in-depth** - a second layer of PII protection.
/// Even though events are redacted at creation time, this catches:
/// - PII that bypassed event builder (e.g., `.skip_pii_redaction()`)
/// - PII in metadata fields added after event creation
/// - PII in context fields that weren't scanned
///
/// ## Compliance
/// - **PCI DSS 3.4**: Last barrier before credit cards reach logs
/// - **SOC 2**: Demonstrates defense in depth
/// - **HIPAA**: Final PHI check before persistent storage
pub(super) fn sanitize_for_writing(text: &str) -> String {
    // Use environment-aware redaction profile
    // This respects RUST_CORE_REDACT_PROFILE and REDACTION_PROFILE env vars
    let profile = RedactionProfile::from_environment();
    redact_pii_with_profile(text, profile)
}
