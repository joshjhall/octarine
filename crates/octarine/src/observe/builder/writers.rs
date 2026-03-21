//! Writer extensions for ObserveBuilder
//!
//! NOTE: Writers are internal infrastructure and not exposed in the public API.
//!
//! Writers (console, file, database, etc.) are configured globally through
//! the observe module's initialization, not per-operation.
//!
//! # How Writers Work
//!
//! Writers are registered once at application startup using the writer registry:
//!
//! ```rust
//! use octarine::observe::writers::{Writer, WriterError, WriterHealthStatus, register_writer};
//! use octarine::observe::Event;
//! use async_trait::async_trait;
//!
//! // Define a custom writer
//! struct ConsoleWriter;
//!
//! #[async_trait]
//! impl Writer for ConsoleWriter {
//!     async fn write(&self, event: &Event) -> Result<(), WriterError> {
//!         println!("{:?}: {}", event.event_type, event.message);
//!         Ok(())
//!     }
//!     async fn flush(&self) -> Result<(), WriterError> { Ok(()) }
//!     fn health_check(&self) -> WriterHealthStatus { WriterHealthStatus::Healthy }
//!     fn name(&self) -> &'static str { "console" }
//! }
//!
//! // Register it at startup
//! register_writer(Box::new(ConsoleWriter));
//! ```
//!
//! Once registered, writers automatically receive ALL events:
//! - When you call `observe::info()`, all registered writers receive the event
//! - When a problem is created, all registered writers receive the error event
//! - No per-operation writer configuration needed
//!
//! # Why Not Exposed Here?
//!
//! Writers are infrastructure concerns, not operation concerns:
//! - Configured once at startup (infrastructure)
//! - Same for all operations (not per-operation)
//! - Internal implementation detail (can change writer without changing API)
//!
//! Users never need to think about writers when logging events - they're
//! automatic infrastructure.
//!
//! See: `observe/writers/` for internal writer implementations.

// No public API - writers are internal infrastructure
