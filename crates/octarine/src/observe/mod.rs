//! # Observe - Compliance-Grade Observability
//!
//! The observe module provides comprehensive logging, metrics, and audit trail
//! capabilities suitable for SOC2, ISO 27001, HIPAA, PCI-DSS, and GDPR compliance.
//!
//! ## Quick Start
//!
//! ```rust
//! use octarine::{info, warn, success, fail};
//!
//! // Simple logging with operation context
//! info("startup", "Application started");
//! warn("rate_limit", "Approaching threshold");
//! success("user_signup", "New user created");
//!
//! // Error handling with automatic audit trail
//! fn validate_email(email: &str) -> octarine::Result<()> {
//!     if email.is_empty() {
//!         return Err(fail("validation", "Email cannot be empty"));
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ## Key Features
//!
//! - **Automatic Context Capture**: WHO/WHAT/WHEN/WHERE captured automatically
//! - **PII Protection**: 30+ PII types detected and auto-redacted (SSN, credit cards, etc.)
//! - **Compliance Ready**: SOC2/HIPAA/GDPR/PCI control mapping built-in
//! - **Multi-Tenant**: Thread-local tenant isolation for SaaS applications
//! - **Distributed Tracing**: Correlation ID propagation across services
//! - **Multiple Writers**: Console, file (JSONL), SQLite, PostgreSQL, custom backends
//! - **Queryable Logs**: Query stored events for audits and debugging
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────┐
//! │  Application Code                                │
//! │  info("op", "msg")  /  fail("op", "msg")        │
//! └──────────────────────┬──────────────────────────┘
//!                        │
//!        ┌───────────────▼───────────────┐
//!        │  Context Capture               │
//!        │  - tenant_id (thread-local)    │
//!        │  - user_id, session_id         │
//!        │  - correlation_id              │
//!        │  - module/file/line            │
//!        └───────────────┬───────────────┘
//!                        │
//!        ┌───────────────▼───────────────┐
//!        │  PII Scanner (Layer 1)         │
//!        │  - 30+ PII types               │
//!        │  - Auto-redaction              │
//!        │  - Compliance tagging          │
//!        └───────────────┬───────────────┘
//!                        │
//!        ┌───────────────▼───────────────┐
//!        │  Writers (Layer 2)             │
//!        │  - Console, File, Database     │
//!        │  - SIEM (syslog, webhook)      │
//!        │  - Defense-in-depth PII scan   │
//!        └──────────────────────────────┘
//! ```
//!
//! ## Logging API
//!
//! The module provides two complementary APIs:
//!
//! ### Shortcuts API (recommended for most use cases)
//!
//! Two-argument functions with explicit operation context:
//!
//! ```rust
//! use octarine::{debug, info, warn, error, success};
//!
//! debug("cache", "Cache lookup starting");
//! info("user_login", "User authenticated successfully");
//! warn("rate_limit", "Rate limit at 80%");
//! error("db_query", "Query timeout after 30s");
//! success("payment", "Payment processed");
//! ```
//!
//! ### Error Handling (returns [`Problem`])
//!
//! ```rust
//! use octarine::{Result, fail, fail_validation, fail_security, fail_permission};
//!
//! fn process_order(user: &str, amount: f64) -> Result<()> {
//!     // Generic failure
//!     if amount <= 0.0 {
//!         return Err(fail("order", "Amount must be positive"));
//!     }
//!
//!     // Validation failure
//!     if amount > 10000.0 {
//!         return Err(fail_validation("amount", "Exceeds maximum order limit"));
//!     }
//!
//!     // Security failure (creates security audit event)
//!     if user.contains("admin") && amount > 1000.0 {
//!         return Err(fail_security("order", "Suspicious admin order flagged"));
//!     }
//!
//!     // Permission failure
//!     if !has_permission(user) {
//!         return Err(fail_permission("order", user, "create_order"));
//!     }
//!
//!     Ok(())
//! }
//!
//! fn has_permission(_user: &str) -> bool { true }
//! ```
//!
//! ## Context Propagation
//!
//! Set identity and correlation context at request boundaries. Context flows
//! automatically into all events created within that scope.
//!
//! > **Note**: Context propagation functions live in `runtime::r#async`
//! > (see [`octarine::runtime`](crate::runtime)), not in the observe module.
//! > The observe module *consumes* context; the runtime module *manages* it.
//!
//! ### Sync Code (Thread-Local)
//!
//! ```rust
//! use octarine::runtime::r#async::{set_user_id, set_session_id, set_correlation_id, clear_context};
//! use octarine::info;
//! use uuid::Uuid;
//!
//! // Set context at request start
//! set_correlation_id(Uuid::new_v4());
//! set_user_id("user-123");
//! set_session_id("sess-456");
//!
//! // All events now include this context
//! info("api", "Processing request");  // Includes user_id, session_id, correlation_id
//!
//! // Clear at request end
//! clear_context();
//! ```
//!
//! ### Async Code (Task-Local)
//!
//! ```rust
//! use octarine::runtime::r#async::TaskContextBuilder;
//! use octarine::info;
//! use uuid::Uuid;
//!
//! # async fn example() {
//! // Context flows through async boundaries
//! TaskContextBuilder::new()
//!     .correlation_id(Uuid::new_v4())
//!     .tenant("acme-corp")
//!     .user("user-123")
//!     .session("sess-456")
//!     .run(async {
//!         info("api", "Async request");  // Context available here
//!         some_async_work().await;
//!         info("api", "Still has context");  // And here
//!     }).await;
//! # }
//! # async fn some_async_work() {}
//! ```
//!
//! ### Multi-Tenant Context (Full struct)
//!
//! For richer tenant metadata, use `TenantContext`:
//!
//! ```rust
//! use octarine::observe::{set_tenant, clear_tenant, with_tenant, TenantContext, TenantId};
//! use octarine::info;
//!
//! // Create tenant context with metadata
//! let tenant_id = TenantId::new("acme-corp").expect("valid ID");
//! let ctx = TenantContext {
//!     tenant_id,
//!     tenant_name: Some("ACME Corporation".to_string()),
//!     tenant_tier: Some("enterprise".to_string()),
//! };
//!
//! // Set context for current thread
//! set_tenant(ctx);
//! info("api", "Processing request");  // Includes tenant_id: "acme-corp"
//!
//! // Or use scoped context
//! let tenant_id2 = TenantId::new("tenant-b").expect("valid ID");
//! let ctx2 = TenantContext {
//!     tenant_id: tenant_id2,
//!     tenant_name: None,
//!     tenant_tier: None,
//! };
//! with_tenant(ctx2, || {
//!     info("api", "Scoped request");  // Different tenant context
//! });
//!
//! clear_tenant();
//! ```
//!
//! ## PII Protection
//!
//! Automatic detection and redaction of 30+ PII types:
//!
//! - **SSN**: `123-45-6789` → `[SSN]`
//! - **Credit Cards**: `4111-1111-1111-1111` → `[CC:****1111]`
//! - **Email**: `user@example.com` → `u***@example.com`
//! - **API Keys**: AWS, Stripe, GitHub tokens
//! - **Passwords**: `password=secret` → `password=[REDACTED]`
//!
//! See `pii` module for manual control and profiles.
//!
//! ## Writers
//!
//! Events can be sent to multiple destinations:
//!
//! ```rust,ignore
//! use octarine::{Writer, MemoryWriter, LogFormat, LogDirectory, LogFilename};
//!
//! // In-memory writer (for testing)
//! let memory = MemoryWriter::new();
//!
//! // File writer with JSONL format (for queryable logs)
//! // Note: FileWriterBuilder is in observe::writers::builder (internal)
//! let file = FileWriterBuilder::new()
//!     .directory(LogDirectory::new("/var/log/app").expect("valid directory"))
//!     .filename(LogFilename::new("audit.jsonl").expect("valid filename"))
//!     .with_format(LogFormat::JsonLines)
//!     .build()
//!     .await
//!     .expect("file writer creation failed");
//!
//! // Database writers (feature-gated)
//! #[cfg(feature = "database")]
//! {
//!     use octarine::{PostgresBackend, SqliteBackend};
//!     // PostgreSQL for production
//!     // SQLite for development/testing
//! }
//! ```
//!
//! ## Querying Events
//!
//! Writers implementing `Queryable` support event retrieval:
//!
//! ```rust,ignore
//! use octarine::{Queryable, AuditQuery};
//!
//! // Query events for compliance reporting
//! let query = AuditQuery::builder()
//!     .since(last_week)
//!     .security_relevant_only(true)
//!     .build();
//!
//! let result = writer.query(&query).await?;
//! for event in result.events {
//!     println!("{}: {}", event.timestamp, event.message);
//! }
//! ```
//!
//! ## Compliance
//!
//! The observe module supports multiple compliance frameworks:
//!
//! | Framework | Features |
//! |-----------|----------|
//! | **SOC2** | Who/what/when/where audit trail, access logging |
//! | **HIPAA** | PHI detection, access logging, retention policies |
//! | **GDPR** | PII redaction, right to erasure, data minimization |
//! | **PCI-DSS** | Credit card masking, defense-in-depth scanning |
//!
//! See the compliance guide in `docs/observe/compliance.md` for detailed mapping.
//!
//! ## Module Structure
//!
//! - `pii` - PII detection, scanning, and redaction
//! - `writers` - Output destinations and configuration
//! - `metrics` - Prometheus-compatible metrics export
//!
//! ## Best Practices
//!
//! 1. **Set context early** - At request/operation boundaries
//! 2. **Use appropriate severity** - Critical for data loss, Info for routine
//! 3. **Use specific error helpers** - `fail_validation`, `fail_security`, etc.
//! 4. **Don't log PII in messages** - Let the scanner catch what slips through
//! 5. **Use `fail_*` for errors** - Creates audit trail automatically
//! 6. **Use correlation IDs** - For distributed tracing across services

// Public API for external consumers - these functions are re-exported but not used internally
#![allow(dead_code)]

// Internal modules - not exposed directly
mod aggregate;
mod builder; // Private - only ObserveBuilder struct is re-exported
pub mod compliance; // Public - Compliance control tagging for SOC2/HIPAA/GDPR/PCI-DSS
mod context;
pub(crate) mod event; // Made pub(crate) so security module can use event functions
pub mod metrics; // Public for now during migration
pub mod pii; // Public - PII detection and redaction API
mod problem;
mod shortcuts;
pub mod tracing; // Public - Integration with tracing crate for distributed tracing
pub(crate) mod types; // Made pub(crate) for writer trait
pub mod writers; // Public - Writer trait and configuration types

// Domain-specific audit logging
pub mod audit; // Public - Fluent audit builders with compliance tagging

// Re-export the main public API at the root level (three-layer pattern)

// Core types for custom writers
pub use types::{Event, EventContext, EventType, Severity, TenantId, UserId};

// Problem types with consistent API
pub use problem::{Problem, Result};

// Context management (for advanced use)
pub use context::{
    TenantContext, clear_tenant, get_tenant, is_development, is_production, set_tenant, tenant_id,
    with_tenant,
};

// Source IP context management (for server applications)
pub use context::{
    clear_source_ip, get_source_ip, get_source_ip_chain, set_source_ip, set_source_ip_chain,
    with_source_ip,
};

// Local network context (for host identification)
pub use context::{LocalNetworkContext, get_local_network, refresh_local_network};

// Note: Context propagation functions (set_user_id, set_correlation_id, etc.)
// are re-exported directly from crate::runtime in lib.rs, not through this module.

// Unified builder - main API for all observability operations
pub use builder::ObserveBuilder;

// Simple shortcuts for common operations (no Problem return)
pub use shortcuts::{auth_success, debug, error, info, success, trace, validation_success, warn};

// Error handling shortcuts (return Problems)
pub use shortcuts::{fail, fail_permission, fail_security, fail_validation, todo};

// Compliance control tagging for audit reporting
pub use compliance::{
    ComplianceTags, GdprBasis, HipaaSafeguard, Iso27001Control, PciDssRequirement, Soc2Control,
};
