//! PII detection and redaction for observability events
//!
//! This module provides automatic PII (Personally Identifiable Information) detection
//! and redaction for event metadata, ensuring compliance with GDPR, HIPAA, SOC2, and
//! other data protection regulations.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────┐
//! │  Event Builder (observe/event/builder.rs)               │
//! │  .with_metadata() → Auto-detects PII                    │
//! │  .with_metadata_raw() → Bypass detection (unsafe)       │
//! └─────────────────────────────────────────────────────────┘
//!          ↓
//! ┌─────────────────────────────────────────────────────────┐
//! │  PII Scanner (pii/scanner.rs)                           │
//! │  - Detects: SSN, credit cards, emails, API keys, etc.  │
//! │  - Returns: PiiType[] with positions                    │
//! └─────────────────────────────────────────────────────────┘
//!          ↓
//! ┌─────────────────────────────────────────────────────────┐
//! │  Redactor (pii/redactor.rs)                             │
//! │  - Uses primitives:: redaction strategies               │
//! │  - Environment-aware (prod strict, dev permissive)      │
//! │  - Metadata tracking (pii_redacted, pii_types)         │
//! └─────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ## Automatic (via Event builder)
//!
//! ```ignore
//! use octarine::ObserveBuilder;
//!
//! // PII is automatically detected and redacted
//! ObserveBuilder::info("user_login")
//!     .with_metadata("email", "user@example.com") // Auto-redacted to "u***@example.com"
//!     .with_metadata("ssn", "123-45-6789")        // Auto-redacted to "[SSN]"
//!     .emit();
//!
//! // Bypass detection (for non-sensitive data)
//! ObserveBuilder::info("config_loaded")
//!     .with_metadata_raw("server_url", "https://example.com") // Not scanned
//!     .emit();
//! ```
//!
//! ## Manual (direct API)
//!
//! ```ignore
//! use octarine::pii::{scan_for_pii, redact_pii};
//! use octarine::pii::RedactionProfile;
//!
//! let text = "Contact: user@example.com, SSN: 123-45-6789";
//!
//! // Detect PII
//! let pii_types = scan_for_pii(text);
//! assert!(pii_types.contains(&PiiType::Email));
//! assert!(pii_types.contains(&PiiType::Ssn));
//!
//! // Redact with profile
//! let safe = redact_pii(text, RedactionProfile::ProductionStrict);
//! assert_eq!(safe, "Contact: u***@example.com, SSN: [SSN]");
//! ```
//!
//! # Compliance
//!
//! - **GDPR Article 32**: Security of processing (automatic PII protection)
//! - **HIPAA §164.312**: Technical safeguards (PHI redaction)
//! - **SOC2 CC6.1**: Logical and physical access controls
//! - **PCI-DSS**: Credit card masking (shows last 4 digits only)
//!
//! # Performance
//!
//! - **LRU Caching**: Recent scan results cached (up to 1000 entries)
//! - **Pre-compiled Regex**: Patterns compiled lazily with once_cell
//! - **Short-circuit**: Exits early on first non-match for `is_pii_present()`
//! - **Target overhead**: <50μs per cached scan, <100μs per uncached scan
//!
//! # Health Monitoring
//!
//! The scanner provides health metrics for production monitoring:
//!
//! ```ignore
//! use octarine::pii::{scanner_stats, scanner_health_score, scanner_is_healthy};
//!
//! // Get detailed statistics
//! let stats = scanner_stats();
//! println!("Cache hit rate: {:.1}%", stats.cache_hit_rate * 100.0);
//! println!("Avg scan time: {:.1}μs", stats.avg_scan_time_us);
//!
//! // Quick health check
//! if !scanner_is_healthy() {
//!     alert("PII scanner degraded!");
//! }
//!
//! // Numeric health score (0.0 to 1.0)
//! let score = scanner_health_score();
//! ```

// Sub-modules
mod config;
mod patterns; // Centralized regex patterns
mod redactor;
mod scanner;
mod types;

// Re-export public API
pub use config::{PiiScannerConfig, RedactionProfile};
pub use redactor::redact_pii_with_profile;
pub use scanner::{
    PiiStatistics, clear_scanner_cache, is_pii_present_with_config, scan_for_pii,
    scan_for_pii_with_config, scanner_cache_size, scanner_health_score, scanner_is_degraded,
    scanner_is_healthy, scanner_stats,
};

// Internal use - used by other modules via full path
#[allow(unused_imports)]
pub(crate) use config::detect_environment;
// Redaction functions - public API
pub use redactor::redact_pii;
// Detection function - public API
pub use scanner::is_pii_present;
pub use types::PiiType;

// Internal API (for Event builder integration)
pub(super) use redactor::scan_and_redact;
pub(super) use types::PiiScanResult;
