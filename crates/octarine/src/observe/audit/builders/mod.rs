//! Audit builders for domain-specific audit events.
//!
//! This module provides fluent builders for common audit patterns:
//!
//! - [`AuthAuditBuilder`] - Authentication events (login, logout, password changes)
//! - [`DataAccessAuditBuilder`] - Data access events (read, write, delete, export)
//! - [`AdminAuditBuilder`] - Administrative actions (config changes, user management)
//! - [`SecurityAuditBuilder`] - Security events (threats, anomalies, incidents)
//! - [`ComplianceAuditBuilder`] - Compliance checks (SOC2, HIPAA, GDPR, PCI-DSS)

mod admin;
mod auth;
mod compliance;
mod data_access;
mod security;

pub use admin::AdminAuditBuilder;
pub use auth::AuthAuditBuilder;
pub use compliance::ComplianceAuditBuilder;
pub use data_access::DataAccessAuditBuilder;
pub use security::SecurityAuditBuilder;
