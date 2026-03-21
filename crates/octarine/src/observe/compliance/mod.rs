//! Compliance control tagging for audit events
//!
//! This module provides enums and types for mapping events to specific
//! compliance framework controls. Events can be tagged with one or more
//! controls from SOC2, HIPAA, GDPR, PCI-DSS, and ISO 27001 frameworks.
//!
//! # Usage
//!
//! ```ignore
//! use octarine::{ObserveBuilder, Soc2Control, HipaaSafeguard, Iso27001Control};
//!
//! ObserveBuilder::for_operation("user.login")
//!     .message("User authenticated successfully")
//!     .soc2_control(Soc2Control::CC6_1)
//!     .hipaa_safeguard(HipaaSafeguard::Technical)
//!     .iso27001_control(Iso27001Control::A8_5)
//!     .info();
//! ```
//!
//! # Compliance Frameworks
//!
//! - **SOC2**: Trust Service Criteria for security, availability, processing integrity
//! - **HIPAA**: Administrative, Physical, and Technical safeguards for PHI
//! - **GDPR**: Lawful basis for personal data processing
//! - **PCI-DSS**: Requirements for cardholder data protection
//! - **ISO 27001**: Information security management (Annex A controls)
//!
//! # Module Organization
//!
//! - `soc2` - SOC2 Trust Service Criteria controls
//! - `hipaa` - HIPAA Safeguard categories
//! - `gdpr` - GDPR Lawful Basis
//! - `pci_dss` - PCI-DSS Requirements
//! - `iso27001` - ISO 27001:2022 Annex A Controls
//! - `tags` - ComplianceTags collection and auto-tagging rules

mod gdpr;
mod hipaa;
mod iso27001;
mod pci_dss;
mod soc2;
mod tags;

// Re-export all public types
pub use gdpr::GdprBasis;
pub use hipaa::HipaaSafeguard;
pub use iso27001::Iso27001Control;
pub use pci_dss::PciDssRequirement;
pub use soc2::Soc2Control;
pub use tags::ComplianceTags;

// Internal use only - accessed via full path by event builder
#[allow(unused_imports)]
pub(crate) use tags::default_tags_for_event_type;
