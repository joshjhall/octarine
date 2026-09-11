//! Domain-specific PII scanning
//!
//! Uses domain builders from the primitives layer to detect PII. Each domain
//! lives in its own module, mirroring the sibling `redactor/` layout, and is
//! wired into the scanner through the single dispatch table in [`dispatch`].
//!
//! ## Module Organization
//!
//! - `personal` - Emails, phones, names, birthdates, usernames, age, NRP
//! - `financial` - Credit cards, bank accounts, routing numbers, IBAN, crypto
//! - `government` - SSNs, driver licenses, passports, national IDs (18 jurisdictions)
//! - `medical` - MRNs, NPIs, insurance numbers, ICD codes, prescriptions
//! - `biometric` - Fingerprints, facial data, voice prints, iris, DNA
//! - `location` - GPS coordinates, addresses, postal codes, named locations
//! - `organizational` - Employee IDs, student IDs, badge numbers
//! - `network` - IPs, MACs, UUIDs, URLs, domains, hostnames, ports
//! - `tokens` - API keys, JWTs, SSH keys, and credentials (passwords, PINs)
//! - `dispatch` - The canonical domain table both entry points iterate
//!
//! Credentials have no module of their own — see [`tokens`] for why.

mod biometric;
mod dispatch;
mod financial;
mod government;
mod location;
mod medical;
mod network;
mod organizational;
mod personal;
mod tokens;

pub(super) use dispatch::{is_pii_present_with_config_impl, scan_for_pii_uncached_with_config};
