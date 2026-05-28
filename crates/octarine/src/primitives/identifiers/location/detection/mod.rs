//! Location detection — structured patterns + named-location gazetteer
//!
//! Split into two submodules:
//!
//! - [`core`] — Regex-based detection of GPS coordinates, street addresses,
//!   and postal codes. The original implementation; behaviour unchanged
//!   from when this was a flat `detection.rs` file.
//! - [`named`] — Aho-Corasick gazetteer detection of free-text city and
//!   country names. Added in support of HIPAA Safe Harbor and Presidio
//!   parity (gap CRIT-2).
//!
//! All public items are re-exported flat so call sites (`detection::is_*`,
//! `detection::find_*_in_text`) keep working without internal-path churn.

pub(crate) mod core;
pub(crate) mod named;

// Re-export every public item from `core` so existing callers see the
// detection module as a flat namespace.
pub use core::{
    detect_location_identifier, find_addresses_in_text, find_all_locations_in_text,
    find_gps_coordinates_in_text, find_postal_codes_in_text, is_australian_postal_code,
    is_brazilian_postal_code, is_dutch_postal_code, is_french_postal_code, is_german_postal_code,
    is_gps_coordinate, is_indian_postal_code, is_japanese_postal_code, is_location_identifier,
    is_postal_code, is_street_address, is_test_gps_coordinate, is_test_postal_code,
};

// Re-export named-location detection (gazetteer-based).
pub use named::{detect_named_locations_in_text, is_named_location};
