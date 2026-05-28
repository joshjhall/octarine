//! Location pattern module — regex patterns and gazetteer lexicons
//!
//! This module is split into two submodules to keep each file under the
//! 500-LOC warning threshold:
//!
//! - [`regex`] — Lazy regex patterns for GPS coordinates, addresses, and
//!   postal codes (DECIMAL_DEGREES, US_ZIP, UK_POSTCODE, etc.). Used by
//!   structured-pattern detection.
//! - [`gazetteer`] — Compile-time string arrays of country and major-city
//!   names. Used by free-text named-location detection via Aho-Corasick.
//!
//! All public items from both submodules are re-exported flat so call sites
//! can use the historical `patterns::location::DECIMAL_DEGREES` path
//! without indirection through `regex::`.

pub(crate) mod gazetteer;
pub(crate) mod regex;

pub(crate) use regex::{
    APT_SUITE, AUSTRALIAN_POSTAL, BRAZILIAN_POSTAL, CANADA_POSTAL, DECIMAL_DEGREES, DMS_FORMAT,
    DUTCH_POSTAL, FRENCH_POSTAL, GERMAN_POSTAL, INDIAN_POSTAL, JAPANESE_POSTAL, LABELED_LAT,
    LABELED_LON, PO_BOX, POSTAL_CONTEXT_KEYWORD, UK_POSTCODE, US_STREET_ADDRESS, US_ZIP,
    US_ZIP_PLUS4, addresses, all, coordinates, postal_codes, postal_codes_requiring_context,
};
