//! Location identifier conversion and normalization
//!
//! Provides conversion between different location identifier formats to enable
//! consistent storage, comparison, and validation.
//!
//! # Supported Conversions
//!
//! ## GPS Coordinates
//! - **Decimal Degrees** (DD): 40.7128, -74.0060 (canonical format)
//! - **Degrees Minutes Seconds** (DMS): 40°42'46"N 74°00'21"W
//! - **Degrees Decimal Minutes** (DDM): 40°42.767'N 74°00.36'W
//!
//! ## Postal Codes
//! - **US ZIP**: Normalize to 5 digits or 5+4 format
//! - **UK Postcode**: Normalize to standard format with space
//! - **Canada**: Normalize to standard A1A 1B1 format
//!
//! # Design Principles
//!
//! - **No logging**: Pure conversion functions (privacy protection)
//! - **No external dependencies**: Only uses primitives module
//! - **Idempotent**: Converting twice produces same result
//! - **Preserves validity**: Invalid input → Error, not silent corruption

mod gps;
mod postal;

// Re-export GPS functions
pub use gps::{
    GpsFormat, calculate_bearing, calculate_distance, calculate_final_bearing, detect_gps_format,
    normalize_gps_coordinate, to_ddm, to_dms, to_gps_format,
};

// Re-export postal code functions
pub use postal::{
    PostalCodeNormalization, PostalCodeType, detect_postal_code_type, normalize_postal_code,
};
