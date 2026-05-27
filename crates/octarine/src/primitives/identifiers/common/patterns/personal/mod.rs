//! Shared regex patterns for personal identifiers (per-region submodules)
//!
//! Split from the original 871-LOC `personal.rs` into three submodules grouped
//! by region to keep each file under 400 LOC. Public surface is preserved via
//! `pub(crate) use` re-exports of the inner sub-modules — call sites continue
//! to import e.g. `personal::ssn`, `personal::india_pan`, etc.
//!
//! # Pattern Categories
//!
//! - **`us_identifiers`**: SSN, tax IDs (EIN/TIN/ITIN), driver licenses,
//!   passports, employee/student IDs.
//! - **`global_identifiers`**: UK NI / Canada SIN (under `national_id`),
//!   Korea RRN, Australia (TFN, ABN), India (Aadhaar, PAN, GSTIN, vehicle
//!   registration, voter ID, passport).
//! - **`regional_identifiers`**: Brazil (CPF, CNPJ), Mexico (CURP), Nigeria
//!   (NIN), Thailand (TNIN), Singapore (NRIC), Finland (HETU), UK NI,
//!   Spain (NIF, NIE), Italy (codice fiscale), Poland (PESEL), plus generic
//!   personal-name and birthdate patterns.
//!
//! # Design Principles
//!
//! - **Conservative matching**: Prefer false negatives over false positives
//! - **Context aware**: Use capture groups to preserve surrounding text
//! - **Performance**: Use lazy_static for one-time compilation
//! - **Extensibility**: Easy to add new patterns per identifier type

pub(crate) mod age;
pub(crate) mod global_identifiers;
pub(crate) mod nrp;
pub(crate) mod regional_identifiers;
pub(crate) mod us_identifiers;

pub(crate) use global_identifiers::{
    australia_abn, australia_acn, australia_medicare, australia_tfn, india_aadhaar, india_gstin,
    india_pan, india_passport, india_vehicle_reg, india_voter_id, korea_brn, korea_driver_license,
    korea_frn, korea_passport, korea_rrn, national_id,
};
pub(crate) use nrp::{NATIONALITIES, POLITICAL_AFFILIATIONS, RELIGIONS};
pub(crate) use regional_identifiers::{
    birthdate, brazil_cnpj, brazil_cpf, finland_hetu, italy_fiscal_code, mexico_curp, nigeria_bvn,
    nigeria_nin, nigeria_vehicle_reg, personal_name, poland_pesel, singapore_nric, singapore_uen,
    spain_nie, spain_nif, thailand_tnin, uk_ni,
};
pub(crate) use us_identifiers::{driver_license, employee_id, passport, ssn, student_id, tax_id};
