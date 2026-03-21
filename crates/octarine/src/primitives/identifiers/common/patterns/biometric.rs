//! Biometric identification patterns
//!
//! Regex patterns for biometric identifiers including fingerprints, face encodings,
//! iris scans, voice prints, and DNA sequences.

// SAFETY: All regex patterns in this module are hardcoded and verified at compile time.
#![allow(clippy::expect_used)]

use once_cell::sync::Lazy;
use regex::Regex;

/// Fingerprint patterns (explicit labels required to avoid false positives with git commits)
/// Detects: "fingerprint: a1b2c3d4...", "fp: abc123..."
pub static FINGERPRINT_LABELED: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:fingerprint|fprint|fp|thumbprint)[\s:#-]*[a-fA-F0-9]{32,64}\b")
        .expect("BUG: Invalid regex pattern")
});

/// Facial recognition data patterns (with context preservation)
/// Detects: "face_encoding: base64data", "faceid: ABC123..."
pub static FACE_ENCODING: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:face_encoding|facial_data)[\s:#-]*[A-Za-z0-9+/]{20,}={0,2}\b")
        .expect("BUG: Invalid regex pattern")
});

pub static FACE_ID: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:faceid|touchid|face_id)[\s:#-]*[A-Za-z0-9]{16,}\b")
        .expect("BUG: Invalid regex pattern")
});

/// Iris scan patterns
/// IrisCode format: typically 2048 bits = 512 hex chars
pub static IRIS_CODE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:iriscode|iris_scan)[\s:#-]*[a-fA-F0-9]{256,512}\b")
        .expect("BUG: Invalid regex pattern")
});

pub static IRIS_TEMPLATE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:iris_template|iris_id)[\s:#-]*[A-Za-z0-9]{16,}\b")
        .expect("BUG: Invalid regex pattern")
});

/// Voice print patterns
pub static VOICE_PRINT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:voiceprint|voice_id|speaker_id)[\s:#-]*[A-Za-z0-9]{12,}\b")
        .expect("BUG: Invalid regex pattern")
});

/// DNA sequence patterns
/// ATCG sequences (minimum 20 nucleotides to avoid false positives)
pub static DNA_SEQUENCE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b[ATCG]{20,}\b").expect("BUG: Invalid regex pattern"));

/// STR (Short Tandem Repeat) markers used in DNA profiling
/// Format: D[chromosome]S[locus] followed by repeat count
pub static DNA_STR_MARKER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:D[0-9]{1,2}S[0-9]{1,4})[\s:#-]*\d+\b").expect("BUG: Invalid regex pattern")
});

/// Biometric template patterns (ISO/IEC 19794 standard)
/// FMR: Finger Minutiae Record
/// FIR: Finger Image Record
/// FTR: Finger Template Record
/// IIR: Iris Image Record
pub static BIOMETRIC_TEMPLATE_ISO: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:FMR|FIR|FTR|IIR)[\s:#-]*[A-Za-z0-9+/]{50,}\b")
        .expect("BUG: Invalid regex pattern")
});

pub static BIOMETRIC_TEMPLATE_GENERIC: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\b(?:biometric|bio_template)[\s:#-]*[A-Za-z0-9+/]{32,}\b")
        .expect("BUG: Invalid regex pattern")
});

pub fn fingerprints() -> Vec<&'static Regex> {
    vec![&*FINGERPRINT_LABELED]
}

pub fn facial() -> Vec<&'static Regex> {
    vec![&*FACE_ENCODING, &*FACE_ID]
}

pub fn iris() -> Vec<&'static Regex> {
    vec![&*IRIS_CODE, &*IRIS_TEMPLATE]
}

pub fn voice() -> Vec<&'static Regex> {
    vec![&*VOICE_PRINT]
}

pub fn dna() -> Vec<&'static Regex> {
    vec![&*DNA_SEQUENCE, &*DNA_STR_MARKER]
}

pub fn templates() -> Vec<&'static Regex> {
    vec![&*BIOMETRIC_TEMPLATE_ISO, &*BIOMETRIC_TEMPLATE_GENERIC]
}

pub fn all() -> Vec<&'static Regex> {
    vec![
        &*FINGERPRINT_LABELED,
        &*FACE_ENCODING,
        &*FACE_ID,
        &*IRIS_CODE,
        &*IRIS_TEMPLATE,
        &*VOICE_PRINT,
        &*DNA_SEQUENCE,
        &*DNA_STR_MARKER,
        &*BIOMETRIC_TEMPLATE_ISO,
        &*BIOMETRIC_TEMPLATE_GENERIC,
    ]
}
