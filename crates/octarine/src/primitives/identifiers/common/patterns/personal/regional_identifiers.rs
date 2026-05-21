//! Regional personal identifier patterns (Latin America, Africa, Europe, etc.)
//!
//! Brazil (CPF, CNPJ), Mexico (CURP), Nigeria (NIN), Thailand (TNIN),
//! Singapore (NRIC), Finland (HETU), UK NI, Spain (NIF, NIE),
//! Italy (codice fiscale), Poland (PESEL), plus generic personal names and
//! birthdate patterns.

#![allow(clippy::expect_used)]
// SAFETY: All regex patterns in this module are hardcoded and verified at compile time.
// Regex::new() only fails on invalid syntax, which would be caught during development/testing.
// Using expect() here is safe because these patterns are static and never change at runtime.

use once_cell::sync::Lazy;
use regex::Regex;

/// Brazil CPF (Cadastro de Pessoas Físicas) patterns
///
/// Format: `NNN.NNN.NNN-NN` or 11 plain digits.
pub(crate) mod brazil_cpf {
    use super::*;

    /// Formatted CPF: NNN.NNN.NNN-NN
    pub static FORMATTED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b").expect("BUG: Invalid regex pattern")
    });

    /// CPF with explicit label (accepts formatted or unformatted)
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?i)\b(?:CPF|cadastro[\s-]?de[\s-]?pessoas[\s-]?f[ií]sicas)[\s:#-]*(\d{3}\.?\d{3}\.?\d{3}-?\d{2})\b",
        )
        .expect("BUG: Invalid regex pattern")
    });

    /// Scanning patterns. Plain 11-digit form is too ambiguous (matches phone
    /// numbers, IDs, etc.) so we only scan formatted or labeled occurrences.
    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*FORMATTED]
    }
}

/// Brazil CNPJ (Cadastro Nacional da Pessoa Jurídica) patterns
///
/// Format: `NN.NNN.NNN/NNNN-NN` or 14 plain digits.
pub(crate) mod brazil_cnpj {
    use super::*;

    /// Formatted CNPJ: NN.NNN.NNN/NNNN-NN
    pub static FORMATTED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}\b").expect("BUG: Invalid regex pattern")
    });

    /// CNPJ with explicit label
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?i)\b(?:CNPJ|cadastro[\s-]?nacional)[\s:#-]*(\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2})\b",
        )
        .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*FORMATTED]
    }
}

/// Mexico CURP (Clave Única de Registro de Población) patterns
///
/// Format: 4 letters + 6 digits (YYMMDD) + gender (H/M) + 2 letters (state) +
/// 3 letters + alphanumeric + digit.
pub(crate) mod mexico_curp {
    use super::*;

    /// CURP standard format (18 characters)
    pub static STANDARD: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b[A-Z]{4}\d{6}[HM][A-Z]{5}[0-9A-Z]\d\b").expect("BUG: Invalid regex pattern")
    });

    /// CURP with explicit label
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?i)\b(?:CURP|clave[\s-]?[uú]nica[\s-]?de[\s-]?registro)[\s:#-]*([A-Z]{4}\d{6}[HM][A-Z]{5}[0-9A-Z]\d)\b",
        )
        .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*STANDARD]
    }
}

/// Nigeria NIN (National Identification Number) patterns
///
/// Format: 11 plain digits. The unlabeled form is identical to phone numbers
/// and many other identifiers, so scanning uses LABELED only — analogous to
/// `india_passport`. Direct `is_nigeria_nin()` checks still accept the bare
/// 11-digit form.
pub(crate) mod nigeria_nin {
    use super::*;

    /// NIN standard format (11 digits, no separators)
    pub static STANDARD: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b\d{11}\b").expect("BUG: Invalid regex pattern"));

    /// NIN with explicit label
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)\b(?:NIN|national[\s-]?identification[\s-]?number|NIMC)[\s:#-]*(\d{11})\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// Returns patterns used for text scanning (LABELED only — STANDARD is
    /// `\d{11}` which matches phone numbers and many other 11-digit strings).
    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED]
    }
}

/// Nigeria BVN (Bank Verification Number) patterns
///
/// Format: 11 plain digits. The unlabeled form is identical to NIN, phone
/// numbers, and many other identifiers, so scanning uses LABELED only —
/// analogous to `nigeria_nin`. Direct `is_nigeria_bvn()` checks still accept
/// the bare 11-digit form.
///
/// Note: NIN and BVN labels are disjoint (`NIN|national identification
/// number|NIMC` vs `BVN|bank verification|verification number`) so the two
/// scanners do not cross-match.
pub(crate) mod nigeria_bvn {
    use super::*;

    /// BVN standard format (11 digits, no separators)
    pub static STANDARD: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b\d{11}\b").expect("BUG: Invalid regex pattern"));

    /// BVN with explicit label
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?i)\b(?:BVN|bank[\s-]?verification(?:[\s-]?number)?|verification[\s-]?number)[\s:#-]*(\d{11})\b",
        )
        .expect("BUG: Invalid regex pattern")
    });

    /// Returns patterns used for text scanning (LABELED only — STANDARD is
    /// `\d{11}` which matches phone numbers, NINs, and many other 11-digit
    /// strings).
    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED]
    }
}

/// Nigeria Vehicle Registration patterns
///
/// Current (post-2020) format: 3-letter LGA code + 3 digits + 2 letters
/// (e.g. `LAG-123-AB`, `ABC456XY`). Pre-2020 legacy format: 2 letters + 3
/// digits + `-` + 3 letters (e.g. `LA123-ABC`).
///
/// LGA codes (e.g. LAG, ABJ, KAN) are not enforced against a closed list —
/// new codes are issued periodically and authoritative lists vary by source.
pub(crate) mod nigeria_vehicle_reg {
    use super::*;

    /// Plate standard format (no separators for current; legacy keeps the
    /// dash because `AA999AAA` is too generic to safely scan)
    pub static STANDARD: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b(?:[A-Z]{3}\d{3}[A-Z]{2}|[A-Z]{2}\d{3}-[A-Z]{3})\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// Plate with spaces or hyphens between current-format segments
    pub static WITH_SEPARATORS: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b[A-Z]{3}[\s-]\d{3}[\s-][A-Z]{2}\b").expect("BUG: Invalid regex pattern")
    });

    /// Plate with explicit label (current format with optional separators)
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?i)\b(?:vehicle[\s-]?(?:registration|plate|number)?|number[\s-]?plate|plate[\s-]?(?:no\.?|number)?|reg[\s-]?no\.?)[\s:#-]*([A-Z]{3}[\s-]?\d{3}[\s-]?[A-Z]{2})\b",
        )
        .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*WITH_SEPARATORS, &*STANDARD]
    }
}

/// Thailand TNIN (National Identification Number) patterns
///
/// Format: 13 digits. Display form `N-NNNN-NNNNN-NN-N`.
pub(crate) mod thailand_tnin {
    use super::*;

    /// Formatted TNIN: N-NNNN-NNNNN-NN-N
    pub static FORMATTED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b\d-\d{4}-\d{5}-\d{2}-\d\b").expect("BUG: Invalid regex pattern")
    });

    /// TNIN with explicit label
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?i)\b(?:TNIN|Thai[\s-]?national[\s-]?ID|TID)[\s:#-]*(\d-?\d{4}-?\d{5}-?\d{2}-?\d)\b",
        )
        .expect("BUG: Invalid regex pattern")
    });

    /// Scanning patterns. Plain 13-digit form is too ambiguous, so only
    /// formatted or labeled occurrences are scanned.
    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*FORMATTED]
    }
}

/// Singapore NRIC/FIN patterns
pub(crate) mod singapore_nric {
    use super::*;

    /// NRIC/FIN format: [STFGM] + 7 digits + check letter
    pub static STANDARD: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b[STFGM]\d{7}[A-Z]\b").expect("BUG: Invalid regex pattern"));

    /// NRIC/FIN with explicit label
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)\b(?:NRIC|FIN|identity[\s-]?card)[\s:#-]*([STFGM]\d{7}[A-Z])\b")
            .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*STANDARD]
    }
}

/// Singapore UEN (Unique Entity Number) patterns
///
/// Three layout variants:
/// - Business (ROB): 8 digits + check letter, e.g. `12345678A`
/// - Local company (ROC): 9 digits + check letter (YYYY + 5 digits), e.g. `201912345K`
/// - Other entity: `T` + 2-digit year + 2 letters + 4 digits + check letter, e.g. `T12LL1234A`
///
/// The check letter has no publicly published algorithm (Presidio treats it as
/// opaque); detection is shape-only.
pub(crate) mod singapore_uen {
    use super::*;

    /// Business (ROB) layout: 8 digits + uppercase letter
    pub static BUSINESS: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b\d{8}[A-Z]\b").expect("BUG: Invalid regex pattern"));

    /// Local company (ROC) layout: 9 digits + uppercase letter
    pub static LOCAL_COMPANY: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b\d{9}[A-Z]\b").expect("BUG: Invalid regex pattern"));

    /// Other entity layout: T + YY + 2 letters + 4 digits + check letter
    pub static OTHER: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\bT\d{2}[A-Z]{2}\d{4}[A-Z]\b").expect("BUG: Invalid regex pattern")
    });

    /// UEN with explicit label, captures any of the three layouts
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?i)\b(?:UEN|unique[\s-]?entity[\s-]?number)[\s:#-]*(\d{8}[A-Z]|\d{9}[A-Z]|T\d{2}[A-Z]{2}\d{4}[A-Z])\b",
        )
        .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*OTHER, &*LOCAL_COMPANY, &*BUSINESS]
    }
}

/// Finland HETU (personal identity code) patterns
pub(crate) mod finland_hetu {
    use super::*;

    /// HETU format: DDMMYY[+-A]NNNC (6 digits + century + 3 digits + check)
    pub static STANDARD: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b\d{6}[-+A]\d{3}[0-9A-Y]\b").expect("BUG: Invalid regex pattern")
    });

    /// HETU with explicit label
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?i)\b(?:HETU|henkilotunnus|personal[\s-]?identity[\s-]?code)[\s:#-]*(\d{6}[-+A]\d{3}[0-9A-Y])\b",
        )
        .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*STANDARD]
    }
}

/// UK National Insurance Number (NINO) patterns
///
/// Format: 2 letters + 6 digits + 1 suffix letter, e.g. `AB123456C`.
/// The `is_uk_ni` / `find_uk_nis_in_text` detection functions apply HMRC
/// prefix/suffix validation (BG, GB, NK, KN, TN, NT, ZZ excluded; suffix
/// must be A-D) on top of these shape-only patterns.
pub(crate) mod uk_ni {
    use super::*;

    /// Bare UK NINO shape: 2 letters + 6 digits + 1 letter
    /// Example: `AB123456C`
    pub static STANDARD: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)\b[A-Z]{2}\d{6}[A-Z]\b").expect("BUG: Invalid regex pattern")
    });

    /// UK NINO with explicit label (two capture groups: label prefix, NINO value)
    /// Example: `NI: AB123456C`, `NINO AB123456C`, `National Insurance: AB123456C`
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(\b(?i:NINO|NI(?:[\s-]?Number)?|National[\s-]?Insurance(?:[\s-]?Number)?)[\s:#-]*)((?i:[A-Z]{2}\d{6}[A-Z]))\b",
        )
        .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*STANDARD]
    }
}

/// Spain NIF (Numero de Identificacion Fiscal) patterns
pub(crate) mod spain_nif {
    use super::*;

    /// NIF format: 8 digits + 1 check letter
    pub static STANDARD: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?i)\b\d{8}[A-Z]\b").expect("BUG: Invalid regex pattern"));

    /// NIF with explicit label
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)\b(?:NIF|DNI|documento[\s-]?nacional)[\s:#-]*(\d{8}[A-Z])\b")
            .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*STANDARD]
    }
}

/// Spain NIE (Numero de Identidad de Extranjero) patterns
pub(crate) mod spain_nie {
    use super::*;

    /// NIE format: X/Y/Z + 7 digits + 1 check letter
    pub static STANDARD: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?i)\b[XYZ]\d{7}[A-Z]\b").expect("BUG: Invalid regex pattern"));

    /// NIE with explicit label
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)\b(?:NIE|numero[\s-]?de[\s-]?identidad[\s-]?de[\s-]?extranjero)[\s:#-]*([XYZ]\d{7}[A-Z])\b")
            .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*STANDARD]
    }
}

/// Italy Codice Fiscale (fiscal code) patterns
pub(crate) mod italy_fiscal_code {
    use super::*;

    /// Codice Fiscale format: 6 letters + 2 digits + 1 letter + 2 digits + 1 letter + 3 digits + 1 letter
    pub static STANDARD: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i)\b[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// Codice Fiscale with explicit label
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?i)\b(?:codice[\s-]?fiscale|C\.?F\.?|fiscal[\s-]?code)[\s:#-]*([A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z])\b",
        )
        .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*STANDARD]
    }
}

/// Poland PESEL (personal identity number) patterns
pub(crate) mod poland_pesel {
    use super::*;

    /// PESEL format: 11 consecutive digits (YYMMDDNNNCC)
    pub static STANDARD: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"\b\d{11}\b").expect("BUG: Invalid regex pattern"));

    /// PESEL with explicit label
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?i)\b(?:PESEL|numer[\s-]?PESEL|personal[\s-]?id(?:entity)?[\s-]?(?:number|code))[\s:#-]*(\d{11})\b",
        )
        .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*STANDARD]
    }
}

pub(crate) mod personal_name {
    use super::*;

    /// First Last (with optional middle initial/name)
    /// Example: "John Smith", "Mary Jane Doe", "Bob A. Wilson"
    /// **Warning**: High false positive rate - matches any capitalized words
    pub static FIRST_LAST: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b[A-Z][a-z]+(?:\s+[A-Z]\.?)?\s+[A-Z][a-z]+\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// Last, First (with optional middle)
    /// Example: "Smith, John", "Doe, Mary Jane"
    pub static LAST_FIRST: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b[A-Z][a-z]+,\s*[A-Z][a-z]+(?:\s+[A-Z]\.?)?\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// Labeled name
    /// Example: "Name: John Smith", "Patient: Mary Doe"
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"(?i:name|patient|client|customer)[\s:]+([A-Z][a-z]+\s+[A-Z][a-z]+)")
            .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![&*LABELED, &*LAST_FIRST, &*FIRST_LAST]
    }
}

/// Birthdate and date patterns
///
/// Supports multiple date formats commonly used for birthdates.
pub(crate) mod birthdate {
    use super::*;

    /// ISO format: YYYY-MM-DD
    /// Example: "1990-05-15", "2000-12-31"
    pub static ISO_FORMAT: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b(19|20)\d{2}[-.](0[1-9]|1[0-2])[-.](0[1-9]|[12]\d|3[01])\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// US format: MM/DD/YYYY or MM-DD-YYYY
    /// Example: "05/15/1990", "12-31-2000"
    pub static US_FORMAT: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b(0[1-9]|1[0-2])[/\-](0[1-9]|[12]\d|3[01])[/\-](19|20)\d{2}\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// European format: DD/MM/YYYY or DD-MM-YYYY
    /// Example: "15/05/1990", "31-12-2000"
    pub static EU_FORMAT: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b(0[1-9]|[12]\d|3[01])[/\-](0[1-9]|1[0-2])[/\-](19|20)\d{2}\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// Month name format: "Month DD, YYYY"
    /// Example: "January 15, 1990", "Dec 31, 2000"
    pub static MONTH_NAME: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?x)
            \b(January|February|March|April|May|June|July|August|September|October|November|December|
               Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)
            \s+(0?[1-9]|[12]\d|3[01]),?\s+(19|20)\d{2}\b
            ",
        )
        .expect("BUG: Invalid regex pattern")
    });

    /// Day-Month-Year with abbreviated month name
    /// Example: "15-Jan-1990", "15 Jan 1990", "1 Feb 2000"
    pub static DAY_MONTH_ABBREV: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?x)
            \b(0?[1-9]|[12]\d|3[01])[-.\s]
            (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[-.\s]?
            (19|20)\d{2}\b
            ",
        )
        .expect("BUG: Invalid regex pattern")
    });

    /// Year-first with slashes: YYYY/MM/DD
    /// Example: "1990/01/15", "2000/12/31"
    pub static YEAR_FIRST_SLASH: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b(19|20)\d{2}/(0[1-9]|1[0-2])/(0[1-9]|[12]\d|3[01])\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// Two-digit year (US-style): MM/DD/YY or MM-DD-YY
    /// Example: "01/15/90", "12-31-00"
    pub static TWO_DIGIT_YEAR: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b(0[1-9]|1[0-2])[/\-](0[1-9]|[12]\d|3[01])[/\-]\d{2}\b")
            .expect("BUG: Invalid regex pattern")
    });

    /// ISO format with time portion (date part extracted)
    /// Example: "1990-01-15T10:30:00", "2023-06-15T08:00:00Z"
    pub static ISO_WITH_TIME: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"\b(19|20)\d{2}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T\d{2}:\d{2}")
            .expect("BUG: Invalid regex pattern")
    });

    /// Labeled birthdate
    /// Example: "DOB: 1990-05-15", "Born: May 15, 1990"
    pub static LABELED: Lazy<Regex> = Lazy::new(|| {
        Regex::new(
            r"(?i:dob|birthdate|born|birth)[\s:]+([0-9/\-]{8,10}|[A-Za-z]+\s+\d{1,2},?\s+\d{4})",
        )
        .expect("BUG: Invalid regex pattern")
    });

    pub fn all() -> Vec<&'static Regex> {
        vec![
            &*LABELED,
            &*MONTH_NAME,
            &*DAY_MONTH_ABBREV,
            &*ISO_WITH_TIME,
            &*ISO_FORMAT,
            &*YEAR_FIRST_SLASH,
            &*US_FORMAT,
            &*EU_FORMAT,
            &*TWO_DIGIT_YEAR,
        ]
    }
}
