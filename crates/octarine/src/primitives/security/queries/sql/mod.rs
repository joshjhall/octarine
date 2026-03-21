//! SQL injection detection and prevention
//!
//! Provides pattern-based detection for SQL injection attacks (CWE-89).
//! Internal module - use `QuerySecurityBuilder` for the public API.
//!
//! # Threat Categories
//!
//! | Threat | Description | Example |
//! |--------|-------------|---------|
//! | Keyword injection | SQL keywords in input | `'; DROP TABLE users; --` |
//! | Comment bypass | Comments to terminate queries | `admin'--` |
//! | Boolean logic | Tautologies and contradictions | `' OR 1=1 --` |
//! | Time-based blind | Delay functions | `'; WAITFOR DELAY '0:0:5'` |
//! | Union-based | UNION to extract data | `' UNION SELECT * FROM users --` |
//! | Stacked queries | Multiple statements | `'; DELETE FROM logs; --` |

pub(super) mod detection;
pub(super) mod patterns;
pub(super) mod sanitization;
pub(super) mod validation;

// Internal re-exports for use by the builder
pub(super) use detection::{detect_sql_threats, is_sql_injection_present};
pub(super) use sanitization::{escape_sql_identifier, escape_sql_string};
pub(super) use validation::validate_sql_parameter;
