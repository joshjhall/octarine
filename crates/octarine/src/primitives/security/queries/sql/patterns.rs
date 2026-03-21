// SAFETY: All expect() calls in this module are on regex patterns that are
// guaranteed to compile (simple fallback patterns like r"^\b$").
#![allow(clippy::expect_used)]

//! SQL injection detection patterns
//!
//! Compiled regex patterns for detecting SQL injection attacks.

use once_cell::sync::Lazy;
use regex::Regex;

// ============================================================================
// SQL Keywords
// ============================================================================

/// SQL keywords that are suspicious in user input
pub const SQL_KEYWORDS: &[&str] = &[
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "TRUNCATE",
    "ALTER",
    "CREATE",
    "GRANT",
    "REVOKE",
    "UNION",
    "JOIN",
    "WHERE",
    "HAVING",
    "GROUP BY",
    "ORDER BY",
    "LIMIT",
    "OFFSET",
    "EXEC",
    "EXECUTE",
    "DECLARE",
    "CAST",
    "CONVERT",
    "CONCAT",
    "SUBSTRING",
    "COALESCE",
    "CASE",
    "WHEN",
    "THEN",
    "ELSE",
    "END",
    "INTO",
    "FROM",
    "VALUES",
    "SET",
    "AND",
    "OR",
    "NOT",
    "IN",
    "EXISTS",
    "BETWEEN",
    "LIKE",
    "IS NULL",
    "IS NOT NULL",
];

/// SQL comment sequences
pub const SQL_COMMENTS: &[&str] = &["--", "/*", "*/", "#"];

/// SQL time-based blind injection functions
pub const SQL_TIME_FUNCTIONS: &[&str] = &[
    "SLEEP(",
    "WAITFOR DELAY",
    "WAITFOR TIME",
    "PG_SLEEP(",
    "BENCHMARK(",
    "DBMS_LOCK.SLEEP",
];

// ============================================================================
// Compiled Patterns
// ============================================================================

/// Fallback regex that matches nothing
fn fallback_regex() -> Regex {
    Regex::new(r"^\b$").expect("fallback regex should compile")
}

/// Pattern for detecting SQL keywords (case-insensitive, word boundaries)
pub static SQL_KEYWORD_PATTERN: Lazy<Regex> = Lazy::new(|| {
    // Build pattern: \b(SELECT|INSERT|UPDATE|...)\b
    let keywords = SQL_KEYWORDS.join("|");
    Regex::new(&format!(r#"(?i)\b({keywords})\b"#)).unwrap_or_else(|_| fallback_regex())
});

/// Pattern for detecting SQL comment sequences
pub static SQL_COMMENT_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(--|/\*|\*/|#)"#).unwrap_or_else(|_| fallback_regex()));

/// Pattern for detecting string terminators (single/double quotes)
pub static SQL_STRING_TERMINATOR_PATTERN: Lazy<Regex> = Lazy::new(|| {
    // Detect unbalanced quotes that might break out of string context
    Regex::new(r#"['"]"#).unwrap_or_else(|_| fallback_regex())
});

/// Pattern for detecting boolean logic injection (OR 1=1, AND 1=0, etc.)
pub static SQL_BOOLEAN_LOGIC_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\b(OR|AND)\s+\d+\s*=\s*\d+"#).unwrap_or_else(|_| fallback_regex())
});

/// Pattern for detecting OR-based tautologies (OR 'a'='a', OR ''='', etc.)
pub static SQL_TAUTOLOGY_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\bOR\s+['"]?\w*['"]?\s*=\s*['"]?\w*['"]?"#)
        .unwrap_or_else(|_| fallback_regex())
});

/// Pattern for detecting time-based blind injection
pub static SQL_TIME_BASED_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?i)(SLEEP\s*\(|WAITFOR\s+(DELAY|TIME)|PG_SLEEP\s*\(|BENCHMARK\s*\(|DBMS_LOCK\.SLEEP)"#,
    )
    .unwrap_or_else(|_| fallback_regex())
});

/// Pattern for detecting stacked queries (semicolon followed by SQL)
pub static SQL_STACKED_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#";\s*(?i)(SELECT|INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE|GRANT|EXEC)"#)
        .unwrap_or_else(|_| fallback_regex())
});

/// Pattern for detecting UNION-based injection
pub static SQL_UNION_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)\bUNION\s+(ALL\s+)?SELECT\b"#).unwrap_or_else(|_| fallback_regex())
});

/// Pattern for detecting hex-encoded strings (0x...)
pub static SQL_HEX_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"0x[0-9A-Fa-f]+"#).unwrap_or_else(|_| fallback_regex()));

/// Pattern for detecting CHAR() function abuse
pub static SQL_CHAR_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"(?i)CHAR\s*\(\s*\d+"#).unwrap_or_else(|_| fallback_regex()));

// ============================================================================
// Pattern Checking Functions
// ============================================================================

/// Check if input contains SQL keywords
#[must_use]
pub fn is_sql_keywords_present(input: &str) -> bool {
    SQL_KEYWORD_PATTERN.is_match(input)
}

/// Check if input contains SQL comment sequences
#[must_use]
pub fn is_sql_comments_present(input: &str) -> bool {
    SQL_COMMENT_PATTERN.is_match(input)
}

/// Check if input contains string terminators
#[must_use]
pub fn is_string_terminators_present(input: &str) -> bool {
    SQL_STRING_TERMINATOR_PATTERN.is_match(input)
}

/// Check if input contains boolean logic patterns
#[must_use]
pub fn is_boolean_logic_present(input: &str) -> bool {
    SQL_BOOLEAN_LOGIC_PATTERN.is_match(input) || SQL_TAUTOLOGY_PATTERN.is_match(input)
}

/// Check if input contains time-based blind injection patterns
#[must_use]
pub fn is_time_based_present(input: &str) -> bool {
    SQL_TIME_BASED_PATTERN.is_match(input)
}

/// Check if input contains stacked query patterns
#[must_use]
pub fn is_stacked_queries_present(input: &str) -> bool {
    SQL_STACKED_PATTERN.is_match(input)
}

/// Check if input contains UNION-based injection patterns
#[must_use]
pub fn is_union_based_present(input: &str) -> bool {
    SQL_UNION_PATTERN.is_match(input)
}

/// Check if input contains hex-encoded strings (potential filter bypass)
#[must_use]
pub fn is_hex_encoded_present(input: &str) -> bool {
    SQL_HEX_PATTERN.is_match(input)
}

/// Check if input contains CHAR() function abuse (potential filter bypass)
#[must_use]
pub fn is_char_function_present(input: &str) -> bool {
    SQL_CHAR_PATTERN.is_match(input)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sql_keywords() {
        assert!(is_sql_keywords_present("SELECT * FROM users"));
        assert!(is_sql_keywords_present("select * from users"));
        assert!(is_sql_keywords_present("DROP TABLE users"));
        assert!(is_sql_keywords_present(
            "' UNION SELECT password FROM users"
        ));
        assert!(!is_sql_keywords_present("hello world"));
        assert!(!is_sql_keywords_present("user@example.com"));
    }

    #[test]
    fn test_sql_comments() {
        assert!(is_sql_comments_present("admin'--"));
        assert!(is_sql_comments_present("/* comment */"));
        assert!(is_sql_comments_present("password# comment"));
        assert!(!is_sql_comments_present("hello world"));
    }

    #[test]
    fn test_string_terminators() {
        assert!(is_string_terminators_present("admin'"));
        assert!(is_string_terminators_present("admin\""));
        assert!(!is_string_terminators_present("admin"));
    }

    #[test]
    fn test_boolean_logic() {
        assert!(is_boolean_logic_present("' OR 1=1 --"));
        assert!(is_boolean_logic_present("' AND 1=0"));
        assert!(is_boolean_logic_present("' or 1=1"));
        assert!(!is_boolean_logic_present("hello world"));
    }

    #[test]
    fn test_time_based() {
        assert!(is_time_based_present("'; SLEEP(5); --"));
        assert!(is_time_based_present("WAITFOR DELAY '0:0:5'"));
        assert!(is_time_based_present("pg_sleep(10)"));
        assert!(is_time_based_present("BENCHMARK(1000000, SHA1('test'))"));
        assert!(!is_time_based_present("hello world"));
    }

    #[test]
    fn test_stacked_queries() {
        assert!(is_stacked_queries_present("'; DROP TABLE users; --"));
        assert!(is_stacked_queries_present("; DELETE FROM logs"));
        assert!(is_stacked_queries_present(";SELECT * FROM passwords"));
        assert!(!is_stacked_queries_present("hello; world"));
    }

    #[test]
    fn test_union_based() {
        assert!(is_union_based_present("' UNION SELECT password FROM users"));
        assert!(is_union_based_present("UNION ALL SELECT * FROM secrets"));
        assert!(!is_union_based_present("hello world"));
    }

    #[test]
    fn test_common_sqli_payloads() {
        // Classic payloads
        assert!(is_sql_keywords_present("' OR '1'='1"));
        assert!(is_sql_comments_present("admin'--"));
        assert!(is_boolean_logic_present("' OR 1=1--"));
        assert!(is_union_based_present(
            "' UNION SELECT username,password FROM users--"
        ));

        // Time-based blind
        assert!(is_time_based_present("'; IF (1=1) WAITFOR DELAY '0:0:5'--"));

        // Stacked queries
        assert!(is_stacked_queries_present("'; DROP TABLE users;--"));
    }

    #[test]
    fn test_hex_encoded() {
        // Hex-encoded strings (filter bypass technique)
        assert!(is_hex_encoded_present("0x414243"));
        assert!(is_hex_encoded_present("SELECT 0x41424344"));
        assert!(is_hex_encoded_present(
            "INSERT INTO users VALUES(0x61646d696e)"
        ));

        // Not hex encoded
        assert!(!is_hex_encoded_present("hello world"));
        assert!(!is_hex_encoded_present("0x")); // Empty hex
        assert!(!is_hex_encoded_present("SELECT * FROM users"));
    }

    #[test]
    fn test_char_function() {
        // CHAR() function abuse (filter bypass technique)
        assert!(is_char_function_present("CHAR(65)"));
        assert!(is_char_function_present("SELECT CHAR(97,100,109,105,110)"));
        assert!(is_char_function_present("char(65)"));
        assert!(is_char_function_present("CHAR( 65 )"));

        // Not CHAR function
        assert!(!is_char_function_present("hello world"));
        assert!(!is_char_function_present("character"));
        assert!(!is_char_function_present("SELECT * FROM users"));
    }
}
