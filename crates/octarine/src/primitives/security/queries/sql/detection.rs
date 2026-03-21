//! SQL injection detection
//!
//! Detection functions for identifying SQL injection patterns in user input.

use super::patterns;
use crate::primitives::security::queries::types::QueryThreat;

// ============================================================================
// Primary Detection Function
// ============================================================================

/// Check if input contains any SQL injection patterns
///
/// This is a comprehensive check that looks for multiple attack vectors.
/// Use this for general-purpose SQL injection detection.
///
/// # Arguments
///
/// * `input` - The user input to check
///
/// # Returns
///
/// `true` if any SQL injection pattern is detected
///
/// # Example
///
/// ```ignore
/// use octarine::primitives::security::queries::sql::detection;
///
/// assert!(detection::is_sql_injection_present("' OR 1=1 --"));
/// assert!(!detection::is_sql_injection_present("hello world"));
/// ```
#[must_use]
pub fn is_sql_injection_present(input: &str) -> bool {
    // Empty input is safe
    if input.is_empty() {
        return false;
    }

    // Check for the most dangerous patterns first
    patterns::is_stacked_queries_present(input)
        || patterns::is_union_based_present(input)
        || patterns::is_time_based_present(input)
        || patterns::is_boolean_logic_present(input)
        // Filter bypass techniques (hex/char combined with SQL context)
        || ((patterns::is_hex_encoded_present(input) || patterns::is_char_function_present(input))
            && patterns::is_sql_keywords_present(input))
        || (patterns::is_string_terminators_present(input)
            && (patterns::is_sql_comments_present(input)
                || patterns::is_sql_keywords_present(input)))
}

/// Detect all SQL injection threats in input
///
/// Returns a list of all detected threat types, useful for detailed
/// logging and analysis.
///
/// # Arguments
///
/// * `input` - The user input to analyze
///
/// # Returns
///
/// A vector of detected `QueryThreat` values
#[must_use]
pub fn detect_sql_threats(input: &str) -> Vec<QueryThreat> {
    let mut threats = Vec::new();

    if input.is_empty() {
        return threats;
    }

    // Check each threat type
    if patterns::is_stacked_queries_present(input) {
        threats.push(QueryThreat::SqlStackedQueries);
    }

    if patterns::is_union_based_present(input) {
        threats.push(QueryThreat::SqlUnionBased);
    }

    if patterns::is_time_based_present(input) {
        threats.push(QueryThreat::SqlTimeBasedBlind);
    }

    if patterns::is_boolean_logic_present(input) {
        threats.push(QueryThreat::SqlBooleanLogic);
    }

    if patterns::is_sql_comments_present(input) {
        threats.push(QueryThreat::SqlCommentSequence);
    }

    if patterns::is_string_terminators_present(input) {
        threats.push(QueryThreat::SqlStringTerminator);
    }

    // Filter bypass techniques
    if patterns::is_hex_encoded_present(input) {
        threats.push(QueryThreat::SqlHexEncoding);
    }

    if patterns::is_char_function_present(input) {
        threats.push(QueryThreat::SqlCharFunction);
    }

    // Only flag keyword if combined with other suspicious patterns
    if patterns::is_sql_keywords_present(input)
        && (threats.iter().any(|t| {
            matches!(
                t,
                QueryThreat::SqlCommentSequence
                    | QueryThreat::SqlStringTerminator
                    | QueryThreat::SqlHexEncoding
                    | QueryThreat::SqlCharFunction
            )
        }))
    {
        threats.push(QueryThreat::SqlKeywordInInput);
    }

    threats
}

/// Check for SQL keywords in input (detection only, high false positive rate)
///
/// This is useful for logging/monitoring but should not be used alone
/// for blocking, as many legitimate inputs contain SQL keywords.
#[must_use]
pub fn is_sql_keywords_in_input(input: &str) -> bool {
    patterns::is_sql_keywords_present(input)
}

/// Check for SQL comment sequences
#[must_use]
pub fn is_sql_comments_in_input(input: &str) -> bool {
    patterns::is_sql_comments_present(input)
}

/// Check for string terminator characters
#[must_use]
pub fn is_string_terminators_in_input(input: &str) -> bool {
    patterns::is_string_terminators_present(input)
}

/// Check for boolean logic injection patterns
#[must_use]
pub fn is_boolean_logic_in_input(input: &str) -> bool {
    patterns::is_boolean_logic_present(input)
}

/// Check for time-based blind injection patterns
#[must_use]
pub fn is_time_based_in_input(input: &str) -> bool {
    patterns::is_time_based_present(input)
}

/// Check for stacked query patterns
#[must_use]
pub fn is_stacked_queries_in_input(input: &str) -> bool {
    patterns::is_stacked_queries_present(input)
}

/// Check for UNION-based injection patterns
#[must_use]
pub fn is_union_based_in_input(input: &str) -> bool {
    patterns::is_union_based_present(input)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_sql_injection_present_safe_inputs() {
        // Normal inputs should not trigger
        assert!(!is_sql_injection_present(""));
        assert!(!is_sql_injection_present("hello"));
        assert!(!is_sql_injection_present("user@example.com"));
        assert!(!is_sql_injection_present("John Doe"));
        assert!(!is_sql_injection_present("123456"));
        assert!(!is_sql_injection_present("hello world 123"));
    }

    #[test]
    fn test_is_sql_injection_present_comment_bypass() {
        assert!(is_sql_injection_present("admin'--"));
        assert!(is_sql_injection_present("admin'/*"));
        assert!(is_sql_injection_present("password'#"));
    }

    #[test]
    fn test_is_sql_injection_present_boolean_logic() {
        assert!(is_sql_injection_present("' OR 1=1 --"));
        assert!(is_sql_injection_present("' OR 1=1"));
        assert!(is_sql_injection_present("' AND 1=0"));
        assert!(is_sql_injection_present("admin' or 1=1--"));
    }

    #[test]
    fn test_is_sql_injection_present_union() {
        assert!(is_sql_injection_present(
            "' UNION SELECT password FROM users --"
        ));
        assert!(is_sql_injection_present("UNION ALL SELECT * FROM secrets"));
    }

    #[test]
    fn test_is_sql_injection_present_stacked() {
        assert!(is_sql_injection_present("'; DROP TABLE users; --"));
        assert!(is_sql_injection_present("'; DELETE FROM logs; --"));
    }

    #[test]
    fn test_is_sql_injection_present_time_based() {
        assert!(is_sql_injection_present("'; SLEEP(5); --"));
        assert!(is_sql_injection_present("WAITFOR DELAY '0:0:5'"));
        assert!(is_sql_injection_present("pg_sleep(10)"));
    }

    #[test]
    fn test_detect_sql_threats_multiple() {
        let threats = detect_sql_threats("'; DROP TABLE users; -- UNION SELECT * FROM passwords");
        assert!(!threats.is_empty());
        assert!(threats.contains(&QueryThreat::SqlStackedQueries));
        assert!(threats.contains(&QueryThreat::SqlUnionBased));
        assert!(threats.contains(&QueryThreat::SqlCommentSequence));
    }

    #[test]
    fn test_detect_sql_threats_empty() {
        let threats = detect_sql_threats("");
        assert!(threats.is_empty());
    }

    #[test]
    fn test_detect_sql_threats_safe_input() {
        let threats = detect_sql_threats("hello world");
        assert!(threats.is_empty());
    }

    #[test]
    fn test_classic_sqli_payloads() {
        // OWASP test payloads
        assert!(is_sql_injection_present("' OR '1'='1'--"));
        assert!(is_sql_injection_present("admin'--"));
        assert!(is_sql_injection_present("1' AND '1'='1"));
        assert!(is_sql_injection_present("' OR 1=1#"));
        assert!(is_sql_injection_present("') OR ('1'='1"));
    }

    #[test]
    fn test_edge_cases() {
        // Just quotes without SQL
        assert!(!is_sql_injection_present("O'Brien"));
        assert!(!is_sql_injection_present("It's a test"));

        // Just keywords without injection context
        assert!(!is_sql_injection_present("SELECT")); // Just keyword, no injection
        assert!(!is_sql_injection_present("Please select an option"));

        // Quote + keyword = injection
        assert!(is_sql_injection_present("' SELECT password FROM users --"));
    }

    #[test]
    fn test_hex_encoding_bypass() {
        // Hex encoding combined with SQL keywords = injection
        assert!(is_sql_injection_present("SELECT 0x61646d696e"));
        assert!(is_sql_injection_present(
            "INSERT INTO users VALUES(0x70617373)"
        ));

        // Just hex without SQL context = not flagged (could be legitimate)
        assert!(!is_sql_injection_present("0x414243")); // Just hex alone
    }

    #[test]
    fn test_char_function_bypass() {
        // CHAR() function combined with SQL keywords = injection
        assert!(is_sql_injection_present("SELECT CHAR(97,100,109,105,110)"));
        assert!(is_sql_injection_present(
            "INSERT INTO users VALUES(CHAR(65,66,67))"
        ));

        // Just CHAR() without SQL context = not flagged
        assert!(!is_sql_injection_present("CHAR(65)")); // Just CHAR alone
    }

    #[test]
    fn test_detect_hex_char_threats() {
        // Detect hex encoding
        let hex_threats = detect_sql_threats("SELECT 0x61646d696e FROM users");
        assert!(hex_threats.contains(&QueryThreat::SqlHexEncoding));
        assert!(hex_threats.contains(&QueryThreat::SqlKeywordInInput));

        // Detect CHAR function
        let char_threats = detect_sql_threats("SELECT CHAR(97,98,99) FROM users");
        assert!(char_threats.contains(&QueryThreat::SqlCharFunction));
        assert!(char_threats.contains(&QueryThreat::SqlKeywordInInput));
    }
}
