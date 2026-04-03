//! Connection string validation (primitives layer)
//!
//! Structural validation for connection strings containing embedded credentials.
//! Unlike opaque credentials (passwords, PINs), connection strings have well-defined
//! formats that can be structurally validated.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with:
//! - No observe:: dependencies
//! - No logging or side effects
//! - Returns data only
//!
//! # Supported Formats
//!
//! - **URL-based**: `scheme://user:pass@host:port/db`
//! - **MSSQL key-value**: `Server=host;Database=db;Password=secret`
//! - **JDBC**: `jdbc:driver://host/db?password=secret`

use super::detection;
use crate::primitives::Problem;

// ============================================================================
// Constants
// ============================================================================

/// Maximum length for connection string inputs (ReDoS protection)
const MAX_LENGTH: usize = 10_000;

/// Known database URL schemes
const DB_SCHEMES: &[&str] = &[
    "postgres://",
    "postgresql://",
    "mysql://",
    "mongodb://",
    "mongodb+srv://",
    "redis://",
    "rediss://",
    "amqp://",
    "amqps://",
    "mqtt://",
    "mqtts://",
];

/// JDBC prefix
const JDBC_PREFIX: &str = "jdbc:";

/// Maximum valid port number
const MAX_PORT: u32 = 65535;

// ============================================================================
// Helper Functions
// ============================================================================

/// Check if value contains shell injection patterns.
///
/// Note: semicolons are valid in MSSQL connection strings as delimiters,
/// so we only check for shell-specific injection patterns here.
fn is_injection_pattern_present(value: &str) -> bool {
    value.contains("$(") || value.contains('`') || value.contains("${")
}

/// Extract the password from a URL-based connection string.
/// Returns the password portion between `:` and `@` in `user:pass@host`.
fn extract_url_password(value: &str) -> Option<&str> {
    // Find the scheme separator
    let after_scheme = value.find("://").map(|i| &value[i.saturating_add(3)..])?;

    // Find the @ separator
    let at_pos = after_scheme.find('@')?;
    let userinfo = &after_scheme[..at_pos];

    // Find the : separator in userinfo
    let colon_pos = userinfo.find(':')?;
    Some(&userinfo[colon_pos.saturating_add(1)..])
}

/// Extract host from a URL-based connection string (after @ or after ://).
fn extract_url_host(value: &str) -> Option<&str> {
    let after_scheme = value.find("://").map(|i| &value[i.saturating_add(3)..])?;

    // If there's an @, host is after it; otherwise host is directly after ://
    let host_start = match after_scheme.find('@') {
        Some(at_pos) => &after_scheme[at_pos.saturating_add(1)..],
        None => after_scheme,
    };

    // Host ends at /, ?, or end of string
    let host_port = match host_start.find(['/', '?']) {
        Some(pos) => &host_start[..pos],
        None => host_start,
    };

    if host_port.is_empty() {
        None
    } else {
        Some(host_port)
    }
}

/// Extract the MSSQL Server/Data Source host value.
fn extract_mssql_host(value: &str) -> Option<&str> {
    let lower = value.to_lowercase();
    for key in &["server=", "data source="] {
        if let Some(start) = lower.find(key) {
            let after_key = &value[start.saturating_add(key.len())..];
            let end = after_key.find(';').unwrap_or(after_key.len());
            let host = after_key[..end].trim();
            if !host.is_empty() {
                return Some(&after_key[..end]);
            }
        }
    }
    None
}

/// Validate a port number string.
fn validate_port(port_str: &str) -> Result<(), Problem> {
    if port_str.is_empty() {
        return Ok(());
    }
    match port_str.parse::<u32>() {
        Ok(port) if port > 0 && port <= MAX_PORT => Ok(()),
        _ => Err(Problem::Validation(format!(
            "Invalid port number: must be 1-{MAX_PORT}"
        ))),
    }
}

// ============================================================================
// Connection String Validation
// ============================================================================

/// Validate a connection string with embedded credentials
///
/// Validates that the input is a well-formed connection string in a recognized
/// format (URL-based, MSSQL key-value, or JDBC) with a present host and
/// non-weak embedded password.
///
/// # Rules
///
/// - Must match a recognized connection string format
/// - URI scheme must be a known database scheme
/// - Host must be present
/// - Embedded passwords must not be weak (checked against common weak passwords)
/// - Maximum 10,000 characters (ReDoS protection)
/// - No shell injection patterns
///
/// # Errors
///
/// Returns `Problem` if the connection string format is invalid
pub fn validate_connection_string(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "Connection string cannot be empty".into(),
        ));
    }

    if trimmed.len() > MAX_LENGTH {
        return Err(Problem::Validation(format!(
            "Connection string exceeds maximum length of {MAX_LENGTH} characters"
        )));
    }

    if is_injection_pattern_present(trimmed) {
        return Err(Problem::Validation(
            "Connection string contains injection patterns".into(),
        ));
    }

    // Must be a recognized connection string format
    if !detection::is_connection_string_with_credentials(trimmed) {
        return Err(Problem::Validation(
            "Connection string does not match a recognized format (URL-based, MSSQL, or JDBC)"
                .into(),
        ));
    }

    // Validate host presence for URL-based strings
    let lower = trimmed.to_lowercase();
    if DB_SCHEMES.iter().any(|s| lower.starts_with(s)) || lower.starts_with(JDBC_PREFIX) {
        if extract_url_host(trimmed).is_none() {
            return Err(Problem::Validation(
                "Connection string must contain a host".into(),
            ));
        }
    } else {
        // MSSQL format
        if extract_mssql_host(trimmed).is_none() {
            return Err(Problem::Validation(
                "Connection string must contain a Server or Data Source".into(),
            ));
        }
    }

    // Check for weak embedded passwords in URL-based strings
    if extract_url_password(trimmed).is_some_and(detection::is_weak_password) {
        return Err(Problem::Validation(
            "Connection string contains a weak embedded password".into(),
        ));
    }

    Ok(())
}

// ============================================================================
// Database Connection String Validation
// ============================================================================

/// Validate a database connection string format
///
/// Validates that the input uses a known database URL scheme with a valid
/// host and optional port. Does NOT require credentials to be present.
///
/// # Rules
///
/// - Must start with a known database scheme
/// - Host must be present after `://` (with or without credentials)
/// - Port (if present) must be numeric and in range 1-65535
/// - Maximum 10,000 characters (ReDoS protection)
/// - No shell injection patterns
///
/// # Errors
///
/// Returns `Problem` if the database connection string format is invalid
pub fn validate_database_connection_string(value: &str) -> Result<(), Problem> {
    let trimmed = value.trim();

    if trimmed.is_empty() {
        return Err(Problem::Validation(
            "Database connection string cannot be empty".into(),
        ));
    }

    if trimmed.len() > MAX_LENGTH {
        return Err(Problem::Validation(format!(
            "Database connection string exceeds maximum length of {MAX_LENGTH} characters"
        )));
    }

    if is_injection_pattern_present(trimmed) {
        return Err(Problem::Validation(
            "Database connection string contains injection patterns".into(),
        ));
    }

    // Must start with a known DB scheme
    let lower = trimmed.to_lowercase();
    if !DB_SCHEMES.iter().any(|s| lower.starts_with(s)) {
        return Err(Problem::Validation(
            "Database connection string must use a known scheme (postgres, mysql, mongodb, redis, amqp, mqtt)".into(),
        ));
    }

    // Extract and validate host
    let host_port = extract_url_host(trimmed).ok_or_else(|| {
        Problem::Validation("Database connection string must contain a host".into())
    })?;

    // Validate port if present (host:port format)
    if let Some(colon_pos) = host_port.rfind(':') {
        let port_str = &host_port[colon_pos.saturating_add(1)..];
        // Only validate as port if it looks numeric (not an IPv6 address)
        if !port_str.is_empty() && port_str.bytes().all(|b| b.is_ascii_digit()) {
            validate_port(port_str)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ===== validate_connection_string Tests =====

    #[test]
    fn test_connection_string_valid_postgres() {
        assert!(
            validate_connection_string("postgres://admin:strongP@ss99@db.example.com:5432/mydb")
                .is_ok()
        );
    }

    #[test]
    fn test_connection_string_valid_mysql() {
        assert!(
            validate_connection_string("mysql://root:MyS3cureP@ss@db.example.com:3306/app").is_ok()
        );
    }

    #[test]
    fn test_connection_string_valid_mongodb() {
        assert!(
            validate_connection_string("mongodb://admin:m0ng0Pass@mongo.example.com:27017/mydb")
                .is_ok()
        );
    }

    #[test]
    fn test_connection_string_valid_mongodb_srv() {
        assert!(
            validate_connection_string("mongodb+srv://user:clust3rP@ss@cluster0.example.net/test")
                .is_ok()
        );
    }

    #[test]
    fn test_connection_string_valid_redis() {
        assert!(
            validate_connection_string("redis://default:r3disP@ss@redis.example.com:6379").is_ok()
        );
    }

    #[test]
    fn test_connection_string_valid_mssql() {
        assert!(
            validate_connection_string("Server=db.example.com;Database=mydb;Password=Str0ngP@ss")
                .is_ok()
        );
    }

    #[test]
    fn test_connection_string_valid_jdbc() {
        assert!(
            validate_connection_string("jdbc:postgresql://host.example.com/db?password=Jdb3P@ss")
                .is_ok()
        );
    }

    #[test]
    fn test_connection_string_empty() {
        assert!(validate_connection_string("").is_err());
        assert!(validate_connection_string("   ").is_err());
    }

    #[test]
    fn test_connection_string_too_long() {
        let long = format!("postgres://user:pass@host/{}", "a".repeat(10_000));
        assert!(validate_connection_string(&long).is_err());
    }

    #[test]
    fn test_connection_string_unknown_format() {
        assert!(validate_connection_string("not-a-connection-string").is_err());
        assert!(validate_connection_string("http://example.com").is_err());
    }

    #[test]
    fn test_connection_string_injection() {
        assert!(
            validate_connection_string("postgres://admin:$(whoami)@db.example.com/mydb").is_err()
        );
        assert!(validate_connection_string("postgres://admin:`ls`@db.example.com/mydb").is_err());
    }

    #[test]
    fn test_connection_string_weak_password() {
        assert!(
            validate_connection_string("postgres://admin:password@db.example.com/mydb").is_err()
        );
        assert!(
            validate_connection_string("mysql://root:admin123@db.example.com:3306/app").is_err()
        );
        assert!(
            validate_connection_string("redis://default:changeme@redis.example.com:6379").is_err()
        );
    }

    #[test]
    fn test_connection_string_whitespace_trimming() {
        assert!(
            validate_connection_string(
                "  postgres://admin:strongP@ss99@db.example.com:5432/mydb  "
            )
            .is_ok()
        );
    }

    // ===== validate_database_connection_string Tests =====

    #[test]
    fn test_db_connection_string_valid_with_creds() {
        assert!(
            validate_database_connection_string("postgres://admin:pass@db.example.com:5432/mydb")
                .is_ok()
        );
    }

    #[test]
    fn test_db_connection_string_valid_without_creds() {
        assert!(validate_database_connection_string("postgres://db.example.com:5432/mydb").is_ok());
        assert!(validate_database_connection_string("redis://localhost:6379").is_ok());
    }

    #[test]
    fn test_db_connection_string_valid_no_port() {
        assert!(validate_database_connection_string("mongodb://mongo.example.com/mydb").is_ok());
    }

    #[test]
    fn test_db_connection_string_valid_schemes() {
        assert!(validate_database_connection_string("postgresql://host/db").is_ok());
        assert!(validate_database_connection_string("mysql://host/db").is_ok());
        assert!(validate_database_connection_string("mongodb+srv://host/db").is_ok());
        assert!(validate_database_connection_string("rediss://host").is_ok());
        assert!(validate_database_connection_string("amqp://host").is_ok());
        assert!(validate_database_connection_string("amqps://host").is_ok());
        assert!(validate_database_connection_string("mqtt://host").is_ok());
        assert!(validate_database_connection_string("mqtts://host").is_ok());
    }

    #[test]
    fn test_db_connection_string_unknown_scheme() {
        assert!(validate_database_connection_string("http://example.com").is_err());
        assert!(validate_database_connection_string("ftp://files.example.com").is_err());
        assert!(validate_database_connection_string("jdbc:postgresql://host/db").is_err());
    }

    #[test]
    fn test_db_connection_string_empty() {
        assert!(validate_database_connection_string("").is_err());
        assert!(validate_database_connection_string("   ").is_err());
    }

    #[test]
    fn test_db_connection_string_missing_host() {
        assert!(validate_database_connection_string("postgres://").is_err());
    }

    #[test]
    fn test_db_connection_string_invalid_port() {
        assert!(validate_database_connection_string("postgres://host:99999/db").is_err());
        assert!(validate_database_connection_string("postgres://host:0/db").is_err());
    }

    #[test]
    fn test_db_connection_string_valid_port() {
        assert!(validate_database_connection_string("postgres://host:5432/db").is_ok());
        assert!(validate_database_connection_string("mysql://host:3306/db").is_ok());
        assert!(validate_database_connection_string("redis://host:6379").is_ok());
    }

    #[test]
    fn test_db_connection_string_injection() {
        assert!(validate_database_connection_string("postgres://$(whoami):5432/db").is_err());
    }

    #[test]
    fn test_db_connection_string_too_long() {
        let long = format!("postgres://host/{}", "a".repeat(10_000));
        assert!(validate_database_connection_string(&long).is_err());
    }

    #[test]
    fn test_db_connection_string_whitespace_trimming() {
        assert!(validate_database_connection_string("  postgres://host:5432/db  ").is_ok());
    }
}
