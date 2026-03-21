//! Configuration value with type conversion and validation

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use super::ConfigError;
use crate::crypto::secrets::{Classification, SecretType, TypedSecret};
use crate::observe::pii::{PiiType, scan_for_pii};

/// A configuration value that can be converted to various types
///
/// Provides type-safe conversion with helpful error messages.
///
/// # Example
///
/// ```ignore
/// use octarine::runtime::config::ConfigValue;
///
/// let value = ConfigValue::new("APP_PORT", "8080", false);
/// let port: u16 = value.parse()?;
/// ```
#[derive(Debug, Clone)]
pub struct ConfigValue {
    /// The full variable name (with prefix)
    name: String,
    /// The raw string value
    value: Option<String>,
    /// Whether this is a secret (masks value in errors)
    is_secret: bool,
    /// Default value if not set
    default: Option<String>,
}

impl ConfigValue {
    /// Create a new config value
    pub fn new(name: impl Into<String>, value: Option<String>, is_secret: bool) -> Self {
        Self {
            name: name.into(),
            value,
            is_secret,
            default: None,
        }
    }

    /// Set a default value to use if the environment variable is not set
    #[must_use]
    pub fn default(mut self, value: impl Into<String>) -> Self {
        self.default = Some(value.into());
        self
    }

    /// Set a typed default value
    #[must_use]
    pub fn default_value<T: ToString>(mut self, value: T) -> Self {
        self.default = Some(value.to_string());
        self
    }

    /// Get the variable name
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Check if this value is marked as a secret
    #[must_use]
    pub fn is_secret(&self) -> bool {
        self.is_secret
    }

    /// Check if the value is set (either from env or default)
    #[must_use]
    pub fn is_set(&self) -> bool {
        self.value.is_some() || self.default.is_some()
    }

    /// Get the raw string value, or None if not set
    #[must_use]
    pub fn raw(&self) -> Option<&str> {
        self.value.as_deref().or(self.default.as_deref())
    }

    /// Get the raw value, returning error if not set
    pub fn require_raw(&self) -> Result<&str, ConfigError> {
        self.raw().ok_or_else(|| ConfigError::missing(&self.name))
    }

    /// Parse the value into a type that implements FromStr
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::Missing` if value is not set and no default.
    /// Returns `ConfigError::ParseError` if parsing fails.
    pub fn parse<T>(&self) -> Result<T, ConfigError>
    where
        T: FromStr,
        T::Err: std::fmt::Display,
    {
        let raw = self.require_raw()?;
        self.parse_str(raw)
    }

    /// Parse the value, returning default if not set
    pub fn parse_or<T>(&self, default: T) -> Result<T, ConfigError>
    where
        T: FromStr,
        T::Err: std::fmt::Display,
    {
        match self.raw() {
            Some(raw) => self.parse_str(raw),
            None => Ok(default),
        }
    }

    /// Parse a string value into the target type
    fn parse_str<T>(&self, raw: &str) -> Result<T, ConfigError>
    where
        T: FromStr,
        T::Err: std::fmt::Display,
    {
        raw.parse().map_err(|e: T::Err| {
            if self.is_secret {
                ConfigError::parse_secret(&self.name, std::any::type_name::<T>(), e.to_string())
            } else {
                ConfigError::parse(&self.name, raw, std::any::type_name::<T>(), e.to_string())
            }
        })
    }

    /// Parse as a boolean
    ///
    /// Accepts: true/false, yes/no, 1/0, on/off (case-insensitive)
    pub fn parse_bool(&self) -> Result<bool, ConfigError> {
        let raw = self.require_raw()?;
        match raw.to_lowercase().as_str() {
            "true" | "yes" | "1" | "on" => Ok(true),
            "false" | "no" | "0" | "off" => Ok(false),
            _ => {
                if self.is_secret {
                    Err(ConfigError::parse_secret(
                        &self.name,
                        "bool",
                        "expected true/false, yes/no, 1/0, or on/off",
                    ))
                } else {
                    Err(ConfigError::parse(
                        &self.name,
                        raw,
                        "bool",
                        "expected true/false, yes/no, 1/0, or on/off",
                    ))
                }
            }
        }
    }

    /// Parse as a boolean with default
    pub fn parse_bool_or(&self, default: bool) -> Result<bool, ConfigError> {
        match self.raw() {
            Some(_) => self.parse_bool(),
            None => Ok(default),
        }
    }

    /// Parse as a Duration from seconds
    ///
    /// Accepts: integer seconds, or strings like "30s", "5m", "1h"
    pub fn parse_duration(&self) -> Result<Duration, ConfigError> {
        let raw = self.require_raw()?;
        self.parse_duration_str(raw)
    }

    /// Parse as Duration with default
    pub fn parse_duration_or(&self, default: Duration) -> Result<Duration, ConfigError> {
        match self.raw() {
            Some(raw) => self.parse_duration_str(raw),
            None => Ok(default),
        }
    }

    /// Parse duration from string
    fn parse_duration_str(&self, raw: &str) -> Result<Duration, ConfigError> {
        let raw = raw.trim();

        // Try parsing as plain seconds first
        if let Ok(secs) = raw.parse::<u64>() {
            return Ok(Duration::from_secs(secs));
        }

        // Try parsing with suffix
        let (num_str, multiplier) = if let Some(n) = raw.strip_suffix("ms") {
            (n, 1)
        } else if let Some(n) = raw.strip_suffix('s') {
            (n, 1000)
        } else if let Some(n) = raw.strip_suffix('m') {
            (n, 60 * 1000)
        } else if let Some(n) = raw.strip_suffix('h') {
            (n, 60 * 60 * 1000)
        } else if let Some(n) = raw.strip_suffix('d') {
            (n, 24 * 60 * 60 * 1000)
        } else {
            return Err(self.duration_parse_error(raw));
        };

        let num: u64 = num_str
            .trim()
            .parse()
            .map_err(|_| self.duration_parse_error(raw))?;
        let millis = num
            .checked_mul(multiplier)
            .ok_or_else(|| self.duration_parse_error(raw))?;
        Ok(Duration::from_millis(millis))
    }

    fn duration_parse_error(&self, raw: &str) -> ConfigError {
        if self.is_secret {
            ConfigError::parse_secret(
                &self.name,
                "Duration",
                "expected seconds or duration like '30s', '5m', '1h'",
            )
        } else {
            ConfigError::parse(
                &self.name,
                raw,
                "Duration",
                "expected seconds or duration like '30s', '5m', '1h'",
            )
        }
    }

    /// Parse as a list (comma-separated)
    ///
    /// Trims whitespace from each element.
    pub fn parse_list(&self) -> Result<Vec<String>, ConfigError> {
        let raw = self.require_raw()?;
        Ok(raw
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect())
    }

    /// Parse as a list with default
    pub fn parse_list_or(&self, default: Vec<String>) -> Result<Vec<String>, ConfigError> {
        match self.raw() {
            Some(_) => self.parse_list(),
            None => Ok(default),
        }
    }

    /// Parse as a PathBuf
    pub fn parse_path(&self) -> Result<PathBuf, ConfigError> {
        let raw = self.require_raw()?;
        Ok(PathBuf::from(raw))
    }

    /// Parse as PathBuf with default
    pub fn parse_path_or(&self, default: impl Into<PathBuf>) -> Result<PathBuf, ConfigError> {
        match self.raw() {
            Some(raw) => Ok(PathBuf::from(raw)),
            None => Ok(default.into()),
        }
    }

    /// Parse as an IP address
    pub fn parse_ip(&self) -> Result<IpAddr, ConfigError> {
        self.parse()
    }

    /// Parse as a socket address (IP:port)
    pub fn parse_socket_addr(&self) -> Result<SocketAddr, ConfigError> {
        self.parse()
    }

    // ========================================================================
    // Validation
    // ========================================================================

    /// Validate that the value is not empty
    pub fn validate_not_empty(&self) -> Result<&Self, ConfigError> {
        if let Some(raw) = self.raw()
            && raw.trim().is_empty()
        {
            return Err(ConfigError::validation(
                &self.name,
                "not_empty",
                "value cannot be empty",
            ));
        }
        Ok(self)
    }

    /// Validate that the value matches a pattern
    pub fn validate_pattern(&self, pattern: &str) -> Result<&Self, ConfigError> {
        if let Some(raw) = self.raw() {
            let re = regex::Regex::new(pattern).map_err(|e| {
                ConfigError::validation(&self.name, "pattern", format!("invalid regex: {}", e))
            })?;
            if !re.is_match(raw) {
                return Err(ConfigError::validation(
                    &self.name,
                    "pattern",
                    format!("value does not match pattern '{}'", pattern),
                ));
            }
        }
        Ok(self)
    }

    /// Validate that the value length is within bounds
    pub fn validate_length(&self, min: usize, max: usize) -> Result<&Self, ConfigError> {
        if let Some(raw) = self.raw() {
            let len = raw.len();
            if len < min || len > max {
                return Err(ConfigError::validation(
                    &self.name,
                    "length",
                    format!("length {} not in range [{}, {}]", len, min, max),
                ));
            }
        }
        Ok(self)
    }

    /// Validate that a numeric value is within range
    pub fn validate_range<T>(&self, min: T, max: T) -> Result<&Self, ConfigError>
    where
        T: FromStr + PartialOrd + std::fmt::Display,
        T::Err: std::fmt::Display,
    {
        if let Some(raw) = self.raw() {
            let value: T = raw.parse().map_err(|e: T::Err| {
                if self.is_secret {
                    ConfigError::parse_secret(&self.name, std::any::type_name::<T>(), e.to_string())
                } else {
                    ConfigError::parse(&self.name, raw, std::any::type_name::<T>(), e.to_string())
                }
            })?;
            if value < min || value > max {
                return Err(ConfigError::validation(
                    &self.name,
                    "range",
                    format!("value not in range [{}, {}]", min, max),
                ));
            }
        }
        Ok(self)
    }

    /// Validate that the value is one of the allowed options
    pub fn validate_one_of(&self, options: &[&str]) -> Result<&Self, ConfigError> {
        if let Some(raw) = self.raw()
            && !options.contains(&raw)
        {
            return Err(ConfigError::validation(
                &self.name,
                "one_of",
                format!("value must be one of: {}", options.join(", ")),
            ));
        }
        Ok(self)
    }

    // ========================================================================
    // TypedSecret Integration
    // ========================================================================

    /// Convert to a TypedSecret with explicit type and classification
    ///
    /// Creates a `TypedSecret<String>` with NIST-compliant metadata for
    /// audit trails and lifecycle management.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use octarine::runtime::config::{ConfigBuilder, SecretType, Classification};
    ///
    /// let secret = ConfigBuilder::new()
    ///     .with_prefix("APP")
    ///     .get_secret("API_KEY")?
    ///     .into_typed_secret(SecretType::ApiKey, Classification::Confidential)?;
    ///
    /// // Access with audit trail
    /// let value = secret.expose_secret_audited("api_call");
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::Missing` if the value is not set.
    pub fn into_typed_secret(
        self,
        secret_type: SecretType,
        classification: Classification,
    ) -> Result<TypedSecret<String>, ConfigError> {
        let value = self.require_raw()?.to_string();

        Ok(TypedSecret::new(value)
            .with_type(secret_type)
            .with_classification(classification)
            .with_id(&self.name))
    }

    /// Convert to a TypedSecret with auto-detected type via PII scanner
    ///
    /// Automatically detects the secret type (API key, JWT, password, etc.)
    /// by scanning the value with the PII detection system.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use octarine::runtime::config::ConfigBuilder;
    ///
    /// // JWT token is auto-detected as AuthToken
    /// std::env::set_var("APP_TOKEN", "eyJhbGciOiJIUzI1NiIs...");
    /// let secret = ConfigBuilder::new()
    ///     .with_prefix("APP")
    ///     .get_secret("TOKEN")?
    ///     .into_auto_secret()?;
    ///
    /// assert_eq!(secret.secret_type(), &SecretType::AuthToken);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `ConfigError::Missing` if the value is not set.
    pub fn into_auto_secret(self) -> Result<TypedSecret<String>, ConfigError> {
        let value = self.require_raw()?;
        let (secret_type, classification) = detect_secret_type(value);

        Ok(TypedSecret::new(value.to_string())
            .with_type(secret_type)
            .with_classification(classification)
            .with_id(&self.name))
    }
}

/// Auto-detect secret type from value using PII scanner
///
/// Maps detected PII types to SecretType with appropriate classification.
fn detect_secret_type(value: &str) -> (SecretType, Classification) {
    let pii_types = scan_for_pii(value);

    // Map first secret-type PII to SecretType
    for pii_type in pii_types {
        if !pii_type.is_secret() {
            continue;
        }
        let secret_type = match pii_type {
            PiiType::ApiKey => SecretType::ApiKey,
            PiiType::Password | PiiType::Passphrase => SecretType::Password,
            PiiType::Jwt | PiiType::OAuthToken | PiiType::BearerToken | PiiType::SessionId => {
                SecretType::AuthToken
            }
            PiiType::SshKey => SecretType::SshKey,
            PiiType::UrlWithCredentials => SecretType::DatabaseCredential,
            PiiType::OnePasswordToken | PiiType::OnePasswordVaultRef => SecretType::ApiKey,
            _ => SecretType::Generic,
        };
        // Get classification before moving secret_type
        let classification = secret_type.minimum_classification();
        return (secret_type, classification);
    }

    // Default for unrecognized secrets
    (SecretType::Generic, Classification::Confidential)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_parse_string() {
        let value = ConfigValue::new("TEST", Some("hello".to_string()), false);
        let result: String = value.parse().unwrap();
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_parse_integer() {
        let value = ConfigValue::new("PORT", Some("8080".to_string()), false);
        let result: u16 = value.parse().unwrap();
        assert_eq!(result, 8080);
    }

    #[test]
    fn test_parse_with_default() {
        let value = ConfigValue::new("PORT", None, false).default("3000");
        let result: u16 = value.parse().unwrap();
        assert_eq!(result, 3000);
    }

    #[test]
    fn test_parse_missing() {
        let value = ConfigValue::new("MISSING", None, false);
        let result: Result<u16, _> = value.parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_bool_true() {
        for s in &["true", "TRUE", "yes", "YES", "1", "on", "ON"] {
            let value = ConfigValue::new("FLAG", Some(s.to_string()), false);
            assert!(value.parse_bool().unwrap(), "failed for '{}'", s);
        }
    }

    #[test]
    fn test_parse_bool_false() {
        for s in &["false", "FALSE", "no", "NO", "0", "off", "OFF"] {
            let value = ConfigValue::new("FLAG", Some(s.to_string()), false);
            assert!(!value.parse_bool().unwrap(), "failed for '{}'", s);
        }
    }

    #[test]
    fn test_parse_duration_seconds() {
        let value = ConfigValue::new("TIMEOUT", Some("30".to_string()), false);
        assert_eq!(value.parse_duration().unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn test_parse_duration_with_suffix() {
        let cases = [
            ("100ms", Duration::from_millis(100)),
            ("30s", Duration::from_secs(30)),
            ("5m", Duration::from_secs(300)),
            ("1h", Duration::from_secs(3600)),
            ("2d", Duration::from_secs(172800)),
        ];
        for (input, expected) in cases {
            let value = ConfigValue::new("DUR", Some(input.to_string()), false);
            assert_eq!(
                value.parse_duration().unwrap(),
                expected,
                "failed for '{}'",
                input
            );
        }
    }

    #[test]
    fn test_parse_list() {
        let value = ConfigValue::new("HOSTS", Some("a, b, c".to_string()), false);
        let result = value.parse_list().unwrap();
        assert_eq!(result, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_parse_list_empty_elements() {
        let value = ConfigValue::new("LIST", Some("a,,b".to_string()), false);
        let result = value.parse_list().unwrap();
        assert_eq!(result, vec!["a", "b"]);
    }

    #[test]
    fn test_validate_not_empty() {
        let value = ConfigValue::new("NAME", Some("test".to_string()), false);
        assert!(value.validate_not_empty().is_ok());

        let empty = ConfigValue::new("NAME", Some("  ".to_string()), false);
        assert!(empty.validate_not_empty().is_err());
    }

    #[test]
    fn test_validate_pattern() {
        let value = ConfigValue::new("EMAIL", Some("test@example.com".to_string()), false);
        assert!(value.validate_pattern(r"^[^@]+@[^@]+\.[^@]+$").is_ok());

        let invalid = ConfigValue::new("EMAIL", Some("not-an-email".to_string()), false);
        assert!(invalid.validate_pattern(r"^[^@]+@[^@]+\.[^@]+$").is_err());
    }

    #[test]
    fn test_validate_length() {
        let value = ConfigValue::new("CODE", Some("ABC123".to_string()), false);
        assert!(value.validate_length(1, 10).is_ok());
        assert!(value.validate_length(10, 20).is_err());
    }

    #[test]
    fn test_validate_range() {
        let value = ConfigValue::new("PORT", Some("8080".to_string()), false);
        assert!(value.validate_range(1u16, 65535u16).is_ok());
        assert!(value.validate_range(1u16, 1000u16).is_err());
    }

    #[test]
    fn test_validate_one_of() {
        let value = ConfigValue::new("ENV", Some("production".to_string()), false);
        assert!(
            value
                .validate_one_of(&["development", "staging", "production"])
                .is_ok()
        );
        assert!(value.validate_one_of(&["development", "staging"]).is_err());
    }

    #[test]
    fn test_secret_masks_value() {
        let value = ConfigValue::new("API_KEY", Some("secret123".to_string()), true);
        let err = value.validate_range(1000i32, 2000i32).unwrap_err();
        let display = format!("{}", err);
        assert!(!display.contains("secret123"));
    }

    #[test]
    fn test_is_set() {
        let with_value = ConfigValue::new("A", Some("x".to_string()), false);
        assert!(with_value.is_set());

        let with_default = ConfigValue::new("B", None, false).default("x");
        assert!(with_default.is_set());

        let empty = ConfigValue::new("C", None, false);
        assert!(!empty.is_set());
    }

    // ========================================================================
    // TypedSecret Integration Tests
    // ========================================================================

    #[test]
    fn test_into_typed_secret_explicit() {
        use crate::crypto::secrets::ExposeSecret;

        let value = ConfigValue::new("APP_API_KEY", Some("sk-12345".to_string()), true);
        let secret = value
            .into_typed_secret(SecretType::ApiKey, Classification::Confidential)
            .unwrap();

        assert_eq!(secret.secret_type(), &SecretType::ApiKey);
        assert_eq!(secret.classification(), Classification::Confidential);
        assert_eq!(secret.expose_secret(), "sk-12345");
    }

    #[test]
    fn test_into_typed_secret_missing() {
        let value = ConfigValue::new("MISSING_KEY", None, true);
        let result = value.into_typed_secret(SecretType::ApiKey, Classification::Confidential);

        assert!(result.is_err());
    }

    #[test]
    fn test_into_auto_secret_generic() {
        use crate::crypto::secrets::ExposeSecret;

        // A generic value that doesn't match known patterns
        let value = ConfigValue::new("MY_SECRET", Some("some-random-value".to_string()), true);
        let secret = value.into_auto_secret().unwrap();

        // Should default to Generic type
        assert_eq!(secret.secret_type(), &SecretType::Generic);
        assert_eq!(secret.classification(), Classification::Confidential);
        assert_eq!(secret.expose_secret(), "some-random-value");
    }

    #[test]
    fn test_into_auto_secret_jwt() {
        use crate::crypto::secrets::ExposeSecret;

        // JWT token pattern - should be detected as AuthToken
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let value = ConfigValue::new("AUTH_TOKEN", Some(jwt.to_string()), true);
        let secret = value.into_auto_secret().unwrap();

        assert_eq!(secret.secret_type(), &SecretType::AuthToken);
        assert_eq!(secret.expose_secret(), jwt);
    }

    #[test]
    fn test_into_auto_secret_missing() {
        let value = ConfigValue::new("MISSING", None, true);
        let result = value.into_auto_secret();

        assert!(result.is_err());
    }

    #[test]
    fn test_detect_secret_type_fallback() {
        // Test the detect_secret_type function with unrecognized input
        let (secret_type, classification) = detect_secret_type("just a plain string");

        assert_eq!(secret_type, SecretType::Generic);
        assert_eq!(classification, Classification::Confidential);
    }
}
