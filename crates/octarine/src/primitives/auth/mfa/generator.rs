//! TOTP generation and verification
//!
//! Core TOTP functionality using the totp-rs crate.

use super::config::TotpConfig;
use crate::primitives::types::Problem;

// ============================================================================
// TOTP Secret
// ============================================================================

/// A TOTP secret key
#[derive(Debug, Clone)]
pub struct TotpSecret {
    /// The raw secret bytes
    secret: Vec<u8>,
    /// Base32-encoded secret (for user display)
    encoded: String,
}

impl TotpSecret {
    /// Create a new TOTP secret from raw bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the secret is too short (< 20 bytes).
    pub fn new(secret: Vec<u8>) -> Result<Self, Problem> {
        if secret.len() < 20 {
            return Err(Problem::Validation(
                "TOTP secret must be at least 20 bytes (160 bits)".to_string(),
            ));
        }

        let encoded = base32_encode(&secret);

        Ok(Self { secret, encoded })
    }

    /// Create from a base32-encoded string
    ///
    /// # Errors
    ///
    /// Returns an error if the string is not valid base32.
    pub fn from_base32(encoded: &str) -> Result<Self, Problem> {
        let secret = base32_decode(encoded)?;
        Self::new(secret)
    }

    /// Get the raw secret bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.secret
    }

    /// Get the base32-encoded secret
    #[must_use]
    pub fn as_base32(&self) -> &str {
        &self.encoded
    }

    /// Get the secret formatted for display (with spaces)
    #[must_use]
    pub fn formatted(&self) -> String {
        // Format as groups of 4 characters
        self.encoded
            .chars()
            .collect::<Vec<_>>()
            .chunks(4)
            .map(|c| c.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join(" ")
    }
}

// ============================================================================
// TOTP Code
// ============================================================================

/// A generated TOTP code
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpCode {
    /// The numeric code
    code: String,
    /// Time step when this code was generated
    time_step: u64,
    /// Valid until this timestamp
    valid_until: u64,
}

impl TotpCode {
    /// Create a new TOTP code
    pub(crate) fn new(code: String, time_step: u64, step_seconds: u64) -> Self {
        #[allow(clippy::arithmetic_side_effects)] // Safe: step * seconds won't overflow
        let valid_until = time_step.saturating_add(1).saturating_mul(step_seconds);
        Self {
            code,
            time_step,
            valid_until,
        }
    }

    /// Get the code as a string
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.code
    }

    /// Get the time step when this code was generated
    #[must_use]
    pub fn time_step(&self) -> u64 {
        self.time_step
    }

    /// Get the timestamp until which this code is valid
    #[must_use]
    pub fn valid_until(&self) -> u64 {
        self.valid_until
    }
}

impl std::fmt::Display for TotpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code)
    }
}

// ============================================================================
// Generation Functions
// ============================================================================

/// Generate a new TOTP secret
///
/// Creates a cryptographically random secret suitable for TOTP authentication.
/// The secret is 32 bytes (256 bits) for strong security.
///
/// # Errors
///
/// Returns an error if random number generation fails.
#[cfg(feature = "auth-totp")]
pub fn generate_totp_secret() -> Result<TotpSecret, Problem> {
    use totp_rs::Secret;

    let secret = Secret::generate_secret();
    let secret_bytes = secret
        .to_bytes()
        .map_err(|e| Problem::OperationFailed(format!("Failed to generate TOTP secret: {e}")))?;

    TotpSecret::new(secret_bytes)
}

/// Stub when feature is not enabled
#[cfg(not(feature = "auth-totp"))]
pub fn generate_totp_secret() -> Result<TotpSecret, Problem> {
    Err(Problem::OperationFailed(
        "TOTP support requires the 'auth-totp' feature".to_string(),
    ))
}

/// Generate a TOTP code for the current time
///
/// # Errors
///
/// Returns an error if code generation fails.
#[cfg(feature = "auth-totp")]
#[allow(clippy::arithmetic_side_effects)] // Safe: dividing time by step
pub fn generate_totp_code(secret: &TotpSecret, config: &TotpConfig) -> Result<TotpCode, Problem> {
    let totp = create_totp(secret, config)?;
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| Problem::OperationFailed(format!("System time error: {e}")))?
        .as_secs();

    let code = totp.generate(time);
    let time_step = time / config.step;

    Ok(TotpCode::new(code, time_step, config.step))
}

/// Verify a TOTP code
///
/// Checks if the provided code is valid for the current time, allowing for
/// the configured time drift (skew).
///
/// # Arguments
///
/// * `code` - The code to verify
/// * `secret` - The TOTP secret
/// * `config` - TOTP configuration
///
/// # Returns
///
/// `Ok(true)` if the code is valid, `Ok(false)` if invalid.
///
/// # Errors
///
/// Returns an error if validation fails due to system error.
#[cfg(feature = "auth-totp")]
pub fn validate_totp_code(
    code: &str,
    secret: &TotpSecret,
    config: &TotpConfig,
) -> Result<bool, Problem> {
    let totp = create_totp(secret, config)?;
    let time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| Problem::OperationFailed(format!("System time error: {e}")))?
        .as_secs();

    Ok(totp.check(code, time))
}

/// Stub when feature is not enabled
#[cfg(not(feature = "auth-totp"))]
pub fn validate_totp_code(
    _code: &str,
    _secret: &TotpSecret,
    _config: &TotpConfig,
) -> Result<bool, Problem> {
    Err(Problem::OperationFailed(
        "TOTP support requires the 'auth-totp' feature".to_string(),
    ))
}

/// Get the otpauth:// URI for QR code generation
///
/// # Arguments
///
/// * `secret` - The TOTP secret
/// * `config` - TOTP configuration
/// * `account_name` - User's account name (e.g., email)
///
/// # Returns
///
/// An otpauth:// URI that can be encoded as a QR code.
#[cfg(feature = "auth-totp")]
pub fn get_otpauth_uri(
    secret: &TotpSecret,
    config: &TotpConfig,
    account_name: &str,
) -> Result<String, Problem> {
    let totp = create_totp_with_account(secret, config, account_name)?;
    Ok(totp.get_url())
}

/// Stub when feature is not enabled
#[cfg(not(feature = "auth-totp"))]
pub fn get_otpauth_uri(
    _secret: &TotpSecret,
    _config: &TotpConfig,
    _account_name: &str,
) -> Result<String, Problem> {
    Err(Problem::OperationFailed(
        "TOTP support requires the 'auth-totp' feature".to_string(),
    ))
}

// ============================================================================
// Private Helpers
// ============================================================================

/// Create a TOTP instance from secret and config
#[cfg(feature = "auth-totp")]
fn create_totp(secret: &TotpSecret, config: &TotpConfig) -> Result<totp_rs::TOTP, Problem> {
    create_totp_with_account(secret, config, "user")
}

/// Create a TOTP instance with account name
#[cfg(feature = "auth-totp")]
fn create_totp_with_account(
    secret: &TotpSecret,
    config: &TotpConfig,
    account_name: &str,
) -> Result<totp_rs::TOTP, Problem> {
    use totp_rs::{Secret, TOTP};

    let secret_obj = Secret::Raw(secret.as_bytes().to_vec());

    TOTP::new(
        config.algorithm.to_totp_rs(),
        config.digits.into(),
        config.skew,
        config.step,
        secret_obj
            .to_bytes()
            .map_err(|e| Problem::OperationFailed(format!("Invalid TOTP secret: {e}")))?,
        Some(config.issuer.clone()),
        account_name.to_string(),
    )
    .map_err(|e| Problem::OperationFailed(format!("Failed to create TOTP: {e}")))
}

/// Base32 encode bytes
#[allow(clippy::arithmetic_side_effects)] // Safe: bit manipulation in base32 encoding
fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::new();
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;

    for &byte in bytes {
        bits = (bits << 8) | u32::from(byte);
        bit_count += 8;

        while bit_count >= 5 {
            bit_count -= 5;
            let index = ((bits >> bit_count) & 0x1F) as usize;
            if let Some(&c) = ALPHABET.get(index) {
                result.push(char::from(c));
            }
        }
    }

    // Handle remaining bits
    if bit_count > 0 {
        let index = ((bits << (5 - bit_count)) & 0x1F) as usize;
        if let Some(&c) = ALPHABET.get(index) {
            result.push(char::from(c));
        }
    }

    // Add padding
    while !result.len().is_multiple_of(8) {
        result.push('=');
    }

    result
}

/// Base32 decode string
#[allow(clippy::arithmetic_side_effects)] // Safe: bit manipulation in base32 decoding
fn base32_decode(encoded: &str) -> Result<Vec<u8>, Problem> {
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = Vec::new();
    let mut bits: u32 = 0;
    let mut bit_count: u32 = 0;

    for c in encoded.chars() {
        if c == '=' {
            break; // Padding
        }
        let c_upper = c.to_ascii_uppercase();
        let value = alphabet
            .find(c_upper)
            .ok_or_else(|| Problem::Validation(format!("Invalid base32 character: {c}")))?;

        bits = (bits << 5) | (value as u32);
        bit_count += 5;

        if bit_count >= 8 {
            bit_count -= 8;
            result.push(((bits >> bit_count) & 0xFF) as u8);
        }
    }

    Ok(result)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_base32_encode_decode() {
        let original = b"Hello, World!";
        let encoded = base32_encode(original);
        let decoded = base32_decode(&encoded).expect("decode should succeed");
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_totp_secret_creation() {
        let secret_bytes = vec![0u8; 32];
        let secret = TotpSecret::new(secret_bytes).expect("secret should be created");
        assert_eq!(secret.as_bytes().len(), 32);
        assert!(!secret.as_base32().is_empty());
    }

    #[test]
    fn test_totp_secret_too_short() {
        let secret_bytes = vec![0u8; 10];
        let result = TotpSecret::new(secret_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_totp_secret_from_base32() {
        // A base32 string that decodes to at least 20 bytes (160 bits)
        let encoded = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"; // 32 chars = 20 bytes
        let secret = TotpSecret::from_base32(encoded).expect("should decode");
        assert!(secret.as_bytes().len() >= 20);
    }

    #[test]
    fn test_totp_secret_formatted() {
        let secret_bytes = vec![0u8; 32];
        let secret = TotpSecret::new(secret_bytes).expect("secret should be created");
        let formatted = secret.formatted();
        assert!(formatted.contains(' '));
    }

    #[test]
    fn test_totp_code_display() {
        let code = TotpCode::new("123456".to_string(), 1000, 30);
        assert_eq!(code.to_string(), "123456");
        assert_eq!(code.as_str(), "123456");
        assert_eq!(code.time_step(), 1000);
    }

    #[cfg(feature = "auth-totp")]
    #[test]
    fn test_generate_totp_secret() {
        let secret = generate_totp_secret().expect("should generate secret");
        assert!(secret.as_bytes().len() >= 20);
    }

    #[cfg(feature = "auth-totp")]
    #[test]
    fn test_generate_and_verify_code() {
        let secret = generate_totp_secret().expect("should generate secret");
        let config = TotpConfig::default();

        let code = generate_totp_code(&secret, &config).expect("should generate code");
        let is_valid = validate_totp_code(code.as_str(), &secret, &config).expect("should verify");

        assert!(is_valid);
    }

    #[cfg(feature = "auth-totp")]
    #[test]
    fn test_verify_invalid_code() {
        let secret = generate_totp_secret().expect("should generate secret");
        let config = TotpConfig::default();

        let is_valid = validate_totp_code("000000", &secret, &config).expect("should verify");
        assert!(!is_valid);
    }

    #[cfg(feature = "auth-totp")]
    #[test]
    fn test_otpauth_uri() {
        let secret = generate_totp_secret().expect("should generate secret");
        let config = TotpConfig::builder().issuer("TestApp").build();

        let uri = get_otpauth_uri(&secret, &config, "testuser").expect("should generate URI");

        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("testuser"));
        assert!(uri.contains("TestApp"));
    }
}
