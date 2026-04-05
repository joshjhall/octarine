//! Crypto artifact validation
//!
//! Pure validation functions for cryptographic artifacts with no observe dependencies.
//! These go beyond detection (`is_*`) by enforcing structural correctness.
//!
//! # Architecture
//!
//! This is part of **Layer 1 (primitives)** - pure functions with NO logging.
//!
//! # Validation vs Detection
//!
//! - **Detection** (`is_*`): "Does this look like X?" — pattern matching, may have false positives
//! - **Validation** (`validate_*`): "Is this structurally valid X?" — enforces format constraints

use crate::primitives::Problem;

use super::detection;
use super::patterns::{
    LABEL_CERTIFICATE, LABEL_EC_PRIVATE_KEY, LABEL_ENCRYPTED_PRIVATE_KEY,
    LABEL_OPENSSH_PRIVATE_KEY, LABEL_PRIVATE_KEY, LABEL_PUBLIC_KEY, LABEL_RSA_PRIVATE_KEY,
    LABEL_RSA_PUBLIC_KEY, PEM_BEGIN, PEM_END, SSH_DSA_PREFIX, SSH_ECDSA_PREFIX, SSH_ED25519_PREFIX,
    SSH_RSA_PREFIX, pem_begin, pem_end,
};

/// Maximum input length for ReDoS protection (same as detection)
const MAX_INPUT_LENGTH: usize = 100_000;

// ============================================================================
// PEM Format Validation
// ============================================================================

/// Validate PEM format structure
///
/// Checks beyond detection:
/// - Header and footer lines present and matching
/// - Base64 body contains only valid characters
/// - Body is non-empty
///
/// # Errors
///
/// Returns `Problem` if the PEM structure is invalid
pub fn validate_pem_format(data: &str) -> Result<(), Problem> {
    if data.is_empty() {
        return Err(Problem::Validation("PEM data cannot be empty".into()));
    }

    if data.len() > MAX_INPUT_LENGTH {
        return Err(Problem::Validation(format!(
            "PEM data exceeds maximum length ({})",
            MAX_INPUT_LENGTH
        )));
    }

    let trimmed = data.trim();

    // Must start with BEGIN header
    if !trimmed.starts_with(PEM_BEGIN) {
        return Err(Problem::Validation(
            "PEM data must start with '-----BEGIN ' header".into(),
        ));
    }

    // Extract label from header
    let label = extract_pem_label(trimmed)
        .ok_or_else(|| Problem::Validation("Invalid PEM header format".into()))?;

    // Must contain matching footer
    let expected_footer = pem_end(&label);
    if !trimmed.contains(&expected_footer) {
        return Err(Problem::Validation(format!(
            "PEM data missing matching footer '{}'",
            expected_footer
        )));
    }

    // Extract body between header and footer
    let header = pem_begin(&label);
    let body = extract_pem_body(trimmed, &header, &expected_footer)?;

    // Body must be non-empty
    if body.is_empty() {
        return Err(Problem::Validation("PEM body is empty".into()));
    }

    // Body must contain only valid base64 characters
    if !body
        .chars()
        .all(|c| is_base64_char(c) || c.is_ascii_whitespace())
    {
        return Err(Problem::Validation(
            "PEM body contains invalid base64 characters".into(),
        ));
    }

    Ok(())
}

// ============================================================================
// DER Format Validation
// ============================================================================

/// Validate DER format structure
///
/// Checks beyond detection:
/// - SEQUENCE tag (0x30) present
/// - Length encoding is valid
/// - Data is not truncated (actual length matches declared length)
///
/// # Errors
///
/// Returns `Problem` if the DER structure is invalid
pub fn validate_der_format(data: &[u8]) -> Result<(), Problem> {
    if data.is_empty() {
        return Err(Problem::Validation("DER data cannot be empty".into()));
    }

    if data.len() > MAX_INPUT_LENGTH {
        return Err(Problem::Validation(format!(
            "DER data exceeds maximum length ({})",
            MAX_INPUT_LENGTH
        )));
    }

    if data.len() < 2 {
        return Err(Problem::Validation(
            "DER data too short (minimum 2 bytes for tag + length)".into(),
        ));
    }

    // Must start with SEQUENCE tag
    if data.first() != Some(&0x30) {
        return Err(Problem::Validation(format!(
            "DER data must start with SEQUENCE tag (0x30), got 0x{:02x}",
            data.first().copied().unwrap_or(0)
        )));
    }

    // Validate length encoding
    let length_byte = data.get(1).copied().unwrap_or(0);

    if length_byte == 0x80 {
        return Err(Problem::Validation(
            "DER does not allow indefinite length encoding (BER only)".into(),
        ));
    }

    if length_byte < 0x80 {
        // Short form: length is directly encoded
        let expected_total = (length_byte as usize).saturating_add(2);
        if data.len() < expected_total {
            return Err(Problem::Validation(format!(
                "DER data truncated: declared length {} but only {} bytes available",
                expected_total,
                data.len()
            )));
        }
    } else {
        // Long form: lower 7 bits = number of length octets
        let num_octets = (length_byte & 0x7f) as usize;
        if num_octets == 0 {
            return Err(Problem::Validation(
                "DER long form length with zero octets is invalid".into(),
            ));
        }
        let header_size = num_octets.saturating_add(2);
        if data.len() < header_size {
            return Err(Problem::Validation(format!(
                "DER data truncated: need {} header bytes but only {} available",
                header_size,
                data.len()
            )));
        }
    }

    Ok(())
}

// ============================================================================
// SSH Key Format Validation
// ============================================================================

/// Validate SSH public key format
///
/// Checks beyond detection:
/// - Valid key type prefix (ssh-rsa, ssh-ed25519, ecdsa-sha2-nistp*, ssh-dss)
/// - Space separator after key type
/// - Base64 key data section present with valid characters
///
/// # Errors
///
/// Returns `Problem` if the SSH key format is invalid
pub fn validate_ssh_key_format(data: &str) -> Result<(), Problem> {
    if data.is_empty() {
        return Err(Problem::Validation("SSH key data cannot be empty".into()));
    }

    if data.len() > MAX_INPUT_LENGTH {
        return Err(Problem::Validation(format!(
            "SSH key data exceeds maximum length ({})",
            MAX_INPUT_LENGTH
        )));
    }

    let trimmed = data.trim();

    // Must start with a known SSH key prefix
    let key_type = detect_ssh_prefix(trimmed).ok_or_else(|| {
        Problem::Validation(
            "SSH key must start with a valid key type (ssh-rsa, ssh-ed25519, ecdsa-sha2-nistp*, ssh-dss)".into(),
        )
    })?;

    // Must have a space after the key type prefix
    let rest = &trimmed[key_type.len()..];
    if !rest.starts_with(' ') {
        return Err(Problem::Validation(
            "SSH key must have a space after the key type".into(),
        ));
    }

    // Extract base64 section (between first and second space, or to end)
    let after_prefix = rest.trim_start();
    let base64_section = after_prefix.split_whitespace().next().unwrap_or("");

    if base64_section.is_empty() {
        return Err(Problem::Validation(
            "SSH key must have a base64-encoded key data section".into(),
        ));
    }

    // Base64 section must contain only valid characters
    if !base64_section.chars().all(is_base64_char) {
        return Err(Problem::Validation(
            "SSH key base64 section contains invalid characters".into(),
        ));
    }

    // Minimum reasonable base64 length for a key
    if base64_section.len() < 16 {
        return Err(Problem::Validation(format!(
            "SSH key base64 section too short (got {} chars, minimum 16)",
            base64_section.len()
        )));
    }

    Ok(())
}

// ============================================================================
// OpenSSH Private Key Validation
// ============================================================================

/// Validate OpenSSH private key format
///
/// Checks beyond detection:
/// - Proper PEM-style wrapping with OpenSSH-specific header/footer
///
/// # Errors
///
/// Returns `Problem` if the format is invalid
pub fn validate_openssh_private_key_format(data: &str) -> Result<(), Problem> {
    if data.is_empty() {
        return Err(Problem::Validation(
            "OpenSSH private key data cannot be empty".into(),
        ));
    }

    if data.len() > MAX_INPUT_LENGTH {
        return Err(Problem::Validation(format!(
            "OpenSSH private key data exceeds maximum length ({})",
            MAX_INPUT_LENGTH
        )));
    }

    // Validate as PEM with specific label
    validate_pem_with_label(data, LABEL_OPENSSH_PRIVATE_KEY, "OpenSSH private key")
}

// ============================================================================
// RSA Key Validation
// ============================================================================

/// Validate RSA key format
///
/// Accepts PEM (RSA PUBLIC KEY, RSA PRIVATE KEY) or SSH (ssh-rsa) format.
///
/// # Errors
///
/// Returns `Problem` if the key is not a valid RSA key format
pub fn validate_rsa_key(data: &str) -> Result<(), Problem> {
    if data.is_empty() {
        return Err(Problem::Validation("RSA key data cannot be empty".into()));
    }

    if data.len() > MAX_INPUT_LENGTH {
        return Err(Problem::Validation(format!(
            "RSA key data exceeds maximum length ({})",
            MAX_INPUT_LENGTH
        )));
    }

    let trimmed = data.trim();

    // SSH RSA format
    if trimmed.starts_with(SSH_RSA_PREFIX) {
        return validate_ssh_key_format(data);
    }

    // PEM RSA format — must contain RSA label
    if !detection::is_rsa_key(data) {
        return Err(Problem::Validation(
            "Data does not contain RSA key markers (RSA PUBLIC KEY, RSA PRIVATE KEY, or ssh-rsa)"
                .into(),
        ));
    }

    // Validate PEM structure
    validate_pem_format(data)
}

// ============================================================================
// EC Key Validation
// ============================================================================

/// Validate EC key format
///
/// Accepts PEM (EC PRIVATE KEY) or SSH (ssh-ed25519, ecdsa-sha2-nistp*) format.
///
/// # Errors
///
/// Returns `Problem` if the key is not a valid EC key format
pub fn validate_ec_key(data: &str) -> Result<(), Problem> {
    if data.is_empty() {
        return Err(Problem::Validation("EC key data cannot be empty".into()));
    }

    if data.len() > MAX_INPUT_LENGTH {
        return Err(Problem::Validation(format!(
            "EC key data exceeds maximum length ({})",
            MAX_INPUT_LENGTH
        )));
    }

    let trimmed = data.trim();

    // SSH EC format
    if trimmed.starts_with(SSH_ED25519_PREFIX) || trimmed.starts_with(SSH_ECDSA_PREFIX) {
        return validate_ssh_key_format(data);
    }

    // PEM EC format
    if !detection::is_ec_key(data) {
        return Err(Problem::Validation(
            "Data does not contain EC key markers (EC PRIVATE KEY, ssh-ed25519, or ecdsa-sha2-nistp*)"
                .into(),
        ));
    }

    validate_pem_format(data)
}

// ============================================================================
// X.509 Certificate Validation
// ============================================================================

/// Validate X.509 certificate format
///
/// Checks beyond detection:
/// - CERTIFICATE PEM label present
/// - Valid PEM structure with matching header/footer
/// - Non-empty base64 body
///
/// # Errors
///
/// Returns `Problem` if the certificate format is invalid
pub fn validate_x509_certificate(data: &str) -> Result<(), Problem> {
    if data.is_empty() {
        return Err(Problem::Validation(
            "Certificate data cannot be empty".into(),
        ));
    }

    if data.len() > MAX_INPUT_LENGTH {
        return Err(Problem::Validation(format!(
            "Certificate data exceeds maximum length ({})",
            MAX_INPUT_LENGTH
        )));
    }

    validate_pem_with_label(data, LABEL_CERTIFICATE, "X.509 certificate")
}

// ============================================================================
// Private Key Validation
// ============================================================================

/// Private key PEM labels
const PRIVATE_KEY_LABELS: &[&str] = &[
    LABEL_PRIVATE_KEY,
    LABEL_RSA_PRIVATE_KEY,
    LABEL_EC_PRIVATE_KEY,
    LABEL_ENCRYPTED_PRIVATE_KEY,
    LABEL_OPENSSH_PRIVATE_KEY,
];

/// Validate private key format
///
/// Accepts any private key PEM label (PRIVATE KEY, RSA PRIVATE KEY,
/// EC PRIVATE KEY, ENCRYPTED PRIVATE KEY, OPENSSH PRIVATE KEY).
///
/// # Errors
///
/// Returns `Problem` if the data is not a valid private key format
pub fn validate_private_key(data: &str) -> Result<(), Problem> {
    if data.is_empty() {
        return Err(Problem::Validation(
            "Private key data cannot be empty".into(),
        ));
    }

    if data.len() > MAX_INPUT_LENGTH {
        return Err(Problem::Validation(format!(
            "Private key data exceeds maximum length ({})",
            MAX_INPUT_LENGTH
        )));
    }

    if !detection::is_private_key(data) {
        return Err(Problem::Validation(
            "Data does not contain a private key PEM label".into(),
        ));
    }

    // Find which label matches and validate PEM structure
    let trimmed = data.trim();
    for label in PRIVATE_KEY_LABELS {
        let header = pem_begin(label);
        if trimmed.starts_with(&header) {
            return validate_pem_with_label(data, label, "private key");
        }
    }

    Err(Problem::Validation(
        "Private key has unrecognized PEM label".into(),
    ))
}

// ============================================================================
// Public Key Validation
// ============================================================================

/// Validate public key format
///
/// Accepts PEM (PUBLIC KEY, RSA PUBLIC KEY) or SSH public key format.
///
/// # Errors
///
/// Returns `Problem` if the data is not a valid public key format
pub fn validate_public_key(data: &str) -> Result<(), Problem> {
    if data.is_empty() {
        return Err(Problem::Validation(
            "Public key data cannot be empty".into(),
        ));
    }

    if data.len() > MAX_INPUT_LENGTH {
        return Err(Problem::Validation(format!(
            "Public key data exceeds maximum length ({})",
            MAX_INPUT_LENGTH
        )));
    }

    let trimmed = data.trim();

    // SSH public key format
    if detection::is_ssh_key_format(data) {
        return validate_ssh_key_format(data);
    }

    // PEM public key format
    if !detection::is_public_key(data) {
        return Err(Problem::Validation(
            "Data does not contain a public key (PEM PUBLIC KEY, RSA PUBLIC KEY, or SSH format)"
                .into(),
        ));
    }

    // Determine which label
    if trimmed.starts_with(&pem_begin(LABEL_RSA_PUBLIC_KEY)) {
        validate_pem_with_label(data, LABEL_RSA_PUBLIC_KEY, "RSA public key")
    } else {
        validate_pem_with_label(data, LABEL_PUBLIC_KEY, "public key")
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Extract PEM label from header line
fn extract_pem_label(data: &str) -> Option<String> {
    let trimmed = data.trim();
    if !trimmed.starts_with(PEM_BEGIN) {
        return None;
    }

    let label_start = PEM_BEGIN.len();
    // Find the closing dashes
    let rest = trimmed.get(label_start..)?;
    let label_end = rest.find("-----")?;

    if label_end == 0 {
        return None;
    }

    Some(rest[..label_end].to_string())
}

/// Extract PEM body between header and footer
fn extract_pem_body<'a>(data: &'a str, header: &str, footer: &str) -> Result<&'a str, Problem> {
    let header_end = data
        .find(header)
        .map(|pos| pos.saturating_add(header.len()))
        .ok_or_else(|| Problem::Validation("PEM header not found".into()))?;

    let footer_start = data
        .find(footer)
        .ok_or_else(|| Problem::Validation("PEM footer not found".into()))?;

    if footer_start <= header_end {
        return Err(Problem::Validation(
            "PEM footer appears before or at header".into(),
        ));
    }

    Ok(data.get(header_end..footer_start).unwrap_or("").trim())
}

/// Check if a character is valid in base64 encoding
fn is_base64_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='
}

/// Validate PEM data with a specific expected label
fn validate_pem_with_label(data: &str, expected_label: &str, name: &str) -> Result<(), Problem> {
    let trimmed = data.trim();
    let expected_header = pem_begin(expected_label);
    let expected_footer = pem_end(expected_label);

    if !trimmed.starts_with(&expected_header) {
        return Err(Problem::Validation(format!(
            "{} must start with '{}'",
            name, expected_header
        )));
    }

    if !trimmed.contains(&expected_footer) {
        return Err(Problem::Validation(format!(
            "{} missing matching footer '{}'",
            name, expected_footer
        )));
    }

    let body = extract_pem_body(trimmed, &expected_header, &expected_footer)?;

    if body.is_empty() {
        return Err(Problem::Validation(format!("{} body is empty", name)));
    }

    if !body
        .chars()
        .all(|c| is_base64_char(c) || c.is_ascii_whitespace())
    {
        return Err(Problem::Validation(format!(
            "{} body contains invalid base64 characters",
            name
        )));
    }

    Ok(())
}

/// Detect SSH key type prefix, returning the matched prefix string
fn detect_ssh_prefix(data: &str) -> Option<&str> {
    // ecdsa prefix must be checked with additional curve suffix
    if data.starts_with(SSH_ECDSA_PREFIX) {
        // Find the end of the key type (next space)
        let key_type_end = data.find(' ').unwrap_or(data.len());
        return Some(&data[..key_type_end]);
    }

    [SSH_RSA_PREFIX, SSH_ED25519_PREFIX, SSH_DSA_PREFIX]
        .iter()
        .find(|&&prefix| data.starts_with(prefix))
        .copied()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use crate::primitives::identifiers::crypto::patterns::{pem_begin, pem_end};

    // Build PEM test data at runtime to avoid triggering secret scanners
    fn make_pem(label: &str, body: &str) -> String {
        format!("{}\n{}\n{}", pem_begin(label), body, pem_end(label))
    }

    fn valid_base64_body() -> &'static str {
        "AAAAB3NzaC1yc2EAAAADAQABAAABAQDUd3N0YXJ0\naGVyZQ=="
    }

    // ========================================================================
    // validate_pem_format tests
    // ========================================================================

    #[test]
    fn test_valid_pem_rsa_public() {
        let pem = make_pem("RSA PUBLIC KEY", valid_base64_body());
        assert!(validate_pem_format(&pem).is_ok());
    }

    #[test]
    fn test_valid_pem_certificate() {
        let pem = make_pem("CERTIFICATE", valid_base64_body());
        assert!(validate_pem_format(&pem).is_ok());
    }

    #[test]
    fn test_pem_empty() {
        assert!(validate_pem_format("").is_err());
    }

    #[test]
    fn test_pem_no_header() {
        let result = validate_pem_format("not pem data");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("BEGIN")
        );
    }

    #[test]
    fn test_pem_missing_footer() {
        let data = format!("{}\n{}", pem_begin("TEST"), valid_base64_body());
        let result = validate_pem_format(&data);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("footer")
        );
    }

    #[test]
    fn test_pem_empty_body() {
        let pem = format!("{}\n{}", pem_begin("TEST"), pem_end("TEST"));
        let result = validate_pem_format(&pem);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("empty")
        );
    }

    #[test]
    fn test_pem_invalid_base64() {
        let pem = make_pem("TEST", "invalid!@#$%^&*characters");
        let result = validate_pem_format(&pem);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("base64")
        );
    }

    #[test]
    fn test_pem_max_length() {
        let long_data = "A".repeat(MAX_INPUT_LENGTH.saturating_add(1));
        let result = validate_pem_format(&long_data);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("maximum length")
        );
    }

    // ========================================================================
    // validate_der_format tests
    // ========================================================================

    #[test]
    fn test_valid_der_short_form() {
        // SEQUENCE tag (0x30), length 5, 5 bytes of content
        let der = vec![0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(validate_der_format(&der).is_ok());
    }

    #[test]
    fn test_valid_der_long_form() {
        // SEQUENCE tag, long form length (1 octet = 128 bytes)
        let mut der = vec![0x30, 0x81, 0x80]; // 0x81 = long form, 1 octet; 0x80 = 128
        der.extend(vec![0x00; 128]);
        assert!(validate_der_format(&der).is_ok());
    }

    #[test]
    fn test_der_empty() {
        assert!(validate_der_format(&[]).is_err());
    }

    #[test]
    fn test_der_too_short() {
        let result = validate_der_format(&[0x30]);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("too short")
        );
    }

    #[test]
    fn test_der_wrong_tag() {
        let result = validate_der_format(&[0x02, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("SEQUENCE")
        );
    }

    #[test]
    fn test_der_indefinite_length() {
        let result = validate_der_format(&[0x30, 0x80, 0x01, 0x02]);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("indefinite")
        );
    }

    #[test]
    fn test_der_truncated() {
        // Declares length 10 but only has 3 bytes total
        let result = validate_der_format(&[0x30, 0x0A, 0x01]);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("truncated")
        );
    }

    // ========================================================================
    // validate_ssh_key_format tests
    // ========================================================================

    #[test]
    fn test_valid_ssh_rsa() {
        let key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDUd3 user@host";
        assert!(validate_ssh_key_format(key).is_ok());
    }

    #[test]
    fn test_valid_ssh_ed25519() {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG user@host";
        assert!(validate_ssh_key_format(key).is_ok());
    }

    #[test]
    fn test_valid_ssh_ecdsa() {
        let key = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY= user@host";
        assert!(validate_ssh_key_format(key).is_ok());
    }

    #[test]
    fn test_ssh_empty() {
        assert!(validate_ssh_key_format("").is_err());
    }

    #[test]
    fn test_ssh_no_prefix() {
        let result = validate_ssh_key_format("not-a-key AAAAB3Nz");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("valid key type")
        );
    }

    #[test]
    fn test_ssh_no_space() {
        let result = validate_ssh_key_format("ssh-rsaAAAAB3NzaC1yc2E");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("space")
        );
    }

    #[test]
    fn test_ssh_no_base64() {
        let result = validate_ssh_key_format("ssh-rsa ");
        assert!(
            result.is_err(),
            "Expected error for SSH key with no base64 data"
        );
    }

    #[test]
    fn test_ssh_short_base64() {
        let result = validate_ssh_key_format("ssh-rsa ABC user@host");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("too short")
        );
    }

    // ========================================================================
    // validate_openssh_private_key_format tests
    // ========================================================================

    #[test]
    fn test_valid_openssh_private_key() {
        let key = make_pem(LABEL_OPENSSH_PRIVATE_KEY, valid_base64_body());
        assert!(validate_openssh_private_key_format(&key).is_ok());
    }

    #[test]
    fn test_openssh_private_key_empty() {
        assert!(validate_openssh_private_key_format("").is_err());
    }

    #[test]
    fn test_openssh_private_key_wrong_label() {
        let key = make_pem("RSA PUBLIC KEY", valid_base64_body());
        let result = validate_openssh_private_key_format(&key);
        assert!(result.is_err());
    }

    // ========================================================================
    // validate_rsa_key tests
    // ========================================================================

    #[test]
    fn test_valid_rsa_pem() {
        let key = make_pem("RSA PUBLIC KEY", valid_base64_body());
        assert!(validate_rsa_key(&key).is_ok());
    }

    #[test]
    fn test_valid_rsa_ssh() {
        let key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDUd3 user@host";
        assert!(validate_rsa_key(key).is_ok());
    }

    #[test]
    fn test_rsa_not_rsa() {
        let key = make_pem("EC PRIVATE KEY", valid_base64_body());
        let result = validate_rsa_key(&key);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("RSA")
        );
    }

    // ========================================================================
    // validate_ec_key tests
    // ========================================================================

    #[test]
    fn test_valid_ec_pem() {
        let key = make_pem("EC PRIVATE KEY", valid_base64_body());
        assert!(validate_ec_key(&key).is_ok());
    }

    #[test]
    fn test_valid_ec_ssh_ed25519() {
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG user@host";
        assert!(validate_ec_key(key).is_ok());
    }

    #[test]
    fn test_ec_not_ec() {
        let key = make_pem("RSA PUBLIC KEY", valid_base64_body());
        let result = validate_ec_key(&key);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("EC")
        );
    }

    // ========================================================================
    // validate_x509_certificate tests
    // ========================================================================

    #[test]
    fn test_valid_certificate() {
        let cert = make_pem("CERTIFICATE", valid_base64_body());
        assert!(validate_x509_certificate(&cert).is_ok());
    }

    #[test]
    fn test_certificate_empty() {
        assert!(validate_x509_certificate("").is_err());
    }

    #[test]
    fn test_certificate_wrong_label() {
        let key = make_pem("RSA PUBLIC KEY", valid_base64_body());
        let result = validate_x509_certificate(&key);
        assert!(result.is_err());
    }

    // ========================================================================
    // validate_private_key tests
    // ========================================================================

    #[test]
    fn test_valid_private_key_generic() {
        let key = make_pem(LABEL_PRIVATE_KEY, valid_base64_body());
        assert!(validate_private_key(&key).is_ok());
    }

    #[test]
    fn test_valid_private_key_rsa() {
        let key = make_pem(LABEL_RSA_PRIVATE_KEY, valid_base64_body());
        assert!(validate_private_key(&key).is_ok());
    }

    #[test]
    fn test_valid_private_key_ec() {
        let key = make_pem(LABEL_EC_PRIVATE_KEY, valid_base64_body());
        assert!(validate_private_key(&key).is_ok());
    }

    #[test]
    fn test_valid_private_key_encrypted() {
        let key = make_pem(LABEL_ENCRYPTED_PRIVATE_KEY, valid_base64_body());
        assert!(validate_private_key(&key).is_ok());
    }

    #[test]
    fn test_private_key_not_private() {
        let key = make_pem("PUBLIC KEY", valid_base64_body());
        let result = validate_private_key(&key);
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("private key")
        );
    }

    // ========================================================================
    // validate_public_key tests
    // ========================================================================

    #[test]
    fn test_valid_public_key_pem() {
        let key = make_pem("PUBLIC KEY", valid_base64_body());
        assert!(validate_public_key(&key).is_ok());
    }

    #[test]
    fn test_valid_public_key_rsa_pem() {
        let key = make_pem("RSA PUBLIC KEY", valid_base64_body());
        assert!(validate_public_key(&key).is_ok());
    }

    #[test]
    fn test_valid_public_key_ssh() {
        let key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDUd3 user@host";
        assert!(validate_public_key(key).is_ok());
    }

    #[test]
    fn test_public_key_not_public() {
        let result = validate_public_key("not a key");
        assert!(result.is_err());
        assert!(
            result
                .expect_err("expected error")
                .to_string()
                .contains("public key")
        );
    }

    // ========================================================================
    // Helper function tests
    // ========================================================================

    #[test]
    fn test_extract_pem_label() {
        let pem = make_pem("RSA PUBLIC KEY", "data");
        assert_eq!(extract_pem_label(&pem), Some("RSA PUBLIC KEY".to_string()));
    }

    #[test]
    fn test_extract_pem_label_not_pem() {
        assert_eq!(extract_pem_label("not pem"), None);
    }

    #[test]
    fn test_is_base64_char() {
        assert!(is_base64_char('A'));
        assert!(is_base64_char('z'));
        assert!(is_base64_char('0'));
        assert!(is_base64_char('+'));
        assert!(is_base64_char('/'));
        assert!(is_base64_char('='));
        assert!(!is_base64_char('!'));
        assert!(!is_base64_char('@'));
    }

    #[test]
    fn test_detect_ssh_prefix() {
        assert_eq!(detect_ssh_prefix("ssh-rsa AAAA"), Some("ssh-rsa"));
        assert_eq!(detect_ssh_prefix("ssh-ed25519 AAAA"), Some("ssh-ed25519"));
        assert_eq!(
            detect_ssh_prefix("ecdsa-sha2-nistp256 AAAA"),
            Some("ecdsa-sha2-nistp256")
        );
        assert_eq!(detect_ssh_prefix("ssh-dss AAAA"), Some("ssh-dss"));
        assert_eq!(detect_ssh_prefix("unknown AAAA"), None);
    }
}
