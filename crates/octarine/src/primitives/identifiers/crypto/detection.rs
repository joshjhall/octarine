//! Crypto artifact detection functions
//!
//! Pure detection functions for identifying cryptographic artifact types.
//! This is the CLASSIFICATION concern - answering "What type is this?"

use super::super::types::IdentifierType;
use super::patterns::{
    LABEL_CERTIFICATE, LABEL_CERTIFICATE_REQUEST, LABEL_EC_PRIVATE_KEY,
    LABEL_ENCRYPTED_PRIVATE_KEY, LABEL_OPENSSH_PRIVATE_KEY, LABEL_PRIVATE_KEY, LABEL_PUBLIC_KEY,
    LABEL_RSA_PRIVATE_KEY, LABEL_RSA_PUBLIC_KEY, LABEL_X509_CRL, PEM_BEGIN, PEM_END,
    SSH_DSA_PREFIX, SSH_ECDSA_PREFIX, SSH_ED25519_PREFIX, SSH_RSA_PREFIX, pem_begin,
};
use super::types::{CryptoDetectionResult, KeyFormat, KeyType, SignatureAlgorithm};

// Maximum input length for ReDoS protection
const MAX_INPUT_LENGTH: usize = 100_000;

// ============================================================================
// Format Detection (is_* functions)
// ============================================================================

/// Check if data appears to be PEM-encoded
///
/// # Arguments
/// * `data` - String data to check
///
/// # Returns
/// `true` if data starts with PEM header
#[must_use]
pub fn is_pem_format(data: &str) -> bool {
    if data.len() > MAX_INPUT_LENGTH {
        return false;
    }
    data.trim().starts_with(PEM_BEGIN)
}

/// Check if data appears to be DER-encoded
///
/// DER data starts with a SEQUENCE tag (0x30) followed by length encoding.
///
/// # Arguments
/// * `data` - Binary data to check
///
/// # Returns
/// `true` if data appears to be DER-encoded
#[must_use]
pub fn is_der_format(data: &[u8]) -> bool {
    if data.len() < 2 || data.len() > MAX_INPUT_LENGTH {
        return false;
    }

    // DER-encoded structures typically start with SEQUENCE (0x30)
    if data.first() != Some(&0x30) {
        return false;
    }

    // Check length encoding is valid
    match data.get(1) {
        Some(&len) if len < 0x80 => {
            // Short form length - total size should be at least len + 2
            data.len() >= (len as usize).saturating_add(2)
        }
        Some(&len) if len > 0x80 => {
            // Long form length - number of length octets follows
            let num_octets = (len & 0x7f) as usize;
            data.len() > num_octets.saturating_add(1)
        }
        Some(&0x80) => {
            // Indefinite length (not valid DER, but valid BER)
            false
        }
        _ => false,
    }
}

/// Check if data appears to be an SSH public key
///
/// # Arguments
/// * `data` - String data to check
///
/// # Returns
/// `true` if data appears to be an SSH public key
#[must_use]
pub fn is_ssh_key_format(data: &str) -> bool {
    if data.len() > MAX_INPUT_LENGTH {
        return false;
    }

    let trimmed = data.trim();

    // Check for common SSH key prefixes
    trimmed.starts_with(SSH_RSA_PREFIX)
        || trimmed.starts_with(SSH_ED25519_PREFIX)
        || trimmed.starts_with(SSH_ECDSA_PREFIX)
        || trimmed.starts_with(SSH_DSA_PREFIX)
}

/// Check if data appears to be an OpenSSH private key
#[must_use]
pub fn is_openssh_private_key_format(data: &str) -> bool {
    if data.len() > MAX_INPUT_LENGTH {
        return false;
    }

    data.trim()
        .starts_with(&pem_begin(LABEL_OPENSSH_PRIVATE_KEY))
}

// ============================================================================
// Key Type Detection (is_* functions)
// ============================================================================

/// Check if data appears to be an RSA key
#[must_use]
pub fn is_rsa_key(data: &str) -> bool {
    if data.len() > MAX_INPUT_LENGTH {
        return false;
    }

    let trimmed = data.trim();

    // Check PEM labels
    trimmed.contains(LABEL_RSA_PUBLIC_KEY)
        || trimmed.contains(LABEL_RSA_PRIVATE_KEY)
        || trimmed.starts_with(SSH_RSA_PREFIX)
}

/// Check if data appears to be an EC key
#[must_use]
pub fn is_ec_key(data: &str) -> bool {
    if data.len() > MAX_INPUT_LENGTH {
        return false;
    }

    let trimmed = data.trim();

    // Check PEM labels
    trimmed.contains(LABEL_EC_PRIVATE_KEY)
        || trimmed.starts_with(SSH_ED25519_PREFIX)
        || trimmed.starts_with(SSH_ECDSA_PREFIX)
}

/// Check if data appears to be an X.509 certificate
#[must_use]
pub fn is_x509_certificate(data: &str) -> bool {
    if data.len() > MAX_INPUT_LENGTH {
        return false;
    }

    extract_pem_label(data)
        .map(|label| label == LABEL_CERTIFICATE)
        .unwrap_or(false)
}

/// Check if data appears to be a private key
#[must_use]
pub fn is_private_key(data: &str) -> bool {
    if data.len() > MAX_INPUT_LENGTH {
        return false;
    }

    extract_pem_label(data)
        .map(|label| {
            label == LABEL_PRIVATE_KEY
                || label == LABEL_RSA_PRIVATE_KEY
                || label == LABEL_EC_PRIVATE_KEY
                || label == LABEL_ENCRYPTED_PRIVATE_KEY
                || label == LABEL_OPENSSH_PRIVATE_KEY
        })
        .unwrap_or(false)
}

/// Check if data appears to be a public key
#[must_use]
pub fn is_public_key(data: &str) -> bool {
    if data.len() > MAX_INPUT_LENGTH {
        return false;
    }

    // Check for PEM public key labels
    if let Some(label) = extract_pem_label(data)
        && (label == LABEL_PUBLIC_KEY || label == LABEL_RSA_PUBLIC_KEY)
    {
        return true;
    }

    // Check for SSH public key format
    is_ssh_key_format(data)
}

// ============================================================================
// Detection Functions (detect_* returning structured results)
// ============================================================================

/// Detect the format of cryptographic data
///
/// # Arguments
/// * `data` - String or binary data to analyze
///
/// # Returns
/// The detected key format
#[must_use]
pub fn detect_key_format(data: &str) -> KeyFormat {
    if data.len() > MAX_INPUT_LENGTH {
        return KeyFormat::Unknown;
    }

    if is_pem_format(data) {
        if is_openssh_private_key_format(data) {
            return KeyFormat::OpenSshPrivate;
        }
        return KeyFormat::Pem;
    }

    if is_ssh_key_format(data) {
        return KeyFormat::Ssh;
    }

    KeyFormat::Unknown
}

/// Detect the format of binary data
#[must_use]
pub fn detect_key_format_binary(data: &[u8]) -> KeyFormat {
    if data.len() > MAX_INPUT_LENGTH {
        return KeyFormat::Unknown;
    }

    if is_der_format(data) {
        return KeyFormat::Der;
    }

    // Try to interpret as UTF-8 string
    if let Ok(text) = std::str::from_utf8(data) {
        return detect_key_format(text);
    }

    KeyFormat::Raw
}

/// Detect the type of key from SSH public key format
#[must_use]
pub fn detect_ssh_key_type(data: &str) -> Option<KeyType> {
    if data.len() > MAX_INPUT_LENGTH {
        return None;
    }

    let trimmed = data.trim();

    if trimmed.starts_with(SSH_RSA_PREFIX) {
        return Some(KeyType::SshRsa);
    }
    if trimmed.starts_with(SSH_ED25519_PREFIX) {
        return Some(KeyType::SshEd25519);
    }
    if trimmed.starts_with(SSH_ECDSA_PREFIX) {
        return Some(KeyType::SshEcdsa);
    }
    if trimmed.starts_with(SSH_DSA_PREFIX) {
        return Some(KeyType::SshDsa);
    }

    None
}

/// Detect key type from PEM label
#[must_use]
pub fn detect_key_type_from_pem(data: &str) -> Option<KeyType> {
    let label = extract_pem_label(data)?;

    match label.as_str() {
        LABEL_RSA_PUBLIC_KEY | LABEL_RSA_PRIVATE_KEY => {
            // Default to RSA-2048, actual size requires parsing
            Some(KeyType::Rsa2048)
        }
        LABEL_EC_PRIVATE_KEY => {
            // Default to P-256, actual curve requires parsing
            Some(KeyType::P256)
        }
        LABEL_PUBLIC_KEY | LABEL_PRIVATE_KEY | LABEL_ENCRYPTED_PRIVATE_KEY => {
            // PKCS#8 format - need to parse to determine type
            Some(KeyType::Unknown)
        }
        LABEL_OPENSSH_PRIVATE_KEY => {
            // OpenSSH format - need to parse to determine type
            Some(KeyType::Unknown)
        }
        _ => None,
    }
}

/// Comprehensive crypto artifact detection
///
/// Analyzes input data and returns detailed information about what type
/// of cryptographic artifact it appears to be.
#[must_use]
#[allow(clippy::field_reassign_with_default)] // Complex initialization logic
pub fn detect_crypto_artifact(data: &str) -> CryptoDetectionResult {
    if data.len() > MAX_INPUT_LENGTH {
        return CryptoDetectionResult::default();
    }

    let mut result = CryptoDetectionResult::default();

    // Detect format
    result.format = detect_key_format(data);

    // Extract PEM label if present
    result.pem_label = extract_pem_label(data);

    // Check for certificate
    if let Some(ref label) = result.pem_label
        && label == LABEL_CERTIFICATE
    {
        result.is_certificate = true;
        result.confidence = 0.95;
        return result;
    }

    // Check for private key
    result.is_private = is_private_key(data);

    // Detect key type
    if result.format == KeyFormat::Ssh {
        result.key_type = detect_ssh_key_type(data);
        result.confidence = 0.9;
    } else if result.format == KeyFormat::Pem || result.format == KeyFormat::OpenSshPrivate {
        result.key_type = detect_key_type_from_pem(data);
        result.confidence = 0.8;
    }

    // Set confidence based on what we detected
    if result.key_type.is_some() {
        result.confidence = result.confidence.max(0.7);
    } else if result.pem_label.is_some() {
        result.confidence = 0.6;
    } else if result.format != KeyFormat::Unknown {
        result.confidence = 0.5;
    }

    result
}

/// Detect crypto identifier type (dual-API contract).
///
/// Companion to [`is_crypto_identifier`] that returns the matched
/// `IdentifierType`. Internally dispatches to [`detect_crypto_artifact`] and
/// maps any recognised artifact (PEM/DER/SSH format, known key type, or
/// certificate) to [`IdentifierType::HighEntropyString`] — this is the
/// closest existing variant, since `IdentifierType` has no dedicated
/// `Certificate` / `PrivateKey` / `SshKey` variant. A follow-up may add
/// those variants and refine this mapping.
#[must_use]
pub fn detect_crypto_identifier(data: &str) -> Option<IdentifierType> {
    let result = detect_crypto_artifact(data);
    if result.format != KeyFormat::Unknown || result.key_type.is_some() || result.is_certificate {
        Some(IdentifierType::HighEntropyString)
    } else {
        None
    }
}

/// Check whether `data` is any cryptographic artifact (dual-API contract).
///
/// Returns `true` when [`detect_crypto_identifier`] would return `Some`.
#[must_use]
pub fn is_crypto_identifier(data: &str) -> bool {
    detect_crypto_identifier(data).is_some()
}

/// Detect signature algorithm from OID string
///
/// Common OIDs:
/// - 1.2.840.113549.1.1.11 = sha256WithRSAEncryption
/// - 1.2.840.113549.1.1.12 = sha384WithRSAEncryption
/// - 1.2.840.113549.1.1.13 = sha512WithRSAEncryption
/// - 1.2.840.10045.4.3.2 = ecdsa-with-SHA256
/// - 1.3.101.112 = Ed25519
#[must_use]
pub fn detect_signature_algorithm_from_oid(oid: &str) -> SignatureAlgorithm {
    match oid {
        // RSA PKCS#1 v1.5
        "1.2.840.113549.1.1.5" => SignatureAlgorithm::RsaPkcs1Sha1,
        "1.2.840.113549.1.1.4" => SignatureAlgorithm::RsaPkcs1Md5,
        "1.2.840.113549.1.1.11" => SignatureAlgorithm::RsaPkcs1Sha256,
        "1.2.840.113549.1.1.12" => SignatureAlgorithm::RsaPkcs1Sha384,
        "1.2.840.113549.1.1.13" => SignatureAlgorithm::RsaPkcs1Sha512,

        // RSA-PSS
        "1.2.840.113549.1.1.10" => SignatureAlgorithm::RsaPssSha256, // PSS (params determine hash)

        // ECDSA
        "1.2.840.10045.4.3.2" => SignatureAlgorithm::EcdsaP256Sha256,
        "1.2.840.10045.4.3.3" => SignatureAlgorithm::EcdsaP384Sha384,
        "1.2.840.10045.4.3.4" => SignatureAlgorithm::EcdsaP521Sha512,

        // EdDSA
        "1.3.101.112" => SignatureAlgorithm::Ed25519,
        "1.3.101.113" => SignatureAlgorithm::Ed448,

        _ => SignatureAlgorithm::Unknown,
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Extract the PEM label from PEM-encoded data
///
/// E.g., for "-----BEGIN RSA PUBLIC KEY-----", returns "RSA PUBLIC KEY"
fn extract_pem_label(data: &str) -> Option<String> {
    let trimmed = data.trim();

    if !trimmed.starts_with(PEM_BEGIN) {
        return None;
    }

    // Find the end of the BEGIN line
    let begin_end = trimmed
        .find("-----\n")
        .or_else(|| trimmed.find("-----\r"))?;
    let label_start = PEM_BEGIN.len();
    let label_end = begin_end;

    if label_end <= label_start {
        return None;
    }

    Some(trimmed[label_start..label_end].to_string())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // Fake content - tests only check format detection, not parsing
    const SAMPLE_RSA_PUBLIC_PEM: &str = r#"-----BEGIN RSA PUBLIC KEY-----
FAKE_TEST_DATA_NOT_A_REAL_RSA_KEY
-----END RSA PUBLIC KEY-----"#;

    // Fake content - tests only check format detection, not parsing
    const SAMPLE_CERTIFICATE_PEM: &str = r#"-----BEGIN CERTIFICATE-----
FAKE_TEST_DATA_NOT_A_REAL_CERTIFICATE
-----END CERTIFICATE-----"#;

    // Build at runtime using patterns module to avoid triggering secret scanners
    fn sample_private_key_pem() -> String {
        use crate::primitives::identifiers::crypto::patterns::{
            LABEL_PRIVATE_KEY, pem_begin, pem_end,
        };
        format!(
            "{}\nFAKE_TEST_DATA\n{}",
            pem_begin(LABEL_PRIVATE_KEY),
            pem_end(LABEL_PRIVATE_KEY)
        )
    }

    const SAMPLE_SSH_RSA_KEY: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDUd3 user@host";

    const SAMPLE_SSH_ED25519_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG user@host";

    #[test]
    fn test_is_pem_format() {
        assert!(is_pem_format(SAMPLE_RSA_PUBLIC_PEM));
        assert!(is_pem_format(SAMPLE_CERTIFICATE_PEM));
        assert!(!is_pem_format(SAMPLE_SSH_RSA_KEY));
        assert!(!is_pem_format("random data"));
    }

    #[test]
    fn test_is_der_format() {
        // Valid DER sequence with short length
        assert!(is_der_format(&[0x30, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05]));

        // Not DER - doesn't start with SEQUENCE
        assert!(!is_der_format(&[0x02, 0x05]));

        // Too short
        assert!(!is_der_format(&[0x30]));
    }

    #[test]
    fn test_is_ssh_key_format() {
        assert!(is_ssh_key_format(SAMPLE_SSH_RSA_KEY));
        assert!(is_ssh_key_format(SAMPLE_SSH_ED25519_KEY));
        assert!(!is_ssh_key_format(SAMPLE_RSA_PUBLIC_PEM));
    }

    #[test]
    fn test_is_rsa_key() {
        assert!(is_rsa_key(SAMPLE_RSA_PUBLIC_PEM));
        assert!(is_rsa_key(SAMPLE_SSH_RSA_KEY));
        assert!(!is_rsa_key(SAMPLE_SSH_ED25519_KEY));
    }

    #[test]
    fn test_is_ec_key() {
        assert!(is_ec_key(SAMPLE_SSH_ED25519_KEY));
        assert!(!is_ec_key(SAMPLE_RSA_PUBLIC_PEM));
    }

    #[test]
    fn test_is_certificate() {
        assert!(is_x509_certificate(SAMPLE_CERTIFICATE_PEM));
        assert!(!is_x509_certificate(SAMPLE_RSA_PUBLIC_PEM));
    }

    #[test]
    fn test_is_private_key() {
        assert!(is_private_key(&sample_private_key_pem()));
        assert!(!is_private_key(SAMPLE_RSA_PUBLIC_PEM));
    }

    #[test]
    fn test_detect_key_format() {
        assert_eq!(detect_key_format(SAMPLE_RSA_PUBLIC_PEM), KeyFormat::Pem);
        assert_eq!(detect_key_format(SAMPLE_SSH_RSA_KEY), KeyFormat::Ssh);
        assert_eq!(detect_key_format("random"), KeyFormat::Unknown);
    }

    #[test]
    fn test_detect_ssh_key_type() {
        assert_eq!(
            detect_ssh_key_type(SAMPLE_SSH_RSA_KEY),
            Some(KeyType::SshRsa)
        );
        assert_eq!(
            detect_ssh_key_type(SAMPLE_SSH_ED25519_KEY),
            Some(KeyType::SshEd25519)
        );
    }

    #[test]
    fn test_detect_crypto_artifact() {
        let result = detect_crypto_artifact(SAMPLE_CERTIFICATE_PEM);
        assert!(result.is_certificate);
        assert_eq!(result.format, KeyFormat::Pem);
        assert!(result.confidence > 0.9);

        let result = detect_crypto_artifact(SAMPLE_SSH_RSA_KEY);
        assert_eq!(result.key_type, Some(KeyType::SshRsa));
        assert_eq!(result.format, KeyFormat::Ssh);
    }

    #[test]
    fn test_detect_crypto_identifier() {
        assert_eq!(
            detect_crypto_identifier(SAMPLE_CERTIFICATE_PEM),
            Some(IdentifierType::HighEntropyString)
        );
        assert_eq!(
            detect_crypto_identifier(SAMPLE_RSA_PUBLIC_PEM),
            Some(IdentifierType::HighEntropyString)
        );
        assert_eq!(
            detect_crypto_identifier(SAMPLE_SSH_ED25519_KEY),
            Some(IdentifierType::HighEntropyString)
        );
        assert_eq!(detect_crypto_identifier("plain text, not a key"), None);
        assert_eq!(detect_crypto_identifier(""), None);
    }

    #[test]
    fn test_is_crypto_identifier() {
        assert!(is_crypto_identifier(SAMPLE_CERTIFICATE_PEM));
        assert!(is_crypto_identifier(SAMPLE_SSH_RSA_KEY));
        assert!(!is_crypto_identifier("plain text"));
        assert!(!is_crypto_identifier(""));
    }

    #[test]
    fn test_detect_signature_algorithm_from_oid() {
        assert_eq!(
            detect_signature_algorithm_from_oid("1.2.840.113549.1.1.11"),
            SignatureAlgorithm::RsaPkcs1Sha256
        );
        assert_eq!(
            detect_signature_algorithm_from_oid("1.3.101.112"),
            SignatureAlgorithm::Ed25519
        );
        assert_eq!(
            detect_signature_algorithm_from_oid("unknown"),
            SignatureAlgorithm::Unknown
        );
    }

    #[test]
    fn test_extract_pem_label() {
        assert_eq!(
            extract_pem_label(SAMPLE_RSA_PUBLIC_PEM),
            Some("RSA PUBLIC KEY".to_string())
        );
        assert_eq!(
            extract_pem_label(SAMPLE_CERTIFICATE_PEM),
            Some("CERTIFICATE".to_string())
        );
        assert_eq!(extract_pem_label("not pem"), None);
    }

    #[test]
    fn test_max_length_protection() {
        let huge_input = "x".repeat(MAX_INPUT_LENGTH + 1);
        assert!(!is_pem_format(&huge_input));
        assert!(!is_ssh_key_format(&huge_input));
        assert!(detect_ssh_key_type(&huge_input).is_none());
    }
}
