//! X.509 certificate parsing
//!
//! Pure functions for parsing X.509 certificates.

use chrono::{DateTime, TimeZone, Utc};

use crate::primitives::identifiers::crypto::{KeyType, SignatureAlgorithm};
use crate::primitives::types::Problem;

use super::types::ParsedCertificate;

/// Maximum certificate size (1 MB)
const MAX_CERT_SIZE: usize = 1_048_576;

/// Parse an X.509 certificate from PEM or DER format
///
/// # Arguments
/// * `data` - Certificate data (PEM string or DER bytes)
///
/// # Returns
/// Parsed certificate or error
#[cfg(feature = "crypto-validation")]
pub fn parse_certificate_pem(data: &str) -> Result<ParsedCertificate, Problem> {
    if data.len() > MAX_CERT_SIZE {
        return Err(Problem::validation(
            "Certificate exceeds maximum allowed size",
        ));
    }

    // Parse PEM first (use :: to reference external crate)
    let pem = ::pem::parse(data).map_err(|e| Problem::validation(format!("Invalid PEM: {e}")))?;

    if pem.tag() != "CERTIFICATE" {
        return Err(Problem::validation(format!(
            "Expected CERTIFICATE, got {}",
            pem.tag()
        )));
    }

    parse_certificate_der(pem.contents())
}

/// Parse an X.509 certificate from DER format
#[cfg(feature = "crypto-validation")]
pub fn parse_certificate_der(data: &[u8]) -> Result<ParsedCertificate, Problem> {
    use x509_parser::prelude::*;

    if data.len() > MAX_CERT_SIZE {
        return Err(Problem::validation(
            "Certificate exceeds maximum allowed size",
        ));
    }

    let (_, cert) = X509Certificate::from_der(data)
        .map_err(|e| Problem::validation(format!("Failed to parse DER: {e}")))?;

    // Extract version
    let version = match cert.version() {
        X509Version::V1 => 1,
        X509Version::V2 => 2,
        X509Version::V3 => 3,
        _ => 0,
    };

    // Extract serial number
    let serial_number = hex::encode(cert.serial.to_bytes_be());

    // Extract subject and issuer
    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();

    // Extract validity dates
    let not_before = asn1_time_to_datetime(cert.validity().not_before)
        .ok_or_else(|| Problem::validation("Invalid not_before date"))?;

    let not_after = asn1_time_to_datetime(cert.validity().not_after)
        .ok_or_else(|| Problem::validation("Invalid not_after date"))?;

    // Detect public key type
    let public_key_type = detect_public_key_type(&cert);

    // Detect signature algorithm
    let signature_algorithm = detect_signature_algorithm(&cert);

    // Check if CA
    let is_ca = cert
        .basic_constraints()
        .ok()
        .flatten()
        .map(|bc| bc.value.ca)
        .unwrap_or(false);

    // Extract key usage
    let key_usage = cert
        .key_usage()
        .ok()
        .flatten()
        .map(|ku| extract_key_usage(ku.value))
        .unwrap_or_default();

    // Extract extended key usage
    let extended_key_usage = cert
        .extended_key_usage()
        .ok()
        .flatten()
        .map(|eku| extract_extended_key_usage(eku.value))
        .unwrap_or_default();

    // Extract SANs
    let subject_alt_names = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| extract_sans(san.value))
        .unwrap_or_default();

    // Check if self-signed
    let is_self_signed = subject == issuer;

    Ok(ParsedCertificate {
        version,
        serial_number,
        subject,
        issuer,
        not_before,
        not_after,
        public_key_type,
        signature_algorithm,
        is_ca,
        key_usage,
        extended_key_usage,
        subject_alt_names,
        is_self_signed,
    })
}

#[cfg(not(feature = "crypto-validation"))]
pub fn parse_certificate_pem(_data: &str) -> Result<ParsedCertificate, Problem> {
    Err(Problem::validation("crypto-validation feature not enabled"))
}

#[cfg(not(feature = "crypto-validation"))]
pub fn parse_certificate_der(_data: &[u8]) -> Result<ParsedCertificate, Problem> {
    Err(Problem::validation("crypto-validation feature not enabled"))
}

/// Validate that data is a valid X.509 certificate
pub fn validate_certificate_format_pem(data: &str) -> Result<(), Problem> {
    #[cfg(feature = "crypto-validation")]
    {
        parse_certificate_pem(data)?;
        Ok(())
    }

    #[cfg(not(feature = "crypto-validation"))]
    {
        let _ = data;
        Err(Problem::validation("crypto-validation feature not enabled"))
    }
}

/// Validate that data is a valid X.509 certificate (DER format)
pub fn validate_certificate_format_der(data: &[u8]) -> Result<(), Problem> {
    #[cfg(feature = "crypto-validation")]
    {
        parse_certificate_der(data)?;
        Ok(())
    }

    #[cfg(not(feature = "crypto-validation"))]
    {
        let _ = data;
        Err(Problem::validation("crypto-validation feature not enabled"))
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

#[cfg(feature = "crypto-validation")]
fn asn1_time_to_datetime(time: x509_parser::time::ASN1Time) -> Option<DateTime<Utc>> {
    // ASN1Time has a timestamp() method that returns seconds since epoch
    Utc.timestamp_opt(time.timestamp(), 0).single()
}

#[cfg(feature = "crypto-validation")]
fn detect_public_key_type(cert: &x509_parser::certificate::X509Certificate<'_>) -> KeyType {
    use x509_parser::public_key::PublicKey;

    match cert.public_key().parsed() {
        Ok(PublicKey::RSA(rsa)) => {
            let bit_size = rsa.key_size();
            match bit_size {
                0..=2047 => KeyType::RsaOther(bit_size),
                2048..=2559 => KeyType::Rsa2048,
                2560..=3583 => KeyType::Rsa3072,
                3584..=4607 => KeyType::Rsa4096,
                _ => KeyType::RsaOther(bit_size),
            }
        }
        Ok(PublicKey::EC(_)) => {
            // Try to determine curve from OID
            let oid = cert.public_key().algorithm.algorithm.to_string();
            if oid.contains("prime256v1") || oid.contains("secp256r1") {
                KeyType::P256
            } else if oid.contains("secp384r1") {
                KeyType::P384
            } else if oid.contains("secp521r1") {
                KeyType::P521
            } else {
                KeyType::Unknown
            }
        }
        _ => KeyType::Unknown,
    }
}

#[cfg(feature = "crypto-validation")]
fn detect_signature_algorithm(
    cert: &x509_parser::certificate::X509Certificate<'_>,
) -> SignatureAlgorithm {
    let oid = cert.signature_algorithm.algorithm.to_id_string();

    // Common OIDs
    match oid.as_str() {
        "1.2.840.113549.1.1.5" => SignatureAlgorithm::RsaPkcs1Sha1,
        "1.2.840.113549.1.1.4" => SignatureAlgorithm::RsaPkcs1Md5,
        "1.2.840.113549.1.1.11" => SignatureAlgorithm::RsaPkcs1Sha256,
        "1.2.840.113549.1.1.12" => SignatureAlgorithm::RsaPkcs1Sha384,
        "1.2.840.113549.1.1.13" => SignatureAlgorithm::RsaPkcs1Sha512,
        "1.2.840.10045.4.3.2" => SignatureAlgorithm::EcdsaP256Sha256,
        "1.2.840.10045.4.3.3" => SignatureAlgorithm::EcdsaP384Sha384,
        "1.2.840.10045.4.3.4" => SignatureAlgorithm::EcdsaP521Sha512,
        "1.3.101.112" => SignatureAlgorithm::Ed25519,
        "1.3.101.113" => SignatureAlgorithm::Ed448,
        _ => SignatureAlgorithm::Unknown,
    }
}

#[cfg(feature = "crypto-validation")]
fn extract_key_usage(ku: &x509_parser::extensions::KeyUsage) -> Vec<String> {
    let mut usages = Vec::new();

    if ku.digital_signature() {
        usages.push("digitalSignature".to_string());
    }
    if ku.non_repudiation() {
        usages.push("nonRepudiation".to_string());
    }
    if ku.key_encipherment() {
        usages.push("keyEncipherment".to_string());
    }
    if ku.data_encipherment() {
        usages.push("dataEncipherment".to_string());
    }
    if ku.key_agreement() {
        usages.push("keyAgreement".to_string());
    }
    if ku.key_cert_sign() {
        usages.push("keyCertSign".to_string());
    }
    if ku.crl_sign() {
        usages.push("cRLSign".to_string());
    }

    usages
}

#[cfg(feature = "crypto-validation")]
fn extract_extended_key_usage(eku: &x509_parser::extensions::ExtendedKeyUsage<'_>) -> Vec<String> {
    eku.other.iter().map(|oid| oid.to_id_string()).collect()
}

#[cfg(feature = "crypto-validation")]
fn extract_sans(san: &x509_parser::extensions::SubjectAlternativeName<'_>) -> Vec<String> {
    san.general_names
        .iter()
        .filter_map(|gn| match gn {
            x509_parser::extensions::GeneralName::DNSName(dns) => Some(dns.to_string()),
            x509_parser::extensions::GeneralName::IPAddress(ip) => {
                Some(format!("IP:{}", hex::encode(ip)))
            }
            x509_parser::extensions::GeneralName::RFC822Name(email) => {
                Some(format!("email:{email}"))
            }
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]

    #[test]
    fn test_validate_certificate_invalid() {
        let result = super::validate_certificate_format_pem("not a certificate");
        // Should return error regardless of feature flag
        assert!(result.is_err());
    }

    #[test]
    fn test_size_limit() {
        let huge = "x".repeat(super::MAX_CERT_SIZE + 1);
        let result = super::validate_certificate_format_pem(&huge);
        assert!(result.is_err());
    }
}
