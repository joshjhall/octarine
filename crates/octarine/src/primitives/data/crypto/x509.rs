//! X.509 certificate parsing
//!
//! Pure functions for parsing X.509 certificates.

use chrono::{DateTime, TimeZone, Utc};

use crate::primitives::identifiers::crypto::{KeyType, SignatureAlgorithm};
use crate::primitives::types::Problem;
use crate::primitives::types::ProblemExt;

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

/// Parse an X.509 certificate from PEM (stub when `crypto-validation` is disabled).
///
/// Always returns `Err(Problem::validation(...))` because certificate
/// parsing requires the `x509-parser` crate gated behind the feature.
/// Enable `crypto-validation` to use the real parser.
#[cfg(not(feature = "crypto-validation"))]
pub fn parse_certificate_pem(_data: &str) -> Result<ParsedCertificate, Problem> {
    Err(Problem::validation("crypto-validation feature not enabled"))
}

/// Parse an X.509 certificate from DER bytes (stub when `crypto-validation` is disabled).
///
/// Always returns `Err(Problem::validation(...))` because certificate
/// parsing requires the `x509-parser` crate gated behind the feature.
/// Enable `crypto-validation` to use the real parser.
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
            // For EC keys the algorithm OID is always `id-ecPublicKey`
            // (1.2.840.10045.2.1); the *named curve* is carried in the
            // AlgorithmIdentifier parameters as its own OID. Match on the
            // curve OID id-string (RFC 5480 / SEC 2):
            //   - prime256v1/secp256r1 => 1.2.840.10045.3.1.7 (P-256)
            //   - secp384r1            => 1.3.132.0.34         (P-384)
            //   - secp521r1            => 1.3.132.0.35         (P-521)
            let curve_oid = cert
                .public_key()
                .algorithm
                .parameters
                .as_ref()
                .and_then(|params| params.as_oid().ok())
                .map(|oid| oid.to_id_string())
                .unwrap_or_default();

            match curve_oid.as_str() {
                "1.2.840.10045.3.1.7" => KeyType::P256,
                "1.3.132.0.34" => KeyType::P384,
                "1.3.132.0.35" => KeyType::P521,
                _ => KeyType::Unknown,
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

    // ========================================================================
    // Feature-gated parsing tests (require `crypto-validation`)
    //
    // Test fixtures are real certificates generated with OpenSSL 3.x with
    // KNOWN structure, so expected values are derived from the certificate
    // spec / generation parameters, NOT from current parser output.
    // ========================================================================

    // Self-signed RSA-2048 / SHA-256 CA certificate.
    //   Subject/Issuer: C=US, O=Octarine, CN=octarine.test
    //   Validity: 2026-07-03 .. 2036-06-30 (10 years, CA:TRUE)
    //   SAN: DNS:octarine.test, DNS:www.octarine.test, email:test@octarine.test
    //   keyUsage: digitalSignature, keyCertSign
    #[cfg(feature = "crypto-validation")]
    const RSA_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDoTCCAomgAwIBAgIUIBqYDTwPs0w1FbKM9mMOE7PJUoYwDQYJKoZIhvcNAQEL
BQAwODEWMBQGA1UEAwwNb2N0YXJpbmUudGVzdDERMA8GA1UECgwIT2N0YXJpbmUx
CzAJBgNVBAYTAlVTMB4XDTI2MDcwMzE3MDQ1NFoXDTM2MDYzMDE3MDQ1NFowODEW
MBQGA1UEAwwNb2N0YXJpbmUudGVzdDERMA8GA1UECgwIT2N0YXJpbmUxCzAJBgNV
BAYTAlVTMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmrg8ir1LmYXF
TjrgU3U7xXa8U25MWcVM17Af0IG3jPPpriGs/IClbYHOi/gHCfJFnU23q1+FVDUW
whaDnymCBWvrcCu0eYMMleF/P/dwOYbjII+9JuTTermGFCT2k3ccwYRFJvXjsfcP
U/Tfq9Rq3yu5mOW014FGf5CCYhG1W9bosJPSfh0GWBDGi9Ohdaw+tlRdvU+pNWSk
IXLGe1rXCU1u3u7cK4/mHSOksW2k1Iz483B5xGX5ifKX6x2XqRtzooP45et6TLWr
qkaUIwPkX4dXpJ4JKM3G4ZeMDPXPm8lhUKUXL4TfNALMNs7nPM+0Aqfd2roRUWg3
TI2uwB1seQIDAQABo4GiMIGfMB0GA1UdDgQWBBRxWIHTY+24T212hsxG8kRS0A4a
wjAfBgNVHSMEGDAWgBRxWIHTY+24T212hsxG8kRS0A4awjA/BgNVHREEODA2gg1v
Y3RhcmluZS50ZXN0ghF3d3cub2N0YXJpbmUudGVzdIESdGVzdEBvY3RhcmluZS50
ZXN0MAsGA1UdDwQEAwIChDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4IBAQAxCxOT/4l3/e9LspAEXohIWzGd03m/7eHCtqKwRBbTxtLQR6uXxJcTw+ou
FhjoJXM0NpuoEX67kYPhK/xlGdSA38erqPIvfRCvWSz0PkvVnGU3wICQYijr61gX
NqkABZp7la/v+Ri4Z0mA6e8Jjn+3y9/kSHAlPVtB2M6LpD+9TRXbY017fzMob95r
TgJHncR9NUia7FyIlgFQD2mAviwTKXo62jwClR/4UbMDyW7WDB7RYsJtlD1ljV5Y
s65IEVG6SQCLEcR2Or1dlnSJEs1Yd2lh/Mm8okWlW+ku4i3Y1VFzlXPchg0qQZ1+
LMkl8mNtd2MbHD07VEPVzgaZQaEg
-----END CERTIFICATE-----";

    // Self-signed EC P-256 (prime256v1) / ecdsa-with-SHA256 certificate.
    //   Subject/Issuer: CN=ec.octarine.test
    //   Validity: 2026-07-03 .. 2027-07-03 (1 year, CA:TRUE)
    #[cfg(feature = "crypto-validation")]
    const EC_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBizCCATGgAwIBAgIUFs+d9rRzFKfmSyUhQNMPC7KQX8AwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQZWMub2N0YXJpbmUudGVzdDAeFw0yNjA3MDMxNzA1MTJaFw0y
NzA3MDMxNzA1MTJaMBsxGTAXBgNVBAMMEGVjLm9jdGFyaW5lLnRlc3QwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAS3UM4g/lq/Y+P2fpf0uVMaJ9G6VKdb0RCE856P
LrW5YmRAt6y/Xid7JCBNzySQCDQcDiAAsa/DmZ/S98EqOFFwo1MwUTAdBgNVHQ4E
FgQUZLvoZBYJkxcUeJIgFeH3kUdhl08wHwYDVR0jBBgwFoAUZLvoZBYJkxcUeJIg
FeH3kUdhl08wDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiAKqbXj
ICwfgCFx9yL32pXjno3ne+WvyycDPx0M67PUKwIhALFW9Z3MKtB4mecGRfBIcqmS
gHpkvc/082nbRHV5AjR2
-----END CERTIFICATE-----";

    #[cfg(feature = "crypto-validation")]
    #[test]
    fn test_parse_rsa_certificate_structure() {
        use crate::primitives::identifiers::crypto::{KeyType, SignatureAlgorithm};

        let cert = super::parse_certificate_pem(RSA_CERT_PEM).expect("valid RSA cert");

        // X.509 v3 (three extensions present)
        assert_eq!(cert.version, 3);

        // Self-signed: subject == issuer, both carry the expected RDNs.
        assert!(cert.is_self_signed);
        assert!(cert.subject.contains("octarine.test"));
        assert!(cert.subject.contains("Octarine"));
        assert_eq!(cert.subject, cert.issuer);

        // RSA-2048 public key, SHA-256 signature.
        assert_eq!(cert.public_key_type, KeyType::Rsa2048);
        assert_eq!(cert.signature_algorithm, SignatureAlgorithm::RsaPkcs1Sha256);

        // basicConstraints CA:TRUE.
        assert!(cert.is_ca);

        // not_before strictly precedes not_after; ~10-year validity.
        assert!(cert.not_before < cert.not_after);
        let validity_days = (cert.not_after - cert.not_before).num_days();
        assert!(
            (3600..3700).contains(&validity_days),
            "expected ~10y validity, got {validity_days} days"
        );

        // keyUsage bits set at generation time.
        assert!(cert.key_usage.contains(&"digitalSignature".to_string()));
        assert!(cert.key_usage.contains(&"keyCertSign".to_string()));

        // Serial number is a non-empty lowercase hex string.
        assert!(!cert.serial_number.is_empty());
        assert!(cert.serial_number.chars().all(|c| c.is_ascii_hexdigit()));

        // Subject Alternative Names: the two DNS names and the RFC822 email.
        assert!(cert.subject_alt_names.iter().any(|s| s == "octarine.test"));
        assert!(
            cert.subject_alt_names
                .iter()
                .any(|s| s == "www.octarine.test")
        );
        assert!(
            cert.subject_alt_names
                .iter()
                .any(|s| s == "email:test@octarine.test")
        );
    }

    #[cfg(feature = "crypto-validation")]
    #[test]
    fn test_parse_ec_certificate_curve_detection() {
        use crate::primitives::identifiers::crypto::{KeyType, SignatureAlgorithm};

        let cert = super::parse_certificate_pem(EC_CERT_PEM).expect("valid EC cert");

        // The curve is prime256v1 (P-256). The named curve lives in the
        // AlgorithmIdentifier parameters, NOT the algorithm OID, so this
        // asserts the parser reads parameters correctly.
        assert_eq!(
            cert.public_key_type,
            KeyType::P256,
            "EC prime256v1 cert must be classified as P-256"
        );
        assert_eq!(
            cert.signature_algorithm,
            SignatureAlgorithm::EcdsaP256Sha256
        );
        assert!(cert.is_self_signed);
        assert!(cert.subject.contains("ec.octarine.test"));
    }

    #[cfg(feature = "crypto-validation")]
    #[test]
    fn test_parse_der_matches_pem() {
        // Decoding the PEM body and parsing as DER must yield an identical
        // ParsedCertificate to parsing the PEM directly.
        let pem = ::pem::parse(RSA_CERT_PEM).expect("pem parses");
        let from_der = super::parse_certificate_der(pem.contents()).expect("der parses");
        let from_pem = super::parse_certificate_pem(RSA_CERT_PEM).expect("pem parses");
        assert_eq!(from_der, from_pem);
    }

    #[cfg(feature = "crypto-validation")]
    #[test]
    fn test_parse_pem_wrong_tag_rejected() {
        // A valid PEM block whose tag is not CERTIFICATE must be rejected.
        let key_pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----";
        let result = super::parse_certificate_pem(key_pem);
        assert!(result.is_err());
    }

    #[cfg(feature = "crypto-validation")]
    #[test]
    fn test_parse_invalid_der_rejected() {
        let result = super::parse_certificate_der(&[0x00, 0x01, 0x02, 0x03]);
        assert!(result.is_err());
    }

    #[cfg(feature = "crypto-validation")]
    #[test]
    fn test_parse_der_size_limit() {
        let huge = vec![0u8; super::MAX_CERT_SIZE + 1];
        let result = super::parse_certificate_der(&huge);
        assert!(result.is_err());
    }

    #[cfg(feature = "crypto-validation")]
    #[test]
    fn test_validate_format_der_ok_and_pem_ok() {
        assert!(super::validate_certificate_format_pem(RSA_CERT_PEM).is_ok());
        let pem = ::pem::parse(RSA_CERT_PEM).expect("pem parses");
        assert!(super::validate_certificate_format_der(pem.contents()).is_ok());
    }
}
