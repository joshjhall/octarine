//! PII detection scanner
//!
//! Scans text for PII using domain-specific identifier builders from the primitives layer.
//!
//! ## Architecture
//!
//! The scanner uses the primitives layer builders:
//! - `PersonalIdentifierBuilder` - emails, phones, names, birthdates
//! - `FinancialIdentifierBuilder` - credit cards, bank accounts, routing numbers
//! - `GovernmentIdentifierBuilder` - SSN, driver license, passport, VIN, EIN
//! - `MedicalIdentifierBuilder` - MRN, NPI, insurance, ICD codes
//! - `TokenIdentifierBuilder` - API keys, JWT, session IDs, passwords
//! - `NetworkIdentifierBuilder` - IPs, MACs, UUIDs, domains, URLs
//! - `LocationIdentifierBuilder` - GPS coordinates, addresses, postal codes
//! - `BiometricIdentifierBuilder` - fingerprint, face, voice, iris, DNA IDs
//! - `OrganizationalIdentifierBuilder` - employee IDs, student IDs, badges
//!
//! ## Performance Features
//!
//! - **LRU Caching**: Recent scan results cached to avoid redundant regex operations
//! - **Health Monitoring**: Tracks cache hits, misses, and scan statistics
//! - **Configurable Domains**: Use `PiiScannerConfig` to control which domains are scanned
//!
//! ## Module Organization
//!
//! - `cache` - LRU cache for scan results
//! - `domains` - Domain-specific scanning functions
//! - `health` - Health monitoring API

mod cache;
mod domains;
mod health;

use super::config::PiiScannerConfig;
use super::patterns;
use super::types::PiiType;
use cache::{CACHE_MAX_TEXT_LENGTH, SCAN_CACHE, SCANNER_STATS, hash_text_with_config};
use domains::{is_pii_present_with_config_impl, scan_for_pii_uncached_with_config};
use std::sync::atomic::Ordering;
use std::time::Instant;

// Re-export health monitoring API
pub use health::{
    PiiStatistics, clear_scanner_cache, scanner_cache_size, scanner_health_score,
    scanner_is_degraded, scanner_is_healthy, scanner_stats,
};

/// Scan text for PII and return all detected types
///
/// Uses the default `PiiScannerConfig` which scans:
/// - Personal (email, phone, name, birthdate)
/// - Financial (credit card, bank account, routing number)
/// - Government (SSN, driver license, passport, VIN, EIN)
/// - Medical (MRN, NPI, insurance, ICD codes)
/// - Location (GPS, address, postal code)
/// - Tokens (API keys, JWT, session IDs, passwords)
///
/// Does NOT scan by default (can be enabled with custom config):
/// - Biometric (rare in typical logs)
/// - Organizational (usually internal data)
/// - Network (can be noisy with false positives)
///
/// # Performance
///
/// - Regex patterns are pre-compiled (lazy_static)
/// - LRU cache for repeated scans of same text
/// - Short-circuits on first match for `is_pii_present()`
/// - Full scan completes in <50μs for typical inputs
///
/// # Examples
///
/// ```
/// use octarine::observe::pii::scan_for_pii;
///
/// let text = "Contact: user@example.com, SSN: 517-29-8346";
/// let pii_types = scan_for_pii(text);
///
/// assert!(pii_types.iter().any(|p| p.name() == "email"));
/// assert!(pii_types.iter().any(|p| p.name() == "ssn"));
/// ```
pub fn scan_for_pii(text: &str) -> Vec<PiiType> {
    scan_for_pii_with_config(text, &PiiScannerConfig::default())
}

/// Scan text for PII with a custom configuration
///
/// Allows fine-grained control over which domains are scanned.
/// Use this for compliance-focused scanning (HIPAA, PCI-DSS, GDPR).
///
/// # Examples
///
/// ```
/// use octarine::observe::pii::{scan_for_pii_with_config, PiiScannerConfig};
///
/// // HIPAA focused - scan medical and personal data
/// let config = PiiScannerConfig::hipaa_focused();
/// let types = scan_for_pii_with_config("NPI: 1234567890", &config);
///
/// // PCI-DSS focused - scan financial data only
/// let config = PiiScannerConfig::pci_focused();
/// let types = scan_for_pii_with_config("Card: 4242424242424242", &config);
/// ```
pub fn scan_for_pii_with_config(text: &str, config: &PiiScannerConfig) -> Vec<PiiType> {
    let start = Instant::now();
    SCANNER_STATS.total_scans.fetch_add(1, Ordering::Relaxed);

    // Check cache for short texts (cache key includes config hash)
    let use_cache = text.len() <= CACHE_MAX_TEXT_LENGTH;
    let hash = if use_cache {
        hash_text_with_config(text, config)
    } else {
        0
    };

    if use_cache {
        let mut cache = SCAN_CACHE.lock();
        if let Some(cached) = cache.get(hash) {
            SCANNER_STATS.cache_hits.fetch_add(1, Ordering::Relaxed);
            return cached;
        }
    }

    SCANNER_STATS.cache_misses.fetch_add(1, Ordering::Relaxed);

    // Perform actual scan with config
    let pii_types = scan_for_pii_uncached_with_config(text, config);

    // Update stats
    SCANNER_STATS
        .total_pii_found
        .fetch_add(pii_types.len() as u64, Ordering::Relaxed);
    SCANNER_STATS
        .total_scan_time_us
        .fetch_add(start.elapsed().as_micros() as u64, Ordering::Relaxed);

    // Cache result for short texts
    if use_cache {
        let mut cache = SCAN_CACHE.lock();
        cache.insert(hash, pii_types.clone());
    }

    pii_types
}

/// Fast check if text contains any PII
///
/// This is optimized to short-circuit on the first PII match,
/// making it faster than `scan_for_pii()` when you only need a yes/no answer.
///
/// Uses the default `PiiScannerConfig` - see `is_pii_present_with_config`
/// for customized domain scanning.
///
/// # Examples
///
/// ```
/// use octarine::observe::pii::scan_for_pii;
///
/// // Use scan_for_pii and check if any results (equivalent to is_pii_present)
/// assert!(!scan_for_pii("SSN: 517-29-8346").is_empty());
/// assert!(scan_for_pii("Clean text with no PII").is_empty());
/// ```
pub fn is_pii_present(text: &str) -> bool {
    is_pii_present_with_config(text, &PiiScannerConfig::default())
}

/// Fast check if text contains any PII using a custom configuration
///
/// # Examples
///
/// ```
/// use octarine::observe::pii::{scan_for_pii_with_config, PiiScannerConfig};
///
/// // Only check for tokens/secrets
/// let config = PiiScannerConfig::secrets_focused();
/// assert!(!scan_for_pii_with_config("api_key=sk_test_123456", &config).is_empty());
/// assert!(scan_for_pii_with_config("user@example.com", &config).is_empty()); // Email not checked
/// ```
pub fn is_pii_present_with_config(text: &str, config: &PiiScannerConfig) -> bool {
    is_pii_present_with_config_impl(text, config)
}

/// Check if text contains IP addresses
///
/// Simple pattern matching for IPv4 addresses.
fn is_ip_address_present(text: &str) -> bool {
    patterns::ip_address::IPV4.is_match(text)
}

/// Scan and create a PiiScanResult (for internal use by redactor)
pub(super) fn scan_and_prepare(text: &str) -> (Vec<PiiType>, bool) {
    let pii_types = scan_for_pii(text);
    let contains_pii = !pii_types.is_empty();
    (pii_types, contains_pii)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::primitives::identifiers::PersonalIdentifierBuilder;

    #[test]
    fn test_contains_email_via_personal_builder() {
        let personal = PersonalIdentifierBuilder::new();
        let result = personal.is_email("user@example.com");
        assert!(result, "Should detect email directly");
    }

    #[test]
    fn test_scan_for_pii_ssn() {
        let text = "SSN: 900-00-0001"; // 900 series is test data
        let types = scan_for_pii(text);
        assert!(types.contains(&PiiType::Ssn));
    }

    #[test]
    fn test_scan_for_pii_credit_card() {
        let text = "Card: 4242424242424242"; // Stripe test card
        let types = scan_for_pii(text);
        assert!(types.contains(&PiiType::CreditCard));
    }

    #[test]
    fn test_scan_for_pii_email() {
        let text = "Contact: user@example.com";
        let types = scan_for_pii(text);
        assert!(types.contains(&PiiType::Email));
    }

    #[test]
    fn test_scan_for_pii_phone() {
        let text = "Call: +1-555-123-4567";
        let types = scan_for_pii(text);
        assert!(types.contains(&PiiType::Phone));
    }

    #[test]
    fn test_scan_for_pii_api_key() {
        let text = &format!("Key: sk_test_{}", "EXAMPLE000000000000KEY01");
        let types = scan_for_pii(text);
        assert!(types.contains(&PiiType::ApiKey));
    }

    #[test]
    fn test_scan_for_pii_password() {
        let text = "password=secret123";
        let types = scan_for_pii(text);
        assert!(types.contains(&PiiType::Password));
    }

    #[test]
    fn test_scan_for_pii_ip_address() {
        let text = "Server: 192.168.1.1";
        let config = PiiScannerConfig::default().with_network(true);
        let types = scan_for_pii_with_config(text, &config);
        assert!(
            types.contains(&PiiType::IpAddress),
            "Should detect IP address with network scanning enabled"
        );
    }

    #[test]
    fn test_scan_for_pii_multiple() {
        let text = "Email: user@example.com, SSN: 900-00-0001, Card: 4242424242424242";
        let types = scan_for_pii(text);
        assert!(
            types.len() >= 3,
            "Should detect at least 3 PII types, got {:?}",
            types
        );
        assert!(types.contains(&PiiType::Email), "Should contain email");
        assert!(types.contains(&PiiType::Ssn), "Should contain SSN");
        assert!(
            types.contains(&PiiType::CreditCard),
            "Should contain credit card"
        );
    }

    #[test]
    fn test_scan_for_pii_none() {
        let text = "This is clean text with no PII";
        let types = scan_for_pii(text);
        assert!(types.is_empty());
    }

    #[test]
    fn test_is_pii_present_true() {
        assert!(is_pii_present("SSN: 900-00-0001"));
        assert!(is_pii_present("user@example.com"));
        assert!(is_pii_present("4242424242424242"));
    }

    #[test]
    fn test_is_pii_present_false() {
        assert!(!is_pii_present("Clean text"));
        assert!(!is_pii_present("No sensitive data here"));
    }

    #[test]
    fn test_ip_address_detection() {
        assert!(is_ip_address_present("192.168.1.1"));
        assert!(is_ip_address_present("Server at 10.0.0.1"));
        assert!(is_ip_address_present("8.8.8.8"));
        assert!(!is_ip_address_present("999.999.999.999")); // Invalid IP
        assert!(!is_ip_address_present("No IP here"));
    }
}
