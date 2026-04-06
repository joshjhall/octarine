//! Cryptocurrency wallet address detection
//!
//! Pure detection functions for Bitcoin and Ethereum addresses.
//! Pattern-based detection without checksum validation.

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};

/// Maximum input length for ReDoS protection
const MAX_INPUT_LENGTH: usize = 10_000;

// ============================================================================
// Public API
// ============================================================================

/// Check if value is a Bitcoin address (P2PKH, P2SH, or Bech32/Bech32m)
#[must_use]
pub fn is_bitcoin_address(value: &str) -> bool {
    let trimmed = value.trim();
    patterns::financial::crypto::BITCOIN_P2PKH.is_match(trimmed)
        || patterns::financial::crypto::BITCOIN_P2SH.is_match(trimmed)
        || patterns::financial::crypto::BITCOIN_BECH32.is_match(trimmed)
}

/// Check if value is an Ethereum address (0x + 40 hex chars)
#[must_use]
pub fn is_ethereum_address(value: &str) -> bool {
    let trimmed = value.trim();
    patterns::financial::crypto::ETHEREUM.is_match(trimmed)
}

/// Check if value is any supported cryptocurrency address
#[must_use]
pub fn is_crypto_address(value: &str) -> bool {
    is_bitcoin_address(value) || is_ethereum_address(value)
}

/// Detect all cryptocurrency addresses in text
///
/// Scans text for Bitcoin (P2PKH, P2SH, Bech32) and Ethereum address patterns.
/// Includes ReDoS protection for large inputs.
#[allow(clippy::expect_used)]
#[must_use]
pub fn detect_crypto_addresses_in_text(text: &str) -> Vec<IdentifierMatch> {
    if text.len() > MAX_INPUT_LENGTH {
        return Vec::new();
    }

    let mut matches = Vec::new();

    for pattern in patterns::financial::crypto::all() {
        for capture in pattern.captures_iter(text) {
            let full_match = capture.get(0).expect("BUG: capture group 0 always exists");
            matches.push(IdentifierMatch::high_confidence(
                full_match.start(),
                full_match.end(),
                full_match.as_str().to_string(),
                IdentifierType::CryptoAddress,
            ));
        }
    }

    super::common::deduplicate_matches(matches)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    // ── Bitcoin detection tests ────────────────────────────────────────

    #[test]
    fn test_is_bitcoin_p2pkh() {
        // P2PKH (Legacy) — starts with 1
        assert!(is_bitcoin_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
        assert!(is_bitcoin_address("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"));
    }

    #[test]
    fn test_is_bitcoin_p2sh() {
        // P2SH (Script Hash) — starts with 3
        assert!(is_bitcoin_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"));
    }

    #[test]
    fn test_is_bitcoin_bech32() {
        // Bech32 (SegWit) — starts with bc1
        assert!(is_bitcoin_address(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        ));
        // Bech32m (Taproot) — starts with bc1p
        assert!(is_bitcoin_address(
            "bc1p5cyxnuxmeuwuvkwfem96lqzszee02v3tg30zjhg8rpd2kmpfessxqszqwa"
        ));
    }

    #[test]
    fn test_invalid_bitcoin_addresses() {
        assert!(!is_bitcoin_address(""));
        assert!(!is_bitcoin_address("not_an_address"));
        assert!(!is_bitcoin_address("1short")); // Too short
        assert!(!is_bitcoin_address("2InvalidPrefix123456789012345678"));
    }

    // ── Ethereum detection tests ───────────────────────────────────────

    #[test]
    fn test_is_ethereum_address() {
        assert!(is_ethereum_address(
            "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18"
        ));
        assert!(is_ethereum_address(
            "0x0000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn test_invalid_ethereum_addresses() {
        assert!(!is_ethereum_address(""));
        assert!(!is_ethereum_address("0x123")); // Too short
        assert!(!is_ethereum_address(
            "742d35Cc6634C0532925a3b844Bc9e7595f2bD18"
        )); // Missing 0x
        assert!(!is_ethereum_address(
            "0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG"
        )); // Invalid hex
    }

    // ── Aggregate detection tests ──────────────────────────────────────

    #[test]
    fn test_is_crypto_address() {
        assert!(is_crypto_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
        assert!(is_crypto_address(
            "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18"
        ));
        assert!(!is_crypto_address("not_crypto"));
    }

    #[test]
    fn test_detect_crypto_in_text() {
        let text = "Send BTC to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or ETH to 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18";
        let matches = detect_crypto_addresses_in_text(text);
        assert_eq!(matches.len(), 2, "expected 2 crypto addresses in text");
        assert!(
            matches
                .iter()
                .all(|m| m.identifier_type == IdentifierType::CryptoAddress)
        );
    }

    #[test]
    fn test_detect_crypto_no_matches() {
        let text = "No crypto addresses here, just 0x123 and some text";
        let matches = detect_crypto_addresses_in_text(text);
        assert!(matches.is_empty());
    }

    #[test]
    fn test_detect_bech32_in_text() {
        let text = "SegWit: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let matches = detect_crypto_addresses_in_text(text);
        assert_eq!(matches.len(), 1);
    }
}
