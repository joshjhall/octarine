//! Cryptocurrency wallet address detection
//!
//! Pure detection functions for Bitcoin and Ethereum addresses.
//!
//! Two layers of checks live here, matching the project-wide detection /
//! validation contract:
//!
//! - `is_*_address`: lenient shape-only checks (regex). Use these for
//!   scanning, logging, and aggregate detection where false positives are
//!   acceptable.
//! - `is_*_checksum_valid`: strict checksum verification using
//!   Base58Check + Bech32/Bech32m for Bitcoin and EIP-55 for Ethereum.
//!   Use these (or `validation::validate_crypto_address`) when a single
//!   typo must not slip through.

use super::super::super::common::patterns;
use super::super::super::types::{IdentifierMatch, IdentifierType};
use super::cache::{BTC_CHECKSUM_CACHE, ETH_EIP55_CACHE};
use tiny_keccak::{Hasher, Keccak};

/// Maximum input length for ReDoS protection
const MAX_INPUT_LENGTH: usize = 10_000;

/// Length of an Ethereum address payload (40 hex chars after `0x`)
const ETH_HEX_LEN: usize = 40;

// ============================================================================
// Public API
// ============================================================================

/// Check if value is a Bitcoin address (P2PKH, P2SH, or Bech32/Bech32m)
///
/// Shape-only detection — does NOT verify the checksum. Use
/// [`is_bitcoin_checksum_valid`] or
/// `validation::validate_crypto_address` for strict checks.
#[must_use]
pub fn is_bitcoin_address(value: &str) -> bool {
    let trimmed = value.trim();
    patterns::financial::crypto::BITCOIN_P2PKH.is_match(trimmed)
        || patterns::financial::crypto::BITCOIN_P2SH.is_match(trimmed)
        || patterns::financial::crypto::BITCOIN_BECH32.is_match(trimmed)
}

/// Check if value is an Ethereum address (0x + 40 hex chars)
///
/// Shape-only detection — does NOT enforce EIP-55 mixed-case checksum.
/// Use [`is_ethereum_eip55_valid`] for strict checks on mixed-case
/// addresses.
#[must_use]
pub fn is_ethereum_address(value: &str) -> bool {
    let trimmed = value.trim();
    patterns::financial::crypto::ETHEREUM.is_match(trimmed)
}

/// Check if value is any supported cryptocurrency address (shape only).
#[must_use]
pub fn is_crypto_address(value: &str) -> bool {
    is_bitcoin_address(value) || is_ethereum_address(value)
}

/// Verify a Bitcoin address checksum.
///
/// Dispatches on the address prefix:
///
/// - `1` (P2PKH) / `3` (P2SH): Base58Check via [`bs58`] — Base58 decode
///   plus double-SHA256 trailing-4-byte verification.
/// - `bc1` (SegWit/Taproot): [`bech32::segwit::decode`], which accepts
///   both Bech32 (witness v0) and Bech32m (witness v1+) and additionally
///   validates the witness program length.
///
/// Results are cached in [`BTC_CHECKSUM_CACHE`] (10k entries, 1h TTL) so
/// scanning a document with many repeated addresses stays cheap.
///
/// Returns `false` for anything that fails shape detection — callers can
/// use this without pre-checking [`is_bitcoin_address`].
#[must_use]
pub fn is_bitcoin_checksum_valid(value: &str) -> bool {
    let trimmed = value.trim();

    if let Some(cached) = BTC_CHECKSUM_CACHE.get(&trimmed.to_string()) {
        return cached;
    }

    let result = compute_btc_checksum(trimmed);
    BTC_CHECKSUM_CACHE.insert(trimmed.to_string(), result);
    result
}

/// Verify an Ethereum EIP-55 mixed-case checksum.
///
/// EIP-55 encodes a checksum by selectively uppercasing hex digits based
/// on the keccak-256 hash of the lowercased address (without the `0x`
/// prefix). The convention is that all-lowercase and all-uppercase
/// addresses are treated as "no checksum present" and accepted as long
/// as the shape is valid.
///
/// Strictness summary:
///
/// - Not an Ethereum address (shape) → `false`.
/// - All-lowercase or all-uppercase hex → `true` (checksum bypass).
/// - Mixed case → verified against keccak-256 of the lowercased payload.
///
/// Results are cached in [`ETH_EIP55_CACHE`] (5k entries, 1h TTL).
#[must_use]
pub fn is_ethereum_eip55_valid(value: &str) -> bool {
    let trimmed = value.trim();

    if let Some(cached) = ETH_EIP55_CACHE.get(&trimmed.to_string()) {
        return cached;
    }

    let result = compute_eth_eip55(trimmed);
    ETH_EIP55_CACHE.insert(trimmed.to_string(), result);
    result
}

/// Detect all cryptocurrency addresses in text
///
/// Scans text for Bitcoin (P2PKH, P2SH, Bech32) and Ethereum address patterns.
/// Includes ReDoS protection for large inputs.
///
/// Shape-only detection — matches are NOT checksum-verified.
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

// ============================================================================
// Internal helpers
// ============================================================================

/// Compute Bitcoin checksum (uncached).
fn compute_btc_checksum(addr: &str) -> bool {
    if !is_bitcoin_address(addr) {
        return false;
    }

    if addr.starts_with("bc1") {
        // SegWit (v0) and Taproot (v1+) — segwit::decode picks the right
        // checksum variant and additionally validates the witness program
        // length for known versions.
        bech32::segwit::decode(addr).is_ok()
    } else {
        // Base58Check decode + double-SHA256 verification. We accept any
        // version byte (`None`) so testnet addresses validate too —
        // strict mainnet-only enforcement is the caller's job.
        bs58::decode(addr).with_check(None).into_vec().is_ok()
    }
}

/// Compute Ethereum EIP-55 checksum (uncached).
///
/// Returns `false` on shape failure; returns `true` for all-lowercase or
/// all-uppercase addresses (no checksum present); otherwise verifies that
/// each hex nibble's case matches the corresponding bit of the
/// keccak-256 hash of the lowercased payload.
fn compute_eth_eip55(addr: &str) -> bool {
    if !is_ethereum_address(addr) {
        return false;
    }

    // Strip the well-known `0x` prefix; shape check above guarantees it.
    let Some(hex) = addr.strip_prefix("0x").or_else(|| addr.strip_prefix("0X")) else {
        return false;
    };

    if hex.len() != ETH_HEX_LEN {
        return false;
    }

    // No-checksum bypass: addresses that are uniformly cased predate
    // EIP-55 or signal "checksum not present" — accept them.
    let has_lower = hex.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = hex.bytes().any(|b| b.is_ascii_uppercase());
    if !has_lower || !has_upper {
        return true;
    }

    // EIP-55: hash the ASCII lowercase form, then for each hex nibble at
    // position `i`, the corresponding nibble of the hash (4 bits) tells
    // us whether to uppercase. We only need to verify that the existing
    // case matches the expected case.
    let lower: Vec<u8> = hex.bytes().map(|b| b.to_ascii_lowercase()).collect();
    let mut hasher = Keccak::v256();
    hasher.update(&lower);
    let mut hash = [0_u8; 32];
    hasher.finalize(&mut hash);

    for (i, &orig) in hex.as_bytes().iter().enumerate() {
        // Hash nibble for position i. Even i → high nibble, odd i → low
        // nibble. Indexing into a fixed 20-byte buffer with i / 2 (i < 40)
        // is bounded; `.get()` keeps clippy::indexing_slicing satisfied.
        let Some(&hash_byte) = hash.get(i / 2) else {
            return false;
        };
        let hash_nibble = if i & 1 == 0 {
            hash_byte >> 4
        } else {
            hash_byte & 0x0f
        };

        // Letters a-f are case-sensitive under EIP-55; digits 0-9 have no
        // case and always pass.
        let is_letter = orig.is_ascii_alphabetic();
        let should_be_upper = hash_nibble >= 8;
        let is_upper = orig.is_ascii_uppercase();
        if is_letter && (should_be_upper != is_upper) {
            return false;
        }
    }

    true
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::super::cache::clear_financial_caches;
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

    // ── Bitcoin checksum validation tests ──────────────────────────────

    #[test]
    fn test_btc_checksum_valid_p2pkh() {
        clear_financial_caches();
        // Genesis-block address — canonical valid P2PKH.
        assert!(is_bitcoin_checksum_valid(
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        ));
        assert!(is_bitcoin_checksum_valid(
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"
        ));
    }

    #[test]
    fn test_btc_checksum_invalid_typo_p2pkh() {
        clear_financial_caches();
        // Last char flipped from `a` to `b` — Base58Check rejects.
        assert!(!is_bitcoin_checksum_valid(
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"
        ));
    }

    #[test]
    fn test_btc_checksum_valid_p2sh() {
        clear_financial_caches();
        assert!(is_bitcoin_checksum_valid(
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"
        ));
    }

    #[test]
    fn test_btc_checksum_valid_bech32_segwit() {
        clear_financial_caches();
        // BIP-173 reference vector.
        assert!(is_bitcoin_checksum_valid(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        ));
    }

    #[test]
    fn test_btc_checksum_valid_bech32m_taproot() {
        clear_financial_caches();
        // BIP-350 / taproot reference vector (witness v1, 32-byte program).
        // From `bech32` crate docs as a known-good decode.
        assert!(is_bitcoin_checksum_valid(
            "bc1py3m7vwnghyne9gnvcjw82j7gqt2rafgdmlmwmqnn3hvcmdm09rjqcgrtxs"
        ));
    }

    #[test]
    fn test_btc_checksum_invalid_bech32_typo() {
        clear_financial_caches();
        // Final char flipped — Bech32 polymod rejects.
        assert!(!is_bitcoin_checksum_valid(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"
        ));
    }

    #[test]
    fn test_btc_checksum_invalid_shape() {
        clear_financial_caches();
        assert!(!is_bitcoin_checksum_valid(""));
        assert!(!is_bitcoin_checksum_valid("not_a_btc_address"));
        assert!(!is_bitcoin_checksum_valid(
            "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18"
        ));
    }

    #[test]
    fn test_btc_checksum_trims_whitespace() {
        clear_financial_caches();
        assert!(is_bitcoin_checksum_valid(
            "  1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa  "
        ));
    }

    // ── Ethereum EIP-55 tests ──────────────────────────────────────────

    #[test]
    fn test_eth_eip55_all_lowercase_passes() {
        clear_financial_caches();
        // All-lowercase ETH addresses bypass EIP-55 (no checksum encoded).
        assert!(is_ethereum_eip55_valid(
            "0x742d35cc6634c0532925a3b844bc9e7595f2bd18"
        ));
    }

    #[test]
    fn test_eth_eip55_all_uppercase_passes() {
        clear_financial_caches();
        // All-uppercase hex (with the conventional lowercase `0x` prefix)
        // is also treated as "no checksum present" — EIP-55 strictly
        // requires mixed case to encode any checksum bits.
        assert!(is_ethereum_eip55_valid(
            "0x742D35CC6634C0532925A3B844BC9E7595F2BD18"
        ));
    }

    #[test]
    fn test_eth_eip55_valid_mixed_case() {
        clear_financial_caches();
        // EIP-55 reference vector.
        assert!(is_ethereum_eip55_valid(
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        ));
        assert!(is_ethereum_eip55_valid(
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
        ));
        assert!(is_ethereum_eip55_valid(
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
        ));
        assert!(is_ethereum_eip55_valid(
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
        ));
    }

    #[test]
    fn test_eth_eip55_invalid_mixed_case() {
        clear_financial_caches();
        // First letter case flipped — EIP-55 should reject.
        assert!(!is_ethereum_eip55_valid(
            "0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        ));
    }

    #[test]
    fn test_eth_eip55_invalid_shape() {
        clear_financial_caches();
        assert!(!is_ethereum_eip55_valid(""));
        assert!(!is_ethereum_eip55_valid("0x123"));
        assert!(!is_ethereum_eip55_valid(
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        ));
    }

    #[test]
    fn test_eth_eip55_trims_whitespace() {
        clear_financial_caches();
        assert!(is_ethereum_eip55_valid(
            "  0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed  "
        ));
    }
}
