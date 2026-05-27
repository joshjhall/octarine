//! Financial identifier builder with observability
//!
//! Wraps `primitives::data::identifiers::FinancialIdentifierBuilder` with observe instrumentation.
//!
//! This is the **public API** (Layer 3) that wraps the primitive builder
//! with observe instrumentation for compliance-grade audit trails.
//!
//! # Why Wrapper Types?
//!
//! Wrapper types are necessary for two reasons:
//! 1. **Visibility bridging**: Primitives are `pub(crate)`, so we can't directly
//!    re-export them as `pub`. Wrapper types provide the public API surface.
//! 2. **API stability**: Wrappers allow the public API to evolve independently
//!    from internal primitives.

use std::borrow::Cow;
use std::time::Instant;

use crate::observe;
use crate::observe::Problem;
use crate::observe::metrics::{increment_by, record};
use crate::primitives::identifiers::{
    BankAccountRedactionStrategy, CreditCardRedactionStrategy, CryptoAddressRedactionStrategy,
    CryptoAddressType, FinancialIdentifierBuilder, RoutingNumberRedactionStrategy,
};

use super::super::types::{
    CreditCardType, DetectionResult, FinancialTextPolicy, IdentifierMatch, IdentifierType,
};

crate::define_metrics! {
    detect_ms => "data.identifiers.financial.detect_ms",
    validate_ms => "data.identifiers.financial.validate_ms",
    redact_ms => "data.identifiers.financial.redact_ms",
    detected => "data.identifiers.financial.detected",
    pci_data_found => "data.identifiers.financial.pci_data_found",
}

/// Financial identifier builder with observability
///
/// Provides detection, validation, and sanitization for financial identifiers
/// (credit cards, bank accounts, routing numbers) with full audit trail via observe.
///
/// # Example
///
/// Pre-existing example - ignored at compile until adapted.
/// ```ignore
/// use octarine::data::identifiers::FinancialBuilder;
///
/// let builder = FinancialBuilder::new();
///
/// // Detection
/// if builder.is_credit_card("4242424242424242") {
///     println!("Found credit card");
/// }
///
/// // Silent mode (no events)
/// let silent = FinancialBuilder::silent();
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct FinancialBuilder {
    /// The underlying primitive builder
    inner: FinancialIdentifierBuilder,
    /// Whether to emit observe events
    emit_events: bool,
}

impl FinancialBuilder {
    /// Create a new FinancialBuilder with observe events enabled
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: FinancialIdentifierBuilder::new(),
            emit_events: true,
        }
    }

    /// Create a builder without observe events (for internal use)
    #[must_use]
    pub fn silent() -> Self {
        Self {
            inner: FinancialIdentifierBuilder::new(),
            emit_events: false,
        }
    }

    /// Enable or disable observe events
    #[must_use]
    pub fn with_events(mut self, emit: bool) -> Self {
        self.emit_events = emit;
        self
    }

    /// Whether observe events are enabled (used by parent builder tests)
    #[cfg(test)]
    pub(crate) fn emit_events(&self) -> bool {
        self.emit_events
    }

    // ========================================================================
    // Detection Methods
    // ========================================================================

    /// Find financial identifier type from value
    #[must_use]
    pub fn find(&self, value: &str) -> Option<IdentifierType> {
        let start = Instant::now();
        let result = self.inner.find(value);

        if self.emit_events {
            record(
                metric_names::detect_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );

            if result.is_some() {
                increment_by(metric_names::detected(), 1);
            }
        }

        result
    }

    /// Check if value is any financial identifier
    #[must_use]
    pub fn is_financial_identifier(&self, value: &str) -> bool {
        self.inner.is_financial_identifier(value)
    }

    /// Detect financial identifier type (dual-API alias for [`Self::find`]).
    ///
    /// Provided to match the `detect_{domain}_identifier` /
    /// `is_{domain}_identifier` contract shared by every identifier domain.
    /// Unlike [`Self::find`], this is a plain pass-through without observe
    /// instrumentation — use [`Self::find`] when you want metrics recorded.
    #[must_use]
    pub fn detect_financial_identifier(&self, value: &str) -> Option<IdentifierType> {
        self.inner.detect_financial_identifier(value)
    }

    /// Check if value is a credit card
    #[must_use]
    pub fn is_credit_card(&self, value: &str) -> bool {
        self.inner.is_credit_card(value)
    }

    /// Check if value is a routing number
    #[must_use]
    pub fn is_routing_number(&self, value: &str) -> bool {
        self.inner.is_routing_number(value)
    }

    /// Check if value might be a bank account
    #[must_use]
    pub fn is_bank_account(&self, value: &str) -> bool {
        self.inner.is_bank_account(value)
    }

    /// Check if value is a valid IBAN (format + MOD-97 checksum)
    #[must_use]
    pub fn is_iban(&self, value: &str) -> bool {
        self.inner.is_iban(value)
    }

    /// Extract country code from an IBAN
    #[must_use]
    pub fn detect_iban_country<'a>(&self, value: &'a str) -> Option<&'a str> {
        self.inner.detect_iban_country(value)
    }

    /// Check if value is a Bitcoin address (P2PKH, P2SH, or Bech32/Bech32m)
    #[must_use]
    pub fn is_bitcoin_address(&self, value: &str) -> bool {
        self.inner.is_bitcoin_address(value)
    }

    /// Check if value is an Ethereum address (0x + 40 hex chars)
    #[must_use]
    pub fn is_ethereum_address(&self, value: &str) -> bool {
        self.inner.is_ethereum_address(value)
    }

    /// Check if value is any supported cryptocurrency address
    #[must_use]
    pub fn is_crypto_address(&self, value: &str) -> bool {
        self.inner.is_crypto_address(value)
    }

    /// Verify a Bitcoin address checksum (Base58Check or Bech32/Bech32m).
    ///
    /// Stricter than [`Self::is_bitcoin_address`] — rejects single-char
    /// typos and rebuilt-from-scratch fakes.
    #[must_use]
    pub fn is_bitcoin_checksum_valid(&self, value: &str) -> bool {
        self.inner.is_bitcoin_checksum_valid(value)
    }

    /// Verify an Ethereum EIP-55 mixed-case checksum.
    ///
    /// All-lowercase and all-uppercase addresses are accepted as "no
    /// checksum present". Mixed-case addresses must match keccak-256.
    #[must_use]
    pub fn is_ethereum_eip55_valid(&self, value: &str) -> bool {
        self.inner.is_ethereum_eip55_valid(value)
    }

    /// Check if value is likely a credit card (less strict)
    #[must_use]
    pub fn is_credit_card_likely(&self, value: &str) -> bool {
        self.inner.is_credit_card_likely(value)
    }

    /// Detect credit card with context for confidence scoring
    #[must_use]
    pub fn detect_credit_card_with_context(
        &self,
        value: &str,
        context: Option<&str>,
    ) -> Option<DetectionResult> {
        self.inner.detect_credit_card_with_context(value, context)
    }

    /// Detect routing number with ABA checksum validation
    #[must_use]
    pub fn detect_routing_number(&self, value: &str) -> Option<DetectionResult> {
        self.inner.detect_routing_number(value)
    }

    /// Detect credit card brand (Visa, MasterCard, etc.)
    #[must_use]
    pub fn detect_card_brand(&self, value: &str) -> Option<CreditCardType> {
        self.inner.detect_card_brand(value)
    }

    /// Check if text contains any financial identifier
    pub fn is_financial_present(&self, text: &str) -> bool {
        let result = self.inner.is_financial_present(text);

        if self.emit_events && result {
            increment_by(metric_names::pci_data_found(), 1);
            observe::warn("financial_data_detected", "PCI data detected in text");
        }

        result
    }

    /// Check if text contains PII (financial PII specifically)
    #[must_use]
    pub fn is_pii_present(&self, text: &str) -> bool {
        self.is_financial_present(text)
    }

    /// Check if text contains payment data
    pub fn is_payment_data_present(&self, text: &str) -> bool {
        let result = self.inner.is_payment_data_present(text);

        if self.emit_events && result {
            increment_by(metric_names::pci_data_found(), 1);
        }

        result
    }

    /// Detect all credit cards in text
    #[must_use]
    pub fn detect_credit_cards_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let matches = self.inner.detect_credit_cards_in_text(text);

        if self.emit_events && !matches.is_empty() {
            increment_by(metric_names::detected(), matches.len() as u64);
            increment_by(metric_names::pci_data_found(), matches.len() as u64);
        }

        matches
    }

    /// Detect all payment tokens in text
    #[must_use]
    pub fn detect_payment_tokens_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.detect_payment_tokens_in_text(text)
    }

    /// Detect all bank accounts in text
    #[must_use]
    pub fn detect_bank_accounts_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        self.inner.detect_bank_accounts_in_text(text)
    }

    /// Detect all routing numbers in text with ABA checksum validation
    ///
    /// Emits `pci_data_found` because routing numbers are financial PII
    /// subject to PCI-DSS handling requirements.
    #[must_use]
    pub fn detect_routing_numbers_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let matches = self.inner.detect_routing_numbers_in_text(text);

        if self.emit_events && !matches.is_empty() {
            increment_by(metric_names::detected(), matches.len() as u64);
            increment_by(metric_names::pci_data_found(), matches.len() as u64);
        }

        matches
    }

    /// Detect all IBANs in text with MOD-97 checksum validation
    ///
    /// Emits `pci_data_found` because IBAN is regulated financial PII
    /// (PCI-DSS scope; GDPR scope in the EU).
    #[must_use]
    pub fn detect_ibans_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let matches = self.inner.detect_ibans_in_text(text);

        if self.emit_events && !matches.is_empty() {
            increment_by(metric_names::detected(), matches.len() as u64);
            increment_by(metric_names::pci_data_found(), matches.len() as u64);
        }

        matches
    }

    /// Detect all cryptocurrency addresses in text
    ///
    /// Covers Bitcoin (P2PKH, P2SH, Bech32/Bech32m) and Ethereum.
    /// Emits `pci_data_found` — crypto wallet addresses are financial
    /// identifiers subject to PCI-DSS handling requirements.
    #[must_use]
    pub fn detect_crypto_addresses_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let matches = self.inner.detect_crypto_addresses_in_text(text);

        if self.emit_events && !matches.is_empty() {
            increment_by(metric_names::detected(), matches.len() as u64);
            increment_by(metric_names::pci_data_found(), matches.len() as u64);
        }

        matches
    }

    /// Detect all financial identifiers in text
    #[must_use]
    pub fn detect_all_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        let matches = self.inner.detect_all_in_text(text);

        if self.emit_events && !matches.is_empty() {
            increment_by(metric_names::detected(), matches.len() as u64);
        }

        matches
    }

    // ========================================================================
    // Validation Methods
    // ========================================================================

    /// Validate credit card number (returns Result with card type)
    pub fn validate_credit_card(&self, card: &str) -> Result<CreditCardType, Problem> {
        let start = Instant::now();
        let result = self.inner.validate_credit_card(card);

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );

            if result.is_err() {
                observe::debug(
                    "credit_card_validation_failed",
                    "Credit card validation failed",
                );
            }
        }

        result
    }

    /// Detect credit card type from pattern
    #[must_use]
    pub fn detect_card_type(&self, card: &str) -> CreditCardType {
        self.inner.detect_card_type(card)
    }

    /// Check if text matches credit card pattern
    #[must_use]
    pub fn is_credit_card_pattern(&self, text: &str) -> bool {
        self.inner.is_credit_card_pattern(text)
    }

    /// Validate routing number (returns Result)
    pub fn validate_routing_number(&self, routing: &str) -> Result<(), Problem> {
        self.inner.validate_routing_number(routing)
    }

    /// Validate account number (returns Result)
    pub fn validate_account_number(&self, account: &str) -> Result<(), Problem> {
        self.inner.validate_account_number(account)
    }

    /// Validate complete bank account (returns Result)
    pub fn validate_bank_account(&self, routing: &str, account: &str) -> Result<(), Problem> {
        self.inner.validate_bank_account(routing, account)
    }

    /// Validate a cryptocurrency wallet address with full checksum verification.
    ///
    /// Emits `validate_ms` timing and a `debug` event on failure when
    /// observe events are enabled (silent mode skips both).
    pub fn validate_crypto_address(&self, addr: &str) -> Result<CryptoAddressType, Problem> {
        let start = Instant::now();
        let result = self.inner.validate_crypto_address(addr);

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );

            if result.is_err() {
                observe::debug(
                    "crypto_address_validation_failed",
                    "Crypto address validation failed",
                );
            }
        }

        result
    }

    // ========================================================================
    // Sanitization Methods (Strategy Required)
    // ========================================================================

    /// Redact credit card with explicit strategy
    #[must_use]
    pub fn redact_credit_card_with_strategy(
        &self,
        card: &str,
        strategy: CreditCardRedactionStrategy,
    ) -> String {
        self.inner.redact_credit_card_with_strategy(card, strategy)
    }

    /// Redact bank account with explicit strategy
    #[must_use]
    pub fn redact_bank_account_with_strategy(
        &self,
        account: &str,
        strategy: BankAccountRedactionStrategy,
    ) -> String {
        self.inner
            .redact_bank_account_with_strategy(account, strategy)
    }

    /// Redact routing number with explicit strategy
    #[must_use]
    pub fn redact_routing_number_with_strategy(
        &self,
        routing: &str,
        strategy: RoutingNumberRedactionStrategy,
    ) -> String {
        self.inner
            .redact_routing_number_with_strategy(routing, strategy)
    }

    /// Sanitize credit card (normalize + validate)
    pub fn sanitize_credit_card(&self, card: &str) -> Result<String, Problem> {
        self.inner.sanitize_credit_card(card)
    }

    /// Sanitize routing number (normalize + validate)
    pub fn sanitize_routing_number(&self, routing: &str) -> Result<String, Problem> {
        self.inner.sanitize_routing_number(routing)
    }

    /// Sanitize account number (normalize + validate)
    pub fn sanitize_account_number(&self, account: &str) -> Result<String, Problem> {
        self.inner.sanitize_account_number(account)
    }

    /// Redact a cryptocurrency wallet address with explicit strategy.
    #[must_use]
    pub fn redact_crypto_address_with_strategy(
        &self,
        addr: &str,
        strategy: CryptoAddressRedactionStrategy,
    ) -> String {
        self.inner
            .redact_crypto_address_with_strategy(addr, strategy)
    }

    /// Sanitize a crypto address (trim + validate checksum).
    ///
    /// Emits `validate_ms` timing on every call.
    pub fn sanitize_crypto_address(&self, addr: &str) -> Result<String, Problem> {
        let start = Instant::now();
        let result = self.inner.sanitize_crypto_address(addr);

        if self.emit_events {
            record(
                metric_names::validate_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );
        }

        result
    }

    /// Redact all crypto addresses in text with explicit strategy.
    #[must_use]
    pub fn redact_crypto_addresses_in_text_with_strategy<'a>(
        &self,
        text: &'a str,
        strategy: CryptoAddressRedactionStrategy,
    ) -> Cow<'a, str> {
        self.inner
            .redact_crypto_addresses_in_text_with_strategy(text, strategy)
    }

    /// Redact all credit cards in text with explicit strategy
    #[must_use]
    pub fn redact_credit_cards_in_text_with_strategy<'a>(
        &self,
        text: &'a str,
        strategy: CreditCardRedactionStrategy,
    ) -> Cow<'a, str> {
        self.inner
            .redact_credit_cards_in_text_with_strategy(text, strategy)
    }

    /// Redact all financial identifiers in text with explicit policy
    #[must_use]
    pub fn redact_all_in_text_with_policy(
        &self,
        text: &str,
        policy: FinancialTextPolicy,
    ) -> String {
        let start = Instant::now();
        let result = self.inner.redact_all_in_text_with_policy(text, policy);

        if self.emit_events {
            record(
                metric_names::redact_ms(),
                start.elapsed().as_micros() as f64 / 1000.0,
            );

            if result != text {
                observe::info(
                    "financial_data_redacted",
                    "Financial data redacted from text",
                );
            }
        }

        result
    }

    // ========================================================================
    // Conversion Methods
    // ========================================================================

    /// Normalize credit card number (remove formatting)
    #[must_use]
    pub fn normalize_card_number(&self, card: &str) -> String {
        self.inner.normalize_card_number(card)
    }

    /// Convert card to dash formatting
    #[must_use]
    pub fn to_card_with_dashes(&self, card: &str) -> String {
        self.inner.to_card_with_dashes(card)
    }

    /// Convert card to space formatting
    #[must_use]
    pub fn to_card_with_spaces(&self, card: &str) -> String {
        self.inner.to_card_with_spaces(card)
    }

    /// Extract card display info (type and last 4)
    #[must_use]
    pub fn extract_card_display_info(&self, card: &str) -> (CreditCardType, String) {
        self.inner.extract_card_display_info(card)
    }

    /// Extract BIN (first 6 digits)
    #[must_use]
    pub fn extract_bin(&self, card: &str) -> Option<String> {
        self.inner.extract_bin(card)
    }

    /// Extract last N digits
    #[must_use]
    pub fn extract_last_digits(&self, card: &str, n: usize) -> Option<String> {
        self.inner.extract_last_digits(card, n)
    }

    /// Convert card to display string (e.g., "Visa ending in 4242")
    #[must_use]
    pub fn to_card_display(&self, card: &str) -> String {
        self.inner.to_card_display(card)
    }

    /// Convert account to display string (e.g., "Account ending in 4567")
    #[must_use]
    pub fn to_account_display(&self, account: &str) -> String {
        self.inner.to_account_display(account)
    }

    /// Normalize account number (remove formatting)
    #[must_use]
    pub fn normalize_account_number(&self, account: &str) -> String {
        self.inner.normalize_account_number(account)
    }

    /// Normalize routing number (remove formatting)
    #[must_use]
    pub fn normalize_routing_number(&self, routing: &str) -> String {
        self.inner.normalize_routing_number(routing)
    }

    // ========================================================================
    // Test Pattern Detection
    // ========================================================================

    /// Check if credit card number is a known test pattern
    #[must_use]
    pub fn is_test_credit_card(&self, card: &str) -> bool {
        self.inner.is_test_credit_card(card)
    }

    // =========================================================================
    // Cache Management
    // =========================================================================

    /// Get combined cache statistics for all financial identifier caches
    ///
    /// Returns aggregated stats across Luhn and ABA validation caches.
    /// Use this for overall module performance monitoring.
    ///
    /// # Example
    ///
    /// ```rust
    /// use octarine::identifiers::FinancialBuilder;
    ///
    /// let builder = FinancialBuilder::new();
    /// let stats = builder.cache_stats();
    ///
    /// println!("Cache size: {}/{}", stats.size, stats.capacity);
    /// println!("Hit rate: {:.1}%", stats.hit_rate());
    /// ```
    #[must_use]
    pub fn cache_stats(&self) -> super::super::types::CacheStats {
        self.inner.cache_stats()
    }

    /// Get Luhn validation cache statistics (credit card checksums)
    ///
    /// Use this for debugging specific cache performance.
    #[must_use]
    pub fn luhn_cache_stats(&self) -> super::super::types::CacheStats {
        self.inner.luhn_cache_stats()
    }

    /// Get ABA routing number validation cache statistics
    ///
    /// Use this for debugging specific cache performance.
    #[must_use]
    pub fn aba_cache_stats(&self) -> super::super::types::CacheStats {
        self.inner.aba_cache_stats()
    }

    /// Clear all financial identifier caches
    ///
    /// Use this to reset cache state, typically for testing or memory management.
    pub fn clear_caches(&self) {
        self.inner.clear_caches();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = FinancialBuilder::new();
        assert!(builder.emit_events);

        let silent = FinancialBuilder::silent();
        assert!(!silent.emit_events);
    }

    #[test]
    fn test_with_events() {
        let builder = FinancialBuilder::new().with_events(false);
        assert!(!builder.emit_events);

        let builder = FinancialBuilder::silent().with_events(true);
        assert!(builder.emit_events);
    }

    #[test]
    fn test_credit_card_detection() {
        let builder = FinancialBuilder::silent();
        assert!(builder.is_credit_card("4242424242424242"));
    }

    #[test]
    fn test_find_credit_card() {
        let builder = FinancialBuilder::silent();
        assert_eq!(
            builder.find("4242424242424242"),
            Some(IdentifierType::CreditCard)
        );
    }

    #[test]
    fn test_redact_credit_card_with_strategy() {
        let builder = FinancialBuilder::silent();

        // ShowLast4 strategy (PCI-DSS)
        assert_eq!(
            builder.redact_credit_card_with_strategy(
                "4242424242424242",
                CreditCardRedactionStrategy::ShowLast4
            ),
            "************4242"
        );

        // ShowBinLast4 strategy (PCI-DSS)
        assert_eq!(
            builder.redact_credit_card_with_strategy(
                "4242424242424242",
                CreditCardRedactionStrategy::ShowBinLast4
            ),
            "424242******4242"
        );

        // Token strategy
        assert_eq!(
            builder.redact_credit_card_with_strategy(
                "4242424242424242",
                CreditCardRedactionStrategy::Token
            ),
            "[CREDIT_CARD]"
        );
    }

    #[test]
    fn test_validate_credit_card() {
        let builder = FinancialBuilder::silent();
        assert!(builder.validate_credit_card("4111111111111111").is_ok());
        assert!(builder.validate_credit_card("4111111111111112").is_err());
    }

    #[test]
    fn test_is_iban() {
        let builder = FinancialBuilder::silent();
        assert!(builder.is_iban("DE89370400440532013000"));
        assert!(!builder.is_iban("not-an-iban"));
    }

    #[test]
    fn test_detect_ibans_in_text() {
        let builder = FinancialBuilder::silent();
        let matches = builder.detect_ibans_in_text("IBAN: DE89 3704 0044 0532 0130 00");
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("one IBAN match expected");
        assert_eq!(first.identifier_type, IdentifierType::Iban);
    }

    #[test]
    fn test_detect_routing_numbers_in_text() {
        let builder = FinancialBuilder::silent();
        let matches = builder.detect_routing_numbers_in_text("ABA routing: 021000021");
        assert!(!matches.is_empty());
        let first = matches.first().expect("one routing match expected");
        assert_eq!(first.identifier_type, IdentifierType::RoutingNumber);

        let none = builder.detect_routing_numbers_in_text("no routing number here");
        assert!(none.is_empty());
    }

    #[test]
    fn test_detect_iban_country() {
        let builder = FinancialBuilder::silent();
        assert_eq!(
            builder.detect_iban_country("GB29NWBK60161331926819"),
            Some("GB")
        );
        assert_eq!(builder.detect_iban_country("not_iban"), None);
    }

    #[test]
    fn test_is_bitcoin_address() {
        let builder = FinancialBuilder::silent();
        assert!(builder.is_bitcoin_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
        assert!(!builder.is_bitcoin_address("not-a-wallet"));
    }

    #[test]
    fn test_is_ethereum_address() {
        let builder = FinancialBuilder::silent();
        assert!(builder.is_ethereum_address("0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18"));
    }

    #[test]
    fn test_is_crypto_address() {
        let builder = FinancialBuilder::silent();
        assert!(builder.is_crypto_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
        assert!(builder.is_crypto_address("0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18"));
    }

    #[test]
    fn test_detect_crypto_addresses_in_text() {
        let builder = FinancialBuilder::silent();
        let matches = builder.detect_crypto_addresses_in_text(
            "Wallets: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa and 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18",
        );
        assert_eq!(matches.len(), 2);
        assert!(
            matches
                .iter()
                .all(|m| m.identifier_type == IdentifierType::CryptoAddress)
        );
    }

    #[test]
    fn test_btc_checksum_validation() {
        let builder = FinancialBuilder::silent();
        assert!(builder.is_bitcoin_checksum_valid("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
        // Single-char typo (final `a` → `b`) breaks Base58Check.
        assert!(!builder.is_bitcoin_checksum_valid("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"));
    }

    #[test]
    fn test_eip55_validation() {
        let builder = FinancialBuilder::silent();
        // All-lowercase bypass.
        assert!(builder.is_ethereum_eip55_valid("0x742d35cc6634c0532925a3b844bc9e7595f2bd18"));
        // Valid EIP-55 mixed case.
        assert!(builder.is_ethereum_eip55_valid("0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"));
        // Flipped first letter case.
        assert!(!builder.is_ethereum_eip55_valid("0x5AAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"));
    }

    #[test]
    fn test_validate_crypto_address_builder() {
        let builder = FinancialBuilder::silent();
        let result = builder
            .validate_crypto_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
            .expect("Satoshi address validates");
        assert_eq!(result, CryptoAddressType::BitcoinP2PKH);

        assert!(
            builder
                .validate_crypto_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")
                .is_err()
        );
    }

    #[test]
    fn test_redact_crypto_address_builder() {
        let builder = FinancialBuilder::silent();
        let out = builder.redact_crypto_address_with_strategy(
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            CryptoAddressRedactionStrategy::Token,
        );
        assert_eq!(out, "[CRYPTO_ADDRESS]");
    }

    #[test]
    fn test_sanitize_crypto_address_builder() {
        let builder = FinancialBuilder::silent();
        assert_eq!(
            builder
                .sanitize_crypto_address("  1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa  ")
                .expect("valid"),
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
        );
        assert!(
            builder
                .sanitize_crypto_address("not-a-crypto-address")
                .is_err()
        );
    }
}
