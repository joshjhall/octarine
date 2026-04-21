//! Financial identifier builder API
//!
//! Provides a fluent API for financial identifier operations.

use super::super::types::{
    CreditCardType, DetectionConfidence, DetectionResult, IdentifierMatch, IdentifierType,
};
use super::{conversion, detection, sanitization, validation};
use crate::primitives::Problem;
use crate::primitives::collections::CacheStats;
use std::borrow::Cow;

/// Builder for financial identifier operations
///
/// Provides access to detection, validation, sanitization, and conversion
/// functions for financial identifiers (credit cards, bank accounts, etc.).
#[derive(Debug, Clone, Copy, Default)]
pub struct FinancialIdentifierBuilder;

impl FinancialIdentifierBuilder {
    /// Create a new builder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    // ========================================================================
    // Detection Methods
    // ========================================================================

    /// Find financial identifier type
    ///
    /// Returns the type of financial identifier (credit card, routing number, bank account).
    #[must_use]
    pub fn find(&self, value: &str) -> Option<IdentifierType> {
        detection::find_financial_identifier(value)
    }

    /// Check if value is any financial identifier
    #[must_use]
    pub fn is_financial_identifier(&self, value: &str) -> bool {
        detection::is_financial_identifier(value)
    }

    /// Detect financial identifier type (dual-API contract alias).
    ///
    /// Companion to [`Self::is_financial_identifier`] — both delegate to the
    /// same aggregate detector; this one returns the matched
    /// `IdentifierType`.
    #[must_use]
    pub fn detect_financial_identifier(&self, value: &str) -> Option<IdentifierType> {
        detection::detect_financial_identifier(value)
    }

    /// Check if value is a credit card
    #[must_use]
    pub fn is_credit_card(&self, value: &str) -> bool {
        detection::is_credit_card(value)
    }

    /// Check if value is a routing number
    #[must_use]
    pub fn is_routing_number(&self, value: &str) -> bool {
        detection::is_routing_number(value)
    }

    /// Check if value might be a bank account
    #[must_use]
    pub fn is_bank_account(&self, value: &str) -> bool {
        detection::is_bank_account(value)
    }

    /// Check if value is a valid IBAN (format + MOD-97 checksum)
    #[must_use]
    pub fn is_iban(&self, value: &str) -> bool {
        detection::is_iban(value)
    }

    /// Extract country code from an IBAN
    #[must_use]
    pub fn detect_iban_country<'a>(&self, value: &'a str) -> Option<&'a str> {
        detection::detect_iban_country(value)
    }

    /// Check if value is a Bitcoin address (P2PKH, P2SH, or Bech32/Bech32m)
    #[must_use]
    pub fn is_bitcoin_address(&self, value: &str) -> bool {
        detection::is_bitcoin_address(value)
    }

    /// Check if value is an Ethereum address (0x + 40 hex chars)
    #[must_use]
    pub fn is_ethereum_address(&self, value: &str) -> bool {
        detection::is_ethereum_address(value)
    }

    /// Check if value is any supported cryptocurrency address
    #[must_use]
    pub fn is_crypto_address(&self, value: &str) -> bool {
        detection::is_crypto_address(value)
    }

    /// Check if value is likely a credit card (less strict)
    #[must_use]
    pub fn is_credit_card_likely(&self, value: &str) -> bool {
        detection::is_credit_card_likely(value)
    }

    /// Detect credit card with context for confidence scoring
    #[must_use]
    pub fn detect_credit_card_with_context(
        &self,
        value: &str,
        context: Option<&str>,
    ) -> Option<DetectionResult> {
        detection::detect_credit_card_with_context(value, context)
    }

    /// Detect routing number with ABA checksum validation
    #[must_use]
    pub fn detect_routing_number(&self, value: &str) -> Option<DetectionResult> {
        detection::detect_routing_number(value)
    }

    /// Detect credit card brand (Visa, MasterCard, etc.)
    #[must_use]
    pub fn detect_card_brand(&self, value: &str) -> Option<CreditCardType> {
        detection::detect_card_brand(value)
    }

    // ========================================================================
    // Text Scanning Methods
    // ========================================================================

    /// Detect all credit cards in text
    #[must_use]
    pub fn detect_credit_cards_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::detect_credit_cards_in_text(text)
    }

    /// Detect all payment tokens in text
    #[must_use]
    pub fn detect_payment_tokens_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::detect_payment_tokens_in_text(text)
    }

    /// Detect all bank accounts in text
    #[must_use]
    pub fn detect_bank_accounts_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::detect_bank_accounts_in_text(text)
    }

    /// Detect all routing numbers in text with ABA checksum validation
    #[must_use]
    pub fn detect_routing_numbers_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::detect_routing_numbers_in_text(text)
    }

    /// Detect all IBANs in text with MOD-97 checksum validation
    #[must_use]
    pub fn detect_ibans_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::detect_ibans_in_text(text)
    }

    /// Detect all cryptocurrency addresses in text
    ///
    /// Covers Bitcoin (P2PKH, P2SH, Bech32/Bech32m) and Ethereum address patterns.
    #[must_use]
    pub fn detect_crypto_addresses_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::detect_crypto_addresses_in_text(text)
    }

    /// Detect all financial identifiers in text
    #[must_use]
    pub fn detect_all_in_text(&self, text: &str) -> Vec<IdentifierMatch> {
        detection::detect_all_financial_in_text(text)
    }

    /// Check if text contains any financial identifier
    #[must_use]
    pub fn is_financial_present(&self, text: &str) -> bool {
        detection::is_financial_present(text)
    }

    // ========================================================================
    // Validation Methods
    // ========================================================================

    /// Validate credit card number
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the card number is invalid
    pub fn validate_credit_card(&self, card_number: &str) -> Result<CreditCardType, Problem> {
        validation::validate_credit_card(card_number)
    }

    /// Detect credit card type from pattern
    #[must_use]
    pub fn detect_card_type(&self, card_number: &str) -> CreditCardType {
        detection::detect_card_brand(card_number).unwrap_or(CreditCardType::Unknown)
    }

    /// Check if text matches credit card pattern
    #[must_use]
    pub fn is_credit_card_pattern(&self, text: &str) -> bool {
        detection::is_credit_card_pattern(text)
    }

    /// Validate routing number
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the routing number is invalid
    pub fn validate_routing_number(&self, routing: &str) -> Result<(), Problem> {
        validation::validate_routing_number(routing)
    }

    /// Validate account number
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the account number is invalid
    pub fn validate_account_number(&self, account: &str) -> Result<(), Problem> {
        validation::validate_account_number(account)
    }

    /// Validate complete bank account
    ///
    /// # Errors
    ///
    /// Returns `Problem` if the routing or account number is invalid
    pub fn validate_bank_account(&self, routing: &str, account: &str) -> Result<(), Problem> {
        validation::validate_bank_account(routing, account)
    }

    /// Check if text contains payment data
    #[must_use]
    pub fn is_payment_data_present(&self, text: &str) -> bool {
        detection::is_payment_data_present(text)
    }

    // ========================================================================
    // Sanitization Methods (Strategy Required)
    // ========================================================================

    /// Redact credit card with explicit strategy
    #[must_use]
    pub fn redact_credit_card_with_strategy(
        &self,
        card: &str,
        strategy: super::CreditCardRedactionStrategy,
    ) -> String {
        sanitization::redact_credit_card_with_strategy(card, strategy)
    }

    /// Redact bank account with explicit strategy
    #[must_use]
    pub fn redact_bank_account_with_strategy(
        &self,
        account: &str,
        strategy: super::BankAccountRedactionStrategy,
    ) -> String {
        sanitization::redact_bank_account_with_strategy(account, strategy)
    }

    /// Redact routing number with explicit strategy
    #[must_use]
    pub fn redact_routing_number_with_strategy(
        &self,
        routing: &str,
        strategy: super::RoutingNumberRedactionStrategy,
    ) -> String {
        sanitization::redact_routing_number_with_strategy(routing, strategy)
    }

    /// Redact payment token with explicit strategy
    #[must_use]
    pub fn redact_payment_token_with_strategy(
        &self,
        token: &str,
        strategy: super::PaymentTokenRedactionStrategy,
    ) -> String {
        sanitization::redact_payment_token_with_strategy(token, strategy)
    }

    /// Sanitize credit card strict (normalize + validate)
    ///
    /// Removes formatting and validates the card number.
    /// Returns normalized digits if valid, error otherwise.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let builder = FinancialIdentifierBuilder::new();
    /// let clean = builder.sanitize_credit_card("4242-4242-4242-4242")?;
    /// assert_eq!(clean, "4242424242424242");
    /// ```
    pub fn sanitize_credit_card(&self, card: &str) -> Result<String, crate::primitives::Problem> {
        sanitization::sanitize_credit_card_strict(card)
    }

    /// Sanitize routing number strict (normalize + validate)
    ///
    /// Removes formatting and validates the routing number.
    /// Returns normalized 9 digits if valid, error otherwise.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let builder = FinancialIdentifierBuilder::new();
    /// let clean = builder.sanitize_routing_number("021-000-021")?;
    /// assert_eq!(clean, "021000021");
    /// ```
    pub fn sanitize_routing_number(
        &self,
        routing: &str,
    ) -> Result<String, crate::primitives::Problem> {
        sanitization::sanitize_routing_number_strict(routing)
    }

    /// Sanitize account number strict (normalize + validate)
    ///
    /// Removes formatting and validates the account number.
    /// Returns normalized digits if valid, error otherwise.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let builder = FinancialIdentifierBuilder::new();
    /// let clean = builder.sanitize_account_number("12345-6789")?;
    /// assert_eq!(clean, "123456789");
    /// ```
    pub fn sanitize_account_number(
        &self,
        account: &str,
    ) -> Result<String, crate::primitives::Problem> {
        sanitization::sanitize_account_number_strict(account)
    }

    /// Redact all credit cards in text with explicit strategy
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::financial::{
    ///     FinancialIdentifierBuilder, CreditCardRedactionStrategy,
    /// };
    ///
    /// let builder = FinancialIdentifierBuilder::new();
    /// let result = builder.redact_credit_cards_in_text_with_strategy(
    ///     "Card: 4242-4242-4242-4242",
    ///     CreditCardRedactionStrategy::Token,
    /// );
    /// assert!(result.contains("[CREDIT_CARD]"));
    /// ```
    #[must_use]
    pub fn redact_credit_cards_in_text_with_strategy<'a>(
        &self,
        text: &'a str,
        strategy: super::CreditCardRedactionStrategy,
    ) -> Cow<'a, str> {
        sanitization::redact_credit_cards_in_text_with_strategy(text, strategy)
    }

    /// Redact all bank accounts in text with explicit strategy
    #[must_use]
    pub fn redact_bank_accounts_in_text_with_strategy<'a>(
        &self,
        text: &'a str,
        strategy: super::BankAccountRedactionStrategy,
    ) -> Cow<'a, str> {
        sanitization::redact_bank_accounts_in_text_with_strategy(text, strategy)
    }

    /// Redact all payment tokens in text with explicit strategy
    #[must_use]
    pub fn redact_payment_tokens_in_text_with_strategy<'a>(
        &self,
        text: &'a str,
        strategy: super::PaymentTokenRedactionStrategy,
    ) -> Cow<'a, str> {
        sanitization::redact_payment_tokens_in_text_with_strategy(text, strategy)
    }

    /// Redact all financial identifiers in text with explicit policy
    #[must_use]
    pub fn redact_all_in_text_with_policy(
        &self,
        text: &str,
        policy: super::redaction::TextRedactionPolicy,
    ) -> String {
        sanitization::redact_all_financial_in_text_with_policy(text, policy)
    }

    // ========================================================================
    // Conversion Methods
    // ========================================================================

    /// Normalize credit card number (remove formatting)
    #[must_use]
    pub fn normalize_card_number(&self, card: &str) -> String {
        conversion::normalize_card_number(card)
    }

    /// Convert card to dash formatting
    #[must_use]
    pub fn to_card_with_dashes(self, card: &str) -> String {
        conversion::to_card_with_dashes(card)
    }

    /// Convert card to space formatting
    #[must_use]
    pub fn to_card_with_spaces(self, card: &str) -> String {
        conversion::to_card_with_spaces(card)
    }

    /// Extract card display info (type and last 4)
    #[must_use]
    pub fn extract_card_display_info(&self, card: &str) -> (CreditCardType, String) {
        conversion::extract_card_display_info(card)
    }

    /// Extract BIN (first 6 digits)
    #[must_use]
    pub fn extract_bin(&self, card: &str) -> Option<String> {
        conversion::extract_bin(card)
    }

    /// Extract last N digits
    #[must_use]
    pub fn extract_last_digits(&self, card: &str, n: usize) -> Option<String> {
        conversion::extract_last_digits(card, n)
    }

    /// Convert card to display string (e.g., "Visa ending in 4242")
    #[must_use]
    pub fn to_card_display(self, card: &str) -> String {
        conversion::to_card_display(card)
    }

    /// Convert account to display string (e.g., "Account ending in 4567")
    #[must_use]
    pub fn to_account_display(self, account: &str) -> String {
        conversion::to_account_display(account)
    }

    /// Normalize account number (remove formatting)
    #[must_use]
    pub fn normalize_account_number(&self, account: &str) -> String {
        conversion::normalize_account_number(account)
    }

    /// Normalize routing number (remove formatting)
    #[must_use]
    pub fn normalize_routing_number(&self, routing: &str) -> String {
        conversion::normalize_routing_number(routing)
    }

    // ========================================================================
    // Cache Operations
    // ========================================================================

    /// Get combined cache statistics for all financial identifier caches
    ///
    /// Returns aggregated stats across Luhn checksum and ABA routing caches.
    /// Use this for overall module performance monitoring.
    #[must_use]
    pub fn cache_stats(&self) -> CacheStats {
        detection::luhn_cache_stats().combine(&detection::aba_cache_stats())
    }

    /// Get Luhn checksum cache statistics
    ///
    /// Use this for debugging specific cache performance.
    #[must_use]
    pub fn luhn_cache_stats(&self) -> CacheStats {
        detection::luhn_cache_stats()
    }

    /// Get ABA routing number cache statistics
    ///
    /// Use this for debugging specific cache performance.
    #[must_use]
    pub fn aba_cache_stats(&self) -> CacheStats {
        detection::aba_cache_stats()
    }

    /// Clear all financial detection caches
    pub fn clear_caches(&self) {
        detection::clear_financial_caches();
    }

    // ========================================================================
    // Test Pattern Detection
    // ========================================================================

    /// Check if credit card number is a known test/sample pattern
    ///
    /// Detects common test card numbers used by payment processors
    /// (Stripe, generic test cards, etc.).
    ///
    /// # Examples
    ///
    /// ```ignore
    /// use octarine::primitives::identifiers::financial::FinancialIdentifierBuilder;
    ///
    /// let builder = FinancialIdentifierBuilder::new();
    /// assert!(builder.is_test_credit_card("4242424242424242"));
    /// assert!(builder.is_test_credit_card("4111-1111-1111-1111"));
    /// assert!(!builder.is_test_credit_card("4532015112830366"));
    /// ```
    #[must_use]
    pub fn is_test_credit_card(&self, card: &str) -> bool {
        detection::is_test_credit_card(card)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_builder_creation() {
        let _builder = FinancialIdentifierBuilder::new();
        let _builder2 = FinancialIdentifierBuilder;
    }

    #[test]
    fn test_find_credit_card() {
        let builder = FinancialIdentifierBuilder::new();
        assert_eq!(
            builder.find("4242424242424242"),
            Some(IdentifierType::CreditCard)
        );
    }

    #[test]
    fn test_find_routing_number() {
        let builder = FinancialIdentifierBuilder::new();
        assert_eq!(
            builder.find("121000358"),
            Some(IdentifierType::RoutingNumber)
        );
    }

    #[test]
    fn test_is_credit_card() {
        let builder = FinancialIdentifierBuilder::new();
        assert!(builder.is_credit_card("4242424242424242"));
        assert!(!builder.is_credit_card("not a card"));
    }

    #[test]
    fn test_is_routing_number() {
        let builder = FinancialIdentifierBuilder::new();
        assert!(builder.is_routing_number("121000358"));
        assert!(!builder.is_routing_number("000000001"));
    }

    #[test]
    fn test_detect_card_brand() {
        let builder = FinancialIdentifierBuilder::new();
        let brand = builder.detect_card_brand("4242424242424242");
        assert_eq!(brand, Some(CreditCardType::Visa));
    }

    #[test]
    fn test_detect_credit_cards_in_text() {
        let builder = FinancialIdentifierBuilder::new();
        let matches = builder.detect_credit_cards_in_text("Card: 4242-4242-4242-4242");
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_detect_all_in_text() {
        let builder = FinancialIdentifierBuilder::new();
        let matches = builder.detect_all_in_text("Card: 4242-4242-4242-4242");
        assert!(!matches.is_empty());
    }

    #[test]
    fn test_is_financial_present() {
        let builder = FinancialIdentifierBuilder::new();
        assert!(builder.is_financial_present("Card: 4242-4242-4242-4242"));
        assert!(!builder.is_financial_present("No financial data"));
    }

    #[test]
    fn test_is_iban() {
        let builder = FinancialIdentifierBuilder::new();
        assert!(builder.is_iban("DE89370400440532013000"));
        assert!(builder.is_iban("GB29 NWBK 6016 1331 9268 19"));
        assert!(!builder.is_iban("DE00370400440532013000"));
        assert!(!builder.is_iban("not-an-iban"));
    }

    #[test]
    fn test_detect_iban_country() {
        let builder = FinancialIdentifierBuilder::new();
        assert_eq!(
            builder.detect_iban_country("DE89370400440532013000"),
            Some("DE")
        );
        assert_eq!(
            builder.detect_iban_country("GB29NWBK60161331926819"),
            Some("GB")
        );
        assert_eq!(builder.detect_iban_country("not_iban"), None);
    }

    #[test]
    fn test_detect_ibans_in_text() {
        let builder = FinancialIdentifierBuilder::new();
        let matches = builder.detect_ibans_in_text(
            "Transfer to DE89 3704 0044 0532 0130 00 or GB29 NWBK 6016 1331 9268 19",
        );
        assert_eq!(matches.len(), 2);
        assert!(
            matches
                .iter()
                .all(|m| m.identifier_type == IdentifierType::Iban)
        );
    }

    #[test]
    fn test_detect_routing_numbers_in_text() {
        let builder = FinancialIdentifierBuilder::new();
        let matches = builder.detect_routing_numbers_in_text("ABA routing: 021000021");
        assert!(!matches.is_empty());
        assert!(
            matches
                .iter()
                .all(|m| m.identifier_type == IdentifierType::RoutingNumber)
        );

        let none = builder.detect_routing_numbers_in_text("no routing number here");
        assert!(none.is_empty());
    }

    #[test]
    fn test_is_bitcoin_address() {
        let builder = FinancialIdentifierBuilder::new();
        assert!(builder.is_bitcoin_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
        assert!(builder.is_bitcoin_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"));
        assert!(builder.is_bitcoin_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
        assert!(!builder.is_bitcoin_address("not-a-wallet"));
    }

    #[test]
    fn test_is_ethereum_address() {
        let builder = FinancialIdentifierBuilder::new();
        assert!(builder.is_ethereum_address("0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18"));
        assert!(!builder.is_ethereum_address("0x123"));
    }

    #[test]
    fn test_is_crypto_address() {
        let builder = FinancialIdentifierBuilder::new();
        assert!(builder.is_crypto_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"));
        assert!(builder.is_crypto_address("0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18"));
        assert!(!builder.is_crypto_address("not_crypto"));
    }

    #[test]
    fn test_detect_crypto_addresses_in_text() {
        let builder = FinancialIdentifierBuilder::new();
        let matches = builder.detect_crypto_addresses_in_text(
            "BTC 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa and ETH 0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18",
        );
        assert_eq!(matches.len(), 2);
        assert!(
            matches
                .iter()
                .all(|m| m.identifier_type == IdentifierType::CryptoAddress)
        );
    }

    // ===== Validation Method Tests =====

    #[test]
    fn test_validate_credit_card() {
        let builder = FinancialIdentifierBuilder::new();
        assert!(builder.validate_credit_card("4111111111111111").is_ok());
        assert!(builder.validate_credit_card("4111111111111112").is_err());
    }

    #[test]
    fn test_validate_credit_card_returns_card_type() {
        let builder = FinancialIdentifierBuilder::new();
        let result = builder.validate_credit_card("4111111111111111");
        assert!(result.is_ok());
        assert_eq!(
            result.expect("Visa validation should succeed"),
            super::CreditCardType::Visa
        );
    }

    #[test]
    fn test_detect_card_type() {
        let builder = FinancialIdentifierBuilder::new();
        assert_eq!(
            builder.detect_card_type("4111111111111111"),
            super::CreditCardType::Visa
        );
    }

    #[test]
    fn test_validate_routing_number() {
        let builder = FinancialIdentifierBuilder::new();
        assert!(builder.validate_routing_number("021000021").is_ok());
        assert!(builder.validate_routing_number("123456789").is_err());
    }

    #[test]
    fn test_validate_account_number() {
        let builder = FinancialIdentifierBuilder::new();
        assert!(builder.validate_account_number("1234567890").is_ok());
        assert!(builder.validate_account_number("").is_err());
    }

    #[test]
    fn test_validate_bank_account() {
        let builder = FinancialIdentifierBuilder::new();
        assert!(
            builder
                .validate_bank_account("021000021", "1234567890")
                .is_ok()
        );
        assert!(
            builder
                .validate_bank_account("123456789", "1234567890")
                .is_err()
        );
    }

    #[test]
    fn test_is_payment_data_present() {
        let builder = FinancialIdentifierBuilder::new();
        assert!(builder.is_payment_data_present("Card: 4111111111111111"));
        assert!(!builder.is_payment_data_present("No payment data here"));
    }

    // ===== Sanitization Method Tests =====

    #[test]
    fn test_redact_credit_card_with_strategy_builder() {
        use super::super::CreditCardRedactionStrategy;
        let builder = FinancialIdentifierBuilder::new();

        // ShowLast4 strategy (PCI-DSS compliant)
        assert_eq!(
            builder.redact_credit_card_with_strategy(
                "4242424242424242",
                CreditCardRedactionStrategy::ShowLast4
            ),
            "************4242"
        );

        // ShowBinLast4 strategy (PCI-DSS compliant)
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
    fn test_redact_bank_account_with_strategy_builder() {
        use super::super::BankAccountRedactionStrategy;
        let builder = FinancialIdentifierBuilder::new();
        assert_eq!(
            builder.redact_bank_account_with_strategy(
                "000000001",
                BankAccountRedactionStrategy::ShowLast4
            ),
            "****0001"
        );
    }

    #[test]
    fn test_redact_routing_number_with_strategy_builder() {
        use super::super::RoutingNumberRedactionStrategy;
        let builder = FinancialIdentifierBuilder::new();
        assert_eq!(
            builder.redact_routing_number_with_strategy(
                "000000001",
                RoutingNumberRedactionStrategy::Token
            ),
            "[ROUTING_NUMBER]"
        );
    }

    #[test]
    fn test_redact_all_in_text_with_policy_builder() {
        use super::super::redaction::TextRedactionPolicy;
        let builder = FinancialIdentifierBuilder::new();
        let text = "Card: 4242-4242-4242-4242, Token: tok_1A2B3C4D5E6F7G8H9I0J1K2L";

        // Complete policy (token replacement)
        let result = builder.redact_all_in_text_with_policy(text, TextRedactionPolicy::Complete);
        assert!(result.contains("[CREDIT_CARD]"));
        assert!(result.contains("[PAYMENT_TOKEN]"));

        // Partial policy (show last 4)
        let result = builder.redact_all_in_text_with_policy(text, TextRedactionPolicy::Partial);
        assert!(result.contains("4242")); // Credit card last 4 visible
        // Payment token with Partial shows last 4 chars: "1K2L"
        assert!(result.contains("1K2L"));
    }

    // ===== Conversion Method Tests =====

    #[test]
    fn test_normalize_card_number_builder() {
        let builder = FinancialIdentifierBuilder::new();
        assert_eq!(
            builder.normalize_card_number("4242-4242-4242-4242"),
            "4242424242424242"
        );
    }

    #[test]
    fn test_to_card_with_dashes_builder() {
        let builder = FinancialIdentifierBuilder::new();
        assert_eq!(
            builder.to_card_with_dashes("4242424242424242"),
            "4242-4242-4242-4242"
        );
    }

    #[test]
    fn test_to_card_display_builder() {
        let builder = FinancialIdentifierBuilder::new();
        assert_eq!(
            builder.to_card_display("4242424242424242"),
            "Visa ending in 4242"
        );
    }

    #[test]
    fn test_extract_bin_builder() {
        let builder = FinancialIdentifierBuilder::new();
        assert_eq!(
            builder.extract_bin("4242424242424242"),
            Some("424242".to_string())
        );
    }

    #[test]
    fn test_extract_last_digits_builder() {
        let builder = FinancialIdentifierBuilder::new();
        assert_eq!(
            builder.extract_last_digits("4242424242424242", 4),
            Some("4242".to_string())
        );
    }
}
