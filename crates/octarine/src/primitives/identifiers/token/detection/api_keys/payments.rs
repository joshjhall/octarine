//! Payment processor API key detection (Stripe, Square, Shopify, PayPal/Braintree).

use super::super::super::super::common::patterns;
use super::MAX_IDENTIFIER_LENGTH;

/// Check if value is a Stripe API key
///
/// Stripe keys start with "sk_" or "pk_" followed by "live" or "test"
#[must_use]
pub fn is_stripe_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_STRIPE.is_match(trimmed)
}

/// Check if value is a Square API key
///
/// Square keys start with "sq0atp-" (OAuth access), "sq0csp-" (OAuth secret),
/// or "sq0idp-" (Application ID)
#[must_use]
pub fn is_square_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_SQUARE.is_match(trimmed)
}

/// Check if value is a Shopify API token
///
/// Shopify tokens start with "shpat_" (app access), "shpca_" (custom app),
/// "shppa_" (private app), or "shpss_" (shared secret), followed by 32 hex chars
#[must_use]
pub fn is_shopify_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_SHOPIFY.is_match(trimmed)
}

/// Check if value is a PayPal/Braintree access token
///
/// Braintree access tokens have the format:
/// `access_token$production$[a-z0-9]{16}$[a-f0-9]{32}` (or sandbox)
#[must_use]
pub fn is_paypal_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_PAYPAL_BRAINTREE.is_match(trimmed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_stripe_key() {
        assert!(is_stripe_key(&format!(
            "sk_live_{}",
            "EXAMPLE000000000KEY01abcdef"
        )));
        assert!(is_stripe_key(&format!(
            "pk_test_{}",
            "EXAMPLE000000000KEY01abcdef"
        )));
        assert!(!is_stripe_key("sk_prod_12345")); // Wrong environment
        assert!(!is_stripe_key("xk_live_12345")); // Wrong prefix
    }

    #[test]
    fn test_is_square_token() {
        // Valid Square OAuth access tokens (sq0atp- + 22+ chars)
        assert!(is_square_token(&format!(
            "sq0atp-{}",
            "ABCDEFghijklmnopqrstuv"
        )));
        // Valid Square OAuth secret (sq0csp- + 43+ chars)
        assert!(is_square_token(&format!(
            "sq0csp-{}",
            "ABCDEFghijklmnopqrstuvwxyz0123456789ABCDEFG"
        )));
        // Valid Square Application ID (sq0idp- + 22+ chars)
        assert!(is_square_token(&format!(
            "sq0idp-{}",
            "ABCDEFghijklmnopqrstuv"
        )));
        // Invalid: wrong prefix
        assert!(!is_square_token("sq1atp-ABCDEFghijklmnopqrstuv"));
        // Invalid: too short
        assert!(!is_square_token("sq0atp-short"));
    }

    #[test]
    fn test_is_shopify_token() {
        // Valid Shopify app access token (shpat_ + 32 hex chars)
        assert!(is_shopify_token(&format!(
            "shpat_{}",
            "abcdef1234567890abcdef1234567890"
        )));
        // Valid custom app token
        assert!(is_shopify_token(&format!(
            "shpca_{}",
            "abcdef1234567890abcdef1234567890"
        )));
        // Valid private app token
        assert!(is_shopify_token(&format!(
            "shppa_{}",
            "abcdef1234567890abcdef1234567890"
        )));
        // Valid shared secret
        assert!(is_shopify_token(&format!(
            "shpss_{}",
            "ABCDEF1234567890ABCDEF1234567890"
        )));
        // Invalid: wrong prefix
        assert!(!is_shopify_token("shpxx_abcdef1234567890abcdef1234567890"));
        // Invalid: too short
        assert!(!is_shopify_token("shpat_abcdef"));
        // Invalid: non-hex chars
        assert!(!is_shopify_token("shpat_ghijklmnopqrstuvwxyz12345678zz"));
    }

    #[test]
    fn test_is_paypal_token() {
        // Valid Braintree production access token
        let prod_token = format!(
            "access_token$production${}${}",
            "abc1234567890xyz", "abcdef1234567890abcdef1234567890"
        );
        assert!(is_paypal_token(&prod_token));
        // Valid Braintree sandbox access token
        let sandbox_token = format!(
            "access_token$sandbox${}${}",
            "abc1234567890xyz", "abcdef1234567890abcdef1234567890"
        );
        assert!(is_paypal_token(&sandbox_token));
        // Invalid: wrong environment
        assert!(!is_paypal_token(
            "access_token$staging$abc1234567890xyz$abcdef1234567890abcdef1234567890"
        ));
        // Invalid: missing parts
        assert!(!is_paypal_token("access_token$production$short"));
    }
}
