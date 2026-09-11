//! Integration tests for CSRF protection (issue #413).
//!
//! `auth/csrf/protection.rs` had inline unit tests for the algorithm but was
//! the only `auth/` submodule with no entry under `tests/auth/`. These tests
//! drive `CsrfProtection` through the public `octarine::auth` surface, the
//! same way `tests/auth/{lockout,reset,session,remember}.rs` drive theirs.

#![allow(clippy::panic, clippy::expect_used)]

use octarine::auth::{CsrfConfig, CsrfProtection, CsrfSameSite};

// ============================================================================
// Synchronizer token pattern
// ============================================================================

/// A freshly generated token validates against itself.
#[test]
fn test_csrf_generate_then_validate_round_trip() {
    let csrf = CsrfProtection::new();
    let token = csrf.generate_token();

    assert!(
        csrf.validate(token.value(), &token).is_ok(),
        "a token must validate against itself"
    );
}

/// A different token is rejected — this is what rules out an
/// always-`Ok` validator.
#[test]
fn test_csrf_validate_rejects_foreign_token() {
    let csrf = CsrfProtection::new();
    let expected = csrf.generate_token();
    let other = csrf.generate_token();

    assert!(
        csrf.validate(other.value(), &expected).is_err(),
        "a token from a different session must be rejected"
    );
}

/// A truncated prefix of the correct token is rejected — a prefix-comparison
/// bug would let this through.
#[test]
fn test_csrf_validate_rejects_truncated_token() {
    let csrf = CsrfProtection::new();
    let token = csrf.generate_token();

    let value = token.value();
    let truncated = value.get(..value.len().saturating_sub(1)).unwrap_or("");

    assert!(
        !truncated.is_empty(),
        "test setup: generated token should be longer than one character"
    );
    assert!(
        csrf.validate(truncated, &token).is_err(),
        "a truncated token must be rejected"
    );
    assert!(
        csrf.validate("", &token).is_err(),
        "an empty submission must be rejected"
    );
}

/// Two independently generated tokens differ — guards against a constant or
/// seeded-once token generator.
#[test]
fn test_csrf_tokens_are_unique_per_generation() {
    let csrf = CsrfProtection::new();

    let first = csrf.generate_token();
    let second = csrf.generate_token();

    assert_ne!(
        first.value(),
        second.value(),
        "each generated CSRF token must be distinct"
    );
    assert!(
        !first.value().is_empty(),
        "a generated token must not be empty"
    );
}

// ============================================================================
// Double-submit cookie pattern
// ============================================================================

/// Matching header and cookie values pass; mismatching ones do not.
#[test]
fn test_csrf_double_submit_match_and_mismatch() {
    let csrf = CsrfProtection::new();
    let token = csrf.generate_token();
    let other = csrf.generate_token();

    assert!(
        csrf.validate_double_submit(token.value(), token.value())
            .is_ok(),
        "identical header and cookie values must validate"
    );
    assert!(
        csrf.validate_double_submit(token.value(), other.value())
            .is_err(),
        "differing header and cookie values must be rejected"
    );
}

/// Two empty strings are trivially equal — assert the real-world asymmetric
/// cases instead, where only one side is missing.
#[test]
fn test_csrf_double_submit_rejects_missing_side() {
    let csrf = CsrfProtection::new();
    let token = csrf.generate_token();

    assert!(
        csrf.validate_double_submit("", token.value()).is_err(),
        "a missing header value must be rejected"
    );
    assert!(
        csrf.validate_double_submit(token.value(), "").is_err(),
        "a missing cookie value must be rejected"
    );
}

// ============================================================================
// Safe-method classification
// ============================================================================

/// Safe methods skip validation; state-changing methods require it.
#[test]
fn test_csrf_requires_validation_by_method() {
    let csrf = CsrfProtection::new();

    for safe in ["GET", "HEAD", "OPTIONS", "TRACE"] {
        assert!(
            !csrf.requires_validation(safe),
            "{safe} is a safe method and must not require CSRF validation"
        );
    }

    for unsafe_method in ["POST", "PUT", "PATCH", "DELETE"] {
        assert!(
            csrf.requires_validation(unsafe_method),
            "{unsafe_method} changes state and must require CSRF validation"
        );
    }
}

/// Method matching is case-insensitive in both directions.
#[test]
fn test_csrf_requires_validation_is_case_insensitive() {
    let csrf = CsrfProtection::new();

    assert!(
        !csrf.requires_validation("get"),
        "lowercase GET must still be treated as safe"
    );
    assert!(
        csrf.requires_validation("post"),
        "lowercase POST must still require validation"
    );
}

// ============================================================================
// Cookie header construction
// ============================================================================

/// The default (secure) config emits a hardened Set-Cookie value.
#[test]
fn test_csrf_cookie_header_value_secure_config() {
    let csrf = CsrfProtection::new();
    let token = csrf.generate_token();
    let cookie = csrf.cookie_header_value(&token);

    assert!(
        cookie.starts_with(&format!("{}={}", csrf.cookie_name(), token.value())),
        "cookie must lead with name=value, got {cookie:?}"
    );
    assert!(cookie.contains("; Path=/"), "got {cookie:?}");
    assert!(cookie.contains("; HttpOnly"), "got {cookie:?}");
    assert!(
        cookie.contains("; Secure"),
        "the default config is secure, so Secure must be present: {cookie:?}"
    );
    assert!(cookie.contains("; SameSite="), "got {cookie:?}");
}

/// `Secure` is emitted **only** when the config asks for it. Without this
/// negative case, the assertion above would also pass for a hardcoded string.
#[test]
fn test_csrf_cookie_header_value_omits_secure_when_disabled() {
    let config = CsrfConfig {
        secure: false,
        ..CsrfConfig::default()
    };
    let csrf = CsrfProtection::with_config(config);
    let token = csrf.generate_token();
    let cookie = csrf.cookie_header_value(&token);

    assert!(
        !cookie.contains("Secure"),
        "Secure must be absent when config.secure is false, got {cookie:?}"
    );
    // The rest of the hardening is unconditional and must still be there.
    assert!(cookie.contains("; HttpOnly"), "got {cookie:?}");
    assert!(cookie.contains("; Path=/"), "got {cookie:?}");
}

/// The `SameSite` policy from the config reaches the cookie header.
#[test]
fn test_csrf_cookie_header_value_reflects_same_site_policy() {
    let config = CsrfConfig {
        same_site: CsrfSameSite::Lax,
        ..CsrfConfig::default()
    };
    let csrf = CsrfProtection::with_config(config);
    let token = csrf.generate_token();
    let cookie = csrf.cookie_header_value(&token);

    assert!(
        cookie.contains("SameSite=Lax"),
        "the configured SameSite policy must appear in the cookie: {cookie:?}"
    );
    assert!(
        !cookie.contains("SameSite=Strict"),
        "the default Strict policy must have been overridden: {cookie:?}"
    );
}

// ============================================================================
// Configuration accessors
// ============================================================================

/// The accessors report the custom config, not the defaults.
#[test]
fn test_csrf_accessors_reflect_custom_config() {
    let config = CsrfConfig {
        cookie_name: "my_csrf_cookie".to_string(),
        header_name: "X-My-Csrf".to_string(),
        form_field_name: "my_csrf_field".to_string(),
        ..CsrfConfig::default()
    };
    let csrf = CsrfProtection::with_config(config);

    assert_eq!(csrf.cookie_name(), "my_csrf_cookie");
    assert_eq!(csrf.header_name(), "X-My-Csrf");
    assert_eq!(csrf.form_field_name(), "my_csrf_field");

    // Each differs from the default it replaced, so a stubbed accessor fails.
    let defaults = CsrfProtection::new();
    assert_ne!(csrf.cookie_name(), defaults.cookie_name());
    assert_ne!(csrf.header_name(), defaults.header_name());
    assert_ne!(csrf.form_field_name(), defaults.form_field_name());
}

/// `config()` exposes the stored configuration.
#[test]
fn test_csrf_config_accessor() {
    let config = CsrfConfig {
        token_length: 48,
        ..CsrfConfig::default()
    };
    let csrf = CsrfProtection::with_config(config);

    assert_eq!(csrf.config().token_length, 48);
    assert_eq!(
        CsrfProtection::new().config().token_length,
        32,
        "default token length is 32 bytes"
    );
}

/// A longer configured token length produces a longer encoded token.
#[test]
fn test_csrf_token_length_affects_generated_token() {
    let short = CsrfProtection::with_config(CsrfConfig {
        token_length: 16,
        ..CsrfConfig::default()
    });
    let long = CsrfProtection::with_config(CsrfConfig {
        token_length: 64,
        ..CsrfConfig::default()
    });

    assert!(
        long.generate_token().value().len() > short.generate_token().value().len(),
        "a larger token_length must yield a longer token"
    );
}
