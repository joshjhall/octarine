//! HTTP security primitives
//!
//! Pure helpers for building security-related header values and detecting
//! the deployment environment from process env vars.

/// Configuration for building a `Strict-Transport-Security` header value.
#[derive(Debug, Clone, Copy)]
pub struct HstsConfig {
    /// Max-age in seconds.
    pub max_age: u64,
    /// Whether to add the `includeSubDomains` directive.
    pub include_subdomains: bool,
    /// Whether to add the `preload` directive.
    pub preload: bool,
}

/// Build a `Strict-Transport-Security` header value from the given config.
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::http::security::{HstsConfig, build_hsts_value};
///
/// let value = build_hsts_value(&HstsConfig {
///     max_age: 31_536_000,
///     include_subdomains: true,
///     preload: false,
/// });
/// assert_eq!(value, "max-age=31536000; includeSubDomains");
/// ```
#[must_use]
pub fn build_hsts_value(config: &HstsConfig) -> String {
    let mut value = format!("max-age={}", config.max_age);
    if config.include_subdomains {
        value.push_str("; includeSubDomains");
    }
    if config.preload {
        value.push_str("; preload");
    }
    value
}

/// Return `true` when the current process is running in a production or
/// staging environment.
///
/// Inspects the `ENVIRONMENT` and `ENV` environment variables (in that
/// order); matches the lowercase values `production`, `prod`, `staging`,
/// and `stage`.
#[must_use]
pub fn is_production_or_staging() -> bool {
    let env = std::env::var("ENVIRONMENT")
        .or_else(|_| std::env::var("ENV"))
        .unwrap_or_default()
        .to_lowercase();

    matches!(env.as_str(), "production" | "prod" | "staging" | "stage")
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn hsts_minimal() {
        let value = build_hsts_value(&HstsConfig {
            max_age: 3600,
            include_subdomains: false,
            preload: false,
        });
        assert_eq!(value, "max-age=3600");
    }

    #[test]
    fn hsts_with_subdomains() {
        let value = build_hsts_value(&HstsConfig {
            max_age: 31_536_000,
            include_subdomains: true,
            preload: false,
        });
        assert_eq!(value, "max-age=31536000; includeSubDomains");
    }

    #[test]
    fn hsts_full() {
        let value = build_hsts_value(&HstsConfig {
            max_age: 63_072_000,
            include_subdomains: true,
            preload: true,
        });
        assert_eq!(value, "max-age=63072000; includeSubDomains; preload");
    }

    #[test]
    fn hsts_preload_without_subdomains() {
        // Preload doesn't depend on includeSubDomains at this layer — the
        // primitive is a faithful builder; policy enforcement lives in the
        // calling middleware.
        let value = build_hsts_value(&HstsConfig {
            max_age: 100,
            include_subdomains: false,
            preload: true,
        });
        assert_eq!(value, "max-age=100; preload");
    }

    // is_production_or_staging() reads process env vars, so we can't test it
    // hermetically here without serialization. The behavior is exercised by
    // integration tests in tests/http/ and by the existing security.rs unit
    // tests that already manipulate ENV. Keep this primitive simple and trust
    // those upstream tests.
}
