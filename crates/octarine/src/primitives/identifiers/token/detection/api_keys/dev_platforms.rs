//! Developer-platform API key detection (Heroku, Linear, Doppler, Netlify,
//! Fly.io, Render, PlanetScale, Supabase).
//!
//! Each provider has a distinctive, unambiguous prefix that makes
//! single-token detection reliable without surrounding context. Providers
//! that require context-aware detection (Heroku legacy UUID, Railway,
//! Vercel) and providers whose tokens are indistinguishable from generic
//! JWT (Supabase service-role keys) are intentionally not included here.

use super::super::super::super::common::patterns;
use super::MAX_IDENTIFIER_LENGTH;

/// Check if value is a Heroku modern API token (HRKU-AA prefix).
#[must_use]
pub fn is_heroku_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_HEROKU.is_match(trimmed)
}

/// Check if value is a Linear API key (lin_api_ prefix).
#[must_use]
pub fn is_linear_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_LINEAR.is_match(trimmed)
}

/// Check if value is a Doppler token (service, CLI, SCM, or service-account).
#[must_use]
pub fn is_doppler_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_DOPPLER.is_match(trimmed)
}

/// Check if value is a Netlify Personal Access Token (nfp_ prefix).
#[must_use]
pub fn is_netlify_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_NETLIFY.is_match(trimmed)
}

/// Check if value is a Fly.io macaroon-based token (FlyV1 prefix).
#[must_use]
pub fn is_fly_io_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_FLY_IO.is_match(trimmed)
}

/// Check if value is a Render API key (rnd_ prefix).
#[must_use]
pub fn is_render_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_RENDER.is_match(trimmed)
}

/// Check if value is a PlanetScale service token (pscale_tkn_ prefix).
#[must_use]
pub fn is_planetscale_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_PLANETSCALE.is_match(trimmed)
}

/// Check if value is a Supabase Personal Access Token (sbp_ prefix).
#[must_use]
pub fn is_supabase_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_SUPABASE.is_match(trimmed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_heroku_token() {
        let token = format!("HRKU-AA{}", "a".repeat(58));
        assert!(is_heroku_token(&token));
        assert!(!is_heroku_token(&format!("HRKU-AA{}", "a".repeat(10))));
        assert!(!is_heroku_token(&format!("hrku-aa{}", "a".repeat(58))));
        assert!(!is_heroku_token(""));
    }

    #[test]
    fn test_is_linear_token() {
        let token = format!("lin_api_{}", "A".repeat(40));
        assert!(is_linear_token(&token));
        assert!(!is_linear_token(&format!("lin_api_{}", "A".repeat(10))));
        assert!(!is_linear_token(&format!("LIN_API_{}", "A".repeat(40))));
    }

    #[test]
    fn test_is_doppler_token() {
        assert!(is_doppler_token(&format!("dp.st.{}", "a".repeat(40))));
        assert!(is_doppler_token(&format!("dp.ct.{}", "a".repeat(40))));
        assert!(is_doppler_token(&format!("dp.scm.{}", "a".repeat(40))));
        assert!(is_doppler_token(&format!("dp.sa.{}", "a".repeat(40))));
        assert!(!is_doppler_token(&format!("dp.xx.{}", "a".repeat(40))));
        assert!(!is_doppler_token(&format!("dp.st.{}", "a".repeat(10))));
    }

    #[test]
    fn test_is_netlify_token() {
        let token = format!("nfp_{}", "a".repeat(40));
        assert!(is_netlify_token(&token));
        assert!(!is_netlify_token(&format!("nfp_{}", "a".repeat(10))));
        assert!(!is_netlify_token(&format!("NFP_{}", "a".repeat(40))));
    }

    #[test]
    fn test_is_fly_io_token() {
        let token = format!("FlyV1 {}", "a".repeat(100));
        assert!(is_fly_io_token(&token));
        assert!(!is_fly_io_token(&format!("FlyV1 {}", "a".repeat(10))));
        assert!(!is_fly_io_token(&format!("FlyV2 {}", "a".repeat(100))));
    }

    #[test]
    fn test_is_render_token() {
        let token = format!("rnd_{}", "A".repeat(32));
        assert!(is_render_token(&token));
        assert!(!is_render_token(&format!("rnd_{}", "A".repeat(10))));
        assert!(!is_render_token(&format!("RND_{}", "A".repeat(32))));
    }

    #[test]
    fn test_is_planetscale_token() {
        let token = format!("pscale_tkn_{}", "A".repeat(40));
        assert!(is_planetscale_token(&token));
        assert!(!is_planetscale_token(&format!(
            "pscale_tkn_{}",
            "A".repeat(10)
        )));
        assert!(!is_planetscale_token(&format!(
            "pscale_pw_{}",
            "A".repeat(40)
        )));
    }

    #[test]
    fn test_is_supabase_token() {
        let token = format!("sbp_{}", "a".repeat(40));
        assert!(is_supabase_token(&token));
        // Wrong charset (uppercase) — sbp_ is hex-only
        assert!(!is_supabase_token(&format!("sbp_{}", "A".repeat(40))));
        // Too short
        assert!(!is_supabase_token(&format!("sbp_{}", "a".repeat(10))));
    }
}
