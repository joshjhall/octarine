//! Security headers middleware
//!
//! Adds security headers to HTTP responses to protect against common web
//! vulnerabilities. Headers are configurable and environment-aware.
//!
//! # Headers Added
//!
//! | Header | Purpose |
//! |--------|---------|
//! | `Strict-Transport-Security` | Force HTTPS (prod/staging only) |
//! | `X-Content-Type-Options` | Prevent MIME sniffing |
//! | `X-Frame-Options` | Prevent clickjacking |
//! | `Referrer-Policy` | Control referrer leakage |
//! | `Content-Security-Policy` | XSS protection |
//! | `Permissions-Policy` | Disable risky browser APIs |
//!
//! # Example
//!
//! ```rust
//! use axum::{Router, routing::get};
//! use octarine::http::middleware::SecurityLayer;
//!
//! // Auto-detects environment for HSTS
//! let app: Router = Router::new()
//!     .route("/", get(|| async { "ok" }))
//!     .layer(SecurityLayer::auto());
//! ```
//!
//! With presets:
//!
//! ```rust
//! use octarine::http::middleware::{SecurityLayer, SecurityConfig, FrameOptions};
//!
//! // For browser-facing apps (includes CSP)
//! let browser_layer = SecurityLayer::browser();
//!
//! // For APIs (no CSP, relaxed frame options)
//! let api_layer = SecurityLayer::api();
//!
//! // Custom configuration
//! let custom = SecurityConfig::new()
//!     .hsts_max_age(86400)
//!     .frame_options(FrameOptions::SameOrigin)
//!     .csp("default-src 'self'; script-src 'self' cdn.example.com");
//! let custom_layer = SecurityLayer::with_config(custom);
//! ```

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use axum::{
    body::Body,
    http::{HeaderValue, Request, Response, header::HeaderName},
};
use tower::{Layer, Service};

/// Header names for security headers
static STRICT_TRANSPORT_SECURITY: HeaderName = HeaderName::from_static("strict-transport-security");
static X_CONTENT_TYPE_OPTIONS: HeaderName = HeaderName::from_static("x-content-type-options");
static X_FRAME_OPTIONS: HeaderName = HeaderName::from_static("x-frame-options");
static REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");
static CONTENT_SECURITY_POLICY: HeaderName = HeaderName::from_static("content-security-policy");
static PERMISSIONS_POLICY: HeaderName = HeaderName::from_static("permissions-policy");

/// Default HSTS max-age: 1 year in seconds
const DEFAULT_HSTS_MAX_AGE: u64 = 31_536_000;

/// Frame options for X-Frame-Options header
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameOptions {
    /// Completely prevent framing (most secure)
    Deny,
    /// Allow framing only from same origin
    SameOrigin,
}

impl FrameOptions {
    fn as_header_value(&self) -> &'static str {
        match self {
            Self::Deny => "DENY",
            Self::SameOrigin => "SAMEORIGIN",
        }
    }
}

/// Configuration for security headers.
#[derive(Debug, Clone)]
pub struct SecurityConfig {
    /// HSTS max-age in seconds (None = don't add header)
    hsts_max_age: Option<u64>,
    /// Include subdomains in HSTS
    hsts_include_subdomains: bool,
    /// Add HSTS preload directive
    hsts_preload: bool,
    /// Add X-Content-Type-Options: nosniff
    content_type_options: bool,
    /// X-Frame-Options value (None = don't add header)
    frame_options: Option<FrameOptions>,
    /// Referrer-Policy value (None = don't add header)
    referrer_policy: Option<String>,
    /// Content-Security-Policy value (None = don't add header)
    csp: Option<String>,
    /// Permissions-Policy value (None = don't add header)
    permissions_policy: Option<String>,
    /// Whether to check environment for HSTS (auto mode)
    environment_aware_hsts: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            hsts_max_age: Some(DEFAULT_HSTS_MAX_AGE),
            hsts_include_subdomains: true,
            hsts_preload: false,
            content_type_options: true,
            frame_options: Some(FrameOptions::Deny),
            referrer_policy: Some("strict-origin-when-cross-origin".to_string()),
            csp: None, // CSP is complex, don't set a default
            permissions_policy: Some("geolocation=(), camera=(), microphone=()".to_string()),
            environment_aware_hsts: true,
        }
    }
}

impl SecurityConfig {
    /// Create a new configuration with sensible defaults.
    ///
    /// By default:
    /// - HSTS enabled (1 year, includeSubDomains)
    /// - X-Content-Type-Options: nosniff
    /// - X-Frame-Options: DENY
    /// - Referrer-Policy: strict-origin-when-cross-origin
    /// - Permissions-Policy: restricts geolocation, camera, microphone
    /// - CSP: not set (requires app-specific configuration)
    /// - Environment-aware HSTS: enabled (only adds HSTS in prod/staging)
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Preset for browser-facing applications.
    ///
    /// Includes a restrictive Content-Security-Policy suitable for
    /// simple applications serving their own content.
    #[must_use]
    pub fn browser() -> Self {
        Self::default()
            .csp("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'")
    }

    /// Preset for APIs.
    ///
    /// - No CSP (APIs don't serve HTML)
    /// - Frame options set to DENY (no framing needed)
    /// - All other security headers enabled
    #[must_use]
    pub fn api() -> Self {
        Self::default()
            .csp_disabled()
            .frame_options(FrameOptions::Deny)
    }

    /// Set HSTS max-age in seconds.
    ///
    /// Common values:
    /// - 86400 (1 day) - for testing
    /// - 31536000 (1 year) - recommended for production
    #[must_use]
    pub fn hsts_max_age(mut self, seconds: u64) -> Self {
        self.hsts_max_age = Some(seconds);
        self
    }

    /// Set HSTS max-age from a Duration.
    #[must_use]
    pub fn hsts_duration(mut self, duration: Duration) -> Self {
        self.hsts_max_age = Some(duration.as_secs());
        self
    }

    /// Disable HSTS header entirely.
    #[must_use]
    pub fn hsts_disabled(mut self) -> Self {
        self.hsts_max_age = None;
        self
    }

    /// Include subdomains in HSTS (default: true).
    #[must_use]
    pub fn hsts_include_subdomains(mut self, include: bool) -> Self {
        self.hsts_include_subdomains = include;
        self
    }

    /// Add HSTS preload directive.
    ///
    /// Only enable this if you're submitting to the HSTS preload list.
    /// Once preloaded, removing HSTS is difficult.
    #[must_use]
    pub fn hsts_preload(mut self, preload: bool) -> Self {
        self.hsts_preload = preload;
        self
    }

    /// Disable environment-aware HSTS.
    ///
    /// By default, HSTS is only added in production and staging environments.
    /// Call this to always add HSTS regardless of environment.
    #[must_use]
    pub fn hsts_all_environments(mut self) -> Self {
        self.environment_aware_hsts = false;
        self
    }

    /// Set X-Frame-Options value.
    #[must_use]
    pub fn frame_options(mut self, options: FrameOptions) -> Self {
        self.frame_options = Some(options);
        self
    }

    /// Disable X-Frame-Options header.
    #[must_use]
    pub fn frame_options_disabled(mut self) -> Self {
        self.frame_options = None;
        self
    }

    /// Set Referrer-Policy value.
    #[must_use]
    pub fn referrer_policy(mut self, policy: impl Into<String>) -> Self {
        self.referrer_policy = Some(policy.into());
        self
    }

    /// Disable Referrer-Policy header.
    #[must_use]
    pub fn referrer_policy_disabled(mut self) -> Self {
        self.referrer_policy = None;
        self
    }

    /// Set Content-Security-Policy value.
    #[must_use]
    pub fn csp(mut self, policy: impl Into<String>) -> Self {
        self.csp = Some(policy.into());
        self
    }

    /// Disable Content-Security-Policy header.
    #[must_use]
    pub fn csp_disabled(mut self) -> Self {
        self.csp = None;
        self
    }

    /// Set Permissions-Policy value.
    #[must_use]
    pub fn permissions_policy(mut self, policy: impl Into<String>) -> Self {
        self.permissions_policy = Some(policy.into());
        self
    }

    /// Disable Permissions-Policy header.
    #[must_use]
    pub fn permissions_policy_disabled(mut self) -> Self {
        self.permissions_policy = None;
        self
    }

    /// Disable X-Content-Type-Options header.
    #[must_use]
    pub fn content_type_options_disabled(mut self) -> Self {
        self.content_type_options = false;
        self
    }

    /// Check if HSTS should be added based on environment.
    fn should_add_hsts(&self) -> bool {
        if self.hsts_max_age.is_none() {
            return false;
        }

        if !self.environment_aware_hsts {
            return true;
        }

        // Only add HSTS in production or staging
        is_production_or_staging()
    }

    /// Build the HSTS header value.
    fn build_hsts_value(&self) -> Option<String> {
        let max_age = self.hsts_max_age?;

        let mut value = format!("max-age={max_age}");

        if self.hsts_include_subdomains {
            value.push_str("; includeSubDomains");
        }

        if self.hsts_preload {
            value.push_str("; preload");
        }

        Some(value)
    }
}

/// Check if running in production or staging environment.
fn is_production_or_staging() -> bool {
    let env = std::env::var("ENVIRONMENT")
        .or_else(|_| std::env::var("ENV"))
        .unwrap_or_default()
        .to_lowercase();

    matches!(env.as_str(), "production" | "prod" | "staging" | "stage")
}

/// Layer that adds security headers to responses.
///
/// # Example
///
/// ```rust
/// use axum::{Router, routing::get};
/// use octarine::http::middleware::SecurityLayer;
///
/// let app: Router = Router::new()
///     .route("/", get(|| async { "ok" }))
///     .layer(SecurityLayer::auto());
/// ```
#[derive(Debug, Clone)]
pub struct SecurityLayer {
    config: SecurityConfig,
}

impl SecurityLayer {
    /// Create a new layer with default configuration.
    ///
    /// Uses environment-aware HSTS (only in prod/staging).
    #[must_use]
    pub fn new() -> Self {
        Self::with_config(SecurityConfig::new())
    }

    /// Create a layer with automatic environment detection.
    ///
    /// Same as `new()`, provided for clarity.
    #[must_use]
    pub fn auto() -> Self {
        Self::new()
    }

    /// Create a layer with browser preset.
    ///
    /// Includes CSP suitable for simple browser applications.
    #[must_use]
    pub fn browser() -> Self {
        Self::with_config(SecurityConfig::browser())
    }

    /// Create a layer with API preset.
    ///
    /// No CSP (APIs don't serve HTML), other headers enabled.
    #[must_use]
    pub fn api() -> Self {
        Self::with_config(SecurityConfig::api())
    }

    /// Create a layer with custom configuration.
    #[must_use]
    pub fn with_config(config: SecurityConfig) -> Self {
        Self { config }
    }
}

impl Default for SecurityLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for SecurityLayer {
    type Service = SecurityService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SecurityService {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Service that adds security headers to responses.
#[derive(Debug, Clone)]
pub struct SecurityService<S> {
    inner: S,
    config: SecurityConfig,
}

impl<S> Service<Request<Body>> for SecurityService<S>
where
    S: Service<Request<Body>, Response = Response<Body>> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let config = self.config.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let mut response = inner.call(request).await?;

            // Add security headers (don't overwrite existing headers)
            let headers = response.headers_mut();

            // HSTS (environment-aware)
            if config.should_add_hsts()
                && let Some(value) = config.build_hsts_value()
                && !headers.contains_key(&STRICT_TRANSPORT_SECURITY)
                && let Ok(header_value) = HeaderValue::from_str(&value)
            {
                headers.insert(STRICT_TRANSPORT_SECURITY.clone(), header_value);
            }

            // X-Content-Type-Options
            if config.content_type_options && !headers.contains_key(&X_CONTENT_TYPE_OPTIONS) {
                headers.insert(
                    X_CONTENT_TYPE_OPTIONS.clone(),
                    HeaderValue::from_static("nosniff"),
                );
            }

            // X-Frame-Options
            if let Some(ref frame_opts) = config.frame_options
                && !headers.contains_key(&X_FRAME_OPTIONS)
            {
                headers.insert(
                    X_FRAME_OPTIONS.clone(),
                    HeaderValue::from_static(frame_opts.as_header_value()),
                );
            }

            // Referrer-Policy
            if let Some(ref policy) = config.referrer_policy
                && !headers.contains_key(&REFERRER_POLICY)
                && let Ok(header_value) = HeaderValue::from_str(policy)
            {
                headers.insert(REFERRER_POLICY.clone(), header_value);
            }

            // Content-Security-Policy
            if let Some(ref csp) = config.csp
                && !headers.contains_key(&CONTENT_SECURITY_POLICY)
                && let Ok(header_value) = HeaderValue::from_str(csp)
            {
                headers.insert(CONTENT_SECURITY_POLICY.clone(), header_value);
            }

            // Permissions-Policy
            if let Some(ref policy) = config.permissions_policy
                && !headers.contains_key(&PERMISSIONS_POLICY)
                && let Ok(header_value) = HeaderValue::from_str(policy)
            {
                headers.insert(PERMISSIONS_POLICY.clone(), header_value);
            }

            Ok(response)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = SecurityConfig::new();
        assert_eq!(config.hsts_max_age, Some(DEFAULT_HSTS_MAX_AGE));
        assert!(config.hsts_include_subdomains);
        assert!(!config.hsts_preload);
        assert!(config.content_type_options);
        assert_eq!(config.frame_options, Some(FrameOptions::Deny));
        assert!(config.referrer_policy.is_some());
        assert!(config.csp.is_none());
        assert!(config.permissions_policy.is_some());
        assert!(config.environment_aware_hsts);
    }

    #[test]
    fn test_config_browser_preset() {
        let config = SecurityConfig::browser();
        assert!(config.csp.is_some());
        assert!(
            config
                .csp
                .as_ref()
                .is_some_and(|c| c.contains("default-src"))
        );
    }

    #[test]
    fn test_config_api_preset() {
        let config = SecurityConfig::api();
        assert!(config.csp.is_none());
        assert_eq!(config.frame_options, Some(FrameOptions::Deny));
    }

    #[test]
    fn test_hsts_builder() {
        let config = SecurityConfig::new()
            .hsts_max_age(86400)
            .hsts_include_subdomains(false)
            .hsts_preload(true);

        assert_eq!(config.hsts_max_age, Some(86400));
        assert!(!config.hsts_include_subdomains);
        assert!(config.hsts_preload);
    }

    #[test]
    fn test_hsts_duration() {
        let config = SecurityConfig::new().hsts_duration(Duration::from_secs(3600));
        assert_eq!(config.hsts_max_age, Some(3600));
    }

    #[test]
    fn test_hsts_disabled() {
        let config = SecurityConfig::new().hsts_disabled();
        assert!(config.hsts_max_age.is_none());
        assert!(!config.should_add_hsts());
    }

    #[test]
    fn test_build_hsts_value() {
        let config = SecurityConfig::new()
            .hsts_max_age(86400)
            .hsts_include_subdomains(true)
            .hsts_preload(false);

        let value = config.build_hsts_value();
        assert_eq!(value, Some("max-age=86400; includeSubDomains".to_string()));
    }

    #[test]
    fn test_build_hsts_value_with_preload() {
        let config = SecurityConfig::new()
            .hsts_max_age(31536000)
            .hsts_include_subdomains(true)
            .hsts_preload(true);

        let value = config.build_hsts_value();
        assert_eq!(
            value,
            Some("max-age=31536000; includeSubDomains; preload".to_string())
        );
    }

    #[test]
    fn test_build_hsts_value_minimal() {
        let config = SecurityConfig::new()
            .hsts_max_age(3600)
            .hsts_include_subdomains(false)
            .hsts_preload(false);

        let value = config.build_hsts_value();
        assert_eq!(value, Some("max-age=3600".to_string()));
    }

    #[test]
    fn test_frame_options() {
        assert_eq!(FrameOptions::Deny.as_header_value(), "DENY");
        assert_eq!(FrameOptions::SameOrigin.as_header_value(), "SAMEORIGIN");
    }

    #[test]
    fn test_csp_config() {
        let config = SecurityConfig::new().csp("default-src 'none'");
        assert_eq!(config.csp, Some("default-src 'none'".to_string()));

        let config = config.csp_disabled();
        assert!(config.csp.is_none());
    }

    #[test]
    fn test_referrer_policy_config() {
        let config = SecurityConfig::new().referrer_policy("no-referrer");
        assert_eq!(config.referrer_policy, Some("no-referrer".to_string()));

        let config = config.referrer_policy_disabled();
        assert!(config.referrer_policy.is_none());
    }

    #[test]
    fn test_permissions_policy_config() {
        let config = SecurityConfig::new().permissions_policy("camera=()");
        assert_eq!(config.permissions_policy, Some("camera=()".to_string()));

        let config = config.permissions_policy_disabled();
        assert!(config.permissions_policy.is_none());
    }

    #[test]
    fn test_layer_presets() {
        let _auto = SecurityLayer::auto();
        let _browser = SecurityLayer::browser();
        let _api = SecurityLayer::api();

        // All should create valid layers
    }

    #[test]
    fn test_environment_check() {
        // In test environment, should not be production/staging
        // (unless CI explicitly sets ENVIRONMENT)
        let is_prod = is_production_or_staging();
        // Can't assert false because CI might set ENVIRONMENT
        let _ = is_prod;
    }

    #[test]
    fn test_hsts_all_environments() {
        let config = SecurityConfig::new().hsts_all_environments();
        assert!(!config.environment_aware_hsts);
        // When environment_aware_hsts is false, should_add_hsts returns true
        // (assuming hsts_max_age is set)
        assert!(config.should_add_hsts());
    }
}
