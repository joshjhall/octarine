//! HTTP client configuration
//!
//! Configuration types and builder for the HTTP client.

use std::collections::HashMap;
use std::time::Duration;

use crate::primitives::runtime::r#async::backoff::{BackoffStrategyCore, RetryPolicy};
use crate::primitives::runtime::r#async::circuit_breaker::CircuitBreakerConfig;

/// Configuration for an HTTP client
#[derive(Debug, Clone)]
pub struct HttpClientConfig {
    /// Base URL for all requests
    pub base_url: Option<String>,
    /// Request timeout
    pub timeout: Duration,
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Retry policy
    pub retry_policy: Option<RetryPolicy>,
    /// Circuit breaker configuration
    pub circuit_breaker: Option<CircuitBreakerConfig>,
    /// Rate limit (requests per window)
    pub rate_limit: Option<RateLimitConfig>,
    /// Default headers for all requests
    pub default_headers: HashMap<String, String>,
    /// User agent string
    pub user_agent: String,
    /// Whether to follow redirects
    pub follow_redirects: bool,
    /// Maximum number of redirects to follow
    pub max_redirects: usize,
}

/// Rate limit configuration
///
/// Configures client-side rate limiting to prevent overwhelming external services.
///
/// # Layer Behavior
///
/// - **Primitives layer** (`primitives::runtime::http::HttpClient`): Stores the configuration
///   but does NOT actively enforce rate limits. It only respects server-side rate limiting
///   by using longer backoff delays when receiving HTTP 429 responses.
///
/// - **Runtime layer** (`runtime::http::HttpClient`): **Actively enforces** rate limits
///   using octarine's rate limiter primitives. Requests exceeding the limit are rejected
///   immediately with observability logging.
///
/// # Example
///
/// ```rust,ignore
/// use octarine::runtime::http::HttpClient;
///
/// // The webhook preset includes rate limiting (10 req/sec)
/// let client = HttpClient::for_webhook()?;
///
/// // Or configure manually
/// let config = HttpClientConfig::builder()
///     .rate_limit(100, Duration::from_secs(60))  // 100 requests per minute
///     .build();
/// let client = HttpClient::new(config)?;
/// ```
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum requests allowed in the window
    pub max_requests: u32,
    /// Time window for rate limiting
    pub window: Duration,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            base_url: None,
            timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            retry_policy: Some(RetryPolicy::default()),
            circuit_breaker: None,
            rate_limit: None,
            default_headers: HashMap::new(),
            user_agent: format!("octarine-http/{}", env!("CARGO_PKG_VERSION")),
            follow_redirects: true,
            max_redirects: 10,
        }
    }
}

impl HttpClientConfig {
    /// Create a new configuration with defaults
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a builder for customizing configuration
    #[must_use]
    pub fn builder() -> HttpClientConfigBuilder {
        HttpClientConfigBuilder::new()
    }

    /// Configuration preset for external APIs
    ///
    /// Features:
    /// - 5 retry attempts with exponential backoff
    /// - Circuit breaker (3 failures to open)
    /// - 30 second timeout
    #[must_use]
    pub fn for_external_api() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(10),
            retry_policy: Some(RetryPolicy::default().with_max_attempts(5).with_backoff(
                BackoffStrategyCore::Exponential {
                    base: Duration::from_millis(100),
                    max: Duration::from_secs(10),
                },
            )),
            circuit_breaker: Some(CircuitBreakerConfig::default().with_failure_threshold(3)),
            ..Self::default()
        }
    }

    /// Configuration preset for internal services
    ///
    /// Features:
    /// - 3 retry attempts with shorter backoff
    /// - Circuit breaker (10 failures to open)
    /// - 10 second timeout
    #[must_use]
    pub fn for_internal_service() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(5),
            retry_policy: Some(RetryPolicy::fixed(3, Duration::from_millis(50))),
            circuit_breaker: Some(CircuitBreakerConfig::default().with_failure_threshold(10)),
            ..Self::default()
        }
    }

    /// Configuration preset for webhooks
    ///
    /// Features:
    /// - 3 retry attempts with 1s backoff
    /// - Circuit breaker (5 failures to open)
    /// - Rate limit: 10 requests/second
    ///
    /// **Note:** Rate limiting is actively enforced in `runtime::http::HttpClient`.
    /// The primitives layer only stores the configuration.
    #[must_use]
    pub fn for_webhook() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(5),
            retry_policy: Some(RetryPolicy::fixed(3, Duration::from_secs(1))),
            circuit_breaker: Some(CircuitBreakerConfig::default().with_failure_threshold(5)),
            rate_limit: Some(RateLimitConfig {
                max_requests: 10,
                window: Duration::from_secs(1),
            }),
            ..Self::default()
        }
    }

    /// Configuration preset for CLI tools
    ///
    /// Features:
    /// - 2 retry attempts with short backoff
    /// - No circuit breaker
    /// - 60 second timeout (user can wait)
    #[must_use]
    pub fn for_cli() -> Self {
        Self {
            timeout: Duration::from_secs(60),
            connect_timeout: Duration::from_secs(10),
            retry_policy: Some(RetryPolicy::fixed(2, Duration::from_millis(100))),
            circuit_breaker: None,
            rate_limit: None,
            ..Self::default()
        }
    }

    /// Configuration with no retries (for testing or simple cases)
    #[must_use]
    pub fn no_retry() -> Self {
        Self {
            retry_policy: None,
            circuit_breaker: None,
            rate_limit: None,
            ..Self::default()
        }
    }
}

/// Builder for `HttpClientConfig`
#[derive(Debug, Clone, Default)]
pub struct HttpClientConfigBuilder {
    config: HttpClientConfig,
}

impl HttpClientConfigBuilder {
    /// Create a new builder with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: HttpClientConfig::default(),
        }
    }

    /// Set the base URL for all requests
    #[must_use]
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.config.base_url = Some(url.into());
        self
    }

    /// Set the request timeout
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = timeout;
        self
    }

    /// Set the connection timeout
    #[must_use]
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.config.connect_timeout = timeout;
        self
    }

    /// Set the retry policy
    #[must_use]
    pub fn retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.config.retry_policy = Some(policy);
        self
    }

    /// Disable retries
    #[must_use]
    pub fn no_retry(mut self) -> Self {
        self.config.retry_policy = None;
        self
    }

    /// Set the circuit breaker configuration
    #[must_use]
    pub fn circuit_breaker(mut self, config: CircuitBreakerConfig) -> Self {
        self.config.circuit_breaker = Some(config);
        self
    }

    /// Disable circuit breaker
    #[must_use]
    pub fn no_circuit_breaker(mut self) -> Self {
        self.config.circuit_breaker = None;
        self
    }

    /// Set rate limiting (requests per window)
    #[must_use]
    pub fn rate_limit(mut self, max_requests: u32, window: Duration) -> Self {
        self.config.rate_limit = Some(RateLimitConfig {
            max_requests,
            window,
        });
        self
    }

    /// Disable rate limiting
    #[must_use]
    pub fn no_rate_limit(mut self) -> Self {
        self.config.rate_limit = None;
        self
    }

    /// Add a default header
    #[must_use]
    pub fn default_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.config
            .default_headers
            .insert(name.into(), value.into());
        self
    }

    /// Set the user agent
    #[must_use]
    pub fn user_agent(mut self, agent: impl Into<String>) -> Self {
        self.config.user_agent = agent.into();
        self
    }

    /// Set whether to follow redirects
    #[must_use]
    pub fn follow_redirects(mut self, follow: bool) -> Self {
        self.config.follow_redirects = follow;
        self
    }

    /// Set the maximum number of redirects to follow
    #[must_use]
    pub fn max_redirects(mut self, max: usize) -> Self {
        self.config.max_redirects = max;
        self
    }

    /// Build the configuration
    #[must_use]
    pub fn build(self) -> HttpClientConfig {
        self.config
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_default_config() {
        let config = HttpClientConfig::new();
        assert!(config.base_url.is_none());
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert!(config.retry_policy.is_some());
        assert!(config.follow_redirects);
    }

    #[test]
    fn test_builder() {
        let config = HttpClientConfig::builder()
            .base_url("https://api.example.com")
            .timeout(Duration::from_secs(60))
            .default_header("Authorization", "Bearer token")
            .rate_limit(100, Duration::from_secs(60))
            .build();

        assert_eq!(config.base_url, Some("https://api.example.com".to_string()));
        assert_eq!(config.timeout, Duration::from_secs(60));
        assert!(config.default_headers.contains_key("Authorization"));
        assert!(config.rate_limit.is_some());
    }

    #[test]
    fn test_external_api_preset() {
        let config = HttpClientConfig::for_external_api();
        assert!(config.circuit_breaker.is_some());
        assert!(config.retry_policy.is_some());
        let retry = config.retry_policy.expect("Should have retry policy");
        assert_eq!(retry.max_attempts, 5);
    }

    #[test]
    fn test_internal_service_preset() {
        let config = HttpClientConfig::for_internal_service();
        assert!(config.circuit_breaker.is_some());
        assert_eq!(config.timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_webhook_preset() {
        let config = HttpClientConfig::for_webhook();
        assert!(config.rate_limit.is_some());
        let rate_limit = config.rate_limit.expect("Should have rate limit");
        assert_eq!(rate_limit.max_requests, 10);
    }

    #[test]
    fn test_cli_preset() {
        let config = HttpClientConfig::for_cli();
        assert!(config.circuit_breaker.is_none());
        assert_eq!(config.timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_no_retry_preset() {
        let config = HttpClientConfig::no_retry();
        assert!(config.retry_policy.is_none());
        assert!(config.circuit_breaker.is_none());
    }
}
