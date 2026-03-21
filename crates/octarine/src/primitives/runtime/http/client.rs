//! HTTP client primitive
//!
//! Pure HTTP client wrapper with retry, rate limiting, and circuit breaker.
//! No observe dependencies.

// Allow arithmetic operations - attempt counter is bounded by max_attempts
#![allow(clippy::arithmetic_side_effects)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::{Client, Method, RequestBuilder};
use serde::Serialize;

use super::config::HttpClientConfig;
use super::response::HttpResponse;
use super::retry::{RetryDecision, classify_error, classify_status};
use crate::primitives::runtime::r#async::backoff::RetryPolicy;
use crate::primitives::runtime::r#async::circuit_breaker::CircuitBreaker;
use crate::primitives::runtime::r#async::sleep_ms;

/// HTTP client error
#[derive(Debug, thiserror::Error)]
pub enum HttpClientError {
    /// Request failed after all retries exhausted
    #[error("request failed after {attempts} attempts: {message}")]
    RequestFailed {
        attempts: u32,
        message: String,
        elapsed: Duration,
    },

    /// Circuit breaker is open
    #[error("circuit breaker is open for {name}")]
    CircuitOpen { name: String },

    /// Rate limit exceeded
    #[error("rate limit exceeded")]
    RateLimited,

    /// Configuration error
    #[error("configuration error: {0}")]
    Config(String),

    /// URL parsing error
    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    /// Underlying reqwest error
    #[error("HTTP error: {0}")]
    Reqwest(#[from] reqwest::Error),
}

/// HTTP client with retry, rate limiting, and circuit breaker support
///
/// This is the primitive client with no observability. Use `runtime::http::HttpClient`
/// for the version with full logging, metrics, and tracing.
///
/// # Example
///
/// ```rust,ignore
/// use octarine::primitives::runtime::http::{HttpClient, HttpClientConfig};
///
/// let client = HttpClient::new(HttpClientConfig::for_external_api())?;
///
/// let response = client.get("https://api.example.com/users/123")
///     .send()
///     .await?;
///
/// println!("Status: {}", response.status());
/// println!("Attempts: {}", response.attempts());
/// ```
#[derive(Clone)]
pub struct HttpClient {
    /// Underlying reqwest client
    client: Client,
    /// Client configuration
    config: HttpClientConfig,
    /// Circuit breaker (shared across clones)
    circuit_breaker: Option<Arc<CircuitBreaker>>,
}

impl std::fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpClient")
            .field("base_url", &self.config.base_url)
            .field("timeout", &self.config.timeout)
            .field("has_circuit_breaker", &self.circuit_breaker.is_some())
            .finish()
    }
}

impl HttpClient {
    /// Create a new HTTP client with the given configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the reqwest client cannot be built.
    pub fn new(config: HttpClientConfig) -> Result<Self, HttpClientError> {
        let mut builder = Client::builder()
            .timeout(config.timeout)
            .connect_timeout(config.connect_timeout)
            .user_agent(&config.user_agent);

        if config.follow_redirects {
            builder = builder.redirect(reqwest::redirect::Policy::limited(config.max_redirects));
        } else {
            builder = builder.redirect(reqwest::redirect::Policy::none());
        }

        let client = builder
            .build()
            .map_err(|e| HttpClientError::Config(e.to_string()))?;

        // Create circuit breaker if configured
        let circuit_breaker = config
            .circuit_breaker
            .as_ref()
            .map(|cb_config| Arc::new(CircuitBreaker::with_config(cb_config.clone())));

        Ok(Self {
            client,
            config,
            circuit_breaker,
        })
    }

    /// Create a client for external APIs (preset configuration)
    ///
    /// # Errors
    ///
    /// Returns an error if the client cannot be built.
    pub fn for_external_api() -> Result<Self, HttpClientError> {
        Self::new(HttpClientConfig::for_external_api())
    }

    /// Create a client for internal services (preset configuration)
    ///
    /// # Errors
    ///
    /// Returns an error if the client cannot be built.
    pub fn for_internal_service() -> Result<Self, HttpClientError> {
        Self::new(HttpClientConfig::for_internal_service())
    }

    /// Create a client for webhooks (preset configuration)
    ///
    /// # Errors
    ///
    /// Returns an error if the client cannot be built.
    pub fn for_webhook() -> Result<Self, HttpClientError> {
        Self::new(HttpClientConfig::for_webhook())
    }

    /// Create a client for CLI tools (preset configuration)
    ///
    /// # Errors
    ///
    /// Returns an error if the client cannot be built.
    pub fn for_cli() -> Result<Self, HttpClientError> {
        Self::new(HttpClientConfig::for_cli())
    }

    /// Start building a GET request
    pub fn get(&self, url: &str) -> HttpRequestBuilder<'_> {
        self.request(Method::GET, url)
    }

    /// Start building a POST request
    pub fn post(&self, url: &str) -> HttpRequestBuilder<'_> {
        self.request(Method::POST, url)
    }

    /// Start building a PUT request
    pub fn put(&self, url: &str) -> HttpRequestBuilder<'_> {
        self.request(Method::PUT, url)
    }

    /// Start building a PATCH request
    pub fn patch(&self, url: &str) -> HttpRequestBuilder<'_> {
        self.request(Method::PATCH, url)
    }

    /// Start building a DELETE request
    pub fn delete(&self, url: &str) -> HttpRequestBuilder<'_> {
        self.request(Method::DELETE, url)
    }

    /// Start building a HEAD request
    pub fn head(&self, url: &str) -> HttpRequestBuilder<'_> {
        self.request(Method::HEAD, url)
    }

    /// Start building a request with a custom method
    pub fn request(&self, method: Method, url: &str) -> HttpRequestBuilder<'_> {
        let full_url = self.build_url(url);
        HttpRequestBuilder::new(self, method, full_url)
    }

    /// Build the full URL from a path or URL
    fn build_url(&self, url: &str) -> String {
        if url.starts_with("http://") || url.starts_with("https://") {
            url.to_string()
        } else if let Some(ref base) = self.config.base_url {
            let base = base.trim_end_matches('/');
            let path = url.trim_start_matches('/');
            format!("{}/{}", base, path)
        } else {
            url.to_string()
        }
    }

    /// Get the retry policy
    fn retry_policy(&self) -> Option<&RetryPolicy> {
        self.config.retry_policy.as_ref()
    }

    /// Get the circuit breaker
    fn circuit_breaker(&self) -> Option<&Arc<CircuitBreaker>> {
        self.circuit_breaker.as_ref()
    }

    /// Get the default headers
    fn default_headers(&self) -> &std::collections::HashMap<String, String> {
        &self.config.default_headers
    }
}

/// Builder for HTTP requests
pub struct HttpRequestBuilder<'a> {
    client: &'a HttpClient,
    method: Method,
    url: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
    timeout: Option<Duration>,
}

impl<'a> HttpRequestBuilder<'a> {
    fn new(client: &'a HttpClient, method: Method, url: String) -> Self {
        Self {
            client,
            method,
            url,
            headers: Vec::new(),
            body: None,
            timeout: None,
        }
    }

    /// Add a header to the request
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Add a bearer token authorization header
    #[must_use]
    pub fn bearer_auth(self, token: impl Into<String>) -> Self {
        self.header("Authorization", format!("Bearer {}", token.into()))
    }

    /// Add basic authorization header
    #[must_use]
    pub fn basic_auth(self, username: impl Into<String>, password: Option<&str>) -> Self {
        use base64::Engine;
        let credentials = match password {
            Some(p) => format!("{}:{}", username.into(), p),
            None => format!("{}:", username.into()),
        };
        let encoded = base64::engine::general_purpose::STANDARD.encode(credentials);
        self.header("Authorization", format!("Basic {}", encoded))
    }

    /// Set JSON body
    #[must_use]
    pub fn json<T: Serialize>(mut self, body: &T) -> Self {
        if let Ok(json) = serde_json::to_vec(body) {
            self.body = Some(json);
            self.headers
                .push(("Content-Type".to_string(), "application/json".to_string()));
        }
        self
    }

    /// Set raw body
    #[must_use]
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = Some(body.into());
        self
    }

    /// Set request timeout (overrides client timeout)
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Send the request
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The circuit breaker is open
    /// - All retry attempts failed
    /// - The request could not be built
    pub async fn send(self) -> Result<HttpResponse, HttpClientError> {
        // Check circuit breaker
        if let Some(cb) = self.client.circuit_breaker()
            && !cb.can_proceed()
        {
            return Err(HttpClientError::CircuitOpen {
                name: "http_client".to_string(),
            });
        }

        let start = Instant::now();
        let retry_policy = self.client.retry_policy().cloned();
        let max_attempts = retry_policy.as_ref().map(|p| p.max_attempts).unwrap_or(1);

        let mut attempt = 0;
        let mut last_error: Option<String> = None;

        while attempt < max_attempts {
            attempt += 1;

            // Build the request
            let request = self.build_request()?;

            // Execute the request
            match request.send().await {
                Ok(response) => {
                    let status = response.status();
                    let decision = classify_status(status);

                    // Record success/failure with circuit breaker
                    if let Some(cb) = self.client.circuit_breaker() {
                        if status.is_success() {
                            cb.record_success();
                        } else if status.is_server_error() {
                            cb.record_failure();
                        }
                    }

                    // Check if we should retry
                    if decision.should_retry() && attempt < max_attempts {
                        last_error = Some(format!("HTTP {}", status.as_u16()));

                        // Calculate backoff delay
                        let delay = self.calculate_delay(&retry_policy, attempt, &decision);
                        sleep_ms(delay.as_millis() as u64).await;
                        continue;
                    }

                    // Return the response
                    return Ok(HttpResponse::new(
                        response,
                        attempt,
                        start.elapsed(),
                        attempt > 1,
                    ));
                }
                Err(err) => {
                    let decision = classify_error(&err);

                    // Record failure with circuit breaker
                    if let Some(cb) = self.client.circuit_breaker() {
                        cb.record_failure();
                    }

                    // Check if we should retry
                    if decision.should_retry() && attempt < max_attempts {
                        last_error = Some(err.to_string());

                        // Calculate backoff delay
                        let delay = self.calculate_delay(&retry_policy, attempt, &decision);
                        sleep_ms(delay.as_millis() as u64).await;
                        continue;
                    }

                    // No more retries
                    return Err(HttpClientError::RequestFailed {
                        attempts: attempt,
                        message: err.to_string(),
                        elapsed: start.elapsed(),
                    });
                }
            }
        }

        // All retries exhausted
        Err(HttpClientError::RequestFailed {
            attempts: attempt,
            message: last_error.unwrap_or_else(|| "unknown error".to_string()),
            elapsed: start.elapsed(),
        })
    }

    /// Build the underlying reqwest request
    fn build_request(&self) -> Result<RequestBuilder, HttpClientError> {
        let mut request = self.client.client.request(self.method.clone(), &self.url);

        // Add default headers
        for (name, value) in self.client.default_headers() {
            request = request.header(name.as_str(), value.as_str());
        }

        // Add request-specific headers
        for (name, value) in &self.headers {
            request = request.header(name.as_str(), value.as_str());
        }

        // Add body
        if let Some(ref body) = self.body {
            request = request.body(body.clone());
        }

        // Set timeout if specified
        if let Some(timeout) = self.timeout {
            request = request.timeout(timeout);
        }

        Ok(request)
    }

    /// Calculate backoff delay
    fn calculate_delay(
        &self,
        retry_policy: &Option<RetryPolicy>,
        attempt: u32,
        decision: &RetryDecision,
    ) -> Duration {
        let base_delay = retry_policy
            .as_ref()
            .map(|p| p.backoff.delay(attempt.saturating_sub(1)))
            .unwrap_or(Duration::from_millis(100));

        // Use longer delay for rate limiting
        if decision.is_rate_limited() {
            base_delay.saturating_mul(2)
        } else {
            base_delay
        }
    }
}

impl std::fmt::Debug for HttpRequestBuilder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRequestBuilder")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("headers_count", &self.headers.len())
            .field("has_body", &self.body.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = HttpClient::new(HttpClientConfig::default());
        assert!(client.is_ok());
    }

    #[test]
    fn test_url_building() {
        let config = HttpClientConfig::builder()
            .base_url("https://api.example.com")
            .build();
        let client = HttpClient::new(config).expect("Should create client");

        // Relative path
        let builder = client.get("/users/123");
        assert_eq!(builder.url, "https://api.example.com/users/123");

        // Absolute URL
        let builder = client.get("https://other.com/path");
        assert_eq!(builder.url, "https://other.com/path");
    }

    #[test]
    fn test_presets() {
        assert!(HttpClient::for_external_api().is_ok());
        assert!(HttpClient::for_internal_service().is_ok());
        assert!(HttpClient::for_webhook().is_ok());
        assert!(HttpClient::for_cli().is_ok());
    }

    #[test]
    fn test_request_builder() {
        let client = HttpClient::new(HttpClientConfig::default()).expect("Should create client");

        let builder = client
            .post("https://api.example.com/users")
            .header("X-Custom", "value")
            .bearer_auth("token123");

        assert_eq!(builder.method, Method::POST);
        assert_eq!(builder.headers.len(), 2);
    }
}
