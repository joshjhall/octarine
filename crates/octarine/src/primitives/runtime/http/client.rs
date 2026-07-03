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

    // =========================================================================
    // I/O path tests via wiremock.
    //
    // These drive the real request/retry/timeout/error machinery of `send()`
    // against a local stub server. Expected results are derived from HTTP
    // retry semantics (retry 5xx/429/timeouts, never retry 4xx, surface the
    // final response for non-2xx), NOT from the current output.
    //
    // Retry backoff uses a 1ms fixed delay so exhausting attempts stays fast;
    // this is the retry mechanism under test, not a fixed sleep in the test
    // body (octarine-test-resilience Rule 4).
    // =========================================================================
    mod io_paths {
        #![allow(clippy::panic, clippy::expect_used)]
        use super::*;
        use crate::primitives::runtime::r#async::backoff::RetryPolicy;
        use crate::primitives::runtime::r#async::circuit_breaker::CircuitBreakerConfig;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;
        use wiremock::matchers::{method as m, path as p};
        use wiremock::{Mock, MockServer, Respond, ResponseTemplate};

        /// Fixed retry policy with a negligible backoff so tests exercising
        /// exhausted retries do not spend real time sleeping.
        fn fast_retry(attempts: u32) -> RetryPolicy {
            RetryPolicy::fixed(attempts, Duration::from_millis(1))
        }

        /// A responder that returns `first` for the initial `fail_count`
        /// requests, then `then` for every subsequent request. Lets us drive
        /// the "fail N times then succeed" retry path with a real request
        /// counter instead of relying on mock ordering.
        struct SequenceResponder {
            calls: Arc<AtomicUsize>,
            fail_count: usize,
            first: u16,
            then: u16,
        }

        impl Respond for SequenceResponder {
            fn respond(&self, _req: &wiremock::Request) -> ResponseTemplate {
                let n = self.calls.fetch_add(1, Ordering::SeqCst);
                if n < self.fail_count {
                    ResponseTemplate::new(self.first)
                } else {
                    ResponseTemplate::new(self.then)
                }
            }
        }

        #[tokio::test]
        async fn get_success_single_attempt() {
            let server = MockServer::start().await;
            Mock::given(m("GET"))
                .and(p("/ok"))
                .respond_with(ResponseTemplate::new(200).set_body_string("hello"))
                .mount(&server)
                .await;

            let client = HttpClient::new(HttpClientConfig::default()).expect("client should build");
            let resp = client
                .get(&format!("{}/ok", server.uri()))
                .send()
                .await
                .expect("request should succeed");

            assert_eq!(resp.status().as_u16(), 200);
            // A first-try success must report exactly one attempt and no retry.
            assert_eq!(resp.attempts(), 1);
            assert!(!resp.retried());
            assert_eq!(resp.text().await.expect("body"), "hello");
        }

        #[tokio::test]
        async fn retries_500_then_succeeds() {
            let server = MockServer::start().await;
            let calls = Arc::new(AtomicUsize::new(0));
            // Fail twice with 500, then return 200.
            Mock::given(m("GET"))
                .and(p("/flaky"))
                .respond_with(SequenceResponder {
                    calls: Arc::clone(&calls),
                    fail_count: 2,
                    first: 500,
                    then: 200,
                })
                .mount(&server)
                .await;

            let config = HttpClientConfig::builder()
                .retry_policy(fast_retry(5))
                .no_circuit_breaker()
                .build();
            let client = HttpClient::new(config).expect("client should build");

            let resp = client
                .get(&format!("{}/flaky", server.uri()))
                .send()
                .await
                .expect("request should eventually succeed");

            // Two 500s then a 200: the client must retry past the failures and
            // return the successful response on the third attempt.
            assert_eq!(resp.status().as_u16(), 200);
            assert_eq!(resp.attempts(), 3);
            assert!(resp.retried());
            assert_eq!(calls.load(Ordering::SeqCst), 3);
        }

        #[tokio::test]
        async fn exhausts_retries_and_returns_last_5xx() {
            let server = MockServer::start().await;
            let calls = Arc::new(AtomicUsize::new(0));
            Mock::given(m("GET"))
                .and(p("/down"))
                .respond_with(SequenceResponder {
                    calls: Arc::clone(&calls),
                    fail_count: usize::MAX, // always 500
                    first: 500,
                    then: 500,
                })
                .mount(&server)
                .await;

            let config = HttpClientConfig::builder()
                .retry_policy(fast_retry(3))
                .no_circuit_breaker()
                .build();
            let client = HttpClient::new(config).expect("client should build");

            let resp = client
                .get(&format!("{}/down", server.uri()))
                .send()
                .await
                .expect("primitive surfaces the final response, not an Err, for 5xx");

            // Retry semantics: after exhausting all attempts on a retryable
            // status, the primitive returns the LAST response (Ok) with the
            // 5xx status rather than fabricating an error. It made exactly
            // max_attempts requests.
            assert_eq!(resp.status().as_u16(), 500);
            assert_eq!(resp.attempts(), 3);
            assert!(resp.retried());
            assert_eq!(calls.load(Ordering::SeqCst), 3);
        }

        #[tokio::test]
        async fn does_not_retry_4xx() {
            let server = MockServer::start().await;
            let calls = Arc::new(AtomicUsize::new(0));
            Mock::given(m("GET"))
                .and(p("/missing"))
                .respond_with(SequenceResponder {
                    calls: Arc::clone(&calls),
                    fail_count: usize::MAX,
                    first: 404,
                    then: 404,
                })
                .mount(&server)
                .await;

            let config = HttpClientConfig::builder()
                .retry_policy(fast_retry(5))
                .no_circuit_breaker()
                .build();
            let client = HttpClient::new(config).expect("client should build");

            let resp = client
                .get(&format!("{}/missing", server.uri()))
                .send()
                .await
                .expect("4xx is a valid response, not a transport error");

            // 404 is a client error: not retryable. Must return after a single
            // request with no retry, even though retries were configured.
            assert_eq!(resp.status().as_u16(), 404);
            assert_eq!(resp.attempts(), 1);
            assert!(!resp.retried());
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn retries_429_rate_limited() {
            let server = MockServer::start().await;
            let calls = Arc::new(AtomicUsize::new(0));
            Mock::given(m("GET"))
                .and(p("/limited"))
                .respond_with(SequenceResponder {
                    calls: Arc::clone(&calls),
                    fail_count: 1,
                    first: 429,
                    then: 200,
                })
                .mount(&server)
                .await;

            let config = HttpClientConfig::builder()
                .retry_policy(fast_retry(3))
                .no_circuit_breaker()
                .build();
            let client = HttpClient::new(config).expect("client should build");

            let resp = client
                .get(&format!("{}/limited", server.uri()))
                .send()
                .await
                .expect("should recover after rate-limit backoff");

            // 429 is retryable (with longer backoff); one 429 then 200 must
            // surface the 200 on the second attempt.
            assert_eq!(resp.status().as_u16(), 200);
            assert_eq!(resp.attempts(), 2);
            assert!(resp.retried());
        }

        #[tokio::test]
        async fn no_retry_policy_makes_single_attempt() {
            let server = MockServer::start().await;
            let calls = Arc::new(AtomicUsize::new(0));
            Mock::given(m("GET"))
                .and(p("/once"))
                .respond_with(SequenceResponder {
                    calls: Arc::clone(&calls),
                    fail_count: usize::MAX,
                    first: 503,
                    then: 503,
                })
                .mount(&server)
                .await;

            // no_retry() => retry_policy None => max_attempts 1.
            let config = HttpClientConfig::no_retry();
            let client = HttpClient::new(config).expect("client should build");

            let resp = client
                .get(&format!("{}/once", server.uri()))
                .send()
                .await
                .expect("returns the 503 response");

            assert_eq!(resp.status().as_u16(), 503);
            assert_eq!(resp.attempts(), 1);
            assert!(!resp.retried());
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn timeout_produces_request_failed_error() {
            let server = MockServer::start().await;
            // Respond after a delay far exceeding the per-request timeout.
            Mock::given(m("GET"))
                .and(p("/slow"))
                .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
                .mount(&server)
                .await;

            let config = HttpClientConfig::no_retry();
            let client = HttpClient::new(config).expect("client should build");

            let err = client
                .get(&format!("{}/slow", server.uri()))
                .timeout(Duration::from_millis(100))
                .send()
                .await
                .expect_err("a request that never returns in time must error");

            // A timeout is a transport failure: with no retries it surfaces as
            // RequestFailed reporting the single attempt made.
            match err {
                HttpClientError::RequestFailed { attempts, .. } => {
                    assert_eq!(attempts, 1);
                }
                other => panic!("expected RequestFailed, got {other:?}"),
            }
        }

        #[tokio::test]
        async fn circuit_breaker_opens_after_threshold() {
            let server = MockServer::start().await;
            Mock::given(m("GET"))
                .and(p("/err"))
                .respond_with(ResponseTemplate::new(500))
                .mount(&server)
                .await;

            // No retries so each send() records exactly one failure; open after
            // 2 failures.
            let config = HttpClientConfig::builder()
                .no_retry()
                .circuit_breaker(CircuitBreakerConfig::default().with_failure_threshold(2))
                .build();
            let client = HttpClient::new(config).expect("client should build");
            let url = format!("{}/err", server.uri());

            // First two requests reach the server (500 responses, Ok) and trip
            // the breaker.
            let r1 = client.get(&url).send().await.expect("reaches server");
            assert_eq!(r1.status().as_u16(), 500);
            let r2 = client.get(&url).send().await.expect("reaches server");
            assert_eq!(r2.status().as_u16(), 500);

            // Third request must be rejected locally by the open circuit
            // without hitting the server.
            let err = client
                .get(&url)
                .send()
                .await
                .expect_err("open circuit must reject the request");
            assert!(
                matches!(err, HttpClientError::CircuitOpen { .. }),
                "expected CircuitOpen, got {err:?}"
            );
        }

        #[tokio::test]
        async fn sends_body_and_headers() {
            use wiremock::matchers::{body_string, header};
            let server = MockServer::start().await;
            Mock::given(m("POST"))
                .and(p("/submit"))
                .and(header("x-custom", "abc"))
                .and(header("authorization", "Bearer tok"))
                .and(body_string("payload"))
                .respond_with(ResponseTemplate::new(201))
                .expect(1)
                .mount(&server)
                .await;

            let client =
                HttpClient::new(HttpClientConfig::no_retry()).expect("client should build");
            let resp = client
                .post(&format!("{}/submit", server.uri()))
                .header("X-Custom", "abc")
                .bearer_auth("tok")
                .body("payload")
                .send()
                .await
                .expect("request should be accepted");

            // The builder must actually transmit the configured headers and
            // body; the mock only matches (and returns 201) if they arrived.
            assert_eq!(resp.status().as_u16(), 201);
            // `expect(1)` on the mock is verified on server drop.
        }
    }
}
