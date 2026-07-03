//! Observable HTTP client
//!
//! Wraps the primitive HTTP client with full observability including:
//! - Request/response logging
//! - Latency metrics
//! - Retry event logging
//! - Circuit breaker state logging
//! - Active rate limiting with observability
//! - Compliance tagging

use std::sync::Arc;
use std::time::Instant;

use reqwest::Method;

use crate::observe::{self, ObserveBuilder, Problem, Soc2Control};
use crate::primitives::identifiers::network::{
    TextRedactionPolicy, UrlRedactionStrategy, redact_url_with_strategy, redact_urls_in_text,
};
use crate::primitives::runtime::http::{
    HttpClient as PrimitiveClient, HttpClientConfig, HttpClientError,
    HttpRequestBuilder as PrimitiveRequestBuilder, HttpResponse,
};
use crate::primitives::runtime::rate_limiter::{Decision, RateLimiter};

/// HTTP client with built-in observability
///
/// This client wraps the primitive HTTP client and adds:
/// - Request/response logging at appropriate levels
/// - Latency metrics for monitoring
/// - Retry attempt logging
/// - Circuit breaker state changes
/// - Active rate limiting (when configured)
/// - Compliance tagging for audit trails
///
/// # Example
///
/// Pre-existing example - ignored at compile until adapted.
/// ```rust,ignore
/// use octarine::runtime::http::HttpClient;
///
/// let client = HttpClient::for_external_api()?;
///
/// let response = client.get("https://api.example.com/users")
///     .bearer_auth("token")
///     .send()
///     .await?;
///
/// println!("Status: {}, Attempts: {}", response.status(), response.attempts());
/// ```
#[derive(Clone)]
pub struct HttpClient {
    inner: PrimitiveClient,
    name: String,
    /// Rate limiter (keyed by a unit key since we rate limit globally for this client)
    rate_limiter: Option<Arc<RateLimiter<()>>>,
}

impl std::fmt::Debug for HttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpClient")
            .field("name", &self.name)
            .field("has_rate_limiter", &self.rate_limiter.is_some())
            .finish()
    }
}

impl HttpClient {
    /// Create a new HTTP client with the given configuration
    ///
    /// # Arguments
    ///
    /// * `config` - Client configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the client cannot be built.
    ///
    /// # Example
    ///
    /// Pre-existing example - ignored at compile until adapted.
    /// ```rust,ignore
    /// use octarine::runtime::http::{HttpClient, HttpClientConfig};
    ///
    /// let config = HttpClientConfig::builder()
    ///     .base_url("https://api.example.com")
    ///     .build();
    ///
    /// let client = HttpClient::new(config)?;
    /// ```
    pub fn new(config: HttpClientConfig) -> Result<Self, Problem> {
        Self::with_name("http_client", config)
    }

    /// Create a new HTTP client with a custom name for logging
    ///
    /// The name is used in log messages and metrics to identify this client.
    ///
    /// # Arguments
    ///
    /// * `name` - Name for logging and metrics
    /// * `config` - Client configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the client cannot be built.
    pub fn with_name(name: impl Into<String>, config: HttpClientConfig) -> Result<Self, Problem> {
        let name = name.into();

        // Create rate limiter from config if specified
        let rate_limiter = if let Some(ref rl_config) = config.rate_limit {
            let limiter = RateLimiter::with_period(rl_config.max_requests, rl_config.window)
                .map_err(|e| {
                    observe::warn(
                        "http_client_rate_limiter_failed",
                        format!("{}: Failed to create rate limiter: {}", name, e),
                    );
                    Problem::Config(format!("Failed to create rate limiter: {}", e))
                })?;

            observe::debug(
                "http_client_rate_limiter_created",
                format!(
                    "{}: Rate limiter configured ({} requests per {:?})",
                    name, rl_config.max_requests, rl_config.window
                ),
            );

            Some(Arc::new(limiter))
        } else {
            None
        };

        let inner = PrimitiveClient::new(config).map_err(|e| {
            observe::warn(
                "http_client_init_failed",
                format!("{}: Failed to create client: {}", name, e),
            );
            Problem::OperationFailed(format!("Failed to create HTTP client: {}", e))
        })?;

        observe::debug(
            "http_client_created",
            format!("{}: HTTP client initialized", name),
        );

        Ok(Self {
            inner,
            name,
            rate_limiter,
        })
    }

    /// Create a client for external APIs (preset configuration)
    ///
    /// Features:
    /// - 5 retry attempts with exponential backoff
    /// - Circuit breaker (3 failures to open)
    /// - 30 second timeout
    ///
    /// # Errors
    ///
    /// Returns an error if the client cannot be built.
    pub fn for_external_api() -> Result<Self, Problem> {
        Self::with_name("external_api", HttpClientConfig::for_external_api())
    }

    /// Create a client for internal services (preset configuration)
    ///
    /// Features:
    /// - 3 retry attempts with shorter backoff
    /// - Circuit breaker (10 failures to open)
    /// - 10 second timeout
    ///
    /// # Errors
    ///
    /// Returns an error if the client cannot be built.
    pub fn for_internal_service() -> Result<Self, Problem> {
        Self::with_name("internal_service", HttpClientConfig::for_internal_service())
    }

    /// Create a client for webhooks (preset configuration)
    ///
    /// Features:
    /// - 3 retry attempts with 1s backoff
    /// - Circuit breaker (5 failures to open)
    /// - Active rate limiting: 10 requests/second
    ///
    /// # Errors
    ///
    /// Returns an error if the client cannot be built.
    pub fn for_webhook() -> Result<Self, Problem> {
        Self::with_name("webhook", HttpClientConfig::for_webhook())
    }

    /// Create a client for CLI tools (preset configuration)
    ///
    /// Features:
    /// - 2 retry attempts with short backoff
    /// - No circuit breaker
    /// - 60 second timeout (user can wait)
    ///
    /// # Errors
    ///
    /// Returns an error if the client cannot be built.
    pub fn for_cli() -> Result<Self, Problem> {
        Self::with_name("cli", HttpClientConfig::for_cli())
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
        HttpRequestBuilder::new(self, method, url)
    }

    /// Get the client name (for logging)
    fn name(&self) -> &str {
        &self.name
    }

    /// Get the rate limiter (if configured)
    fn rate_limiter(&self) -> Option<&Arc<RateLimiter<()>>> {
        self.rate_limiter.as_ref()
    }
}

/// Builder for HTTP requests with observability
pub struct HttpRequestBuilder<'a> {
    client: &'a HttpClient,
    inner: PrimitiveRequestBuilder<'a>,
    method: Method,
    url: String,
}

impl<'a> HttpRequestBuilder<'a> {
    fn new(client: &'a HttpClient, method: Method, url: &str) -> Self {
        let inner = client.inner.request(method.clone(), url);
        Self {
            client,
            inner,
            method,
            url: url.to_string(),
        }
    }

    /// Add a header to the request
    #[must_use]
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.inner = self.inner.header(name, value);
        self
    }

    /// Add a bearer token authorization header
    #[must_use]
    pub fn bearer_auth(mut self, token: impl Into<String>) -> Self {
        self.inner = self.inner.bearer_auth(token);
        self
    }

    /// Add basic authorization header
    #[must_use]
    pub fn basic_auth(mut self, username: impl Into<String>, password: Option<&str>) -> Self {
        self.inner = self.inner.basic_auth(username, password);
        self
    }

    /// Set JSON body
    #[must_use]
    pub fn json<T: serde::Serialize>(mut self, body: &T) -> Self {
        self.inner = self.inner.json(body);
        self
    }

    /// Set raw body
    #[must_use]
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.inner = self.inner.body(body);
        self
    }

    /// Set request timeout (overrides client timeout)
    #[must_use]
    pub fn timeout(mut self, timeout: std::time::Duration) -> Self {
        self.inner = self.inner.timeout(timeout);
        self
    }

    /// Send the request with full observability
    ///
    /// Logs the request, records metrics, and provides rich error context.
    ///
    /// # Errors
    ///
    /// Returns a `Problem` error if:
    /// - Rate limit exceeded (when rate limiting is configured)
    /// - The circuit breaker is open
    /// - All retry attempts failed
    /// - The request could not be built
    pub async fn send(self) -> Result<HttpResponse, Problem> {
        let start = Instant::now();
        let method = self.method.to_string();
        let url = self.url.clone();
        let redacted_url = redact_url_with_strategy(&url, UrlRedactionStrategy::ShowDomain);
        let client_name = self.client.name().to_string();

        // Check rate limiter if configured
        if let Some(rate_limiter) = self.client.rate_limiter() {
            match rate_limiter.check(&()) {
                Decision::Allow => {
                    // Request allowed, continue
                }
                Decision::Deny { retry_after } => {
                    ObserveBuilder::new()
                        .message("HTTP request rate limited")
                        .with_metadata("client", client_name.clone())
                        .with_metadata("method", method.clone())
                        .with_metadata("url", redacted_url.clone())
                        .with_metadata("retry_after_ms", retry_after.as_millis() as i64)
                        .soc2_control(Soc2Control::CC6_1) // Logical access control
                        .warn();

                    return Err(Problem::OperationFailed(format!(
                        "Rate limit exceeded for {}: retry after {:?}",
                        client_name, retry_after
                    )));
                }
            }
        }

        // Log request start
        ObserveBuilder::new()
            .message("HTTP request started")
            .with_metadata("client", client_name.clone())
            .with_metadata("method", method.clone())
            .with_metadata("url", redacted_url.clone())
            .soc2_control(Soc2Control::CC7_2) // System monitoring
            .debug();

        // Execute the request
        match self.inner.send().await {
            Ok(response) => {
                let elapsed = start.elapsed();
                let status = response.status().as_u16();
                let attempts = response.attempts();

                // Log success
                if response.retried() {
                    ObserveBuilder::new()
                        .message("HTTP request completed after retries")
                        .with_metadata("client", client_name.clone())
                        .with_metadata("method", method.clone())
                        .with_metadata("url", redacted_url.clone())
                        .with_metadata("status", i64::from(status))
                        .with_metadata("attempts", i64::from(attempts))
                        .with_metadata("elapsed_ms", elapsed.as_millis() as i64)
                        .soc2_control(Soc2Control::CC7_2)
                        .info();
                } else {
                    ObserveBuilder::new()
                        .message("HTTP request completed")
                        .with_metadata("client", client_name.clone())
                        .with_metadata("method", method.clone())
                        .with_metadata("url", redacted_url.clone())
                        .with_metadata("status", i64::from(status))
                        .with_metadata("elapsed_ms", elapsed.as_millis() as i64)
                        .soc2_control(Soc2Control::CC7_2)
                        .debug();
                }

                // Log warning for error responses
                if response.is_client_error() || response.is_server_error() {
                    ObserveBuilder::new()
                        .message("HTTP request returned error status")
                        .with_metadata("client", client_name.clone())
                        .with_metadata("method", method.clone())
                        .with_metadata("url", redacted_url.clone())
                        .with_metadata("status", i64::from(status))
                        .with_metadata("attempts", i64::from(attempts))
                        .soc2_control(Soc2Control::CC7_2)
                        .warn();
                }

                Ok(response)
            }
            Err(err) => {
                let elapsed = start.elapsed();

                // Convert error and log
                let problem = match &err {
                    HttpClientError::CircuitOpen { name } => {
                        ObserveBuilder::new()
                            .message("HTTP request rejected - circuit breaker open")
                            .with_metadata("client", client_name.clone())
                            .with_metadata("circuit", name.clone())
                            .with_metadata("method", method.clone())
                            .with_metadata("url", redacted_url.clone())
                            .soc2_control(Soc2Control::CC7_2)
                            .warn();

                        Problem::OperationFailed(format!(
                            "Circuit breaker is open for {}: request rejected",
                            name
                        ))
                    }
                    HttpClientError::RequestFailed {
                        attempts,
                        message,
                        elapsed: req_elapsed,
                    } => {
                        ObserveBuilder::new()
                            .message("HTTP request failed after retries")
                            .with_metadata("client", client_name.clone())
                            .with_metadata("method", method.clone())
                            .with_metadata("url", redacted_url.clone())
                            .with_metadata("attempts", i64::from(*attempts))
                            .with_metadata("elapsed_ms", req_elapsed.as_millis() as i64)
                            .with_metadata("error", message.clone())
                            .soc2_control(Soc2Control::CC7_2)
                            .error();

                        Problem::OperationFailed(format!(
                            "HTTP {} {} failed after {} attempts: {}",
                            method, redacted_url, attempts, message
                        ))
                    }
                    HttpClientError::RateLimited => {
                        ObserveBuilder::new()
                            .message("HTTP request rate limited")
                            .with_metadata("client", client_name.clone())
                            .with_metadata("method", method.clone())
                            .with_metadata("url", redacted_url.clone())
                            .soc2_control(Soc2Control::CC6_1) // Logical access control
                            .warn();

                        Problem::OperationFailed("Rate limit exceeded".into())
                    }
                    HttpClientError::Config(msg) => {
                        ObserveBuilder::new()
                            .message("HTTP client configuration error")
                            .with_metadata("client", client_name.clone())
                            .with_metadata("error", msg.clone())
                            .error();

                        Problem::OperationFailed(format!(
                            "HTTP client configuration error: {}",
                            msg
                        ))
                    }
                    HttpClientError::InvalidUrl(msg) => {
                        ObserveBuilder::new()
                            .message("Invalid URL")
                            .with_metadata("client", client_name.clone())
                            .with_metadata("url", redacted_url.clone())
                            .with_metadata("error", msg.clone())
                            .warn();

                        Problem::OperationFailed(format!("Invalid URL: {}", msg))
                    }
                    HttpClientError::Reqwest(req_err) => {
                        let redacted_err =
                            redact_urls_in_text(&req_err.to_string(), TextRedactionPolicy::Partial)
                                .into_owned();
                        ObserveBuilder::new()
                            .message("HTTP request error")
                            .with_metadata("client", client_name.clone())
                            .with_metadata("method", method.clone())
                            .with_metadata("url", redacted_url.clone())
                            .with_metadata("elapsed_ms", elapsed.as_millis() as i64)
                            .with_metadata("error", redacted_err.clone())
                            .soc2_control(Soc2Control::CC7_2)
                            .error();

                        Problem::OperationFailed(format!(
                            "HTTP {} {} failed: {}",
                            method, redacted_url, redacted_err
                        ))
                    }
                };

                Err(problem)
            }
        }
    }
}

impl std::fmt::Debug for HttpRequestBuilder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRequestBuilder")
            .field("method", &self.method)
            .field(
                "url",
                &redact_url_with_strategy(&self.url, UrlRedactionStrategy::ShowDomain),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_client_presets() {
        assert!(HttpClient::for_external_api().is_ok());
        assert!(HttpClient::for_internal_service().is_ok());
        assert!(HttpClient::for_webhook().is_ok());
        assert!(HttpClient::for_cli().is_ok());
    }

    #[test]
    fn test_client_with_name() {
        let config = HttpClientConfig::default();
        let client = HttpClient::with_name("test_client", config);
        assert!(client.is_ok());
        assert_eq!(
            client.expect("Client should be created").name(),
            "test_client"
        );
    }

    #[test]
    fn test_client_with_rate_limit() {
        let config = HttpClientConfig::builder()
            .rate_limit(10, Duration::from_secs(1))
            .build();
        let client =
            HttpClient::with_name("rate_limited", config).expect("Client should be created");

        assert!(client.rate_limiter.is_some());
    }

    #[test]
    fn test_client_without_rate_limit() {
        let config = HttpClientConfig::default();
        let client =
            HttpClient::with_name("no_rate_limit", config).expect("Client should be created");

        assert!(client.rate_limiter.is_none());
    }

    #[test]
    fn test_webhook_preset_has_rate_limiter() {
        let client = HttpClient::for_webhook().expect("Client should be created");
        assert!(client.rate_limiter.is_some());
    }

    #[test]
    fn test_external_api_preset_no_rate_limiter() {
        let client = HttpClient::for_external_api().expect("Client should be created");
        assert!(client.rate_limiter.is_none());
    }

    #[test]
    fn test_rate_limiter_shared_on_clone() {
        let config = HttpClientConfig::builder()
            .rate_limit(10, Duration::from_secs(1))
            .build();
        let client = HttpClient::with_name("shared", config).expect("Client should be created");

        let client2 = client.clone();

        // Both should have rate limiters
        assert!(client.rate_limiter.is_some());
        assert!(client2.rate_limiter.is_some());

        // And they should point to the same Arc
        assert!(Arc::ptr_eq(
            client.rate_limiter.as_ref().expect("has limiter"),
            client2.rate_limiter.as_ref().expect("has limiter")
        ));
    }

    #[test]
    fn test_client_debug_shows_rate_limiter() {
        let config_with = HttpClientConfig::builder()
            .rate_limit(10, Duration::from_secs(1))
            .build();
        let client_with =
            HttpClient::with_name("with_limiter", config_with).expect("Client should be created");

        let debug_str = format!("{:?}", client_with);
        assert!(debug_str.contains("has_rate_limiter: true"));

        let config_without = HttpClientConfig::default();
        let client_without = HttpClient::with_name("without_limiter", config_without)
            .expect("Client should be created");

        let debug_str = format!("{:?}", client_without);
        assert!(debug_str.contains("has_rate_limiter: false"));
    }

    #[test]
    fn test_send_redacts_query_string() {
        // Locks in the redaction strategy used by HttpRequestBuilder::send() so
        // no future refactor silently downgrades the log hygiene for query
        // strings that may carry tokens, emails, or other PII.
        let redacted = redact_url_with_strategy(
            "https://api.example.com/users/42?token=secret123&email=a@b.com",
            UrlRedactionStrategy::ShowDomain,
        );
        assert_eq!(redacted, "https://api.example.com***");
        assert!(!redacted.contains("token"));
        assert!(!redacted.contains("secret123"));
        assert!(!redacted.contains("a@b.com"));
        assert!(!redacted.contains("/users/42"));
    }

    // =========================================================================
    // I/O path tests via wiremock for the observable (Layer 3) client.
    //
    // This layer wraps the primitive client and (a) enforces rate limiting
    // BEFORE dispatch and (b) maps primitive errors to `Problem`. Expected
    // results are derived from those two responsibilities plus HTTP retry
    // semantics, not from current output.
    // =========================================================================
    mod io_paths {
        #![allow(clippy::panic, clippy::expect_used)]
        use super::*;
        use crate::primitives::runtime::r#async::backoff::RetryPolicy;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use wiremock::matchers::{method as m, path as pth};
        use wiremock::{Mock, MockServer, Respond, ResponseTemplate};

        fn fast_retry(attempts: u32) -> RetryPolicy {
            RetryPolicy::fixed(attempts, Duration::from_millis(1))
        }

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
        async fn success_returns_response() {
            let server = MockServer::start().await;
            Mock::given(m("GET"))
                .and(pth("/ok"))
                .respond_with(ResponseTemplate::new(200).set_body_string("body"))
                .mount(&server)
                .await;

            let client = HttpClient::new(HttpClientConfig::default()).expect("client should build");
            let resp = client
                .get(&format!("{}/ok", server.uri()))
                .send()
                .await
                .expect("2xx should be Ok");

            assert_eq!(resp.status().as_u16(), 200);
            assert_eq!(resp.text().await.expect("body"), "body");
        }

        #[tokio::test]
        async fn retries_then_succeeds_through_wrapper() {
            let server = MockServer::start().await;
            let calls = Arc::new(AtomicUsize::new(0));
            Mock::given(m("GET"))
                .and(pth("/flaky"))
                .respond_with(SequenceResponder {
                    calls: Arc::clone(&calls),
                    fail_count: 2,
                    first: 503,
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
                .expect("should recover after retries");

            // The observable wrapper must preserve the primitive's retry
            // behavior: two 503s then a 200 yields a successful 200 that
            // reports it was retried.
            assert_eq!(resp.status().as_u16(), 200);
            assert!(resp.retried());
            assert_eq!(resp.attempts(), 3);
        }

        #[tokio::test]
        async fn non_2xx_final_response_is_ok_not_problem() {
            let server = MockServer::start().await;
            Mock::given(m("GET"))
                .and(pth("/notfound"))
                .respond_with(ResponseTemplate::new(404))
                .mount(&server)
                .await;

            let client =
                HttpClient::new(HttpClientConfig::no_retry()).expect("client should build");
            let resp = client
                .get(&format!("{}/notfound", server.uri()))
                .send()
                .await
                .expect("a delivered 404 is Ok at this layer, logged as a warning");

            // The wrapper logs a warning for 4xx/5xx but still returns the
            // response; it does not convert delivered non-2xx into a Problem.
            assert_eq!(resp.status().as_u16(), 404);
            assert!(resp.is_client_error());
        }

        #[tokio::test]
        async fn timeout_maps_to_problem() {
            let server = MockServer::start().await;
            Mock::given(m("GET"))
                .and(pth("/slow"))
                .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
                .mount(&server)
                .await;

            let client =
                HttpClient::new(HttpClientConfig::no_retry()).expect("client should build");
            let err = client
                .get(&format!("{}/slow", server.uri()))
                .timeout(Duration::from_millis(100))
                .send()
                .await
                .expect_err("timeout should surface as an error");

            // Transport failures are mapped to Problem::OperationFailed by the
            // wrapper's error-conversion arm.
            assert!(
                matches!(err, Problem::OperationFailed(_)),
                "expected OperationFailed, got {err:?}"
            );
        }

        #[tokio::test]
        async fn rate_limit_denies_before_dispatch() {
            let server = MockServer::start().await;
            let calls = Arc::new(AtomicUsize::new(0));
            // Count how many requests actually reach the server.
            Mock::given(m("GET"))
                .and(pth("/rl"))
                .respond_with(SequenceResponder {
                    calls: Arc::clone(&calls),
                    fail_count: 0,
                    first: 200,
                    then: 200,
                })
                .mount(&server)
                .await;

            // Allow exactly 1 request per long window so the second send() is
            // denied by the active limiter in this layer.
            let config = HttpClientConfig::builder()
                .rate_limit(1, Duration::from_secs(60))
                .no_retry()
                .build();
            let client = HttpClient::with_name("rl_test", config).expect("client should build");
            let url = format!("{}/rl", server.uri());

            let first = client.get(&url).send().await;
            assert!(first.is_ok(), "first request within budget should pass");

            let second = client
                .get(&url)
                .send()
                .await
                .expect_err("second request must be rate limited");
            match second {
                Problem::OperationFailed(msg) => {
                    assert!(
                        msg.contains("Rate limit exceeded"),
                        "unexpected message: {msg}"
                    );
                }
                other => panic!("expected rate-limit OperationFailed, got {other:?}"),
            }

            // Crucially, the denied request must NOT have been dispatched to the
            // server: only the first call reached it.
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "rate-limited request should not hit the network"
            );
        }
    }
}
