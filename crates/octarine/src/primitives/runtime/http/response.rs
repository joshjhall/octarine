//! HTTP response wrapper with metadata
//!
//! Wraps reqwest::Response with additional metadata about retry attempts,
//! latency, and other execution details.

use bytes::Bytes;
use reqwest::StatusCode;
use serde::de::DeserializeOwned;
use std::time::Duration;

/// HTTP response with metadata about execution
#[derive(Debug)]
pub struct HttpResponse {
    /// The underlying reqwest response
    inner: reqwest::Response,
    /// Number of attempts made (1 = no retries)
    attempts: u32,
    /// Total time elapsed (including retries and backoff delays)
    elapsed: Duration,
    /// Whether any retries were performed
    retried: bool,
}

impl HttpResponse {
    /// Create a new response wrapper
    pub(crate) fn new(
        inner: reqwest::Response,
        attempts: u32,
        elapsed: Duration,
        retried: bool,
    ) -> Self {
        Self {
            inner,
            attempts,
            elapsed,
            retried,
        }
    }

    /// Get the HTTP status code
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.inner.status()
    }

    /// Check if the response was successful (2xx status)
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.inner.status().is_success()
    }

    /// Check if the response was a client error (4xx status)
    #[must_use]
    pub fn is_client_error(&self) -> bool {
        self.inner.status().is_client_error()
    }

    /// Check if the response was a server error (5xx status)
    #[must_use]
    pub fn is_server_error(&self) -> bool {
        self.inner.status().is_server_error()
    }

    /// Get the number of attempts made
    ///
    /// Returns 1 if no retries were needed.
    #[must_use]
    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    /// Get the total elapsed time (including retries and delays)
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.elapsed
    }

    /// Check if any retries were performed
    #[must_use]
    pub fn retried(&self) -> bool {
        self.retried
    }

    /// Get a header value by name
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.inner.headers().get(name).and_then(|v| v.to_str().ok())
    }

    /// Get the Content-Type header
    #[must_use]
    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }

    /// Get the Content-Length header
    #[must_use]
    pub fn content_length(&self) -> Option<u64> {
        self.inner.content_length()
    }

    /// Get the remote address if available
    #[must_use]
    pub fn remote_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.remote_addr()
    }

    /// Deserialize the response body as JSON
    ///
    /// Consumes the response.
    ///
    /// # Errors
    ///
    /// Returns an error if the response body cannot be parsed as JSON.
    pub async fn json<T: DeserializeOwned>(self) -> Result<T, reqwest::Error> {
        self.inner.json().await
    }

    /// Get the response body as text
    ///
    /// Consumes the response.
    ///
    /// # Errors
    ///
    /// Returns an error if the response body cannot be decoded as UTF-8.
    pub async fn text(self) -> Result<String, reqwest::Error> {
        self.inner.text().await
    }

    /// Get the response body as bytes
    ///
    /// Consumes the response.
    ///
    /// # Errors
    ///
    /// Returns an error if the response body cannot be read.
    pub async fn bytes(self) -> Result<Bytes, reqwest::Error> {
        self.inner.bytes().await
    }

    /// Get the underlying reqwest::Response
    ///
    /// Use this for operations not covered by this wrapper.
    #[must_use]
    pub fn into_inner(self) -> reqwest::Response {
        self.inner
    }
}

/// Metadata about an HTTP request/response cycle
#[derive(Debug, Clone)]
pub struct HttpMetadata {
    /// HTTP method used
    pub method: String,
    /// Request URL
    pub url: String,
    /// Response status code (if response received)
    pub status: Option<u16>,
    /// Number of attempts made
    pub attempts: u32,
    /// Total elapsed time
    pub elapsed: Duration,
    /// Whether retries were performed
    pub retried: bool,
}

impl HttpMetadata {
    /// Create metadata for a successful response
    pub(crate) fn from_response(method: &str, url: &str, response: &HttpResponse) -> Self {
        Self {
            method: method.to_string(),
            url: url.to_string(),
            status: Some(response.status().as_u16()),
            attempts: response.attempts(),
            elapsed: response.elapsed(),
            retried: response.retried(),
        }
    }

    /// Create metadata for a failed request
    pub(crate) fn from_error(method: &str, url: &str, attempts: u32, elapsed: Duration) -> Self {
        Self {
            method: method.to_string(),
            url: url.to_string(),
            status: None,
            attempts,
            elapsed,
            retried: attempts > 1,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_metadata_from_error_single_attempt() {
        let metadata = HttpMetadata::from_error(
            "GET",
            "https://api.example.com/users",
            1,
            Duration::from_millis(150),
        );

        assert_eq!(metadata.method, "GET");
        assert_eq!(metadata.url, "https://api.example.com/users");
        assert!(metadata.status.is_none());
        assert_eq!(metadata.attempts, 1);
        assert_eq!(metadata.elapsed, Duration::from_millis(150));
        assert!(!metadata.retried); // Single attempt = no retries
    }

    #[test]
    fn test_metadata_from_error_with_retries() {
        let metadata = HttpMetadata::from_error(
            "POST",
            "https://api.example.com/data",
            3,
            Duration::from_secs(2),
        );

        assert_eq!(metadata.method, "POST");
        assert_eq!(metadata.url, "https://api.example.com/data");
        assert!(metadata.status.is_none());
        assert_eq!(metadata.attempts, 3);
        assert_eq!(metadata.elapsed, Duration::from_secs(2));
        assert!(metadata.retried); // Multiple attempts = retried
    }

    #[test]
    fn test_metadata_retried_boundary() {
        // 1 attempt = not retried
        let meta1 = HttpMetadata::from_error("GET", "/", 1, Duration::ZERO);
        assert!(!meta1.retried);

        // 2 attempts = retried
        let meta2 = HttpMetadata::from_error("GET", "/", 2, Duration::ZERO);
        assert!(meta2.retried);

        // 0 attempts (edge case) = not retried
        let meta0 = HttpMetadata::from_error("GET", "/", 0, Duration::ZERO);
        assert!(!meta0.retried);
    }

    #[test]
    fn test_metadata_all_http_methods() {
        let methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
        for method in methods {
            let metadata = HttpMetadata::from_error(method, "/test", 1, Duration::ZERO);
            assert_eq!(metadata.method, method);
        }
    }

    #[test]
    fn test_metadata_preserves_full_url() {
        let complex_url = "https://api.example.com:8443/v2/users?page=1&limit=50#section";
        let metadata = HttpMetadata::from_error("GET", complex_url, 1, Duration::ZERO);
        assert_eq!(metadata.url, complex_url);
    }

    #[test]
    fn test_metadata_clone() {
        let metadata = HttpMetadata::from_error("GET", "/test", 2, Duration::from_millis(100));
        let cloned = metadata.clone();

        assert_eq!(cloned.method, metadata.method);
        assert_eq!(cloned.url, metadata.url);
        assert_eq!(cloned.status, metadata.status);
        assert_eq!(cloned.attempts, metadata.attempts);
        assert_eq!(cloned.elapsed, metadata.elapsed);
        assert_eq!(cloned.retried, metadata.retried);
    }

    #[test]
    fn test_metadata_debug() {
        let metadata = HttpMetadata::from_error("GET", "/test", 1, Duration::from_millis(50));
        let debug_str = format!("{:?}", metadata);

        assert!(debug_str.contains("GET"));
        assert!(debug_str.contains("/test"));
        assert!(debug_str.contains("50ms") || debug_str.contains("50000000")); // Duration format varies
    }
}
