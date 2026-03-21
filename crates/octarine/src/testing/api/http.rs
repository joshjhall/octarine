//! HTTP API Testing Utilities
//!
//! Helpers for testing HTTP APIs using wiremock.

use serde::Serialize;
use wiremock::matchers::{body_json, header, method, path, path_regex, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Start a mock HTTP server
///
/// # Example
///
/// ```rust,ignore
/// use octarine::testing::api::start_mock_server;
///
/// #[tokio::test]
/// async fn test_with_mock() {
///     let server = start_mock_server().await;
///     // Use server.uri() to get the base URL
/// }
/// ```
pub async fn start_mock_server() -> MockServer {
    MockServer::start().await
}

/// Start a mock server with builder
///
/// For more control over the mock server configuration.
pub async fn start_mock_server_builder() -> wiremock::MockServer {
    MockServer::builder().start().await
}

/// Builder for common HTTP mock scenarios
///
/// # Example
///
/// ```rust,ignore
/// use octarine::testing::api::HttpMockBuilder;
/// use serde_json::json;
///
/// #[tokio::test]
/// async fn test_api() {
///     let server = start_mock_server().await;
///
///     HttpMockBuilder::get("/api/users")
///         .with_query("limit", "10")
///         .respond_json(&json!({"users": []}))
///         .mount(&server)
///         .await;
/// }
/// ```
pub struct HttpMockBuilder {
    method: String,
    path_pattern: PathPattern,
    query_params: Vec<(String, String)>,
    headers: Vec<(String, String)>,
    body_matcher: Option<serde_json::Value>,
    response_status: u16,
    response_body: Option<String>,
    response_headers: Vec<(String, String)>,
    times: Option<u64>,
}

enum PathPattern {
    Exact(String),
    Regex(String),
}

impl HttpMockBuilder {
    /// Create a GET request mock
    pub fn get(path: &str) -> Self {
        Self::new("GET", path)
    }

    /// Create a POST request mock
    pub fn post(path: &str) -> Self {
        Self::new("POST", path)
    }

    /// Create a PUT request mock
    pub fn put(path: &str) -> Self {
        Self::new("PUT", path)
    }

    /// Create a DELETE request mock
    pub fn delete(path: &str) -> Self {
        Self::new("DELETE", path)
    }

    /// Create a PATCH request mock
    pub fn patch(path: &str) -> Self {
        Self::new("PATCH", path)
    }

    /// Create a mock with custom method
    pub fn new(method: &str, path: &str) -> Self {
        Self {
            method: method.to_string(),
            path_pattern: PathPattern::Exact(path.to_string()),
            query_params: Vec::new(),
            headers: Vec::new(),
            body_matcher: None,
            response_status: 200,
            response_body: None,
            response_headers: Vec::new(),
            times: None,
        }
    }

    /// Match path with regex
    pub fn path_regex(mut self, pattern: &str) -> Self {
        self.path_pattern = PathPattern::Regex(pattern.to_string());
        self
    }

    /// Add a query parameter matcher
    pub fn with_query(mut self, key: &str, value: &str) -> Self {
        self.query_params.push((key.to_string(), value.to_string()));
        self
    }

    /// Add a header matcher
    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    /// Add authorization header matcher
    pub fn with_bearer_token(self, token: &str) -> Self {
        self.with_header("Authorization", &format!("Bearer {}", token))
    }

    /// Match request body as JSON
    pub fn with_json_body<T: Serialize>(mut self, body: &T) -> Self {
        self.body_matcher = Some(serde_json::to_value(body).expect("Failed to serialize body"));
        self
    }

    /// Set response status code
    pub fn respond_with_status(mut self, status: u16) -> Self {
        self.response_status = status;
        self
    }

    /// Set response body as JSON
    pub fn respond_json<T: Serialize>(mut self, body: &T) -> Self {
        self.response_body = Some(serde_json::to_string(body).expect("Failed to serialize body"));
        self.response_headers
            .push(("Content-Type".to_string(), "application/json".to_string()));
        self
    }

    /// Set response body as text
    pub fn respond_text(mut self, body: &str) -> Self {
        self.response_body = Some(body.to_string());
        self.response_headers
            .push(("Content-Type".to_string(), "text/plain".to_string()));
        self
    }

    /// Add a response header
    pub fn with_response_header(mut self, name: &str, value: &str) -> Self {
        self.response_headers
            .push((name.to_string(), value.to_string()));
        self
    }

    /// Limit how many times this mock should match
    pub fn times(mut self, n: u64) -> Self {
        self.times = Some(n);
        self
    }

    /// Mount the mock on a server
    pub async fn mount(self, server: &MockServer) {
        let mut mock = Mock::given(method(self.method.as_str()));

        // Add path matcher
        match self.path_pattern {
            PathPattern::Exact(p) => {
                mock = mock.and(path(p));
            }
            PathPattern::Regex(p) => {
                mock = mock.and(path_regex(p));
            }
        }

        // Add query param matchers
        for (key, value) in self.query_params {
            mock = mock.and(query_param(key, value));
        }

        // Add header matchers
        for (name, value) in self.headers {
            mock = mock.and(header(name, value));
        }

        // Add body matcher
        if let Some(body) = self.body_matcher {
            mock = mock.and(body_json(body));
        }

        // Build response
        let mut response = ResponseTemplate::new(self.response_status);

        if let Some(body) = self.response_body {
            response = response.set_body_string(body);
        }

        for (name, value) in self.response_headers {
            response = response.insert_header(name.as_str(), value.as_str());
        }

        // Convert MockBuilder to Mock, then apply expect if needed
        let mut final_mock = mock.respond_with(response);

        // Set times if specified (expect is on Mock, not MockBuilder)
        if let Some(n) = self.times {
            final_mock = final_mock.expect(1..=n);
        }

        final_mock.mount(server).await;
    }
}

/// Common HTTP response mocks
pub mod responses {
    use serde_json::json;
    use wiremock::ResponseTemplate;

    /// 200 OK with empty JSON object
    pub fn ok_empty() -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({}))
    }

    /// 200 OK with JSON body
    pub fn ok_json<T: serde::Serialize>(body: &T) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(body)
    }

    /// 201 Created
    pub fn created<T: serde::Serialize>(body: &T) -> ResponseTemplate {
        ResponseTemplate::new(201).set_body_json(body)
    }

    /// 204 No Content
    pub fn no_content() -> ResponseTemplate {
        ResponseTemplate::new(204)
    }

    /// 400 Bad Request
    pub fn bad_request(message: &str) -> ResponseTemplate {
        ResponseTemplate::new(400).set_body_json(json!({
            "error": "Bad Request",
            "message": message
        }))
    }

    /// 401 Unauthorized
    pub fn unauthorized() -> ResponseTemplate {
        ResponseTemplate::new(401).set_body_json(json!({
            "error": "Unauthorized",
            "message": "Authentication required"
        }))
    }

    /// 403 Forbidden
    pub fn forbidden() -> ResponseTemplate {
        ResponseTemplate::new(403).set_body_json(json!({
            "error": "Forbidden",
            "message": "Access denied"
        }))
    }

    /// 404 Not Found
    pub fn not_found() -> ResponseTemplate {
        ResponseTemplate::new(404).set_body_json(json!({
            "error": "Not Found",
            "message": "Resource not found"
        }))
    }

    /// 422 Unprocessable Entity (validation error)
    pub fn validation_error(field: &str, message: &str) -> ResponseTemplate {
        ResponseTemplate::new(422).set_body_json(json!({
            "error": "Validation Error",
            "details": [{
                "field": field,
                "message": message
            }]
        }))
    }

    /// 429 Too Many Requests
    pub fn rate_limited(retry_after_secs: u64) -> ResponseTemplate {
        ResponseTemplate::new(429)
            .insert_header("Retry-After", retry_after_secs.to_string())
            .set_body_json(json!({
                "error": "Too Many Requests",
                "retry_after": retry_after_secs
            }))
    }

    /// 500 Internal Server Error
    pub fn internal_error() -> ResponseTemplate {
        ResponseTemplate::new(500).set_body_json(json!({
            "error": "Internal Server Error",
            "message": "An unexpected error occurred"
        }))
    }

    /// 503 Service Unavailable
    pub fn service_unavailable() -> ResponseTemplate {
        ResponseTemplate::new(503).set_body_json(json!({
            "error": "Service Unavailable",
            "message": "The service is temporarily unavailable"
        }))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[tokio::test]
    async fn test_mock_server_starts() {
        let server = start_mock_server().await;
        assert!(!server.uri().is_empty());
    }

    #[tokio::test]
    async fn test_http_mock_builder() {
        let server = start_mock_server().await;

        HttpMockBuilder::get("/api/test")
            .with_query("foo", "bar")
            .respond_json(&serde_json::json!({"status": "ok"}))
            .mount(&server)
            .await;

        // Verify mock is mounted and responds correctly
        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/api/test?foo=bar", server.uri()))
            .send()
            .await
            .expect("Failed to send HTTP request");

        assert_eq!(response.status(), 200);
    }

    #[test]
    fn test_response_templates() {
        let ok = responses::ok_empty();
        let not_found = responses::not_found();
        let rate_limited = responses::rate_limited(60);

        // These are just builder tests, they return ResponseTemplate
        assert!(format!("{:?}", ok).contains("200"));
        assert!(format!("{:?}", not_found).contains("404"));
        assert!(format!("{:?}", rate_limited).contains("429"));
    }
}
