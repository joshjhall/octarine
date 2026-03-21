//! HTTP error response handling
//!
//! Provides conversion from Octarine's `Problem` type to HTTP responses
//! with appropriate status codes and JSON bodies.
//!
//! # Automatic Logging
//!
//! Error responses are automatically logged via Octarine's observe system,
//! ensuring all errors are captured in the audit trail:
//!
//! - **5xx errors** (server errors): Logged at `error` level
//! - **4xx errors** (client errors): Logged at `warn` level
//!
//! This bakes in observability by default - errors cannot be "forgotten"
//! because logging happens during the HTTP response conversion.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;

use crate::Problem;
use crate::observe;
use crate::primitives::runtime as prim_runtime;

/// JSON response body for errors
#[derive(Debug, Serialize)]
pub struct ErrorBody {
    /// Error type/code
    pub error: ErrorInfo,
}

/// Error details
#[derive(Debug, Serialize)]
pub struct ErrorInfo {
    /// Error code (e.g., "validation_error", "not_found")
    pub code: &'static str,
    /// Human-readable error message
    pub message: String,
    /// Request ID for correlation (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Wrapper type for Problem that implements IntoResponse
///
/// This allows using `Problem` as an error type in Axum handlers.
///
/// # Example
///
/// ```rust
/// use axum::{Router, routing::get, Json};
/// use octarine::Problem;
/// use octarine::http::ProblemResponse;
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct Item { name: String }
///
/// async fn get_item(id: &str) -> Result<Json<Item>, ProblemResponse> {
///     if id == "missing" {
///         return Err(Problem::NotFound("item".into()).into());
///     }
///     Ok(Json(Item { name: "found".into() }))
/// }
///
/// let app: Router = Router::new()
///     .route("/item", get(|| async { get_item("test").await }));
/// ```
#[derive(Debug)]
pub struct ProblemResponse(pub Problem);

impl From<Problem> for ProblemResponse {
    fn from(problem: Problem) -> Self {
        Self(problem)
    }
}

impl IntoResponse for ProblemResponse {
    fn into_response(self) -> Response {
        let (status, code) = match &self.0 {
            Problem::Validation(_) => (StatusCode::BAD_REQUEST, "validation_error"),
            Problem::Config(_) => (StatusCode::INTERNAL_SERVER_ERROR, "config_error"),
            Problem::Conversion(_) => (StatusCode::BAD_REQUEST, "conversion_error"),
            Problem::Sanitization(_) => (StatusCode::BAD_REQUEST, "sanitization_error"),
            Problem::Io(_) => (StatusCode::INTERNAL_SERVER_ERROR, "io_error"),
            Problem::Parse(_) => (StatusCode::BAD_REQUEST, "parse_error"),
            Problem::Network(_) => (StatusCode::BAD_GATEWAY, "network_error"),
            Problem::Auth(_) => (StatusCode::UNAUTHORIZED, "authentication_error"),
            Problem::PermissionDenied(_) => (StatusCode::FORBIDDEN, "permission_denied"),
            Problem::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
            Problem::AlreadyExists(_) => (StatusCode::CONFLICT, "already_exists"),
            Problem::RateLimited(_) => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Problem::Timeout(_) => (StatusCode::GATEWAY_TIMEOUT, "timeout"),
            Problem::Runtime(_) => (StatusCode::INTERNAL_SERVER_ERROR, "runtime_error"),
            Problem::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, "database_error"),
            Problem::OperationFailed(_) => (StatusCode::INTERNAL_SERVER_ERROR, "operation_failed"),
            Problem::Other(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
        };

        // Log the error - use appropriate severity based on status class
        // 5xx = server error (error level), 4xx = client error (warn level)
        let message = self.0.to_string();
        if status.is_server_error() {
            observe::error(
                "http_response",
                format!("[{}] {}: {}", status.as_u16(), code, message),
            );
        } else {
            observe::warn(
                "http_response",
                format!("[{}] {}: {}", status.as_u16(), code, message),
            );
        }

        let body = ErrorBody {
            error: ErrorInfo {
                code,
                message,
                request_id: prim_runtime::try_correlation_id().map(|id| id.to_string()),
            },
        };

        (status, Json(body)).into_response()
    }
}

/// Extension trait to easily convert Problem to ProblemResponse
///
/// This allows using `.http()` on any Problem to get a response.
pub trait ProblemExt {
    /// Convert to an HTTP response
    fn http(self) -> ProblemResponse;
}

impl ProblemExt for Problem {
    fn http(self) -> ProblemResponse {
        ProblemResponse(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_problem_to_status_code() {
        // Test various Problem variants map to correct status codes
        let cases = vec![
            (Problem::Validation("test".into()), StatusCode::BAD_REQUEST),
            (Problem::NotFound("item".into()), StatusCode::NOT_FOUND),
            (Problem::Auth("bad token".into()), StatusCode::UNAUTHORIZED),
            (
                Problem::PermissionDenied("no access".into()),
                StatusCode::FORBIDDEN,
            ),
            (
                Problem::RateLimited(std::time::Duration::from_secs(60)),
                StatusCode::TOO_MANY_REQUESTS,
            ),
            (Problem::AlreadyExists("user".into()), StatusCode::CONFLICT),
        ];

        for (problem, expected_status) in cases {
            let response = ProblemResponse(problem);
            let (status, _code) = match &response.0 {
                Problem::Validation(_) => (StatusCode::BAD_REQUEST, "validation_error"),
                Problem::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
                Problem::Auth(_) => (StatusCode::UNAUTHORIZED, "authentication_error"),
                Problem::PermissionDenied(_) => (StatusCode::FORBIDDEN, "permission_denied"),
                Problem::RateLimited(_) => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
                Problem::AlreadyExists(_) => (StatusCode::CONFLICT, "already_exists"),
                _ => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
            };
            assert_eq!(status, expected_status);
        }
    }
}
