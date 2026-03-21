//! HTTP-specific retry classification
//!
//! Determines whether HTTP responses and errors should be retried.

use reqwest::StatusCode;

/// Check if an HTTP status code is retryable
///
/// Retryable statuses:
/// - 408 Request Timeout
/// - 425 Too Early
/// - 429 Too Many Requests (rate limited)
/// - 500-599 Server errors
///
/// Non-retryable:
/// - 4xx client errors (except 408, 425, 429)
/// - 1xx, 2xx, 3xx (not errors)
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::runtime::http::is_retryable_status;
/// use reqwest::StatusCode;
///
/// assert!(is_retryable_status(StatusCode::INTERNAL_SERVER_ERROR));
/// assert!(is_retryable_status(StatusCode::TOO_MANY_REQUESTS));
/// assert!(!is_retryable_status(StatusCode::NOT_FOUND));
/// assert!(!is_retryable_status(StatusCode::BAD_REQUEST));
/// ```
#[must_use]
pub fn is_retryable_status(status: StatusCode) -> bool {
    match status.as_u16() {
        408 | 425 | 429 => true, // Timeout, Too Early, Rate Limited
        500..=599 => true,       // Server errors
        _ => false,              // Client errors = don't retry
    }
}

/// Check if a reqwest error is retryable
///
/// Retryable errors:
/// - Timeout errors
/// - Connection errors
/// - Request errors (failed to build/send)
///
/// Non-retryable:
/// - Decode errors (response body issues)
/// - Redirect errors
/// - Builder errors
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::runtime::http::is_retryable_error;
///
/// // Timeout errors are retryable
/// let err = reqwest::Error::from(...); // timeout error
/// assert!(is_retryable_error(&err));
/// ```
#[must_use]
pub fn is_retryable_error(err: &reqwest::Error) -> bool {
    err.is_timeout() || err.is_connect() || err.is_request()
}

/// Retry classification result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    /// Do not retry - operation succeeded or is not retryable
    NoRetry,
    /// Retry with standard backoff
    Retry,
    /// Retry with longer backoff (e.g., rate limited)
    RetryWithBackoff,
}

impl RetryDecision {
    /// Check if retry should be attempted
    #[must_use]
    pub fn should_retry(&self) -> bool {
        matches!(self, Self::Retry | Self::RetryWithBackoff)
    }

    /// Check if this is a rate-limit backoff
    #[must_use]
    pub fn is_rate_limited(&self) -> bool {
        matches!(self, Self::RetryWithBackoff)
    }
}

/// Classify a status code for retry decisions
#[must_use]
pub fn classify_status(status: StatusCode) -> RetryDecision {
    match status.as_u16() {
        429 => RetryDecision::RetryWithBackoff, // Rate limited - use longer backoff
        408 | 425 => RetryDecision::Retry,      // Timeout, Too Early
        500..=599 => RetryDecision::Retry,      // Server errors
        _ => RetryDecision::NoRetry,            // Success or client error
    }
}

/// Classify a reqwest error for retry decisions
#[must_use]
pub fn classify_error(err: &reqwest::Error) -> RetryDecision {
    if is_retryable_error(err) {
        RetryDecision::Retry
    } else {
        RetryDecision::NoRetry
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_retryable_server_errors() {
        assert!(is_retryable_status(StatusCode::INTERNAL_SERVER_ERROR));
        assert!(is_retryable_status(StatusCode::BAD_GATEWAY));
        assert!(is_retryable_status(StatusCode::SERVICE_UNAVAILABLE));
        assert!(is_retryable_status(StatusCode::GATEWAY_TIMEOUT));
    }

    #[test]
    fn test_retryable_special_cases() {
        assert!(is_retryable_status(StatusCode::REQUEST_TIMEOUT)); // 408
        assert!(is_retryable_status(StatusCode::TOO_MANY_REQUESTS)); // 429
    }

    #[test]
    fn test_non_retryable_client_errors() {
        assert!(!is_retryable_status(StatusCode::BAD_REQUEST));
        assert!(!is_retryable_status(StatusCode::UNAUTHORIZED));
        assert!(!is_retryable_status(StatusCode::FORBIDDEN));
        assert!(!is_retryable_status(StatusCode::NOT_FOUND));
        assert!(!is_retryable_status(StatusCode::METHOD_NOT_ALLOWED));
        assert!(!is_retryable_status(StatusCode::CONFLICT));
        assert!(!is_retryable_status(StatusCode::GONE));
        assert!(!is_retryable_status(StatusCode::UNPROCESSABLE_ENTITY));
    }

    #[test]
    fn test_non_retryable_success() {
        assert!(!is_retryable_status(StatusCode::OK));
        assert!(!is_retryable_status(StatusCode::CREATED));
        assert!(!is_retryable_status(StatusCode::NO_CONTENT));
    }

    #[test]
    fn test_classify_status() {
        assert_eq!(
            classify_status(StatusCode::TOO_MANY_REQUESTS),
            RetryDecision::RetryWithBackoff
        );
        assert_eq!(
            classify_status(StatusCode::INTERNAL_SERVER_ERROR),
            RetryDecision::Retry
        );
        assert_eq!(
            classify_status(StatusCode::NOT_FOUND),
            RetryDecision::NoRetry
        );
        assert_eq!(classify_status(StatusCode::OK), RetryDecision::NoRetry);
    }

    #[test]
    fn test_retry_decision() {
        assert!(RetryDecision::Retry.should_retry());
        assert!(RetryDecision::RetryWithBackoff.should_retry());
        assert!(!RetryDecision::NoRetry.should_retry());

        assert!(RetryDecision::RetryWithBackoff.is_rate_limited());
        assert!(!RetryDecision::Retry.is_rate_limited());
        assert!(!RetryDecision::NoRetry.is_rate_limited());
    }

    // Edge case tests for boundary conditions

    #[test]
    fn test_425_too_early() {
        // 425 Too Early is retryable (used in TLS early data scenarios)
        let status = StatusCode::from_u16(425).expect("425 is valid");
        assert!(is_retryable_status(status));
        assert_eq!(classify_status(status), RetryDecision::Retry);
    }

    #[test]
    fn test_server_error_boundaries() {
        // 499 is NOT retryable (last 4xx)
        let status_499 = StatusCode::from_u16(499).expect("499 is valid");
        assert!(!is_retryable_status(status_499));
        assert_eq!(classify_status(status_499), RetryDecision::NoRetry);

        // 500 IS retryable (first 5xx)
        assert!(is_retryable_status(StatusCode::INTERNAL_SERVER_ERROR)); // 500
        assert_eq!(
            classify_status(StatusCode::INTERNAL_SERVER_ERROR),
            RetryDecision::Retry
        );

        // 599 IS retryable (last 5xx)
        let status_599 = StatusCode::from_u16(599).expect("599 is valid");
        assert!(is_retryable_status(status_599));
        assert_eq!(classify_status(status_599), RetryDecision::Retry);

        // 600 doesn't exist in HTTP but would NOT be retryable
        // (reqwest StatusCode::from_u16 would fail, so we can't test this directly)
    }

    #[test]
    fn test_4xx_not_retryable_except_special_cases() {
        // Standard 4xx errors are NOT retryable
        let non_retryable_4xx = [
            400, 401, 402, 403, 404, 405, 406, 407, 409, 410, 411, 412, 413, 414, 415, 416, 417,
            418, 421, 422, 423, 424, 426, 428, 431, 451,
        ];

        for code in non_retryable_4xx {
            let status = StatusCode::from_u16(code).expect("valid status code");
            assert!(
                !is_retryable_status(status),
                "Expected {} to NOT be retryable",
                code
            );
            assert_eq!(
                classify_status(status),
                RetryDecision::NoRetry,
                "Expected {} to have NoRetry decision",
                code
            );
        }

        // These 4xx ARE retryable (special cases)
        let retryable_4xx = [408, 425, 429];
        for code in retryable_4xx {
            let status = StatusCode::from_u16(code).expect("valid status code");
            assert!(
                is_retryable_status(status),
                "Expected {} to be retryable",
                code
            );
        }
    }

    #[test]
    fn test_1xx_2xx_3xx_not_retryable() {
        // 1xx Informational
        assert!(!is_retryable_status(StatusCode::CONTINUE)); // 100
        assert!(!is_retryable_status(StatusCode::SWITCHING_PROTOCOLS)); // 101

        // 2xx Success
        assert!(!is_retryable_status(StatusCode::OK)); // 200
        assert!(!is_retryable_status(StatusCode::CREATED)); // 201
        assert!(!is_retryable_status(StatusCode::ACCEPTED)); // 202
        assert!(!is_retryable_status(StatusCode::NO_CONTENT)); // 204

        // 3xx Redirection
        assert!(!is_retryable_status(StatusCode::MOVED_PERMANENTLY)); // 301
        assert!(!is_retryable_status(StatusCode::FOUND)); // 302
        assert!(!is_retryable_status(StatusCode::NOT_MODIFIED)); // 304
        assert!(!is_retryable_status(StatusCode::TEMPORARY_REDIRECT)); // 307
    }

    #[test]
    fn test_classify_all_5xx_as_retry() {
        // All 5xx codes should be Retry (not RetryWithBackoff)
        for code in 500..=511 {
            let status = StatusCode::from_u16(code).expect("valid status code");
            assert_eq!(
                classify_status(status),
                RetryDecision::Retry,
                "Expected {} to have Retry decision (not RetryWithBackoff)",
                code
            );
        }
    }

    #[test]
    fn test_429_uses_retry_with_backoff() {
        // 429 specifically gets longer backoff (rate limiting)
        assert_eq!(
            classify_status(StatusCode::TOO_MANY_REQUESTS),
            RetryDecision::RetryWithBackoff
        );

        // But 408 and 425 get regular retry
        assert_eq!(
            classify_status(StatusCode::REQUEST_TIMEOUT),
            RetryDecision::Retry
        );
        let status_425 = StatusCode::from_u16(425).expect("425 is valid");
        assert_eq!(classify_status(status_425), RetryDecision::Retry);
    }

    #[test]
    fn test_retry_decision_equality() {
        // Ensure PartialEq and Eq work correctly
        assert_eq!(RetryDecision::Retry, RetryDecision::Retry);
        assert_eq!(RetryDecision::NoRetry, RetryDecision::NoRetry);
        assert_eq!(
            RetryDecision::RetryWithBackoff,
            RetryDecision::RetryWithBackoff
        );

        assert_ne!(RetryDecision::Retry, RetryDecision::NoRetry);
        assert_ne!(RetryDecision::Retry, RetryDecision::RetryWithBackoff);
        assert_ne!(RetryDecision::NoRetry, RetryDecision::RetryWithBackoff);
    }

    #[test]
    fn test_retry_decision_copy() {
        // Ensure Copy works (Clone is implied by Copy)
        let decision = RetryDecision::Retry;
        let copied = decision; // Copy

        assert_eq!(decision, copied);

        // Both should still be usable after copy
        assert!(decision.should_retry());
        assert!(copied.should_retry());
    }

    #[test]
    fn test_retry_decision_debug() {
        assert_eq!(format!("{:?}", RetryDecision::Retry), "Retry");
        assert_eq!(format!("{:?}", RetryDecision::NoRetry), "NoRetry");
        assert_eq!(
            format!("{:?}", RetryDecision::RetryWithBackoff),
            "RetryWithBackoff"
        );
    }
}
