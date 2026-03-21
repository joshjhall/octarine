//! API Testing Utilities
//!
//! Provides utilities for testing HTTP APIs and MCP (Model Context Protocol)
//! servers using wiremock for mocking.
//!
//! ## HTTP Mocking
//!
//! ```rust,ignore
//! use octarine::testing::api::*;
//! use wiremock::{Mock, ResponseTemplate};
//! use wiremock::matchers::*;
//!
//! #[tokio::test]
//! async fn test_api_call() {
//!     let mock_server = MockServer::start().await;
//!
//!     Mock::given(method("GET"))
//!         .and(path("/api/users"))
//!         .respond_with(ResponseTemplate::new(200).set_body_json(json!({"users": []})))
//!         .mount(&mock_server)
//!         .await;
//!
//!     let client = reqwest::Client::new();
//!     let response = client.get(mock_server.uri("/api/users")).send().await.unwrap();
//!
//!     assert_eq!(response.status(), 200);
//! }
//! ```

mod http;
mod mcp;

pub use http::*;
pub use mcp::*;

// Re-export wiremock for convenience
pub use wiremock;
