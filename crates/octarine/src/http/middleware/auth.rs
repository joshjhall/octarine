//! HTTP authentication middleware
//!
//! Validates JWT tokens and API keys in incoming requests, setting the
//! user context for downstream handlers.
//!
//! # Authentication Methods
//!
//! - **JWT**: Bearer tokens in the `Authorization` header
//! - **API Key**: Keys in a configurable header (default: `X-Api-Key`)
//!
//! # Example
//!
//! ```rust,ignore
//! use axum::{Router, routing::get};
//! use octarine::http::middleware::{AuthLayer, AuthConfig};
//!
//! let config = AuthConfig::jwt("my-secret-key")
//!     .exclude_paths(["/health", "/public"]);
//!
//! let app: Router = Router::new()
//!     .route("/api/protected", get(|| async { "secret data" }))
//!     .layer(AuthLayer::with_config(config));
//! ```
//!
//! # JWT Claims
//!
//! The middleware extracts standard claims from JWT tokens:
//! - `sub` (subject): Set as user ID
//! - `tenant` or `tenant_id`: Set as tenant ID
//! - `exp` (expiration): Validated automatically
//!
//! # API Key Validation
//!
//! For API keys, provide a validation function:
//!
//! ```rust,ignore
//! use octarine::http::middleware::{AuthConfig, AuthLayer};
//!
//! let config = AuthConfig::api_key(|key: &str| {
//!     // Validate key against your store
//!     if key == "valid-key" {
//!         Some(("user-123".to_string(), Some("tenant-abc".to_string())))
//!     } else {
//!         None
//!     }
//! });
//!
//! let layer = AuthLayer::with_config(config);
//! ```

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use axum::{
    body::Body,
    http::{Request, Response, header::HeaderName},
    response::IntoResponse,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use tower::{Layer, Service};

use super::super::ProblemResponse;
use crate::Problem;
use crate::observe;
use crate::primitives::runtime as prim_runtime;

/// Type alias for API key validation function.
///
/// Returns `(user_id, tenant_id)` on success, `None` on failure.
pub type ApiKeyValidator = Arc<dyn Fn(&str) -> Option<(String, Option<String>)> + Send + Sync>;

/// Header name for API key
pub static X_API_KEY: HeaderName = HeaderName::from_static("x-api-key");

/// Header name for Authorization
pub static AUTHORIZATION: HeaderName = HeaderName::from_static("authorization");

/// Standard JWT claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    pub sub: String,
    /// Expiration time (seconds since epoch)
    pub exp: u64,
    /// Issued at time (seconds since epoch)
    #[serde(default)]
    pub iat: Option<u64>,
    /// Tenant ID (custom claim)
    #[serde(default, alias = "tenant")]
    pub tenant_id: Option<String>,
    /// User roles (custom claim)
    #[serde(default)]
    pub roles: Vec<String>,
}

/// Authentication method configuration
#[derive(Clone)]
pub enum AuthMethod {
    /// JWT token validation
    Jwt {
        /// Secret key for HS256 or public key for RS256
        key: Arc<DecodingKey>,
        /// JWT validation configuration
        validation: Validation,
    },
    /// API key validation
    ApiKey {
        /// Header name for the API key
        header: HeaderName,
        /// Validation function returning (user_id, tenant_id) on success
        validator: ApiKeyValidator,
    },
    /// Support both JWT and API key
    Both {
        /// JWT configuration
        jwt_key: Arc<DecodingKey>,
        jwt_validation: Validation,
        /// API key header
        api_key_header: HeaderName,
        /// API key validator
        api_key_validator: ApiKeyValidator,
    },
}

impl std::fmt::Debug for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Jwt { .. } => f.debug_struct("Jwt").finish_non_exhaustive(),
            Self::ApiKey { header, .. } => f
                .debug_struct("ApiKey")
                .field("header", header)
                .finish_non_exhaustive(),
            Self::Both { api_key_header, .. } => f
                .debug_struct("Both")
                .field("api_key_header", api_key_header)
                .finish_non_exhaustive(),
        }
    }
}

/// Configuration for authentication middleware
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Authentication method
    method: AuthMethod,
    /// Paths to exclude from authentication
    exclude_paths: Vec<String>,
    /// Whether to require authentication on all paths (except excluded)
    require_auth: bool,
}

impl AuthConfig {
    /// Create a JWT authentication config with HMAC-SHA256.
    ///
    /// # Arguments
    ///
    /// * `secret` - The secret key for HMAC-SHA256 signing
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use octarine::http::middleware::AuthConfig;
    ///
    /// let config = AuthConfig::jwt("my-secret-key");
    /// ```
    #[must_use]
    pub fn jwt(secret: &str) -> Self {
        let key = DecodingKey::from_secret(secret.as_bytes());
        let validation = Validation::new(Algorithm::HS256);

        Self {
            method: AuthMethod::Jwt {
                key: Arc::new(key),
                validation,
            },
            exclude_paths: Vec::new(),
            require_auth: true,
        }
    }

    /// Create a JWT authentication config with RSA-SHA256.
    ///
    /// # Arguments
    ///
    /// * `public_key_pem` - The RSA public key in PEM format
    ///
    /// # Errors
    ///
    /// Returns an error if the PEM key is invalid.
    pub fn jwt_rsa(public_key_pem: &str) -> Result<Self, Problem> {
        let key = DecodingKey::from_rsa_pem(public_key_pem.as_bytes())
            .map_err(|e| Problem::Config(format!("Invalid RSA public key: {}", e)))?;
        let validation = Validation::new(Algorithm::RS256);

        Ok(Self {
            method: AuthMethod::Jwt {
                key: Arc::new(key),
                validation,
            },
            exclude_paths: Vec::new(),
            require_auth: true,
        })
    }

    /// Create an API key authentication config.
    ///
    /// # Arguments
    ///
    /// * `validator` - Function that validates API keys and returns (user_id, tenant_id)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use octarine::http::middleware::AuthConfig;
    ///
    /// let config = AuthConfig::api_key(|key: &str| {
    ///     if key == "valid-key" {
    ///         Some(("user-123".to_string(), Some("tenant-abc".to_string())))
    ///     } else {
    ///         None
    ///     }
    /// });
    /// ```
    #[must_use]
    pub fn api_key<F>(validator: F) -> Self
    where
        F: Fn(&str) -> Option<(String, Option<String>)> + Send + Sync + 'static,
    {
        Self {
            method: AuthMethod::ApiKey {
                header: X_API_KEY.clone(),
                validator: Arc::new(validator),
            },
            exclude_paths: Vec::new(),
            require_auth: true,
        }
    }

    /// Create a config that accepts both JWT and API key.
    ///
    /// The middleware will first check for a JWT Bearer token, then fall back
    /// to checking for an API key.
    #[must_use]
    pub fn both<F>(secret: &str, api_key_validator: F) -> Self
    where
        F: Fn(&str) -> Option<(String, Option<String>)> + Send + Sync + 'static,
    {
        let key = DecodingKey::from_secret(secret.as_bytes());
        let validation = Validation::new(Algorithm::HS256);

        Self {
            method: AuthMethod::Both {
                jwt_key: Arc::new(key),
                jwt_validation: validation,
                api_key_header: X_API_KEY.clone(),
                api_key_validator: Arc::new(api_key_validator),
            },
            exclude_paths: Vec::new(),
            require_auth: true,
        }
    }

    /// Set paths to exclude from authentication.
    ///
    /// Paths are matched as prefixes, so `/health` will match `/health/live`.
    #[must_use]
    pub fn exclude_paths<I, S>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.exclude_paths = paths.into_iter().map(Into::into).collect();
        self
    }

    /// Set custom header name for API key.
    #[must_use]
    pub fn with_api_key_header(mut self, header: HeaderName) -> Self {
        match &mut self.method {
            AuthMethod::ApiKey { header: h, .. } => *h = header,
            AuthMethod::Both {
                api_key_header: h, ..
            } => *h = header,
            AuthMethod::Jwt { .. } => {
                // Silently ignore for JWT-only config
            }
        }
        self
    }

    /// Make authentication optional.
    ///
    /// When optional, requests without credentials will be allowed through
    /// without setting user context. Invalid credentials will still be rejected.
    #[must_use]
    pub fn optional(mut self) -> Self {
        self.require_auth = false;
        self
    }

    /// Check if a path should be excluded from authentication.
    fn is_excluded(&self, path: &str) -> bool {
        self.exclude_paths.iter().any(|p| path.starts_with(p))
    }
}

/// Layer that adds authentication to a service.
#[derive(Debug, Clone)]
pub struct AuthLayer {
    config: AuthConfig,
}

impl AuthLayer {
    /// Create a new auth layer with JWT authentication.
    #[must_use]
    pub fn jwt(secret: &str) -> Self {
        Self {
            config: AuthConfig::jwt(secret),
        }
    }

    /// Create an auth layer with custom configuration.
    #[must_use]
    pub fn with_config(config: AuthConfig) -> Self {
        Self { config }
    }
}

impl<S> Layer<S> for AuthLayer {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            config: self.config.clone(),
        }
    }
}

/// Service that validates authentication credentials.
#[derive(Debug, Clone)]
pub struct AuthService<S> {
    inner: S,
    config: AuthConfig,
}

/// Result of authentication attempt
enum AuthResult {
    /// Authentication succeeded
    Success {
        user_id: String,
        tenant_id: Option<String>,
    },
    /// No credentials provided
    NoCredentials,
    /// Invalid credentials
    Invalid(String),
}

impl<S> AuthService<S> {
    /// Extract and validate authentication from request.
    fn authenticate(&self, request: &Request<Body>) -> AuthResult {
        match &self.config.method {
            AuthMethod::Jwt { key, validation } => self.authenticate_jwt(request, key, validation),
            AuthMethod::ApiKey { header, validator } => {
                self.authenticate_api_key(request, header, validator)
            }
            AuthMethod::Both {
                jwt_key,
                jwt_validation,
                api_key_header,
                api_key_validator,
            } => {
                // Try JWT first
                match self.authenticate_jwt(request, jwt_key, jwt_validation) {
                    AuthResult::Success { user_id, tenant_id } => {
                        AuthResult::Success { user_id, tenant_id }
                    }
                    AuthResult::Invalid(reason) => AuthResult::Invalid(reason),
                    AuthResult::NoCredentials => {
                        // Fall back to API key
                        self.authenticate_api_key(request, api_key_header, api_key_validator)
                    }
                }
            }
        }
    }

    /// Authenticate via JWT Bearer token.
    fn authenticate_jwt(
        &self,
        request: &Request<Body>,
        key: &DecodingKey,
        validation: &Validation,
    ) -> AuthResult {
        // Get Authorization header
        let auth_header = match request.headers().get(&AUTHORIZATION) {
            Some(h) => h,
            None => return AuthResult::NoCredentials,
        };

        // Parse header value
        let auth_str = match auth_header.to_str() {
            Ok(s) => s,
            Err(_) => return AuthResult::Invalid("Invalid Authorization header encoding".into()),
        };

        // Check for Bearer prefix
        if !auth_str.starts_with("Bearer ") {
            return AuthResult::NoCredentials;
        }

        let token = &auth_str[7..]; // Skip "Bearer "

        // Decode and validate JWT
        match decode::<Claims>(token, key, validation) {
            Ok(token_data) => {
                let claims = token_data.claims;
                AuthResult::Success {
                    user_id: claims.sub,
                    tenant_id: claims.tenant_id,
                }
            }
            Err(e) => AuthResult::Invalid(format!("Invalid token: {}", e)),
        }
    }

    /// Authenticate via API key.
    fn authenticate_api_key(
        &self,
        request: &Request<Body>,
        header: &HeaderName,
        validator: &ApiKeyValidator,
    ) -> AuthResult {
        // Get API key header
        let api_key = match request.headers().get(header) {
            Some(h) => h,
            None => return AuthResult::NoCredentials,
        };

        // Parse header value
        let key_str = match api_key.to_str() {
            Ok(s) => s,
            Err(_) => return AuthResult::Invalid("Invalid API key header encoding".into()),
        };

        // Validate the key
        match validator(key_str) {
            Some((user_id, tenant_id)) => AuthResult::Success { user_id, tenant_id },
            None => AuthResult::Invalid("Invalid API key".into()),
        }
    }
}

impl<S> Service<Request<Body>> for AuthService<S>
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
        let path = request.uri().path().to_string();

        // Skip authentication for excluded paths
        if self.config.is_excluded(&path) {
            let mut inner = self.inner.clone();
            return Box::pin(async move { inner.call(request).await });
        }

        // Attempt authentication
        let auth_result = self.authenticate(&request);
        let require_auth = self.config.require_auth;

        match auth_result {
            AuthResult::Success { user_id, tenant_id } => {
                // Set user context
                prim_runtime::set_user_id(&user_id);
                if let Some(ref tenant) = tenant_id {
                    prim_runtime::set_tenant_id(tenant);
                }

                // Log success
                observe::event::auth_success(&user_id);

                let mut inner = self.inner.clone();
                Box::pin(async move { inner.call(request).await })
            }
            AuthResult::NoCredentials => {
                if require_auth {
                    // Log failure
                    observe::event::auth_failure("anonymous", "No credentials provided");

                    // Return 401 Unauthorized
                    Box::pin(async move {
                        let response =
                            ProblemResponse(Problem::Auth("Authentication required".into()))
                                .into_response();
                        Ok(response.map(Body::new))
                    })
                } else {
                    // Optional auth - allow through without context
                    let mut inner = self.inner.clone();
                    Box::pin(async move { inner.call(request).await })
                }
            }
            AuthResult::Invalid(reason) => {
                // Log failure
                observe::event::auth_failure("unknown", &reason);

                // Return 401 Unauthorized
                Box::pin(async move {
                    let response = ProblemResponse(Problem::Auth(reason)).into_response();
                    Ok(response.map(Body::new))
                })
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_config_jwt() {
        let config = AuthConfig::jwt("secret");
        assert!(config.require_auth);
        assert!(config.exclude_paths.is_empty());
        assert!(matches!(config.method, AuthMethod::Jwt { .. }));
    }

    #[test]
    fn test_config_api_key() {
        let config = AuthConfig::api_key(|_| None);
        assert!(matches!(config.method, AuthMethod::ApiKey { .. }));
    }

    #[test]
    fn test_config_both() {
        let config = AuthConfig::both("secret", |_| None);
        assert!(matches!(config.method, AuthMethod::Both { .. }));
    }

    #[test]
    fn test_config_exclude_paths() {
        let config = AuthConfig::jwt("secret").exclude_paths(["/health", "/metrics"]);
        assert!(config.is_excluded("/health"));
        assert!(config.is_excluded("/health/live"));
        assert!(config.is_excluded("/metrics"));
        assert!(!config.is_excluded("/api/users"));
    }

    #[test]
    fn test_config_optional() {
        let config = AuthConfig::jwt("secret").optional();
        assert!(!config.require_auth);
    }

    #[test]
    fn test_config_custom_api_key_header() {
        let custom = HeaderName::from_static("x-custom-key");
        let config = AuthConfig::api_key(|_| None).with_api_key_header(custom.clone());

        assert!(
            matches!(&config.method, AuthMethod::ApiKey { header, .. } if *header == custom),
            "Expected ApiKey method with custom header"
        );
    }

    #[test]
    fn test_layer_creation() {
        let _layer = AuthLayer::jwt("secret");
        let _layer = AuthLayer::with_config(AuthConfig::jwt("secret"));
    }

    #[test]
    fn test_claims_deserialization() {
        let json = r#"{
            "sub": "user-123",
            "exp": 1735689600,
            "iat": 1735686000,
            "tenant_id": "tenant-abc",
            "roles": ["admin", "user"]
        }"#;

        let claims: Claims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.exp, 1735689600);
        assert_eq!(claims.iat, Some(1735686000));
        assert_eq!(claims.tenant_id, Some("tenant-abc".to_string()));
        assert_eq!(claims.roles, vec!["admin", "user"]);
    }

    #[test]
    fn test_claims_tenant_alias() {
        // Test that "tenant" is aliased to "tenant_id"
        let json = r#"{
            "sub": "user-123",
            "exp": 1735689600,
            "tenant": "tenant-abc"
        }"#;

        let claims: Claims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.tenant_id, Some("tenant-abc".to_string()));
    }

    #[test]
    fn test_claims_minimal() {
        // Only required fields
        let json = r#"{
            "sub": "user-123",
            "exp": 1735689600
        }"#;

        let claims: Claims = serde_json::from_str(json).unwrap();
        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.exp, 1735689600);
        assert!(claims.iat.is_none());
        assert!(claims.tenant_id.is_none());
        assert!(claims.roles.is_empty());
    }
}
