//! Azure OpenAI client.
//!
//! Same wire format as [`openai`](super::openai), but three deployment
//! differences:
//!
//! - The model is addressed by **deployment name** in the URL path, not by a
//!   `model` field in the body.
//! - An `api-version` query parameter is mandatory.
//! - Authentication is either an `api-key` header (key auth) or an
//!   `Authorization: Bearer` header (Entra ID / Managed Identity).

use async_trait::async_trait;
use octarine::runtime::http::HttpClient;
use octarine_problem::Result;

use super::openai::{post_chat_completion, stream_chat_completion};
use super::{Credential, build_client, require_non_empty, validate_url_segment};
use crate::types::{LlmProvider, LlmRequest, LlmResponse};

/// API version used when the caller does not specify one.
///
/// Pinned rather than floating: Azure's API versions change response shapes,
/// and a silently-moving default would turn an upstream release into an
/// unexplained parse failure here.
const DEFAULT_API_VERSION: &str = "2024-10-21";

/// How the client authenticates to Azure.
#[derive(Debug, Clone)]
enum AzureAuth {
    /// A resource key, sent as the `api-key` header.
    ApiKey(Credential),
    /// An Entra ID access token, sent as `Authorization: Bearer`.
    ///
    /// Tokens expire, so this holds a caller-refreshed value: the caller
    /// rebuilds the provider with a fresh token rather than this crate taking a
    /// dependency on an Azure identity SDK to do the refresh itself.
    BearerToken(Credential),
}

/// A client for an Azure OpenAI deployment.
#[derive(Debug, Clone)]
pub struct AzureOpenAiProvider {
    client: HttpClient,
    auth: AzureAuth,
    deployment: String,
    api_version: String,
}

impl AzureOpenAiProvider {
    /// Builds a provider using resource-key authentication.
    ///
    /// `endpoint` is the resource root
    /// (`https://my-resource.openai.azure.com`); `deployment` is the
    /// deployment name, which is what appears in the URL rather than a model
    /// identifier.
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Config`](octarine_problem::Problem::Config) if any
    /// argument is empty.
    pub fn with_api_key(endpoint: &str, api_key: &str, deployment: &str) -> Result<Self> {
        let api_key = require_non_empty("api_key", api_key)?;
        Self::build(
            endpoint,
            AzureAuth::ApiKey(Credential::new(api_key)),
            deployment,
            None,
        )
    }

    /// Builds a provider using an Entra ID / Managed Identity access token.
    ///
    /// The caller owns token lifetime. Rebuild the provider when the token is
    /// refreshed — an expired token surfaces as
    /// [`Problem::Auth`](octarine_problem::Problem::Auth).
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Config`](octarine_problem::Problem::Config) if any
    /// argument is empty.
    pub fn with_bearer_token(endpoint: &str, token: &str, deployment: &str) -> Result<Self> {
        let token = require_non_empty("token", token)?;
        Self::build(
            endpoint,
            AzureAuth::BearerToken(Credential::new(token)),
            deployment,
            None,
        )
    }

    /// Overrides the pinned `api-version`.
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Config`](octarine_problem::Problem::Config) if
    /// `api_version` is empty or contains a character outside
    /// `[A-Za-z0-9._-]`, which could otherwise rewrite the request URL.
    pub fn with_api_version(mut self, api_version: impl Into<String>) -> Result<Self> {
        self.api_version = validate_url_segment("api_version", &api_version.into())?;
        Ok(self)
    }

    /// Shared construction path.
    fn build(
        endpoint: &str,
        auth: AzureAuth,
        deployment: &str,
        api_version: Option<&str>,
    ) -> Result<Self> {
        let endpoint = require_non_empty("endpoint", endpoint)?;
        // Spliced into the request path — must not be able to alter the URL.
        let deployment = validate_url_segment("deployment", deployment)?;
        // Trailing slashes would otherwise produce a double slash in the path.
        let endpoint = endpoint.trim_end_matches('/').to_string();

        Ok(Self {
            client: build_client("azure_openai", &endpoint)?,
            auth,
            deployment,
            api_version: api_version.unwrap_or(DEFAULT_API_VERSION).to_string(),
        })
    }

    /// Builds the deployment-scoped request path, including `api-version`.
    fn request_path(&self) -> String {
        format!(
            "/openai/deployments/{}/chat/completions?api-version={}",
            self.deployment, self.api_version
        )
    }

    /// The credential header for the configured auth mode.
    fn auth_header(&self) -> (&'static str, String) {
        match &self.auth {
            AzureAuth::ApiKey(key) => ("api-key", key.expose().to_string()),
            AzureAuth::BearerToken(token) => {
                ("Authorization", format!("Bearer {}", token.expose()))
            }
        }
    }
}

#[async_trait]
impl LlmProvider for AzureOpenAiProvider {
    async fn complete(&self, request: &LlmRequest) -> Result<LlmResponse> {
        post_chat_completion(
            &self.client,
            "azure_openai",
            &self.request_path(),
            self.auth_header(),
            request,
            // Azure ignores the body `model` field — the deployment in the URL
            // selects the model — but it is echoed for response attribution.
            &self.deployment,
        )
        .await
    }

    async fn complete_streaming(&self, request: &LlmRequest) -> Result<LlmResponse> {
        stream_chat_completion(
            &self.client,
            "azure_openai",
            &self.request_path(),
            self.auth_header(),
            request,
            &self.deployment,
        )
        .await
    }

    fn name(&self) -> &str {
        "azure_openai"
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    fn provider() -> AzureOpenAiProvider {
        AzureOpenAiProvider::with_api_key("https://res.openai.azure.com", "key123", "gpt4o-deploy")
            .expect("valid")
    }

    #[test]
    fn path_addresses_the_deployment_and_pins_the_api_version() {
        let path = provider().request_path();
        assert_eq!(
            path,
            format!(
                "/openai/deployments/gpt4o-deploy/chat/completions?api-version={DEFAULT_API_VERSION}"
            ),
        );
    }

    #[test]
    fn api_version_override_reaches_the_path() {
        let path = provider()
            .with_api_version("2025-01-01-preview")
            .expect("a well-formed api-version is accepted")
            .request_path();
        assert!(
            path.ends_with("api-version=2025-01-01-preview"),
            "the override must win over the pinned default, got: {path}"
        );
    }

    #[test]
    fn a_deployment_name_cannot_rewrite_the_query_string() {
        // Each of these would alter the request target if interpolated raw.
        for hostile in [
            "deploy?api-version=evil",
            "deploy&x=1",
            "deploy#frag",
            "../../other/deployment",
            "deploy/extra",
            "deploy with space",
        ] {
            assert!(
                AzureOpenAiProvider::with_api_key("https://res.openai.azure.com", "k", hostile)
                    .is_err(),
                "deployment {hostile:?} must be rejected, not spliced into the URL"
            );
        }
    }

    #[test]
    fn a_hostile_api_version_is_rejected() {
        let outcome = provider().with_api_version("2024-10-21&injected=1");
        assert!(
            outcome.is_err(),
            "an api-version must not be able to append query parameters"
        );
    }

    #[test]
    fn legitimate_deployment_names_are_still_accepted() {
        // The guard must not be so tight it rejects real Azure names.
        for ok in ["gpt-4o", "gpt4o_deploy", "my.deployment-2", "GPT4O"] {
            assert!(
                AzureOpenAiProvider::with_api_key("https://res.openai.azure.com", "k", ok).is_ok(),
                "deployment {ok:?} is well-formed and must be accepted"
            );
        }
    }

    #[test]
    fn key_auth_uses_the_api_key_header_not_bearer() {
        // Azure rejects a bearer-formatted resource key, so the distinction is
        // functional, not cosmetic.
        let (header, value) = provider().auth_header();
        assert_eq!(header, "api-key");
        assert_eq!(value, "key123");
        assert!(!value.starts_with("Bearer"));
    }

    #[test]
    fn token_auth_uses_bearer_authorization() {
        let provider =
            AzureOpenAiProvider::with_bearer_token("https://res.openai.azure.com", "eyJ0eA", "d")
                .expect("valid");
        let (header, value) = provider.auth_header();
        assert_eq!(header, "Authorization");
        assert_eq!(value, "Bearer eyJ0eA");
    }

    #[test]
    fn trailing_slash_on_the_endpoint_does_not_double_the_separator() {
        let provider = AzureOpenAiProvider::with_api_key("https://res.openai.azure.com/", "k", "d")
            .expect("valid");
        // The path always starts with '/', so the base must not also end with one.
        assert!(provider.request_path().starts_with("/openai/"));
    }

    #[test]
    fn construction_rejects_empty_arguments() {
        assert!(AzureOpenAiProvider::with_api_key("", "k", "d").is_err());
        assert!(AzureOpenAiProvider::with_api_key("https://x", "", "d").is_err());
        assert!(AzureOpenAiProvider::with_api_key("https://x", "k", "").is_err());
        assert!(AzureOpenAiProvider::with_bearer_token("https://x", "", "d").is_err());
    }
}
