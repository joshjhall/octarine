//! Authentication audit builder.
//!
//! Provides a fluent API for auditing authentication events.

use crate::observe::audit::event::AuditEvent;
use crate::observe::audit::types::{AuthType, Outcome};
use crate::observe::compliance::{ComplianceTags, HipaaSafeguard, Iso27001Control, Soc2Control};
use crate::observe::types::EventType;

/// Builder for authentication audit events.
///
/// # Example
///
/// ```ignore
/// use octarine::observe::audit::Audit;
///
/// // Login success
/// Audit::auth()
///     .login("user@example.com")
///     .with_mfa()
///     .success()
///     .emit();
///
/// // Login failure
/// Audit::auth()
///     .login("user@example.com")
///     .failure("Invalid password")
///     .emit();
/// ```
#[derive(Debug, Clone)]
pub struct AuthAuditBuilder {
    auth_type: AuthType,
    username: Option<String>,
    mfa_used: bool,
    provider: Option<String>,
}

impl AuthAuditBuilder {
    /// Create a new authentication audit builder.
    pub fn new() -> Self {
        Self {
            auth_type: AuthType::Login,
            username: None,
            mfa_used: false,
            provider: None,
        }
    }

    /// Set this as a login event.
    #[must_use]
    pub fn login(mut self, username: &str) -> Self {
        self.auth_type = AuthType::Login;
        self.username = Some(username.to_string());
        self
    }

    /// Set this as a logout event.
    #[must_use]
    pub fn logout(mut self, username: &str) -> Self {
        self.auth_type = AuthType::Logout;
        self.username = Some(username.to_string());
        self
    }

    /// Set this as a password change event.
    #[must_use]
    pub fn password_change(mut self, username: &str) -> Self {
        self.auth_type = AuthType::PasswordChange;
        self.username = Some(username.to_string());
        self
    }

    /// Set this as a password reset event.
    #[must_use]
    pub fn password_reset(mut self, username: &str) -> Self {
        self.auth_type = AuthType::PasswordReset;
        self.username = Some(username.to_string());
        self
    }

    /// Set this as a token refresh event.
    #[must_use]
    pub fn token_refresh(mut self, username: &str) -> Self {
        self.auth_type = AuthType::TokenRefresh;
        self.username = Some(username.to_string());
        self
    }

    /// Set this as a session creation event.
    #[must_use]
    pub fn session_create(mut self, username: &str) -> Self {
        self.auth_type = AuthType::SessionCreate;
        self.username = Some(username.to_string());
        self
    }

    /// Set this as a session destruction event.
    #[must_use]
    pub fn session_destroy(mut self, username: &str) -> Self {
        self.auth_type = AuthType::SessionDestroy;
        self.username = Some(username.to_string());
        self
    }

    /// Indicate that MFA was used.
    #[must_use]
    pub fn with_mfa(mut self) -> Self {
        self.mfa_used = true;
        self
    }

    /// Set the authentication provider (e.g., "oauth", "ldap", "saml").
    #[must_use]
    pub fn provider(mut self, provider: &str) -> Self {
        self.provider = Some(provider.to_string());
        self
    }

    /// Build a successful authentication event.
    #[must_use]
    pub fn success(self) -> AuditEvent {
        self.build_event(Outcome::Success)
    }

    /// Build a failed authentication event.
    #[must_use]
    pub fn failure(self, reason: &str) -> AuditEvent {
        self.build_event(Outcome::Failure(reason.to_string()))
    }

    /// Build a pending authentication event.
    ///
    /// Use this for multi-step authentication where the final outcome is not yet known.
    #[must_use]
    pub fn pending(self) -> AuditEvent {
        self.build_event(Outcome::Pending)
    }

    /// Build an authentication event with unknown outcome.
    ///
    /// Use this when the authentication result cannot be determined.
    #[must_use]
    pub fn unknown(self) -> AuditEvent {
        self.build_event(Outcome::Unknown)
    }

    fn build_event(self, outcome: Outcome) -> AuditEvent {
        let operation = format!("auth.{}", self.auth_type_str());
        let username = self.username.as_deref().unwrap_or("unknown");

        let message = match &outcome {
            Outcome::Success => format!(
                "{} {} for user {}",
                self.auth_type_action(),
                "succeeded",
                username
            ),
            Outcome::Failure(reason) => format!(
                "{} {} for user {}: {}",
                self.auth_type_action(),
                "failed",
                username,
                reason
            ),
            Outcome::Pending => format!(
                "{} {} for user {}",
                self.auth_type_action(),
                "pending",
                username
            ),
            Outcome::Unknown => format!(
                "{} {} for user {}",
                self.auth_type_action(),
                "outcome unknown",
                username
            ),
        };

        let event_type = match (&self.auth_type, &outcome) {
            (AuthType::Login, Outcome::Success) => EventType::LoginSuccess,
            (AuthType::Login, Outcome::Failure(_)) => EventType::LoginFailure,
            (_, Outcome::Success) => EventType::AuthenticationSuccess,
            (_, Outcome::Failure(_)) => EventType::AuthenticationError,
            (_, Outcome::Pending | Outcome::Unknown) => EventType::Info,
        };

        let mut event = AuditEvent::new(&operation, message, outcome, event_type)
            .with_metadata("auth.type", serde_json::json!(self.auth_type_str()))
            .with_metadata("auth.username", serde_json::json!(username))
            .with_metadata("auth.mfa_used", serde_json::json!(self.mfa_used));

        if let Some(provider) = &self.provider {
            event = event.with_metadata("auth.provider", serde_json::json!(provider));
        }

        // Apply compliance tags for authentication
        let tags = ComplianceTags::new()
            .with_soc2(Soc2Control::CC6_1) // Logical access security
            .with_soc2(Soc2Control::CC6_2) // User registration and authorization
            .with_hipaa(HipaaSafeguard::Technical)
            .with_iso27001(Iso27001Control::A8_5) // Secure authentication
            .with_iso27001(Iso27001Control::A8_15) // Logging
            .as_evidence();

        event.with_compliance_tags(tags)
    }

    fn auth_type_str(&self) -> &'static str {
        match self.auth_type {
            AuthType::Login => "login",
            AuthType::Logout => "logout",
            AuthType::PasswordChange => "password_change",
            AuthType::PasswordReset => "password_reset",
            AuthType::TokenRefresh => "token_refresh",
            AuthType::SessionCreate => "session_create",
            AuthType::SessionDestroy => "session_destroy",
        }
    }

    fn auth_type_action(&self) -> &'static str {
        match self.auth_type {
            AuthType::Login => "Login",
            AuthType::Logout => "Logout",
            AuthType::PasswordChange => "Password change",
            AuthType::PasswordReset => "Password reset",
            AuthType::TokenRefresh => "Token refresh",
            AuthType::SessionCreate => "Session creation",
            AuthType::SessionDestroy => "Session destruction",
        }
    }
}

impl Default for AuthAuditBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_login_success() {
        let event = AuthAuditBuilder::new().login("alice").success();

        assert_eq!(event.operation(), "auth.login");
        assert!(event.is_success());
        assert!(event.message().contains("alice"));
    }

    #[test]
    fn test_login_failure() {
        let event = AuthAuditBuilder::new()
            .login("bob")
            .failure("Invalid password");

        assert_eq!(event.operation(), "auth.login");
        assert!(!event.is_success());
        assert!(event.message().contains("Invalid password"));
    }

    #[test]
    fn test_login_with_mfa() {
        let event = AuthAuditBuilder::new()
            .login("alice")
            .with_mfa()
            .provider("totp")
            .success();

        assert_eq!(
            event.metadata.get("auth.mfa_used"),
            Some(&serde_json::json!(true))
        );
        assert_eq!(
            event.metadata.get("auth.provider"),
            Some(&serde_json::json!("totp"))
        );
    }

    #[test]
    fn test_password_change() {
        let event = AuthAuditBuilder::new().password_change("charlie").success();

        assert_eq!(event.operation(), "auth.password_change");
        assert!(event.message().contains("Password change"));
    }

    #[test]
    fn test_session_create() {
        let event = AuthAuditBuilder::new().session_create("david").success();

        assert_eq!(event.operation(), "auth.session_create");
    }

    #[test]
    fn test_compliance_tags() {
        let event = AuthAuditBuilder::new().login("eve").success();

        assert!(event.compliance_tags.soc2.contains(&Soc2Control::CC6_1));
        assert!(event.compliance_tags.soc2.contains(&Soc2Control::CC6_2));
        assert!(
            event
                .compliance_tags
                .hipaa
                .contains(&HipaaSafeguard::Technical)
        );
        assert!(event.compliance_tags.is_evidence);
    }
}
