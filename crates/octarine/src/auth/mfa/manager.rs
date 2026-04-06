//! MFA Manager with observe integration
//!
//! Provides MFA operations with audit logging.

use crate::observe;
use crate::primitives::auth::totp::{
    RecoveryCodes, TotpCode, TotpConfig, TotpSecret, generate_recovery_codes, generate_totp_code,
    generate_totp_secret, get_otpauth_uri, validate_totp_code,
};
use crate::primitives::types::Problem;

// ============================================================================
// MFA Enrollment Result
// ============================================================================

/// Result of MFA enrollment
#[derive(Debug)]
pub struct MfaEnrollment {
    /// The TOTP secret
    pub secret: TotpSecret,
    /// The otpauth:// URI for QR code generation
    pub otpauth_uri: String,
    /// Recovery codes for backup access
    pub recovery_codes: RecoveryCodes,
}

// ============================================================================
// MFA Manager
// ============================================================================

/// Manager for MFA operations with audit logging
///
/// Handles TOTP enrollment, verification, and recovery codes with
/// compliance-grade audit trails.
pub struct MfaManager {
    /// TOTP configuration
    config: TotpConfig,
}

impl MfaManager {
    /// Create a new MFA manager with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: TotpConfig::default(),
        }
    }

    /// Create a new MFA manager with custom configuration
    #[must_use]
    pub fn with_config(config: TotpConfig) -> Self {
        Self { config }
    }

    /// Start MFA enrollment for a user
    ///
    /// Generates a new TOTP secret and recovery codes.
    ///
    /// # Arguments
    ///
    /// * `account_name` - The user's account name (e.g., email)
    ///
    /// # Audit Events
    ///
    /// - `auth.mfa.enrollment_started` (INFO)
    ///
    /// # Errors
    ///
    /// Returns an error if secret generation fails.
    pub fn start_enrollment(&self, account_name: &str) -> Result<MfaEnrollment, Problem> {
        observe::info(
            "auth.mfa.enrollment_started",
            format!("Starting MFA enrollment for {}", account_name),
        );

        let secret = generate_totp_secret()?;
        let otpauth_uri = get_otpauth_uri(&secret, &self.config, account_name)?;
        let recovery_codes = generate_recovery_codes(
            self.config.recovery_code_count,
            self.config.recovery_code_length,
        )?;

        Ok(MfaEnrollment {
            secret,
            otpauth_uri,
            recovery_codes,
        })
    }

    /// Complete MFA enrollment by verifying a code
    ///
    /// Verifies that the user has successfully configured their authenticator
    /// by checking a generated code.
    ///
    /// # Arguments
    ///
    /// * `code` - The TOTP code from the user's authenticator
    /// * `secret` - The TOTP secret from enrollment
    /// * `user_id` - The user's identifier (for logging)
    ///
    /// # Audit Events
    ///
    /// - `auth.mfa.enrolled` (INFO) on success
    /// - `auth.mfa.enrollment_failed` (WARN) on failure
    ///
    /// # Errors
    ///
    /// Returns an error if verification fails due to system error.
    pub fn complete_enrollment(
        &self,
        code: &str,
        secret: &TotpSecret,
        user_id: &str,
    ) -> Result<bool, Problem> {
        let is_valid = validate_totp_code(code, secret, &self.config)?;

        if is_valid {
            observe::info(
                "auth.mfa.enrolled",
                format!("MFA enrollment completed for user {}", user_id),
            );
        } else {
            observe::warn(
                "auth.mfa.enrollment_failed",
                format!("MFA enrollment verification failed for user {}", user_id),
            );
        }

        Ok(is_valid)
    }

    /// Verify a TOTP code
    ///
    /// # Arguments
    ///
    /// * `code` - The TOTP code from the user
    /// * `secret` - The user's TOTP secret
    /// * `user_id` - The user's identifier (for logging)
    ///
    /// # Audit Events
    ///
    /// - `auth.mfa.verified` (DEBUG) on success
    /// - `auth.mfa.failed` (WARN) on failure
    ///
    /// # Errors
    ///
    /// Returns an error if verification fails due to system error.
    /// Validate a TOTP code
    ///
    /// # Errors
    ///
    /// Returns an error if validation fails due to system error.
    pub fn validate_code(
        &self,
        code: &str,
        secret: &TotpSecret,
        user_id: &str,
    ) -> Result<bool, Problem> {
        let is_valid = validate_totp_code(code, secret, &self.config)?;

        if is_valid {
            observe::debug(
                "auth.mfa.verified",
                format!("MFA verification successful for user {}", user_id),
            );
        } else {
            observe::warn(
                "auth.mfa.failed",
                format!("MFA verification failed for user {}", user_id),
            );
        }

        Ok(is_valid)
    }

    /// Validate a recovery code
    ///
    /// If valid, the code is consumed and cannot be used again.
    ///
    /// # Audit Events
    ///
    /// - `auth.mfa.recovery_used` (WARN) on success (warning because recovery should be rare)
    /// - `auth.mfa.recovery_failed` (WARN) on failure
    pub fn validate_recovery_code(
        &self,
        code: &str,
        recovery_codes: &mut RecoveryCodes,
        user_id: &str,
    ) -> bool {
        let is_valid = recovery_codes.try_consume(code);

        if is_valid {
            observe::warn(
                "auth.mfa.recovery_used",
                format!(
                    "Recovery code used for user {} ({} remaining)",
                    user_id,
                    recovery_codes.unused_count()
                ),
            );
        } else {
            observe::warn(
                "auth.mfa.recovery_failed",
                format!("Invalid recovery code attempt for user {}", user_id),
            );
        }

        is_valid
    }

    /// Generate a TOTP code (for testing or display)
    ///
    /// # Errors
    ///
    /// Returns an error if code generation fails.
    pub fn generate_code(&self, secret: &TotpSecret) -> Result<TotpCode, Problem> {
        generate_totp_code(secret, &self.config)
    }

    /// Generate new recovery codes
    ///
    /// This invalidates all previous recovery codes.
    ///
    /// # Arguments
    ///
    /// * `user_id` - The user's identifier (for logging)
    ///
    /// # Audit Events
    ///
    /// - `auth.mfa.recovery_regenerated` (INFO)
    ///
    /// # Errors
    ///
    /// Returns an error if generation fails.
    pub fn regenerate_recovery_codes(&self, user_id: &str) -> Result<RecoveryCodes, Problem> {
        let codes = generate_recovery_codes(
            self.config.recovery_code_count,
            self.config.recovery_code_length,
        )?;

        observe::info(
            "auth.mfa.recovery_regenerated",
            format!(
                "Recovery codes regenerated for user {} ({} codes)",
                user_id,
                codes.codes().len()
            ),
        );

        Ok(codes)
    }

    /// Get the configuration
    #[must_use]
    pub fn config(&self) -> &TotpConfig {
        &self.config
    }
}

impl Default for MfaManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_manager_creation() {
        let manager = MfaManager::new();
        assert_eq!(manager.config().digits, 6);
        assert_eq!(manager.config().step, 30);
    }

    #[test]
    fn test_manager_with_config() {
        let config = TotpConfig::builder().digits(8).issuer("TestApp").build();
        let manager = MfaManager::with_config(config);
        assert_eq!(manager.config().digits, 8);
        assert_eq!(manager.config().issuer, "TestApp");
    }

    #[test]
    fn test_start_enrollment() {
        let manager = MfaManager::new();
        let enrollment = manager.start_enrollment("testuser").expect("should enroll");

        assert!(!enrollment.secret.as_bytes().is_empty());
        assert!(enrollment.otpauth_uri.contains("testuser"));
        assert_eq!(enrollment.recovery_codes.unused_count(), 10);
    }

    #[test]
    fn test_complete_enrollment() {
        let manager = MfaManager::new();
        let enrollment = manager
            .start_enrollment("user@example.com")
            .expect("should enroll");

        // Generate a valid code
        let code = manager
            .generate_code(&enrollment.secret)
            .expect("should generate");

        // Complete enrollment
        let result = manager.complete_enrollment(code.as_str(), &enrollment.secret, "user123");
        assert!(result.expect("should verify"));
    }

    #[test]
    fn test_validate_code() {
        let manager = MfaManager::new();
        let enrollment = manager
            .start_enrollment("user@example.com")
            .expect("should enroll");

        // Generate and verify a code
        let code = manager
            .generate_code(&enrollment.secret)
            .expect("should generate");
        let result = manager.validate_code(code.as_str(), &enrollment.secret, "user123");
        assert!(result.expect("should verify"));
    }

    #[test]
    fn test_verify_invalid_code() {
        let manager = MfaManager::new();
        let enrollment = manager
            .start_enrollment("user@example.com")
            .expect("should enroll");

        let result = manager.validate_code("000000", &enrollment.secret, "user123");
        assert!(!result.expect("should verify"));
    }

    #[test]
    fn test_validate_recovery_code() {
        let manager = MfaManager::new();
        let enrollment = manager
            .start_enrollment("user@example.com")
            .expect("should enroll");

        let mut recovery_codes = enrollment.recovery_codes;
        let first_code = recovery_codes
            .codes()
            .first()
            .expect("should have code")
            .code()
            .to_string();

        // First use should succeed
        assert!(manager.validate_recovery_code(&first_code, &mut recovery_codes, "user123"));
        assert_eq!(recovery_codes.unused_count(), 9);

        // Second use should fail
        assert!(!manager.validate_recovery_code(&first_code, &mut recovery_codes, "user123"));
    }

    #[test]
    fn test_regenerate_recovery_codes() {
        let manager = MfaManager::new();
        let codes = manager
            .regenerate_recovery_codes("user123")
            .expect("should generate");
        assert_eq!(codes.codes().len(), 10);
    }
}
