//! TOTP configuration
//!
//! Configuration for Time-based One-Time Password generation and validation.

use std::time::Duration;

// ============================================================================
// TOTP Algorithm
// ============================================================================

/// Hash algorithm for TOTP
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TotpAlgorithm {
    /// SHA-1 (most widely compatible, default)
    #[default]
    Sha1,
    /// SHA-256 (more secure, less compatible)
    Sha256,
    /// SHA-512 (most secure, least compatible)
    Sha512,
}

impl TotpAlgorithm {
    /// Convert to totp-rs algorithm
    #[cfg(feature = "auth-totp")]
    pub(crate) fn to_totp_rs(self) -> totp_rs::Algorithm {
        match self {
            Self::Sha1 => totp_rs::Algorithm::SHA1,
            Self::Sha256 => totp_rs::Algorithm::SHA256,
            Self::Sha512 => totp_rs::Algorithm::SHA512,
        }
    }
}

// ============================================================================
// TOTP Configuration
// ============================================================================

/// Configuration for TOTP generation and validation
#[derive(Debug, Clone)]
pub struct TotpConfig {
    /// Number of digits in the code (default: 6)
    pub digits: u8,
    /// Time step in seconds (default: 30)
    pub step: u64,
    /// Allowed time drift in steps (default: 1)
    ///
    /// A drift of 1 means codes from the previous and next time step are also accepted.
    pub skew: u8,
    /// Hash algorithm (default: SHA-1)
    pub algorithm: TotpAlgorithm,
    /// Issuer name for QR codes
    pub issuer: String,
    /// Number of recovery codes to generate (default: 10)
    pub recovery_code_count: usize,
    /// Length of each recovery code (default: 8 characters)
    pub recovery_code_length: usize,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            digits: 6,
            step: 30,
            skew: 1,
            algorithm: TotpAlgorithm::default(),
            issuer: "Octarine".to_string(),
            recovery_code_count: 10,
            recovery_code_length: 8,
        }
    }
}

impl TotpConfig {
    /// Create a new TOTP config builder
    #[must_use]
    pub fn builder() -> TotpConfigBuilder {
        TotpConfigBuilder::default()
    }

    /// Get the time step as a Duration
    #[must_use]
    pub fn step_duration(&self) -> Duration {
        Duration::from_secs(self.step)
    }
}

// ============================================================================
// TOTP Config Builder
// ============================================================================

/// Builder for TOTP configuration
#[derive(Debug, Default)]
pub struct TotpConfigBuilder {
    digits: Option<u8>,
    step: Option<u64>,
    skew: Option<u8>,
    algorithm: Option<TotpAlgorithm>,
    issuer: Option<String>,
    recovery_code_count: Option<usize>,
    recovery_code_length: Option<usize>,
}

impl TotpConfigBuilder {
    /// Set the number of digits (6 or 8)
    #[must_use]
    pub fn digits(mut self, digits: u8) -> Self {
        self.digits = Some(digits);
        self
    }

    /// Set the time step in seconds
    #[must_use]
    pub fn step(mut self, step: u64) -> Self {
        self.step = Some(step);
        self
    }

    /// Set the allowed time drift in steps
    #[must_use]
    pub fn skew(mut self, skew: u8) -> Self {
        self.skew = Some(skew);
        self
    }

    /// Set the hash algorithm
    #[must_use]
    pub fn algorithm(mut self, algorithm: TotpAlgorithm) -> Self {
        self.algorithm = Some(algorithm);
        self
    }

    /// Set the issuer name
    #[must_use]
    pub fn issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// Set the number of recovery codes to generate
    #[must_use]
    pub fn recovery_code_count(mut self, count: usize) -> Self {
        self.recovery_code_count = Some(count);
        self
    }

    /// Set the length of each recovery code
    #[must_use]
    pub fn recovery_code_length(mut self, length: usize) -> Self {
        self.recovery_code_length = Some(length);
        self
    }

    /// Build the configuration
    #[must_use]
    pub fn build(self) -> TotpConfig {
        TotpConfig {
            digits: self.digits.unwrap_or(6),
            step: self.step.unwrap_or(30),
            skew: self.skew.unwrap_or(1),
            algorithm: self.algorithm.unwrap_or_default(),
            issuer: self.issuer.unwrap_or_else(|| "Octarine".to_string()),
            recovery_code_count: self.recovery_code_count.unwrap_or(10),
            recovery_code_length: self.recovery_code_length.unwrap_or(8),
        }
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
    fn test_default_config() {
        let config = TotpConfig::default();
        assert_eq!(config.digits, 6);
        assert_eq!(config.step, 30);
        assert_eq!(config.skew, 1);
        assert_eq!(config.algorithm, TotpAlgorithm::Sha1);
        assert_eq!(config.issuer, "Octarine");
        assert_eq!(config.recovery_code_count, 10);
        assert_eq!(config.recovery_code_length, 8);
    }

    #[test]
    fn test_config_builder() {
        let config = TotpConfig::builder()
            .digits(8)
            .step(60)
            .skew(2)
            .algorithm(TotpAlgorithm::Sha256)
            .issuer("MyApp")
            .recovery_code_count(8)
            .recovery_code_length(10)
            .build();

        assert_eq!(config.digits, 8);
        assert_eq!(config.step, 60);
        assert_eq!(config.skew, 2);
        assert_eq!(config.algorithm, TotpAlgorithm::Sha256);
        assert_eq!(config.issuer, "MyApp");
        assert_eq!(config.recovery_code_count, 8);
        assert_eq!(config.recovery_code_length, 10);
    }

    #[test]
    fn test_step_duration() {
        let config = TotpConfig::builder().step(60).build();
        assert_eq!(config.step_duration(), Duration::from_secs(60));
    }
}
