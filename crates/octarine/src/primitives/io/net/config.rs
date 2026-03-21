//! Network configuration types
//!
//! Pure configuration types for network connections. These types have no
//! external dependencies and can be used to configure network clients
//! in higher layers.

#![allow(dead_code)] // API types for higher layers

use std::time::Duration;

/// Network connection configuration
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Connection timeout
    pub connect_timeout: Duration,

    /// Read timeout
    pub read_timeout: Duration,

    /// Write timeout
    pub write_timeout: Duration,

    /// TLS configuration (if applicable)
    pub tls: Option<TlsConfig>,

    /// Retry configuration
    pub retry: RetryConfig,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(30),
            write_timeout: Duration::from_secs(30),
            tls: None,
            retry: RetryConfig::default(),
        }
    }
}

impl NetworkConfig {
    /// Create a new network config with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Set connection timeout
    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set read timeout
    #[must_use]
    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// Set write timeout
    #[must_use]
    pub fn with_write_timeout(mut self, timeout: Duration) -> Self {
        self.write_timeout = timeout;
        self
    }

    /// Enable TLS with default configuration
    #[must_use]
    pub fn with_tls(mut self) -> Self {
        self.tls = Some(TlsConfig::default());
        self
    }

    /// Set TLS configuration
    #[must_use]
    pub fn with_tls_config(mut self, config: TlsConfig) -> Self {
        self.tls = Some(config);
        self
    }

    /// Set retry configuration
    #[must_use]
    pub fn with_retry(mut self, config: RetryConfig) -> Self {
        self.retry = config;
        self
    }
}

/// TLS configuration
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Verify server certificate
    pub verify_server: bool,

    /// Path to CA certificate file (PEM format)
    pub ca_cert_path: Option<String>,

    /// Path to client certificate file (PEM format)
    pub client_cert_path: Option<String>,

    /// Path to client key file (PEM format)
    pub client_key_path: Option<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            verify_server: true,
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
        }
    }
}

impl TlsConfig {
    /// Create a new TLS config with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Disable server certificate verification (NOT recommended for production)
    #[must_use]
    pub fn without_verify(mut self) -> Self {
        self.verify_server = false;
        self
    }

    /// Set CA certificate path
    #[must_use]
    pub fn with_ca_cert(mut self, path: impl Into<String>) -> Self {
        self.ca_cert_path = Some(path.into());
        self
    }

    /// Set client certificate and key paths
    #[must_use]
    pub fn with_client_cert(
        mut self,
        cert_path: impl Into<String>,
        key_path: impl Into<String>,
    ) -> Self {
        self.client_cert_path = Some(cert_path.into());
        self.client_key_path = Some(key_path.into());
        self
    }
}

/// Retry configuration for network operations
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    pub max_retries: u32,

    /// Initial delay between retries
    pub initial_delay: Duration,

    /// Maximum delay between retries
    pub max_delay: Duration,

    /// Multiplier for exponential backoff
    pub multiplier: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 3,
            initial_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(10),
            multiplier: 2.0,
        }
    }
}

impl RetryConfig {
    /// Create a new retry config with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum retry attempts
    #[must_use]
    pub fn with_max_retries(mut self, max: u32) -> Self {
        self.max_retries = max;
        self
    }

    /// Set initial delay
    #[must_use]
    pub fn with_initial_delay(mut self, delay: Duration) -> Self {
        self.initial_delay = delay;
        self
    }

    /// Set maximum delay
    #[must_use]
    pub fn with_max_delay(mut self, delay: Duration) -> Self {
        self.max_delay = delay;
        self
    }

    /// Set backoff multiplier
    #[must_use]
    pub fn with_multiplier(mut self, multiplier: f64) -> Self {
        self.multiplier = multiplier;
        self
    }

    /// Create a config with no retries
    pub fn no_retry() -> Self {
        Self {
            max_retries: 0,
            ..Self::default()
        }
    }

    /// Create a config for aggressive retry (many attempts, short delays)
    pub fn aggressive() -> Self {
        Self {
            max_retries: 5,
            initial_delay: Duration::from_millis(50),
            max_delay: Duration::from_secs(2),
            multiplier: 1.5,
        }
    }

    /// Create a config for conservative retry (few attempts, longer delays)
    pub fn conservative() -> Self {
        Self {
            max_retries: 2,
            initial_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
            multiplier: 3.0,
        }
    }
}

// Note: Database configuration has moved to `runtime::database::DatabaseConfig`
// which provides a proper public API with environment variable loading,
// builder pattern, and integration with the managed pool system.

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_network_config_defaults() {
        let config = NetworkConfig::default();
        assert_eq!(config.connect_timeout, Duration::from_secs(10));
        assert!(config.tls.is_none());
    }

    #[test]
    fn test_network_config_builder() {
        let config = NetworkConfig::new()
            .with_connect_timeout(Duration::from_secs(5))
            .with_tls()
            .with_retry(RetryConfig::aggressive());

        assert_eq!(config.connect_timeout, Duration::from_secs(5));
        assert!(config.tls.is_some());
        assert_eq!(config.retry.max_retries, 5);
    }

    #[test]
    fn test_retry_config_presets() {
        let no_retry = RetryConfig::no_retry();
        assert_eq!(no_retry.max_retries, 0);

        let aggressive = RetryConfig::aggressive();
        assert_eq!(aggressive.max_retries, 5);

        let conservative = RetryConfig::conservative();
        assert_eq!(conservative.max_retries, 2);
    }
}
