//! Have I Been Pwned (HIBP) password breach checking
//!
//! Implements k-anonymity password checking against the HIBP Pwned Passwords API.
//!
//! # How it works
//!
//! 1. Password is SHA-1 hashed locally
//! 2. First 5 characters of hash (prefix) sent to HIBP API
//! 3. API returns all hash suffixes matching that prefix
//! 4. We check if our full hash suffix appears in the list
//!
//! This approach ensures the actual password never leaves the local system.
//!
//! # Example
//!
//! ```ignore
//! use octarine::auth::password::HibpClient;
//!
//! let client = HibpClient::new();
//! match client.detect_breach("password123").await {
//!     Ok(Some(count)) => println!("Password found {} times in breaches!", count),
//!     Ok(None) => println!("Password not found in known breaches"),
//!     Err(e) => println!("Failed to check: {}", e),
//! }
//! ```

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};

// audit:acknowledge category=insecure-crypto
// SHA-1 is required by the HIBP k-anonymity protocol (https://haveibeenpwned.com/API/v3).
// The first 5 hex chars of the SHA-1 hash are sent as a prefix query — this is not
// a security-critical use of SHA-1 (no collision resistance needed). Do not use SHA-1
// for any other purpose in this codebase.
use sha1::{Digest, Sha1};

use crate::observe;
use crate::primitives::types::Problem;

// ============================================================================
// Configuration
// ============================================================================

/// Default timeout for HIBP API requests
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Default cache TTL (15 minutes)
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(900);

/// HIBP API base URL
const HIBP_API_BASE: &str = "https://api.pwnedpasswords.com/range";

// ============================================================================
// Cache Entry
// ============================================================================

/// A cached response from the HIBP API
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Hash suffixes and their breach counts
    suffixes: HashMap<String, u64>,
    /// When this entry was cached
    cached_at: Instant,
}

impl CacheEntry {
    /// Check if this cache entry has expired
    fn is_expired(&self, ttl: Duration) -> bool {
        self.cached_at.elapsed() > ttl
    }
}

// ============================================================================
// HIBP Client Configuration
// ============================================================================

/// Configuration for the HIBP client
#[derive(Debug, Clone)]
pub struct HibpConfig {
    /// Request timeout
    pub timeout: Duration,
    /// Cache TTL (time to live)
    pub cache_ttl: Duration,
    /// Maximum cache entries
    pub max_cache_entries: usize,
    /// Custom API base URL (for testing)
    pub api_base_url: String,
}

impl Default for HibpConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            cache_ttl: DEFAULT_CACHE_TTL,
            max_cache_entries: 1000,
            api_base_url: HIBP_API_BASE.to_string(),
        }
    }
}

impl HibpConfig {
    /// Create a new HIBP config builder
    #[must_use]
    pub fn builder() -> HibpConfigBuilder {
        HibpConfigBuilder::default()
    }
}

/// Builder for HIBP client configuration
#[derive(Debug, Default)]
pub struct HibpConfigBuilder {
    timeout: Option<Duration>,
    cache_ttl: Option<Duration>,
    max_cache_entries: Option<usize>,
    api_base_url: Option<String>,
}

impl HibpConfigBuilder {
    /// Set the request timeout
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set the cache TTL
    #[must_use]
    pub fn cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = Some(ttl);
        self
    }

    /// Set maximum cache entries
    #[must_use]
    pub fn max_cache_entries(mut self, max: usize) -> Self {
        self.max_cache_entries = Some(max);
        self
    }

    /// Set custom API base URL (primarily for testing)
    #[must_use]
    pub fn api_base_url(mut self, url: impl Into<String>) -> Self {
        self.api_base_url = Some(url.into());
        self
    }

    /// Build the configuration
    #[must_use]
    pub fn build(self) -> HibpConfig {
        HibpConfig {
            timeout: self.timeout.unwrap_or(DEFAULT_TIMEOUT),
            cache_ttl: self.cache_ttl.unwrap_or(DEFAULT_CACHE_TTL),
            max_cache_entries: self.max_cache_entries.unwrap_or(1000),
            api_base_url: self
                .api_base_url
                .unwrap_or_else(|| HIBP_API_BASE.to_string()),
        }
    }
}

// ============================================================================
// HIBP Client
// ============================================================================

/// Client for checking passwords against Have I Been Pwned
///
/// Uses k-anonymity to check passwords without exposing them to the API.
/// Includes an in-memory cache to reduce API calls for repeated prefix queries.
pub struct HibpClient {
    /// HTTP client
    client: reqwest::Client,
    /// Configuration
    config: HibpConfig,
    /// Cache of prefix -> suffixes
    cache: RwLock<HashMap<String, CacheEntry>>,
}

impl std::fmt::Debug for HibpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HibpClient")
            .field("config", &self.config)
            .field("cache_size", &self.cache_size())
            .finish()
    }
}

impl HibpClient {
    /// Create a new HIBP client with default configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be created.
    pub fn new() -> Result<Self, Problem> {
        Self::with_config(HibpConfig::default())
    }

    /// Create a new HIBP client with custom configuration
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be created.
    pub fn with_config(config: HibpConfig) -> Result<Self, Problem> {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .user_agent("octarine-hibp-client/1.0")
            .build()
            .map_err(|e| Problem::OperationFailed(format!("Failed to create HTTP client: {e}")))?;

        Ok(Self {
            client,
            config,
            cache: RwLock::new(HashMap::new()),
        })
    }

    /// Check if a password has been found in known data breaches
    ///
    /// Returns the number of times the password appears in breaches,
    /// or `None` if the password is not found.
    ///
    /// # Arguments
    ///
    /// * `password` - The password to check
    ///
    /// # Returns
    ///
    /// * `Ok(Some(count))` - Password found `count` times in breaches
    /// * `Ok(None)` - Password not found in known breaches
    /// * `Err(Problem)` - Failed to check (network error, etc.)
    ///
    /// # Audit Events
    ///
    /// - `auth.password.breach_check` (DEBUG) - Check performed
    /// - `auth.password.breach_detected` (WARN) - Password found in breaches
    pub async fn detect_breach(&self, password: &str) -> Result<Option<u64>, Problem> {
        // Hash the password with SHA-1
        let hash = self.hash_password(password);
        let (prefix, suffix) = self.split_hash(&hash);

        observe::debug(
            "auth.password.breach_check",
            format!("Checking password against HIBP (prefix: {}...)", prefix),
        );

        // Check cache first
        if let Some(count) = self.lookup_cache(&prefix, &suffix) {
            if count > 0 {
                observe::warn(
                    "auth.password.breach_detected",
                    format!("Password found in {} breaches (cached)", count),
                );
            }
            return Ok(if count > 0 { Some(count) } else { None });
        }

        // Query the API
        let suffixes = self.query_api(&prefix).await?;

        // Cache the result
        self.update_cache(prefix, suffixes.clone());

        // Check if our suffix is in the results
        let count = suffixes.get(&suffix).copied().unwrap_or(0);

        if count > 0 {
            observe::warn(
                "auth.password.breach_detected",
                format!("Password found in {} breaches", count),
            );
            Ok(Some(count))
        } else {
            Ok(None)
        }
    }

    /// Check multiple passwords efficiently
    ///
    /// Groups passwords by prefix to minimize API calls.
    ///
    /// # Returns
    ///
    /// A vector of results in the same order as the input passwords.
    pub async fn detect_breaches(&self, passwords: &[&str]) -> Vec<Result<Option<u64>, Problem>> {
        let mut results = Vec::with_capacity(passwords.len());

        // Group by prefix for efficiency
        let mut prefix_groups: HashMap<String, Vec<(usize, String)>> = HashMap::new();

        for (idx, password) in passwords.iter().enumerate() {
            let hash = self.hash_password(password);
            let (prefix, suffix) = self.split_hash(&hash);
            prefix_groups.entry(prefix).or_default().push((idx, suffix));
        }

        // Pre-fill results with placeholders
        results.resize_with(passwords.len(), || Ok(None));

        // Process each prefix group
        for (prefix, entries) in prefix_groups {
            // Try cache first
            let cached_suffixes = self.get_cached_suffixes(&prefix);

            let suffixes = if let Some(s) = cached_suffixes {
                s
            } else {
                // Query API
                match self.query_api(&prefix).await {
                    Ok(s) => {
                        self.update_cache(prefix.clone(), s.clone());
                        s
                    }
                    Err(e) => {
                        // Mark all entries in this group as failed
                        let error_msg = e.to_string();
                        for (idx, _) in entries {
                            if let Some(result) = results.get_mut(idx) {
                                *result = Err(Problem::OperationFailed(error_msg.clone()));
                            }
                        }
                        continue;
                    }
                }
            };

            // Check each suffix in the group
            for (idx, suffix) in entries {
                let count = suffixes.get(&suffix).copied().unwrap_or(0);
                if let Some(result) = results.get_mut(idx) {
                    *result = Ok(if count > 0 { Some(count) } else { None });
                }
            }
        }

        results
    }

    /// Get the current cache size
    #[must_use]
    pub fn cache_size(&self) -> usize {
        match self.cache.read() {
            Ok(cache) => cache.len(),
            Err(poisoned) => {
                observe::warn(
                    "hibp.cache.lock_poisoned",
                    "Cache read lock poisoned, recovering",
                );
                poisoned.into_inner().len()
            }
        }
    }

    /// Clear the cache
    pub fn clear_cache(&self) {
        match self.cache.write() {
            Ok(mut cache) => cache.clear(),
            Err(poisoned) => {
                observe::warn(
                    "hibp.cache.lock_poisoned",
                    "Cache write lock poisoned, recovering",
                );
                poisoned.into_inner().clear();
            }
        }
    }

    // ------------------------------------------------------------------------
    // Private helpers
    // ------------------------------------------------------------------------

    /// Hash a password with SHA-1 and return uppercase hex
    fn hash_password(&self, password: &str) -> String {
        let mut hasher = Sha1::new();
        hasher.update(password.as_bytes());
        let result = hasher.finalize();
        hex::encode_upper(result)
    }

    /// Split a hash into prefix (5 chars) and suffix (rest)
    fn split_hash(&self, hash: &str) -> (String, String) {
        let prefix = hash.get(..5).unwrap_or("").to_string();
        let suffix = hash.get(5..).unwrap_or("").to_string();
        (prefix, suffix)
    }

    /// Check cache for a prefix and return count if found
    fn lookup_cache(&self, prefix: &str, suffix: &str) -> Option<u64> {
        let cache = match self.cache.read() {
            Ok(guard) => guard,
            Err(poisoned) => {
                observe::warn(
                    "hibp.cache.lock_poisoned",
                    "Cache read lock poisoned, recovering",
                );
                poisoned.into_inner()
            }
        };

        let entry = cache.get(prefix)?;

        if entry.is_expired(self.config.cache_ttl) {
            return None;
        }

        Some(entry.suffixes.get(suffix).copied().unwrap_or(0))
    }

    /// Get cached suffixes for a prefix
    fn get_cached_suffixes(&self, prefix: &str) -> Option<HashMap<String, u64>> {
        let cache = match self.cache.read() {
            Ok(guard) => guard,
            Err(poisoned) => {
                observe::warn(
                    "hibp.cache.lock_poisoned",
                    "Cache read lock poisoned, recovering",
                );
                poisoned.into_inner()
            }
        };

        let entry = cache.get(prefix)?;

        if entry.is_expired(self.config.cache_ttl) {
            return None;
        }

        Some(entry.suffixes.clone())
    }

    /// Update cache with new suffixes
    fn update_cache(&self, prefix: String, suffixes: HashMap<String, u64>) {
        let mut cache = match self.cache.write() {
            Ok(guard) => guard,
            Err(poisoned) => {
                observe::warn(
                    "hibp.cache.lock_poisoned",
                    "Cache write lock poisoned, recovering",
                );
                poisoned.into_inner()
            }
        };

        // Evict old entries if cache is full
        if cache.len() >= self.config.max_cache_entries {
            // Remove expired entries first
            cache.retain(|_, entry| !entry.is_expired(self.config.cache_ttl));

            // If still full, remove oldest entry
            if cache.len() >= self.config.max_cache_entries
                && let Some(oldest_key) = cache
                    .iter()
                    .min_by_key(|(_, entry)| entry.cached_at)
                    .map(|(k, _)| k.clone())
            {
                cache.remove(&oldest_key);
            }
        }

        cache.insert(
            prefix,
            CacheEntry {
                suffixes,
                cached_at: Instant::now(),
            },
        );
    }

    /// Query the HIBP API for a prefix
    async fn query_api(&self, prefix: &str) -> Result<HashMap<String, u64>, Problem> {
        let url = format!("{}/{}", self.config.api_base_url, prefix);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| Problem::OperationFailed(format!("HIBP API request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(Problem::OperationFailed(format!(
                "HIBP API returned status {}",
                response.status()
            )));
        }

        let body = response
            .text()
            .await
            .map_err(|e| Problem::OperationFailed(format!("Failed to read HIBP response: {e}")))?;

        self.parse_response(&body)
    }

    /// Parse the HIBP API response
    ///
    /// Response format: "SUFFIX:COUNT\r\n" per line
    fn parse_response(&self, body: &str) -> Result<HashMap<String, u64>, Problem> {
        let mut suffixes = HashMap::new();

        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() != 2 {
                continue; // Skip malformed lines
            }

            let suffix = parts.first().copied().unwrap_or("").to_uppercase();
            let count = parts
                .get(1)
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);

            if !suffix.is_empty() && count > 0 {
                suffixes.insert(suffix, count);
            }
        }

        Ok(suffixes)
    }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Check a password against HIBP using a default client
///
/// Creates a temporary client for single-password checks.
/// For checking multiple passwords, create an `HibpClient` instance.
///
/// # Example
///
/// ```ignore
/// use octarine::auth::password::detect_password_breach;
///
/// match detect_password_breach("password123").await {
///     Ok(Some(count)) => println!("Found {} times!", count),
///     Ok(None) => println!("Not found in breaches"),
///     Err(e) => println!("Check failed: {}", e),
/// }
/// ```
pub async fn detect_password_breach(password: &str) -> Result<Option<u64>, Problem> {
    let client = HibpClient::new()?;
    client.detect_breach(password).await
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used, clippy::print_stdout)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_password() {
        let client = HibpClient::new().expect("client should be created");

        // Known SHA-1 hash for "password"
        let hash = client.hash_password("password");
        assert_eq!(hash, "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn test_split_hash() {
        let client = HibpClient::new().expect("client should be created");

        let hash = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";
        let (prefix, suffix) = client.split_hash(hash);

        assert_eq!(prefix, "5BAA6");
        assert_eq!(suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
    }

    #[test]
    fn test_parse_response() {
        let client = HibpClient::new().expect("client should be created");

        let response = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:10000\r\nABCDEF1234567890ABCDEF1234567890ABC:5\r\n";
        let suffixes = client
            .parse_response(response)
            .expect("parse should succeed");

        assert_eq!(
            suffixes.get("1E4C9B93F3F0682250B6CF8331B7EE68FD8"),
            Some(&10000)
        );
        assert_eq!(
            suffixes.get("ABCDEF1234567890ABCDEF1234567890ABC"),
            Some(&5)
        );
    }

    #[test]
    fn test_parse_response_with_malformed_lines() {
        let client = HibpClient::new().expect("client should be created");

        let response = "VALID:100\r\ninvalid_line\r\n:nocount\r\nALSOVALID:200\r\n";
        let suffixes = client
            .parse_response(response)
            .expect("parse should succeed");

        assert_eq!(suffixes.len(), 2);
        assert_eq!(suffixes.get("VALID"), Some(&100));
        assert_eq!(suffixes.get("ALSOVALID"), Some(&200));
    }

    #[test]
    fn test_config_builder() {
        let config = HibpConfig::builder()
            .timeout(Duration::from_secs(10))
            .cache_ttl(Duration::from_secs(1800))
            .max_cache_entries(500)
            .build();

        assert_eq!(config.timeout, Duration::from_secs(10));
        assert_eq!(config.cache_ttl, Duration::from_secs(1800));
        assert_eq!(config.max_cache_entries, 500);
    }

    #[test]
    fn test_cache_operations() {
        let client = HibpClient::new().expect("client should be created");

        // Initially empty
        assert_eq!(client.cache_size(), 0);

        // Add to cache
        let mut suffixes = HashMap::new();
        suffixes.insert("ABCDEF".to_string(), 100);
        client.update_cache("12345".to_string(), suffixes);

        assert_eq!(client.cache_size(), 1);

        // Check cache hit
        let count = client.lookup_cache("12345", "ABCDEF");
        assert_eq!(count, Some(100));

        // Check cache miss (wrong suffix)
        let count = client.lookup_cache("12345", "NOTFOUND");
        assert_eq!(count, Some(0));

        // Check cache miss (wrong prefix)
        let count = client.lookup_cache("99999", "ABCDEF");
        assert!(count.is_none());

        // Clear cache
        client.clear_cache();
        assert_eq!(client.cache_size(), 0);
    }

    #[test]
    fn test_cache_expiration() {
        let config = HibpConfig::builder()
            .cache_ttl(Duration::from_millis(10))
            .build();
        let client = HibpClient::with_config(config).expect("client should be created");

        // Add to cache
        let mut suffixes = HashMap::new();
        suffixes.insert("ABCDEF".to_string(), 100);
        client.update_cache("12345".to_string(), suffixes);

        // Should be in cache immediately
        assert_eq!(client.lookup_cache("12345", "ABCDEF"), Some(100));

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(20));

        // Should be expired
        assert!(client.lookup_cache("12345", "ABCDEF").is_none());
    }

    // Integration test - only run manually
    #[tokio::test]
    #[ignore]
    async fn test_check_known_breached_password() {
        let client = HibpClient::new().expect("client should be created");

        // "password" is definitely in the breach database
        let result = client.detect_breach("password").await;

        match result {
            Ok(Some(count)) => {
                assert!(count > 0, "password should be found in breaches");
                println!("'password' found {} times in breaches", count);
            }
            Ok(None) => panic!("'password' should be found in breaches"),
            Err(e) => panic!("Failed to check password: {}", e),
        }
    }

    #[tokio::test]
    #[ignore]
    async fn test_check_unlikely_password() {
        let client = HibpClient::new().expect("client should be created");

        // Very unlikely to be in breaches
        let unique_password = format!("OctarineTest{}!@#$%^&*", uuid::Uuid::new_v4());
        let result = client.detect_breach(&unique_password).await;

        match result {
            Ok(None) => println!("Unique password not found in breaches (expected)"),
            Ok(Some(count)) => println!("Surprisingly, found {} times", count),
            Err(e) => panic!("Failed to check password: {}", e),
        }
    }
}
