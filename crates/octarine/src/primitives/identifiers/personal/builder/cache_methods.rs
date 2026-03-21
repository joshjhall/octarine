//! Cache methods for PersonalIdentifierBuilder

use crate::primitives::collections::CacheStats;

use super::super::detection;
use super::core::PersonalIdentifierBuilder;

impl PersonalIdentifierBuilder {
    /// Get combined cache statistics for all personal identifier caches
    #[must_use]
    pub fn cache_stats(&self) -> CacheStats {
        detection::email_cache_stats().combine(&detection::phone_cache_stats())
    }

    /// Get email validation cache statistics
    #[must_use]
    pub fn email_cache_stats(&self) -> CacheStats {
        detection::email_cache_stats()
    }

    /// Get phone validation cache statistics
    #[must_use]
    pub fn phone_cache_stats(&self) -> CacheStats {
        detection::phone_cache_stats()
    }

    /// Clear all personal identifier caches
    pub fn clear_caches(&self) {
        detection::clear_personal_caches();
    }
}
