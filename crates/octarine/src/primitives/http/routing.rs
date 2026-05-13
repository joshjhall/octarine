//! Routing primitives
//!
//! Pure helpers for matching request paths against configured rule lists.

/// Return `true` when `path` begins with any prefix in `exclusions`.
///
/// Matches the historical Layer 3 middleware behavior: a prefix match (not
/// a glob or regex), checked in the order the exclusions were supplied.
/// Useful for "skip auth/metrics/rate-limit for these paths" patterns.
///
/// # Examples
///
/// ```rust,ignore
/// use octarine::primitives::http::routing::is_path_excluded;
///
/// let exclusions = vec!["/health".to_string(), "/public".to_string()];
/// assert!(is_path_excluded("/health/live", &exclusions));
/// assert!(!is_path_excluded("/api/data", &exclusions));
/// ```
#[must_use]
pub fn is_path_excluded(path: &str, exclusions: &[String]) -> bool {
    exclusions.iter().any(|p| path.starts_with(p.as_str()))
}

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;

    fn exclusions() -> Vec<String> {
        vec!["/health".to_string(), "/public".to_string()]
    }

    #[test]
    fn matches_exact_prefix() {
        assert!(is_path_excluded("/health", &exclusions()));
        assert!(is_path_excluded("/public", &exclusions()));
    }

    #[test]
    fn matches_path_under_prefix() {
        assert!(is_path_excluded("/health/live", &exclusions()));
        assert!(is_path_excluded("/public/assets/logo.png", &exclusions()));
    }

    #[test]
    fn does_not_match_unrelated_paths() {
        assert!(!is_path_excluded("/api/data", &exclusions()));
        assert!(!is_path_excluded("/admin", &exclusions()));
    }

    #[test]
    fn empty_exclusions_never_match() {
        assert!(!is_path_excluded("/anything", &[]));
    }

    #[test]
    fn matches_root_prefix() {
        let only_root = vec!["/".to_string()];
        assert!(is_path_excluded("/anything", &only_root));
    }
}
