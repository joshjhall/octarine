//! Source control API token detection (GitHub, GitLab, Bitbucket).

use super::super::super::super::common::patterns;
use super::MAX_IDENTIFIER_LENGTH;

/// Check if value is a GitHub Personal Access Token
///
/// Matches classic tokens (ghp_, gho_, ghu_, ghs_, ghr_ + 36 chars) and
/// fine-grained PATs (github_pat_ + 22 chars + _ + 59 chars)
#[must_use]
pub fn is_github_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_GITHUB.is_match(trimmed)
}

/// Check if value is a GitLab Personal Access Token
///
/// GitLab tokens start with "glpat-" (personal access token) or "gldt-" (deploy token)
#[must_use]
pub fn is_gitlab_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_GITLAB.is_match(trimmed)
}

/// Check if value is a Bitbucket Cloud App Password
///
/// Bitbucket app passwords start with "ATBB" followed by 32 alphanumeric characters.
#[must_use]
pub fn is_bitbucket_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_BITBUCKET.is_match(trimmed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_github_token() {
        // Classic token prefixes
        assert!(is_github_token("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"));
        assert!(is_github_token("gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"));
        assert!(is_github_token("ghu_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"));
        assert!(is_github_token("ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"));
        assert!(is_github_token("ghr_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"));
        // Fine-grained PAT (github_pat_ + 22 + _ + 59)
        assert!(is_github_token(
            "github_pat_ABCDEFGHIJKLMNOPQRSTUv_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456"
        ));
        // Negative cases
        assert!(!is_github_token("ghp_short")); // Too short
        assert!(!is_github_token(
            "xyz_EXAMPLE0000000000KEY01abcdefwxyz123456"
        )); // Wrong prefix
        assert!(!is_github_token("github_pat_short_short")); // Fine-grained too short
    }

    #[test]
    fn test_is_gitlab_token() {
        assert!(is_gitlab_token("glpat-xxxxxxxxxxxxxxxxxxxx"));
        assert!(is_gitlab_token("gldt-yyyyyyyyyyyyyyyyyyyy"));
        assert!(!is_gitlab_token("glpat-short")); // Too short
        assert!(!is_gitlab_token("ghpat-xxxxxxxxxxxxxxxxxxxx")); // Wrong prefix
    }

    #[test]
    fn test_is_gitlab_token_extended_prefixes() {
        // All tokens need at least 20 chars after the dash
        let suffix = "abcdefghijklmnopqrstu"; // 21 chars

        // Pipeline trigger token
        assert!(is_gitlab_token(&format!("glptt-{suffix}")));
        // CI job token
        assert!(is_gitlab_token(&format!("glcbt-{suffix}")));
        // Runner authentication token
        assert!(is_gitlab_token(&format!("glrt-{suffix}")));
        // Feed token
        assert!(is_gitlab_token(&format!("glft-{suffix}")));
        // SCIM token
        assert!(is_gitlab_token(&format!("glsoat-{suffix}")));
        // Incoming mail token
        assert!(is_gitlab_token(&format!("glimt-{suffix}")));
    }

    #[test]
    fn test_is_bitbucket_token() {
        // Valid: ATBB + exactly 32 alphanumeric chars = 36 total
        assert!(is_bitbucket_token("ATBBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
        // Invalid: wrong prefix
        assert!(!is_bitbucket_token("ATBCxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"));
        // Invalid: too short
        assert!(!is_bitbucket_token("ATBBshort"));
        // Invalid: empty
        assert!(!is_bitbucket_token(""));
    }
}
