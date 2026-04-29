//! Package registry API key detection (npm, PyPI, NuGet, Artifactory, Docker Hub).

use super::super::super::super::common::patterns;
use super::MAX_IDENTIFIER_LENGTH;

/// Check if value is an NPM access token
///
/// NPM tokens start with "npm_" followed by 36 alphanumeric characters
#[must_use]
pub fn is_npm_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_NPM.is_match(trimmed)
}

/// Check if value is a PyPI API token
///
/// PyPI tokens start with "pypi-AgEIcHlwaS5vcmc" followed by 50+ base64 characters
#[must_use]
pub fn is_pypi_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_PYPI.is_match(trimmed)
}

/// Check if value is a NuGet API key
///
/// NuGet keys start with "oy2" followed by exactly 43 lowercase alphanumeric characters
#[must_use]
pub fn is_nuget_key(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_NUGET.is_match(trimmed)
}

/// Check if value is a JFrog Artifactory API key
///
/// Artifactory keys start with "AKC" followed by 10+ alphanumeric characters
#[must_use]
pub fn is_artifactory_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_ARTIFACTORY.is_match(trimmed)
}

/// Check if value is a Docker Hub Personal Access Token
///
/// Docker Hub PATs start with "dckr_pat_" followed by 27+ alphanumeric characters
#[must_use]
pub fn is_docker_hub_token(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() > MAX_IDENTIFIER_LENGTH {
        return false;
    }
    patterns::network::API_KEY_DOCKER_HUB.is_match(trimmed)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_npm_token() {
        // Valid NPM token (npm_ + 36 alnum)
        assert!(is_npm_token(&format!("npm_{}", "A".repeat(36))));
        // Invalid: wrong prefix
        assert!(!is_npm_token(&format!("npx_{}", "A".repeat(36))));
        // Invalid: too short
        assert!(!is_npm_token("npm_short"));
    }

    #[test]
    fn test_is_pypi_token() {
        // Valid PyPI token (pypi-AgEIcHlwaS5vcmc + 50+ base64)
        assert!(is_pypi_token(&format!(
            "pypi-AgEIcHlwaS5vcmc{}",
            "A".repeat(50)
        )));
        // Invalid: wrong prefix
        assert!(!is_pypi_token(&format!("pypi-XYZ{}", "A".repeat(50))));
        // Invalid: too short
        assert!(!is_pypi_token("pypi-AgEIcHlwaS5vcmcShort"));
    }

    #[test]
    fn test_is_nuget_key() {
        // Valid NuGet key (oy2 + 43 lowercase alnum)
        assert!(is_nuget_key(&format!("oy2{}", "a".repeat(43))));
        // Invalid: wrong prefix
        assert!(!is_nuget_key(&format!("oy3{}", "a".repeat(43))));
        // Invalid: too short
        assert!(!is_nuget_key("oy2short"));
        // Invalid: uppercase chars (NuGet keys are lowercase)
        assert!(!is_nuget_key(&format!("oy2{}", "A".repeat(43))));
    }

    #[test]
    fn test_is_artifactory_token() {
        // Valid Artifactory key (AKC + 10+ alnum)
        assert!(is_artifactory_token(&format!("AKC{}", "a".repeat(10))));
        assert!(is_artifactory_token(&format!("AKC{}", "B".repeat(20))));
        // Invalid: wrong prefix
        assert!(!is_artifactory_token(&format!("AKD{}", "a".repeat(10))));
        // Invalid: too short
        assert!(!is_artifactory_token("AKCshort"));
    }

    #[test]
    fn test_is_docker_hub_token() {
        // Valid Docker Hub PAT (dckr_pat_ + 27+ alnum)
        assert!(is_docker_hub_token(&format!("dckr_pat_{}", "A".repeat(27))));
        // Invalid: wrong prefix
        assert!(!is_docker_hub_token(&format!(
            "dckr_xxx_{}",
            "A".repeat(27)
        )));
        // Invalid: too short
        assert!(!is_docker_hub_token("dckr_pat_short"));
    }
}
