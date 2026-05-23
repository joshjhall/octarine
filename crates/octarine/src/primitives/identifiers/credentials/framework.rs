//! Framework-style credential detection
//!
//! Detects database credentials in application framework config formats:
//! Django settings.py `'PASSWORD': '...'`, Rails / generic YAML
//! `password: ...`, `.env` keys (`DB_PASSWORD`, `MYSQL_PASSWORD`, etc.),
//! and Docker Compose env vars (`MYSQL_ROOT_PASSWORD`, `POSTGRES_PASSWORD`,
//! etc.).
//!
//! Sibling to [`super::detection`]'s connection-string detection, which
//! handles URL-style connection strings (postgres://, mysql://, …) and
//! JDBC variants.
//!
//! Commented-out credentials (`# DB_PASSWORD=secret`) are flagged because
//! comments can be uncommented.

use super::super::common::patterns::network;
use super::super::types::{CredentialMatch, CredentialType};

/// Check if text contains framework-style credential assignments
///
/// Detects Django settings.py, Rails / generic YAML, `.env`, and Docker
/// Compose password patterns. Commented-out credentials are also flagged.
#[must_use]
pub fn is_framework_credential_present(text: &str) -> bool {
    // Cheap pre-filter: every supported format contains "PASSWORD",
    // "password", or the "PASS" stem (for RABBITMQ_DEFAULT_PASS).
    let has_keyword =
        text.contains("PASSWORD") || text.contains("password") || text.contains("PASS");
    if !has_keyword {
        return false;
    }

    network::FRAMEWORK_DJANGO_PASSWORD.is_match(text)
        || network::FRAMEWORK_RAILS_YAML_PASSWORD.is_match(text)
        || network::FRAMEWORK_ENV_DB_PASSWORD.is_match(text)
        || network::FRAMEWORK_DOCKER_COMPOSE_PASSWORD.is_match(text)
}

/// Find all framework-style credential matches in text
///
/// Returns matches with format-specific labels:
/// - `"django_password"` — Django settings.py PASSWORD entries
/// - `"rails_yaml_password"` — Rails / generic YAML `password:` entries
/// - `"env_db_password"` — `.env` file database password keys
/// - `"docker_compose_password"` — Docker Compose root-password env vars
///
/// Matches are deduped by start position (some keys like
/// `POSTGRES_PASSWORD` are covered by both .env and Docker Compose
/// patterns), then sorted by position.
#[must_use]
pub fn find_framework_credentials_in_text(text: &str) -> Vec<CredentialMatch> {
    let mut matches = Vec::new();

    // Django settings.py — group 1 (single-quoted) or group 2 (double-quoted).
    for caps in network::FRAMEWORK_DJANGO_PASSWORD.captures_iter(text) {
        let value_cap = caps.get(1).or_else(|| caps.get(2));
        if let (Some(full), Some(value)) = (caps.get(0), value_cap) {
            matches.push(CredentialMatch {
                start: full.start(),
                end: full.end(),
                value: value.as_str().to_string(),
                credential_type: CredentialType::Generic,
                label: "django_password".to_string(),
            });
        }
    }

    // Rails / generic YAML — single capture group is the value.
    for caps in network::FRAMEWORK_RAILS_YAML_PASSWORD.captures_iter(text) {
        if let (Some(full), Some(value)) = (caps.get(0), caps.get(1)) {
            let start = full.start();
            if !matches.iter().any(|existing| existing.start == start) {
                matches.push(CredentialMatch {
                    start,
                    end: full.end(),
                    value: value.as_str().to_string(),
                    credential_type: CredentialType::Generic,
                    label: "rails_yaml_password".to_string(),
                });
            }
        }
    }

    // .env file db password keys — group 1 = key, group 2 = value.
    for caps in network::FRAMEWORK_ENV_DB_PASSWORD.captures_iter(text) {
        if let (Some(full), Some(value)) = (caps.get(0), caps.get(2)) {
            let start = full.start();
            if !matches.iter().any(|existing| existing.start == start) {
                matches.push(CredentialMatch {
                    start,
                    end: full.end(),
                    value: value.as_str().to_string(),
                    credential_type: CredentialType::Generic,
                    label: "env_db_password".to_string(),
                });
            }
        }
    }

    // Docker Compose env vars — group 1 = key, group 2 = value.
    for caps in network::FRAMEWORK_DOCKER_COMPOSE_PASSWORD.captures_iter(text) {
        if let (Some(full), Some(value)) = (caps.get(0), caps.get(2)) {
            let start = full.start();
            if !matches.iter().any(|existing| existing.start == start) {
                matches.push(CredentialMatch {
                    start,
                    end: full.end(),
                    value: value.as_str().to_string(),
                    credential_type: CredentialType::Generic,
                    label: "docker_compose_password".to_string(),
                });
            }
        }
    }

    matches.sort_by_key(|m| m.start);
    matches
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn test_is_framework_credential_present_django() {
        assert!(is_framework_credential_present(
            "'PASSWORD': 'secret_value'"
        ));
        assert!(is_framework_credential_present(
            r#""PASSWORD": "secret_value""#
        ));
        // Lowercase Django key is not Django convention -> not Django pattern.
        assert!(!is_framework_credential_present("'password': 'x'"));
    }

    #[test]
    fn test_is_framework_credential_present_rails_yaml() {
        assert!(is_framework_credential_present(
            "production:\n  password: secret_value\n  host: db\n"
        ));
        // No whitespace after colon -> URL-style, not Rails YAML.
        assert!(!is_framework_credential_present("foo password:nospace bar"));
    }

    #[test]
    fn test_is_framework_credential_present_env_file() {
        assert!(is_framework_credential_present("DB_PASSWORD=secret123"));
        assert!(is_framework_credential_present("DATABASE_PASSWORD=p@ss"));
        assert!(is_framework_credential_present("REDIS_PASSWORD=foobar"));
        assert!(is_framework_credential_present("MYSQL_PASSWORD=barbaz"));
        assert!(is_framework_credential_present("POSTGRES_PASSWORD=barbaz"));
        assert!(is_framework_credential_present("POSTGRESQL_PASSWORD=baz"));
        assert!(is_framework_credential_present("MONGO_PASSWORD=baz"));
        // Empty value -> no match (\S+ requires at least one non-whitespace char).
        assert!(!is_framework_credential_present("DB_PASSWORD="));
        // Unrelated env key -> no match.
        assert!(!is_framework_credential_present("APP_HOST=localhost"));
    }

    #[test]
    fn test_is_framework_credential_present_docker_compose() {
        assert!(is_framework_credential_present(
            "environment:\n  - MYSQL_ROOT_PASSWORD=secret\n"
        ));
        assert!(is_framework_credential_present(
            "environment:\n  MYSQL_ROOT_PASSWORD: secret\n"
        ));
        assert!(is_framework_credential_present(
            "  - MONGO_INITDB_ROOT_PASSWORD=hunter2"
        ));
        // No value -> no match.
        assert!(!is_framework_credential_present(
            "environment:\n  - MYSQL_ROOT_PASSWORD=\n"
        ));
    }

    #[test]
    fn test_is_framework_credential_present_flags_commented_lines() {
        // Issue #30: commented credentials can be uncommented, so flag them.
        assert!(is_framework_credential_present("# DB_PASSWORD=secret"));
        assert!(is_framework_credential_present(
            "production:\n  # password: secret\n"
        ));
        assert!(is_framework_credential_present(
            "#  - MYSQL_ROOT_PASSWORD=secret"
        ));
    }

    #[test]
    fn test_is_framework_credential_present_no_keyword() {
        assert!(!is_framework_credential_present("APP_HOST=localhost"));
        assert!(!is_framework_credential_present(
            "{\"user\": \"alice\", \"port\": 5432}"
        ));
    }

    #[test]
    fn test_find_framework_credentials_django_match_labels() {
        let matches = find_framework_credentials_in_text("config = {'PASSWORD': 'sv'}");
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("one match");
        assert_eq!(first.label, "django_password");
        assert_eq!(first.value, "sv");
    }

    #[test]
    fn test_find_framework_credentials_django_double_quoted() {
        let matches = find_framework_credentials_in_text(r#"config = {"PASSWORD": "sv-double"}"#);
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("one match");
        assert_eq!(first.value, "sv-double");
    }

    #[test]
    fn test_find_framework_credentials_rails_yaml() {
        let matches = find_framework_credentials_in_text(
            "production:\n  password: secret_value\n  host: db\n",
        );
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("one match");
        assert_eq!(first.label, "rails_yaml_password");
        assert_eq!(first.value, "secret_value");
    }

    #[test]
    fn test_find_framework_credentials_env() {
        let matches = find_framework_credentials_in_text("DB_PASSWORD=secret123");
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("one match");
        assert_eq!(first.label, "env_db_password");
        assert_eq!(first.value, "secret123");
    }

    #[test]
    fn test_find_framework_credentials_docker_compose() {
        let matches =
            find_framework_credentials_in_text("environment:\n  - MYSQL_ROOT_PASSWORD=hunter2\n");
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("one match");
        assert_eq!(first.label, "docker_compose_password");
        assert_eq!(first.value, "hunter2");
    }

    #[test]
    fn test_find_framework_credentials_dedupes_postgres_overlap() {
        // POSTGRES_PASSWORD is in both env and docker-compose patterns —
        // dedupe by start position leaves one match per occurrence.
        let matches = find_framework_credentials_in_text("POSTGRES_PASSWORD=secret\n");
        assert_eq!(matches.len(), 1);
        let first = matches.first().expect("one match");
        assert_eq!(first.label, "env_db_password");
    }

    #[test]
    fn test_find_framework_credentials_mixed_blob() {
        let text = "\
DATABASES = {'default': {'PASSWORD': 'pg_secret'}}
DB_PASSWORD=dotenv_secret
environment:
  - MONGO_INITDB_ROOT_PASSWORD=mongo_secret
production:
  password: rails_secret
";
        let matches = find_framework_credentials_in_text(text);
        assert_eq!(matches.len(), 4);
        let labels: Vec<&str> = matches.iter().map(|m| m.label.as_str()).collect();
        assert_eq!(
            labels,
            vec![
                "django_password",
                "env_db_password",
                "docker_compose_password",
                "rails_yaml_password",
            ]
        );
    }
}
