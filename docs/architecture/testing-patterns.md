# Testing Patterns

This document describes octarine's shared test infrastructure and how to use it effectively in both octarine itself and consuming projects.

## Overview

The `testing` module provides reusable test utilities that are:

- **Feature-gated**: Only compiled when `testing` feature is enabled
- **Shared**: Available to all projects that depend on octarine
- **Security-focused**: Generators produce attack patterns that match our defenses
- **Comprehensive**: Covers filesystem, CLI, API, and property-based testing

## Quick Start

### For octarine Internal Tests

```rust
// In any test module within octarine
#[cfg(test)]
mod tests {
    use crate::testing::prelude::*;

    #[rstest]
    fn test_with_temp_dir(temp_dir: TempDir) {
        let file = temp_dir.child("test.txt");
        file.write_str("hello").unwrap();
        file.assert(predicate::str::contains("hello"));
    }
}
```

### For Consuming Projects

```toml
# Cargo.toml
[dependencies]
octarine = { version = "0.2", features = ["full"] }

[dev-dependencies]
octarine = { version = "0.2", features = ["testing"] }
```

```rust
// In your test files
use octarine::testing::prelude::*;

#[rstest]
fn my_app_handles_attacks(#[from(arb_path_traversal)] attack: String) {
    let result = my_app::process_path(&attack);
    assert!(result.is_err(), "Should reject path traversal: {}", attack);
}
```

## Module Structure

```text
src/testing/
├── mod.rs              # Module root and prelude
├── fixtures/           # Test fixtures (temp dirs, permissions, etc.)
│   ├── mod.rs
│   ├── filesystem.rs   # Local filesystem fixtures
│   └── network_fs.rs   # NFS container fixtures
├── generators/         # Data generators for property testing
│   ├── mod.rs
│   ├── attacks.rs      # Injection, traversal, SSRF patterns
│   ├── pii.rs          # Fake PII for redaction testing
│   └── identifiers.rs  # Fake SSN, credit cards, emails
├── cli/                # CLI testing utilities
│   ├── mod.rs
│   ├── runner.rs       # Command execution helpers
│   └── interactive.rs  # Interactive CLI testing (expect-style)
├── api/                # API testing utilities
│   ├── mod.rs
│   ├── http.rs         # HTTP/REST testing helpers
│   └── mcp.rs          # MCP protocol testing
└── assertions/         # Security-focused assertions
    ├── mod.rs
    ├── security.rs     # assert_no_pii, assert_safe_path, etc.
    └── predicates.rs   # Custom predicates for complex assertions
```

## Fixtures

### Filesystem Fixtures

```rust
use crate::testing::prelude::*;

// Basic temporary directory (cleaned up after test)
#[rstest]
fn test_basic(temp_dir: TempDir) {
    let path = temp_dir.path().join("file.txt");
    std::fs::write(&path, "data").unwrap();
}

// Nested directory structure
#[rstest]
fn test_nested(nested_temp_dir: TempDir) {
    // Structure: temp/subdir1/nested/, temp/subdir2/, temp/file.txt
    assert!(nested_temp_dir.path().join("subdir1/nested").exists());
}

// Read-only directory (permission denied testing)
#[cfg(unix)]
#[rstest]
fn test_readonly(readonly_dir: TempDir) {
    let result = std::fs::write(readonly_dir.path().join("new.txt"), "data");
    assert!(result.is_err());
}

// Symlink scenarios (including broken links and loops)
#[cfg(unix)]
#[rstest]
fn test_symlinks(symlink_dir: TempDir) {
    assert!(symlink_dir.path().join("link_to_file").exists());
    assert!(!symlink_dir.path().join("broken_link").exists());
}
```

### NFS/Network Filesystem Fixtures

For testing network filesystem edge cases (stale handles, latency, etc.):

```rust
use crate::testing::fixtures::network_fs::NfsTestContainer;

#[tokio::test]
#[ignore] // Requires Docker
async fn test_nfs_stale_handle() {
    let nfs = NfsTestContainer::start().await.unwrap();
    let mount_path = nfs.mount_path();

    // Test operations on NFS mount
    let file = mount_path.join("test.txt");
    std::fs::write(&file, "data").unwrap();

    // Simulate stale handle by remounting
    nfs.remount().await.unwrap();

    // This should handle ESTALE gracefully
    let result = std::fs::read(&file);
    // ...
}
```

## Generators

### Attack Pattern Generators

These generate inputs that should be rejected by security functions:

```rust
use crate::testing::prelude::*;

proptest! {
    // Path traversal attacks
    #[test]
    fn rejects_path_traversal(attack in arb_path_traversal()) {
        assert!(validate_path(&attack).is_err());
    }

    // Command injection attacks
    #[test]
    fn rejects_command_injection(attack in arb_command_injection()) {
        assert!(sanitize_command(&attack).is_err());
    }

    // SSRF attacks
    #[test]
    fn rejects_ssrf(attack in arb_ssrf_url()) {
        assert!(!is_ssrf_safe(&attack));
    }

    // SQL injection
    #[test]
    fn rejects_sql_injection(attack in arb_sql_injection()) {
        assert!(validate_identifier(&attack).is_err());
    }
}
```

### PII Generators

Generate fake PII data for testing redaction:

```rust
use crate::testing::generators::pii::*;

proptest! {
    #[test]
    fn redacts_all_ssns(ssn in arb_ssn()) {
        let redacted = redact_pii(&format!("SSN: {}", ssn));
        assert!(!redacted.contains(&ssn));
        assert!(redacted.contains("[SSN]"));
    }

    #[test]
    fn redacts_all_emails(email in arb_email()) {
        let redacted = redact_pii(&format!("Contact: {}", email));
        assert!(!redacted.contains(&email));
    }

    #[test]
    fn redacts_credit_cards(cc in arb_credit_card()) {
        let redacted = redact_pii(&format!("Card: {}", cc));
        assert!(!redacted.contains(&cc));
    }
}
```

### Identifier Generators

Generate valid and invalid identifiers for testing:

```rust
use crate::testing::generators::identifiers::*;

proptest! {
    // Valid identifiers should pass
    #[test]
    fn accepts_valid_emails(email in arb_valid_email()) {
        assert!(is_email(&email));
    }

    // Invalid identifiers should fail
    #[test]
    fn rejects_invalid_emails(email in arb_invalid_email()) {
        assert!(!is_email(&email));
    }
}
```

## CLI Testing

### Running Commands

```rust
use crate::testing::cli::*;

#[test]
fn test_cli_help() {
    cli("my-app")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Usage:"));
}

#[test]
fn test_cli_validates_input() {
    cli("my-app")
        .arg("--path")
        .arg("../../../etc/passwd")  // Attack attempt
        .assert()
        .failure()
        .stderr(predicate::str::contains("path traversal"));
}
```

### Interactive CLI Testing

For CLIs that require user input:

```rust
use crate::testing::cli::interactive::*;

#[test]
fn test_interactive_prompt() {
    let mut session = spawn_cli("my-app", &["--interactive"]).unwrap();

    session.expect("Enter username:").unwrap();
    session.send_line("admin").unwrap();

    session.expect("Enter password:").unwrap();
    session.send_line("secret").unwrap();

    session.expect("Login successful").unwrap();
}
```

## API Testing

### HTTP/REST Testing

```rust
use crate::testing::api::http::*;

#[tokio::test]
async fn test_api_rejects_bad_input() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/users"))
        .respond_with(ResponseTemplate::new(400))
        .mount(&mock_server)
        .await;

    let client = MyApiClient::new(&mock_server.uri());
    let result = client.create_user("invalid<script>").await;

    assert!(result.is_err());
}
```

### MCP Protocol Testing

```rust
use crate::testing::api::mcp::*;

#[tokio::test]
async fn test_mcp_tool_call() {
    let harness = McpTestHarness::spawn("my-mcp-server").await.unwrap();

    // Call a tool
    let response = harness
        .call_tool("validate_path", json!({ "path": "/safe/path" }))
        .await
        .unwrap();

    assert!(response.is_success());

    // Test with attack input
    let response = harness
        .call_tool("validate_path", json!({ "path": "../../../etc/passwd" }))
        .await
        .unwrap();

    assert!(response.is_error());
}
```

## Security Assertions

### Built-in Security Assertions

```rust
use crate::testing::assertions::security::*;

#[test]
fn test_output_is_safe() {
    let output = process_user_input("test@example.com");

    // Assert no PII leaked
    assert_no_pii(&output);

    // Assert path is safe
    assert_safe_path(&output);

    // Assert no injection patterns
    assert_no_injection(&output);
}
```

### Custom Security Predicates

```rust
use crate::testing::assertions::predicates::*;

#[test]
fn test_with_predicates() {
    let output = sanitize("user input");

    assert_that(&output, is_safe_for_logging());
    assert_that(&output, contains_no_control_chars());
    assert_that(&output, is_within_length(1000));
}
```

## Best Practices

### 1. Use Property-Based Testing for Security

```rust
// DON'T: Just test a few examples
#[test]
fn test_rejects_traversal() {
    assert!(validate("../etc/passwd").is_err());
    assert!(validate("..\\..\\windows").is_err());
}

// DO: Test ALL traversal patterns
proptest! {
    #[test]
    fn test_rejects_all_traversal(attack in arb_path_traversal()) {
        assert!(validate(&attack).is_err());
    }
}
```

### 2. Test Both Valid and Invalid Inputs

```rust
proptest! {
    // Valid inputs should pass
    #[test]
    fn accepts_valid(input in arb_valid_email()) {
        assert!(is_email(&input));
    }

    // Invalid inputs should fail
    #[test]
    fn rejects_invalid(input in arb_invalid_email()) {
        assert!(!is_email(&input));
    }

    // Attack inputs should definitely fail
    #[test]
    fn rejects_attacks(input in arb_email_injection()) {
        assert!(!is_email(&input));
    }
}
```

### 3. Use Fixtures for Complex Setup

```rust
// DON'T: Repeat setup in every test
#[test]
fn test_one() {
    let dir = TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join("a/b/c")).unwrap();
    // ... test
}

#[test]
fn test_two() {
    let dir = TempDir::new().unwrap();
    std::fs::create_dir_all(dir.path().join("a/b/c")).unwrap();
    // ... test
}

// DO: Use fixtures
#[rstest]
fn test_one(nested_temp_dir: TempDir) {
    // Setup already done
}

#[rstest]
fn test_two(nested_temp_dir: TempDir) {
    // Same fixture, no duplication
}
```

### 4. Parameterize Tests with rstest

```rust
// Test multiple cases with one test function
#[rstest]
#[case("../etc/passwd", true)]
#[case("/safe/path", false)]
#[case("a/../../../b", true)]
#[case("./relative", false)]
fn test_path_traversal_detection(#[case] path: &str, #[case] is_attack: bool) {
    assert_eq!(contains_traversal(path), is_attack);
}
```

## Available Test Dependencies

The testing feature brings in these crates:

| Crate | Purpose |
|-------|---------|
| `rstest` | Fixtures and parameterized tests |
| `proptest` | Property-based testing |
| `arbitrary` | Structured fuzzing input |
| `assert_fs` | Filesystem fixtures and assertions |
| `predicates` | Composable test predicates |
| `tempfile` | Temporary files and directories |
| `assert_cmd` | CLI binary testing |
| `rexpect` | Interactive CLI testing |
| `wiremock` | HTTP mocking |
| `testcontainers` | Docker containers in tests |
| `fake` | Fake data generation |

## Performance Tests

Performance tests (`test_perf_*`) are **ignored by default** because they contain
timing assertions that fail under CI coverage instrumentation. These tests verify
that security operations remain fast enough for production use.

### Running Performance Tests

```bash
# Run all performance tests
cargo test -p octarine test_perf_ -- --ignored

# Run a specific performance test
cargo test -p octarine test_perf_shannon_entropy -- --ignored
```

### When to Run Performance Tests

- **Before releases**: Run locally to verify no performance regressions
- **After optimization work**: Verify improvements haven't broken thresholds
- **When investigating latency issues**: Identify slow operations

### Performance Test Locations

| Module | Tests | What They Measure |
|--------|-------|-------------------|
| `entropy.rs` | 7 tests | Entropy calculation, key strength analysis |
| `jwt.rs` | 3 tests | JWT format and algorithm validation |
| `api_keys.rs` | 2 tests | API key format validation |
| `session.rs` | 1 test | Session ID validation |

### Performance Thresholds

Tests assert sub-millisecond performance for security operations:

- Entropy calculations: \<50-100µs
- Key strength analysis: \<150µs
- JWT validation: \<500-2000µs
- API key validation: \<50-150µs

These thresholds are calibrated for release builds on typical hardware. Coverage
instrumentation can inflate times 10-100x, hence the `#[ignore]` attribute.

## Related Documentation

- [Layer Architecture](./layer-architecture.md) - Why testing is in Layer 1
- [CLAUDE.md](../../CLAUDE.md) - Development guidelines
- [proptest book](https://proptest-rs.github.io/proptest/intro.html) - Property testing guide
- [rstest docs](https://docs.rs/rstest) - Fixture documentation
