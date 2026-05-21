# Octarine

Foundation library for security and observability in Rust. Named after the
eighth color of the Discworld spectrum — the color of magic, visible only to
wizards.

[![codecov](https://codecov.io/gh/joshjhall/octarine/graph/badge.svg)](https://codecov.io/gh/joshjhall/octarine)

## Features

- **Security Primitives** — Input validation, sanitization, and threat
  detection following OWASP patterns
- **Compliance-Grade Observability** — Automatic WHO/WHAT/WHEN/WHERE context
  capture, PII redaction, SOC2/HIPAA/GDPR/PCI-DSS control mapping
- **Three-Layer Architecture** — Clean separation of primitives, observability, and instrumented operations
- **Post-Quantum Cryptography** — ML-KEM and X25519 key exchange, ChaCha20-Poly1305 and AES-GCM encryption
- **Modular Feature Flags** — Enable only what you need (20 feature flags)

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
octarine = { git = "https://github.com/joshjhall/octarine", tag = "v0.3.0-beta.3" }
```

Enable only the features you need:

```toml
[dependencies]
octarine = { git = "https://github.com/joshjhall/octarine", tag = "v0.3.0-beta.3", default-features = false, features = ["observe", "security"] }
```

## Feature Flags

| Feature | Description |
|---------|-------------|
| `default` | `console` + `full` + `derive` |
| `full` | `observe` + `security` + `cli` |
| `observe` | Observability system |
| `security` | Security module |
| `cli` | CLI framework (clap, indicatif) |
| `derive` | `#[derive(Config)]` macro |
| `http` | Axum/Tower middleware stack |
| `auth` | JWT authentication (OWASP ASVS) |
| `auth-hibp` | HIBP breach checking for passwords |
| `auth-totp` | TOTP/MFA support |
| `auth-full` | Auth + HIBP breach checking + TOTP/MFA |
| `postgres` | PostgreSQL support via sqlx |
| `sqlite` | SQLite support via sqlx |
| `otel` | OpenTelemetry integration |
| `crypto-validation` | PEM, X.509, SSH key validation |
| `database` | Database utilities (GraphQL parsing) |
| `formats` | XML and YAML parsing |
| `shell` | Shell scripting support |
| `testing` | Test infrastructure (fixtures, generators, assertions) |

## Usage

```rust
use octarine::{info, warn, fail_validation, Result};

// Logging with automatic context capture
info("startup", "Service initialized");

// Validation with audit trails
fn validate_input(input: &str) -> Result<()> {
    if input.is_empty() {
        return Err(fail_validation("input", "Cannot be empty"));
    }
    Ok(())
}
```

## Architecture

Three-layer architecture preventing circular dependencies:

```text
Layer 1: primitives/  — Pure functions, no side effects
Layer 2: observe/     — Observability, uses primitives only
Layer 3: data/, security/, identifiers/, runtime/, crypto/, io/, auth/, http/  — Uses primitives + observe
```

See [`docs/`](docs/) for detailed documentation and [`crates/octarine/examples/`](crates/octarine/examples/) for runnable examples.

## Maintenance Status

octarine is currently maintained by a single author
([@joshjhall](https://github.com/joshjhall)). Domain knowledge for
specialized subsystems — memory zeroization, compliance control mappings,
post-quantum encryption, and provider-specific token detection — is
concentrated in this maintainer.

This posture is intentional for the pre-1.0 phase. Before tagging `1.0`,
the following high-risk subsystems are targeted for third-party review:

- `crypto/secrets/*` — memory zeroization, mlock, NIST key classification
- `observe/compliance/*` — SOC2, HIPAA, GDPR, PCI-DSS, ISO 27001 control
  mappings
- `primitives/crypto/encryption/hybrid/*` — hybrid (post-quantum +
  classical) encryption scheme
- `primitives/identifiers/token/detection/api_keys/*` — provider-specific
  token format detection

See [`.github/CODEOWNERS`](.github/CODEOWNERS) for the review-required
path list and [`CONTRIBUTING.md`](CONTRIBUTING.md) for the contributor
on-ramp (dev setup, commit format, SemVer policy).

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
