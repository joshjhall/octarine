# Security Policy

## Supported Versions

Octarine is pre-1.0 and under active development. Security fixes are
applied to the latest minor release only. See [`CHANGELOG.md`](./CHANGELOG.md)
for the current version.

| Version | Supported |
| ------- | --------- |
| latest  | ✓         |
| older   | ✗         |

## Reporting a Vulnerability

**Do not open a public issue for suspected vulnerabilities.**

Please report security issues privately via GitHub's private vulnerability
reporting:

1. Go to <https://github.com/joshjhall/octarine/security/advisories/new>
2. Provide a clear description, reproduction steps, and affected version(s)
3. Include proof-of-concept code or a minimal reproducer where possible

You can expect an acknowledgement within 7 days. We will work with you on
coordinated disclosure — typical timeline is 30–90 days from acknowledgement
to public advisory, depending on severity and complexity.

## Scope

In scope:

- The `octarine` crate (`crates/octarine/`), including all Layer 1
  (`primitives/`), Layer 2 (`observe/`), and Layer 3 (`data/`, `security/`,
  `identifiers/`, etc.) modules
- Documented public APIs
- Audit trail and PII redaction guarantees (see
  [`docs/observe/compliance.md`](./docs/observe/compliance.md))

Out of scope:

- Issues in downstream consumers of the crate
- Denial-of-service via unbounded input where API docs explicitly require
  caller-side size limits
- Vulnerabilities in transitive dependencies (report to the upstream crate)

## Security-Sensitive Modules

The following areas warrant extra attention in reports:

- `primitives/security/` — threat detection logic
- `primitives/identifiers/` — PII classification
- `observe/pii/` — redaction
- `observe/audit/` — tamper-evident audit trails
- `crypto/` — cryptographic operations
