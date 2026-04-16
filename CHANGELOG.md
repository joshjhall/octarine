# Changelog

All notable changes to octarine will be documented in this file.

## [0.3.0-beta.1] - 2026-04-15

### Added

- feat(release): add just release recipe and CHANGELOG.md
- docs(architecture): update stale feature flags example in layer-architecture.md
- feat(identifiers): add detect_* companion functions to metrics domain
- feat(identifiers): add Spain NIF/NIE detection with mod-23 checksum
- feat(identifiers): add Italy Codice Fiscale detection with check character
- feat(identifiers): add Poland PESEL detection with weighted checksum
- feat(identifiers): add Finland HETU detection with mod-31 checksum
- feat(identifiers): add Singapore NRIC/FIN detection with check letter
- feat(identifiers): add India Aadhaar and PAN detection
- feat(identifiers): add Australia TFN and ABN detection with checksums
- feat(identifiers): add South Korea RRN detection with weighted checksum
- feat(identifiers): add missing financial domain shortcuts
- feat(identifiers): add missing personal domain shortcuts
- feat(identifiers): add location domain shortcuts for GPS, street address, and postal code
- feat(identifiers): add network domain shortcuts for MAC, domain, hostname, and UUID validation
- feat(identifiers): add token domain shortcuts for SSH keys, GitLab, and bearer tokens
- feat(ci): add GitHub Actions CI pipeline
- feat(identifiers): add IBAN detection with MOD-97 checksum validation
- feat(identifiers): add cryptocurrency wallet address detection for Bitcoin and Ethereum
- feat(identifiers): extend date/time PII detection with new formats and context awareness
- feat(identifiers): add UnionPay, Maestro, Verve, RuPay card detection and ISBN-13 filtering
- feat(identifiers): harden email detection with IP literals and code context filtering
- feat(identifiers): harden phone detection with international formats and false positive filters
- feat(identifiers): add crypto Layer 3 builder and is_username to personal chain
- feat(identifiers): add crypto validation module with 9 validators
- feat(identifiers): add 7 missing token validate_* functions
- feat(identifiers): add Layer 3 confidence builder with observe and pipeline integration
- feat(identifiers): add Azure connection string detection for 5 service types
- feat(identifiers): add Bitbucket and extended GitLab token detection
- feat(identifiers): add DEA number detection with checksum validation
- feat(identifiers): expand credential keyword denylist with international translations
- feat(identifiers): harden GCP credential detection with service accounts and Firebase
- feat(identifiers): add ConfidenceBuilder with fluent configuration API
- feat(identifiers): implement context keyword matching algorithm
- feat(identifiers): add context scoring types and keyword dictionaries
- feat(identifiers): add EntropyBuilder with configurable threshold API
- feat(identifiers): add Layer 3 entropy builder and StreamingScanner integration
- feat(identifiers): add entropy detection with false positive filters
- feat(identifiers): add charset classification for entropy analysis
- feat(identifiers): add OpenAI API key detection
- feat(identifiers): add Discord token builder, sanitization, and Layer 3 wrapping
- feat(identifiers): add Slack token builder, sanitization, and Layer 3 wrapping
- feat(identifiers): add Twilio credential builder, sanitization, and Layer 3 wrapping
- feat(identifiers): add SendGrid key builder, sanitization, and Layer 3 wrapping
- feat(identifiers): add Telegram bot token builder, sanitization, and Layer 3 wrapping
- feat(identifiers): add SendGrid API key detection
- feat(identifiers): add Twilio credential detection
- feat(identifiers): add Slack token and webhook URL detection
- feat(identifiers): add Discord bot token and webhook URL detection
- feat(identifiers): add Telegram bot token detection
- feat(identifiers): integrate credential pair detection with StreamingScanner
- feat(identifiers): add CorrelationBuilder with Layer 3 observe wrapper
- feat(identifiers): implement credential pair detection API
- feat(identifiers): implement credential pair recognition rules
- feat(identifiers): implement proximity window scanning for credential pairs
- feat(identifiers): add credential pair correlation types and module scaffold
- feat(identifiers): add NPM, PyPI, NuGet, Artifactory, and Docker Hub token detection
- feat(identifiers): add Databricks, HashiCorp Vault, and Cloudflare token detection
- feat(identifiers): add Mailchimp, Mailgun, Resend, and Brevo token detection
- feat(identifiers): add Square, PayPal/Braintree, and Shopify token detection
- feat(claude): add project-specific skills and audit agents for pattern enforcement
- feat(credentials): expand connection string detection and redaction
- feat(identifiers): expose AWS session token detection in Layer 2/3 public API

### Fixed

- fix(release): ensure trailing newline in changelog and retry on hook fixups
- fix(platform): move unix-only variables inside cfg(unix) block
- fix(platform): add explicit type annotation for parse() on Windows
- fix(deps): update crypto dependencies to stable releases and resolve advisories
- fix(ci): resolve Windows compilation and rustdoc failures
- fix(api): resolve cross-platform compilation, visibility chain, and public API gaps
- fix(identifiers): wire up unreachable PiiType variants Vin, Domain, Username
- fix(auth): reject CSRF token_length below 16 bytes in config builder
- fix(http): add explicit credentials guard to CORS development preset
- fix(docs): escape remaining brackets in redaction doc comments
- fix(docs): escape brackets and angle brackets in doc comments
- fix(observe): add missing PII compliance classifications
- fix(identifiers): add metrics instrumentation to 5 identifier builders
- fix(identifiers): add validate_passport and validate_national_id
- fix(identifiers): fix borrow in Azure app config connection string test
- fix(identifiers): harden SSN detection with SSA validation and ITIN reclassification
- fix(crypto): add audit acknowledgments for SHA-1 and RSA advisory
- fix(shell): make ObservableCmd::arg() reject dangerous patterns by default
- fix(pii): add PaymentToken variant and fix misclassification in scanner
- fix(test): resolve hard timing assertions causing CI flakiness
- fix(pii): add NationalId, Hostname, Port PiiType variants
- fix(identifiers): add connection string validation to credentials domain
- fix(identifiers): add validate_dna_sequence and validate_biometric_template
- fix(identifiers): delegate is_api_keys_present to NetworkBuilder
- fix(devcontainer): unset core.hooksPath before pre-commit install
- fix: change date utility functions to pub(crate) in primitives/types
- fix(security): defuse AWS example key literals to prevent secret scanner false positives
- fix(lints): deny indexing_slicing and arithmetic_side_effects clippy lints
- fix(identifiers): harden AWS credential detection with ASIA prefix and session tokens
- fix(identifiers): harden GitHub token detection with fine-grained PAT support

### Changed

- refactor(ai): upgrade all agents/skills to modern authoring standards and add cross-platform audit
- refactor(architecture): remove inconsistent cross-module re-exports
- refactor(auth): rename primitives/auth/totp to primitives/auth/mfa
- refactor(identifiers): deduplicate network API key detection by re-exporting from token
- refactor: rename 30 functions with prohibited prefixes per naming conventions
- refactor(http): decompose ObserveMiddleware::call() into helper functions
- refactor(identifiers): extract Shannon entropy into shared module
- refactor(identifiers): replace L3 mirror types with direct re-exports from primitives
- refactor: remove all file-level allow(clippy::indexing_slicing) in production code
- refactor: remove allow(clippy::indexing_slicing) from 42 test modules

### Documentation

- docs(architecture): update stale feature flags example in layer-architecture.md
- docs(observe): fix broken rustdoc link for runtime::r#async
- docs(observe): fix broken links and replace internal import paths in api-guide
- docs(claude-md): fix module sub-tree listings to match filesystem
- docs(shell): document ObservableCmd security model for arg() behavior
- docs(architecture): fix stale module paths and Layer 3 listings
- docs(examples): rewrite basic_validation.rs with current public API
- docs: replace prohibited has_* prefix with is_*_present in examples
- docs: add just test-mod recipe and update test documentation
- docs: update README feature count to 20 and add missing features to table

### Testing

- test(auth): add missing edge-case tests and fix bind_network_only dead code
- feat(ci): add GitHub Actions CI pipeline
- test(crypto): add integration tests for crypto module (30 tests)
- test(auth): add integration tests for auth module (33 tests)
- test(io): add integration tests for io module (32 tests)
- test(crypto): add missing edge-case tests for boundary conditions

### Other

- Update containers submodule to latest
- Fix containers submodule URL: use slash instead of colon with ssh:// scheme
- Update containers submodule URL to use ssh:// scheme
- Add Claude MCP and memory environment variables to devcontainer
- Update dependencies and fix sha3/keccak compatibility
- Add dependency management tooling
- Add justfile for common development commands
- Add .cargo/config.toml to limit build parallelism
- Add containers submodule and update .gitignore
- Allow clippy::result_large_err in config test modules
- Format test assertions with cargo fmt
- Add devcontainer, pre-commit hooks, and linting config
- Add readme field to crate Cargo.toml files
- Update CLAUDE.md and README.md for repo-level scope
- Remove crate-level CLAUDE.md and AGENTS.md
- Move docs from crates/octarine/docs/ to top-level docs/

## [0.2.0] - 2025-12-15

Initial public release of octarine with three-layer architecture, compliance-grade
observability, and comprehensive identifier detection for 30+ PII types.
