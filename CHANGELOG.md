# Changelog

All notable changes to octarine will be documented in this file.

## [0.3.0-beta.7] - 2026-09-06

> **Security fixes.** Three logging paths leaked sensitive material into
> observability output: `SecureMap` keys (#737), anonymize `SessionId` handles
> (#742), and unbounded snapshot TTLs (#739). Upgrading is recommended for any
> deployment that ships observe output off-host.

### Added

- feat(analyze): add conflict resolution with cross-type dedup strategy (#731)
- feat(anonymize): add Keep and DeanonymizeKeep no-op operators (#729)

### Fixed

- fix(crypto): stop logging SecureMap keys in cleartext (#737)
- fix(anonymize): log a SessionId digest instead of the raw handle (#742)
- fix(observe): saturate overflowing snapshot TTL to never-expires (#739)
- fix(auth): time constant_time_response on Tokio's clock, not the real one (#726)
- fix(deps): update all deps, resolving RUSTSEC-2026-0258 (h2) (#714)
- fix(devcontainer): run post-create setup under Zed (#715)

### Changed

- refactor(crypto): migrate to argon2 0.6 password-hash API (#730)
- chore(tooling): ignore _notes.md and local codebase-audit output

### Documentation

- docs(architecture): decide crate layout for LLM and OTel integrations (#725)

### Testing

- test(primitives): stop racing wall-clock TTL in cache expiration tests (#736)

### Build

- build(deps): bump base64 0.23, pem 4.0, rstest 0.27 (#743)
- build(deps): bump quick-xml 0.41 -> 0.42 (#727)
- build(deps): bump totp-rs 5 -> 6 (Secret::Raw removed) (#721)
- build(deps): bump jsonwebtoken 10 -> 11 and serial_test 3 -> 4 (#717)
- build(deps): bump syn 2 -> 3 and darling 0.23 -> 0.24 (#716)

## [0.3.0-beta.6] - 2026-07-16

> **MSRV bump — action required.** The minimum supported Rust version is now
> **1.97.0** (was 1.95.0). Downstream consumers must build with Rust ≥ 1.97.0.
> Pre-1.0 SemVer treats this as a notable change; it is bundled in this beta so
> it lands before the 0.3.0 stable line. See #701 / #703.

### Added

- feat(identifiers): add context-aware find_financial_identifier_with_context (#696)
- feat(identifiers): extend IBAN COUNTRY_LENGTHS to full ISO 13616 registry (#680)
- feat(identifiers): add Indian UPI ID (IN_UPI) payment-PII detector (#679)
- feat(identifiers): US CLIA number (medical lab cert) (#677)
- feat(identifiers): add Spanish Passport (ES_PASSPORT) (#676)
- feat(identifiers): add US Medicare Beneficiary Identifier (MBI) (#673)
- feat(identifiers): add German core identifier suite (TaxId, IdCard, Passport) (#669)

### Fixed

- fix(identifiers): restore Warning audit events for L3 validation failures (#700)
- fix(identifiers): bank-account input guard + PCI metric + i18n keywords (#699)
- fix(identifiers): bound credit-card context scan to MAX_INPUT_LENGTH (#698)
- fix(devcontainer): build CodeGraph index under Zed via recover-entrypoint (#690)
- fix(identifiers): drop inverted Luhn exclusion from bank account heuristic (#693)
- deps(deps): patch RUSTSEC-2026-0204 + refresh lockfile (#686)
- fix(runtime): route spawn_blocking shortcut through Layer 3 Executor (#681)
- fix(observe): sanitize template variables in FilenamePattern::expand() (#678)
- fix(claude): correct stale paths in three audit agents (#671)
- fix(anonymize): escape dict path encoding via RFC 6901 JSON Pointer (#665)
- fix(anonymize): hold vault originals/tokens in zeroize-on-drop secure memory (#664)

### Changed

- refactor(architecture): sever Layer 1→2 coupling in ProblemExt re-export (#682)
- fix(claude): correct stale paths in three audit agents (#671)
- refactor(architecture): import Problem/Result from canonical crate::observe in Layer 3 (#674)
- refactor(identifiers): keyword registry keyed by (IdentifierType, language) (#666)
- chore(tooling): migrate Rust toolchain 1.95.0 -> 1.97.0 (#703)
- chore(containers): bump submodule v4.19.12 → v4.19.14
- chore(deps): upgrade x25519-dalek 2.x → 3.0.0 (#688)
- chore(memory): add session learnings (blocked-by, L3 merge, dep/test notes)
- chore(containers): bump submodule to v4.19.12; update crypto secrets memory
- chore(devcontainer): CodeGraph indexing, worktree-friendly compose, submodule v4.19.10 (#663)

### Documentation

- docs(claude): make audit-agent grep paths layout-agnostic (#670) (#702)
- docs(claude-md): sync skills and CLAUDE.md with current code state (#691)
- docs(docs): fix code examples referencing non-existent APIs (#692)
- docs(docs): fix stale references to removed/renamed paths (#675)
- docs: add CI, crates.io, docs.rs, license, and MSRV badges to README

### Testing

- test(primitives): fix flaky cache cleanup test under parallel load (#705)
- test(primitives): cover x509, crypto detection, paths, random, and compliance (#662)
- test(runtime): cover stateful I/O paths for HTTP, DB, tracing, and CLI (#661)
- test(identifiers): cover Layer 3 government builders (#660)

### CI

- ci: fail CI on Codecov upload error now that token is set
- ci(release): make publish jobs idempotent via crates.io API check

### Build

- fix(runtime): route spawn_blocking shortcut through Layer 3 Executor (#681)

## [0.3.0-beta.5] - 2026-07-02

<!-- TODO: review and curate before push -->

### CI

- ci(release): install mold linker before cargo publish

### Build

- build(release): update just recipes to -p octarine-core after package rename
- build(release): publish umbrella crate as octarine-core (keep lib name octarine)

## [0.3.0-beta.4] - 2026-07-02

<!-- TODO: review and curate before push -->

### Added

- feat(anonymize): add InstanceCounter operators for reversible pseudonymization (#653)
- feat(http): add CorrelationLayer middleware for correlation-id propagation (#648)
- feat(observe): add OTLP/HTTP transport to complement OTLP/gRPC exporter (#644)
- feat(anonymize): add parallel batch deanonymizer engine via rayon (#513) (#642)
- feat(anonymize): add session lifecycle API with TTL expiry (#544) (#635)
- feat(anonymize): add parallel batch anonymizer engine via rayon (#634)
- feat(http): serve Prometheus /metrics via axum preset (#632)
- feat(anonymize): add InMemoryStore default StateStore backend (#627)
- feat(identifiers): phone validation via phonenumber crate (libphonenumber) (#617)
- feat(identifiers): Swedish Personnummer + Organisationsnummer (#435) (#616)
- feat(anonymize): Hash operator over SHA-2/BLAKE3/HMAC/Argon2 (#484) (#614)
- feat(anonymize): Encrypt/Decrypt operators over keyed AEAD (#485) (#613)
- feat(anonymize): StateStore trait + SessionId/EntityKey vault foundation (#608)
- feat(anonymize): Mask operator with multi-char units + strict validation (#607)
- feat(anonymize): Custom operator with no-probe-call discipline (#487) (#606)
- feat(anonymize): operator engine + Replace/Redact operators (#605)
- feat(anonymize): shared operator/engine type system (#603)
- feat(identifiers): Turkey pack — TCKN (NVI mod-10) + License Plate (#461)
- feat(identifiers): UK pack — NHS Number, Passport, Driving Licence (#460)
- feat(identifiers): Italian completeness (VAT, passport, identity card, driver license) (#459)
- feat(identifiers): NamedLocation gazetteer detector (~280 countries + ~1500 cities) (#458)
- feat(identifiers): add AGE + NRP entities (HIPAA Safe Harbor + GDPR Art 9) (#457)
- feat(identifiers): PSL validation for email + URL, plus bare-URL detection via linkify (#456)
- feat(identifiers): BTC base58check/Bech32m + ETH EIP-55 checksum validation (#454)
- feat(ci): automate crates.io publishing and GitHub Release on tag push (#398)
- feat(arch-check): promote doctest-ignores to default ERROR + docs (#395)
- feat(arch-check): add opt-in doctest-ignores check (#393)
- feat(observe): cache Registry::snapshot() with 1s TTL (#392)
- feat(runtime): cache auto-generated correlation IDs per thread (#391)
- feat(identifiers): add framework database credential detection (#390)
- feat(identifiers): add Korea extended IDs (driver license, FRN, passport, BRN) (#389)
- feat(identifiers): support CJK, Arabic, Hindi credential keywords (#388)
- feat(identifiers): add 8 developer-platform token detectors (#384)
- feat(identifiers): add Singapore UEN and Australia Medicare/ACN detection (#383)
- feat(identifiers): add Nigeria Vehicle Registration and BVN detection (#382)
- feat(arch-check): enforce 800 production-LOC file-length limit (#347)
- feat(identifiers): add LATAM/Africa government IDs (Brazil CPF/CNPJ, Mexico CURP, Nigeria NIN, Thailand TNIN) (#312)
- feat(identifiers): add US street address normalization (USPS Pub 28) (#311)
- feat(identifiers): add international postal codes (DE, FR, AU, JP, IN, NL, BR) (#310)
- feat(identifiers): add India extended IDs (GSTIN, vehicle reg, voter ID, passport) (#305)
- feat(release): add `just release <type>` keyword bumps, skill, and docs (#295)

### Fixed

- chore(tooling): bump Rust toolchain 1.94 -> 1.95.0, fix LSP and clippy (#618)
- fix(identifiers): US ITIN — strict IRS middle-group rule + reject 9xx as SSN (#602)
- fix(ci): install cargo-nextest in nightly test job (#387)
- fix(tests): poll for TTL expiration instead of fixed-sleep assertions (#372)
- fix(ci): detach to PR head before linting commits with conform (#358)
- fix(ci): unbreak macOS Check — PATH + cache invalidation + no bin caching (#333)
- fix(ci): harden macOS Check against rustup-init shim flake (#332)
- refactor(identifiers): split government/builder.rs into per-country modules (#331)
- fix(ci): replace broken osv-scanner-action with install-action + just recipe (#326)
- fix(observe): add silent mode to 5 Layer 3 builders (#302)
- fix(tests): replace fixed sleeps with poll-until-condition loops (#299)
- fix(pii): emit provider-specific PiiType variants for tokens (#298)
- fix(arch-check): collapse multi-line pub use blocks in unwrapped-fn (#294)
- fix(pii-sync): scan_network now detects PiiType::Hostname and PiiType::Port (#291)
- fix(license): align dual-license artifacts with ecosystem (#288)

### Changed

- refactor(anonymize): async session-aware engine path (sans-IO core) (#610)
- refactor(runtime): use FileMode::PRIVATE constant in with_secure_file (#364)
- refactor(observe): migrate builders to crate::define_metrics! macro (#349)
- refactor(lints): reduce cognitive complexity & enforce in CI (#348)
- refactor(observe): split observe/pii/types.rs into per-section submodules (#346)
- refactor(crypto): split crypto/secrets/storage.rs into per-section submodules (#345)
- refactor(io): split io/ops.rs into per-section submodules (#344)
- refactor(identifiers): split Layer 1 token/builder.rs into per-section submodules (#343)
- refactor(identifiers): split network.rs into per-category submodules (#342)
- refactor(identifiers): split personal.rs into per-region submodules (#341)
- refactor(security): wrap PrimAllowList directly to fix leak (#336) (#337)
- refactor(identifiers): split Layer 3 builder/token.rs into per-section submodules (#335)
- refactor(identifiers): split government/builder.rs into per-country modules (#331)
- refactor(types): extract Problem/Result into octarine-problem micro-crate (#328)
- refactor(http): extract pure logic into primitives/http/ (#320)
- refactor(identifiers): split Layer 3 builder/government.rs into per-country submodules (#318)
- refactor(identifiers): split government/detection.rs into per-country submodules (#317)
- refactor(naming): rename Layer 3 public verify_*/has_*/ensure_*/check_* (#316)
- refactor(naming): rename internal prohibited-prefix functions (#315)
- refactor: complete unimplemented checksums and normalizations (#304)
- refactor(data/paths): drop cross-concern security re-exports (#303)
- refactor(observe): convert Layer 3 builders to 2-arg observe API (#301)
- refactor(primitives): tighten inline pub mod to pub(crate) mod in pattern files (#300)
- refactor(arch-check): rewrite as Python package with pytest suite (#292)
- refactor(visibility): re-export primitives types from L3 shortcuts (#290)
- refactor(identifiers): split api_keys.rs into per-provider submodules (#289)
- refactor(identifiers): split shortcuts.rs god file into per-domain submodules (#287)
- refactor(data/paths): split PathBuilder god-module into per-concern impl blocks (#286)
- build(release): include chore: commits in CHANGELOG generation
- chore(memory): record unpushed-dep-fixes-on-local-main diagnostic
- chore(deps): bump linkify 0.10 -> 0.11 (#626)
- chore(deps): fix RUSTSEC-2026-0185 (quinn-proto) + bring deps to latest semver (#625)
- chore(deps): fix RUSTSEC-2026-0173 + bring all deps to latest semver (#622)
- chore(memory): record anonymize sans-IO split and CodeQL crypto FP notes (#620)
- chore(tooling): bump Rust toolchain 1.94 -> 1.95.0, fix LSP and clippy (#618)
- chore(memory): note Presidio audit issue namespace
- chore(deps): bump sqlx 0.8→0.9 and refresh all dependencies (#455)
- chore(claude): split audit-octarine-platforms rules into companion file (#381)
- chore(observe): clean up metric-naming drift and flaky timer assertion (#380)
- chore(claude): ignore Claude Code scheduled-tasks lock file
- chore(tooling): adopt taplo for TOML formatting and schema linting (#378)
- chore(tooling): add just quarterly recipe and quarterly-review workflow (#377)
- chore(tooling): adopt actionlint for GitHub Actions workflow linting (#376)
- chore(tooling): adopt cargo-nextest for test runs (#375)
- chore(tooling): adopt cargo-machete for unused-dependency detection (#373)
- chore(deps): bump containers submodule to v4.19.2 (#370)
- chore(ci): adopt cargo-llvm-cov for coverage reporting (#369)
- chore(tooling): adopt bacon for continuous background checks (#368)
- chore(ci): enable mold linker on Linux for faster builds (#367)
- chore(ci): align remaining jobs to just recipes (#366)
- chore(tooling): adopt rumdl for Markdown linting (#361)
- chore(tooling): adopt shfmt for shell script formatting (#360)
- chore(tooling): adopt hadolint for Dockerfile linting (#359)
- chore(tooling): adopt conform for conventional-commit enforcement (#357)
- chore(tooling): replace cspell (Node) with typos (Rust) for spell-check (#356)
- chore(tooling): remove biome now that dprint owns JSON formatting (#355)
- chore(tooling): adopt dprint for YAML and JSON formatting (#354)
- chore(tooling): add .zed/settings.json with dprint/taplo LSP overrides (#352)
- chore(deps): bump containers submodule to v4.19.0
- chore(memory): record macOS CI cache-poisoning lesson (#334)
- chore(deps): bump assert_cmd, jsonwebtoken, nix to latest patch/minor (#322)
- chore(ci): wire osv-scanner for broader vulnerability coverage (#321)
- chore(memory): add coordinated dependabot bumps learning
- chore(deps): bump opentelemetry crates from 0.31 to 0.32 (unified) (#313)
- chore(memory): record PR auto-merge-on-green preference

### Documentation

- docs(release): drop stale Unreleased section from CHANGELOG
- docs: Presidio gap analysis — feature inventory and superset posture
- docs(arch-check): justify 338 ignore doctests across 134 Layer 2/3 files (#394)
- docs(architecture): document solo-maintainer posture and high-risk subsystems (#386)
- docs(ci): add GitHub issue templates for bug, feature, and task (#385)
- docs(auth): remove stale "coming soon" markers from lib.rs (#365)
- docs(architecture): rename index.md to README.md (#330)
- docs: explain platform-conditional logic in observe writer and home fallback (#329)

### Testing

- feat(http): add CorrelationLayer middleware for correlation-id propagation (#648)
- test(anonymize): add vault concurrency conformance suite (#639)
- test(runtime): make async timing tests deterministic via paused clock (#623)
- chore(ci): enable mold linker on Linux for faster builds (#367)
- test(data): add integration test for Data facade (#351)
- refactor(identifiers): split Layer 1 token/builder.rs into per-section submodules (#343)
- refactor(identifiers): split Layer 3 builder/token.rs into per-section submodules (#335)
- refactor(identifiers): split government/builder.rs into per-country modules (#331)
- test(timing): add diagnostic messages to bare timing assertions (#319)
- fix(tests): replace fixed sleeps with poll-until-condition loops (#299)
- test(security): cover error paths and edge cases in Layer 3 builders (#285)

### CI

- deps: bump quick-xml to 0.41 and migrate AEAD crates to 0.11 (#654)
- feat(anonymize): Encrypt/Decrypt operators over keyed AEAD (#485) (#613)

### Build

- build(deps): bump the minor-and-patch group across 1 directory with 4 updates (#379)
- build(deps): bump sha3 from 0.11.0 to 0.12.0 (#363)
- chore(deps): bump opentelemetry crates from 0.31 to 0.32 (unified) (#313)
- build(deps): bump the minor-and-patch group with 4 updates (#306)
- refactor(observe): convert Layer 3 builders to 2-arg observe API (#301)
- build(deps): bump the minor-and-patch group with 2 updates (#296)
- build(deps): bump pkcs8 from 0.10.2 to 0.11.0 (#297)
- build(release): include chore: commits in CHANGELOG generation

### Other

- deps(testing): bump rexpect 0.6 → 0.7 (#327)
- deps(xml): bump quick-xml 0.39 → 0.40 (#325)

## [0.3.0-beta.3] - 2026-04-28

### Fixed

- fix(tooling): make .gitmodules anonymous-readable and skip cargo fetches
- fix(observe): add metrics instrumentation to 5 Layer 3 builders (#273)

### Changed

- chore(deps): bundle dependabot bumps and migrate to rand 0.10 (closes #277-#281)
  - rand 0.9 → 0.10 (`rand_core::RngCore` is now `rand_core::Rng`; old `rand::Rng` extension trait is now `rand::RngExt`)
  - sha1 0.10 → 0.11, sha2 0.10 → 0.11, fake 4.4 → 5.1
  - tokio 1.52.0 → 1.52.1, uuid 1.23.0 → 1.23.1, zxcvbn 3.1.0 → 3.1.1, assert_cmd 2.2.0 → 2.2.1, local-ip-address 0.6.11 → 0.6.12, libc 0.2.185 → 0.2.186

### Testing

- test(auth,observe): use paused time and real concurrency in flaky tests (#284)
- test(http,runtime,io,observe): assertion density and missing-scenario coverage (#282)
- test(crypto, observe): add per-test tokio::time::timeout guards (#272)

## [0.3.0-beta.2] - 2026-04-25

### Added

- feat(identifiers): add dedicated UK NINO identifier (#258)
- feat(identifiers): add IdentifierType::Ein variant for EIN-specific classification (#239)
- feat(identifiers): complete dual-API contract for financial, personal, token, crypto (#238)

### Fixed

- fix(auth): zeroize plaintext token buffers for reset and remember-me (#270)
- chore(tooling): migrate pre-commit (Python) to lefthook (Go binary) (#268)
- fix(deps): bump rustls-webpki to 0.103.13 (RUSTSEC-2026-0104) (#267)
- fix(http): redact URL query strings in observability logs (#241)
- fix(identifiers): add 6 IdentifierType variants for PiiType symmetry (#240)
- fix(identifiers): add missing shortcuts for ssn/jwt/medical/organizational/token-validate (#237)
- Merge pull request #225 from joshjhall/fix/issue-223-dispatcher-test-config
- fix(observe): harden integration-test dispatcher config against CI flakes
- fix(test): increase poll deadline for failing_writer_does_not_block_others
- Merge pull request #222 from joshjhall/fix/issue-169-data-network-shortcuts-bypasses
- Merge pull request #216 from joshjhall/fix/issue-210-observe-dispatch-to-writers-sync-panics
- Merge pull request #215 from joshjhall/fix/issue-158-detection-validation-arrow
- Merge pull request #213 from joshjhall/fix/issue-161-biometric-template-pii-type
- Merge pull request #207 from joshjhall/fix/issue-154-redact-token-debug-impls
- fix(data): route network shortcuts through UrlNormalizationBuilder
- fix(observe): dispatch writers async-natively from the dispatcher runtime
- fix(identifiers): move SSA helpers out of validation to break inheritance arrow
- fix(observe): add PiiType::BiometricTemplate variant to close pii-sync gap
- fix(auth): redact plaintext tokens from Debug impls
- fix(observe): parameterize audit writer WHERE clauses

### Changed

- refactor: reduce complexity in detection dispatch and shutdown hooks (#243)
- refactor(io): remove module-level dead_code suppression in ops.rs (#242)
- refactor(observe): replace pub(super) use with pub(in crate::observe) use (#236)
- Merge pull request #214 from joshjhall/refactor/issue-159-biometric-detect-rename
- docs: fix src/ path prefix to crates/octarine/src/
- refactor(identifiers): rename find_biometric_identifier to detect_biometric_identifier

### Documentation

- docs(architecture): standardize on three-layer terminology (#234)
- docs(identifiers,crypto,runtime): add doc comments to public APIs (#233)
- docs: remove stale broken link references
- Merge pull request #231 from joshjhall/docs/issue-217-phantom-api-paths-in-example-cod
- docs: replace phantom API paths in example code blocks
- Merge pull request #219 from joshjhall/docs/issue-184-fix-broken-docs-links
- Merge pull request #218 from joshjhall/docs/issue-185-phantom-api-docs
- Merge pull request #209 from joshjhall/docs/issue-183-refactor-plan-staleness
- docs: prune/redirect dead sibling and index links
- docs: prune PRIMITIVES-REFACTOR.md references
- docs: redirect refactor-plan links to docs/architecture/refactor-plan.md
- docs: fix src/ path prefix to crates/octarine/src/
- docs: add SECURITY.md with vulnerability reporting policy
- docs: remove phantom API docs and prohibit get_* prefix
- docs(architecture): make refactor-plan self-contained; drop dead src/refactor-plan.md links
- docs: update README version, layer list, and switch docs/index to just (#204)

### Testing

- test(http): add behavioral assertions for HTTP presets (#271)
- refactor(io): remove module-level dead_code suppression in ops.rs (#242)
- test(security): cover %VAR% and ^ in escape_shell_arg_windows (#232)
- fix(observe): harden integration-test dispatcher config against CI flakes
- test(observe): ignore flaky failing_writer test in CI (issue #223)
- Merge pull request #221 from joshjhall/test/issue-177-pii-redactor-submodule-tests
- Merge pull request #220 from joshjhall/test/issue-179-securefileops-async-test-coverage
- Merge pull request #212 from joshjhall/test/issue-176-security-shortcut-coverage
- Merge pull request #211 from joshjhall/test/issue-178-shortcut-tests
- test(observe): add tests for PII redactor submodules
- test(io): add async test coverage for SecureFileOps methods
- test(security): add shortcut coverage for network/paths/commands/queries
- test(observe): add unit tests for Problem and Event shortcuts
- test(just): enable --all-features in test recipes so gated tests run (#206)

### CI

- ci: add lychee link-check workflow for docs and root markdown
- ci: skip workflow on docs-only changes via paths-ignore (#205)

### Build

- feat(identifiers): complete dual-API contract for financial, personal, token, crypto (#238)
- fix(identifiers): add missing shortcuts for ssn/jwt/medical/organizational/token-validate (#237)

### Other

- resolve merge conflict: keep biometric_templates function and add tests
- resolve merge conflicts: combine link fixes with phantom-api and refactor-plan changes
- resolve merge conflict: keep Data Module Architecture removal, use Refactor Status title

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
