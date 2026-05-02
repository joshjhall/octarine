# Contributing to octarine

octarine is the foundation library providing security primitives and
observability tools for Rust applications. See [README.md](README.md) for an
overview and [docs/architecture/](docs/architecture/) for the three-layer
design.

This file is deliberately minimal — it covers dev setup and the SemVer policy.
Branching, commit conventions, and the full PR workflow are documented in
[CLAUDE.md](CLAUDE.md) and the project skills under `.claude/skills/`.

## Development Setup

```bash
git clone git@github.com:joshjhall/octarine.git
cd octarine
just preflight    # fmt + clippy + shellcheck + arch-check + tests
```

Run `just --list` to discover the full recipe set. All tooling is invoked
through `just` — never invoke `cargo test`, `cargo clippy`, or scripts
directly, as recipes encode the correct feature flags and arguments.

## SemVer Policy

octarine is a foundational library. Downstream crates depend on a stable
public API, so we track SemVer discipline closely.

### Current status: pre-release (0.x)

The workspace is at `v0.3.0-beta.3` and is not yet published to crates.io.
While we're on `0.x`:

- Breaking public-API changes are **allowed** within minor version bumps.
- Every breaking change **must** be recorded in [CHANGELOG.md](CHANGELOG.md)
  under the release entry.

### After 1.0

Once the crate ships its first `1.0` release:

- No breaking public-API changes within minor or patch versions.
- Breaking changes require either:
  - a major version bump, **or**
  - an explicit intent annotation in [CHANGELOG.md](CHANGELOG.md) under an
    `### Intentional Breaking Changes` subheading, naming the affected APIs
    and the rationale.

### Automated checks

[cargo-semver-checks](https://github.com/obi1kenobi/cargo-semver-checks) runs
on every pull request as an **advisory** gate — it compares the rustdoc JSON
of the PR branch against `origin/main` and flags SemVer-incompatible changes
(new `pub fn`, changed return types, removed re-exports, etc.).

The check is currently `continue-on-error: true`; findings do not block
merge. After one release cycle of calibration, the gate will flip to required.

**Running locally:**

```bash
git fetch origin main
just semver-check
```

When the tool reports findings:

1. Read the output — it names each affected item.
2. If the change is accidental, revert it or add a non-breaking alternative.
3. If the change is intentional, follow the policy above (version bump or
   CHANGELOG.md annotation).

## Getting Help

- Open an issue: <https://github.com/joshjhall/octarine/issues>
- Architecture questions: see `docs/architecture/layer-architecture.md`
- Security patterns: see `docs/security/patterns/`
