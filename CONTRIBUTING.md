# Contributing to octarine

octarine is the foundation library providing security primitives and
observability tools for Rust applications. See [README.md](README.md) for an
overview and [docs/architecture/](docs/architecture/) for the three-layer
design.

This file is deliberately minimal — it covers dev setup and the SemVer policy.
Branching and the full PR workflow are documented in the project skills under
`.claude/skills/git-workflow/`. Commit format is enforced automatically — see
[Commit Format](#commit-format) below.

## Commit Format

octarine enforces [Conventional Commits](https://www.conventionalcommits.org/)
via [conform](https://github.com/siderolabs/conform). The source of truth for
allowed types, scopes, and length limits is [`.conform.yaml`](.conform.yaml) —
read that file before adding a new scope.

### Format

```text
<type>(<scope>): <subject>

<optional body>

<optional footers>
```

- **type** — one of: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`,
  `build`, `ci`, `deps`, `perf`.
- **scope** — a single entry from `.conform.yaml` (no comma-separated
  lists). New scopes welcome: open a PR adding an anchored `^name$` entry.
- **subject** — imperative mood, no trailing period. The Conventional
  Commits spec caps the **description** (text after `<type>(<scope>):`) at
  **72 characters**, enforced by conform. The full header has a generous
  89-character ceiling so longer `type(scope):` prefixes still fit.

### Examples

```text
feat(crypto): add Ed25519 keypair generation
fix(observe): prevent panic on writer shutdown race
docs(architecture): document layer-3 cascading visibility
chore(deps): bump tokio to 1.42
```

### Local enforcement

The `commit-msg` lefthook hook runs conform on every commit. Install hooks
once per clone:

```bash
lefthook install
```

If you're working outside the dev container and don't have conform installed,
the hook is a no-op locally — but CI's `Commit Lint` job will reject the PR.
Install conform via:

```bash
go install github.com/siderolabs/conform/cmd/conform@latest
```

### CI enforcement

The `Commit Lint` job in `.github/workflows/ci.yml` runs on every PR and
validates:

1. Every commit in the branch (against `origin/main`).
2. The PR title (used as the squash-merge subject).

Both must pass before the PR can merge.

## Development Setup

```bash
git clone git@github.com:joshjhall/octarine.git
cd octarine
just preflight    # fmt + clippy + shellcheck + lint-docker + arch-check + tests
```

Run `just --list` to discover the full recipe set. All tooling is invoked
through `just` — never invoke `cargo test`, `cargo clippy`, or scripts
directly, as recipes encode the correct feature flags and arguments.

### Linker on Linux

`.cargo/config.toml` configures the [mold linker](https://github.com/rui314/mold)
on `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`, which links
5-10x faster than the default. mold and clang are installed by the
devcontainer's `INCLUDE_RUST_DEV` feature (containers v4.19.0+).

Non-devcontainer Linux contributors need both tools:

```bash
sudo apt-get install -y mold clang   # Debian/Ubuntu
sudo dnf install -y mold clang        # Fedora/RHEL
```

If you can't install mold (locked-down workstation, unsupported distro),
override globally in `~/.cargo/config.toml` — it takes precedence over the
project config:

```toml
[target.x86_64-unknown-linux-gnu]
linker = "cc"
rustflags = []

[target.aarch64-unknown-linux-gnu]
linker = "cc"
rustflags = []
```

macOS and Windows contributors are unaffected — the project config has no
`[target.*-apple-darwin]` or `*-windows-*` overrides, so the platform
default linker is used.

### Continuous Checks (bacon)

[bacon](https://github.com/Canop/bacon) re-runs `cargo check` / `clippy` /
`test` on every save in a live TUI pane, eliminating the "wait for the last
run before starting the next edit" delay. Pre-installed in the devcontainer
via `INCLUDE_RUST_DEV`.

```bash
just bacon                                    # default: cargo check --workspace --all-features
just bacon clippy                             # or press `c` once running
just bacon test                               # or press `t`
just bacon test-filter -- module::path::test  # focused test run
```

Project config: `bacon.toml`. The `check` / `clippy` / `test` jobs use the
same flag set as `just check` / `just clippy` / `just test`, so bacon
output matches `just preflight` and CI.

### Dependency hygiene

[cargo-machete](https://github.com/bnjbvr/cargo-machete) flags unused
dependencies on every CI run and on pre-commit when `Cargo.toml` changes.
Pre-installed in the devcontainer via `INCLUDE_RUST_DEV`. Run locally:

```bash
just lint-deps
```

If machete flags a dependency you intentionally keep (e.g., a feature-gated
re-export used only at the boundary), document it with a
`[package.metadata.cargo-machete]` entry in the relevant `Cargo.toml`:

```toml
[package.metadata.cargo-machete]
ignored = ["some-dep"]   # why it's kept
```

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
