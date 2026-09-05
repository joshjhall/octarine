# Crate Layout

Where does a new integration live — a feature flag on the main crate, or its
own workspace crate?

This document records the decision made in
[#467](https://github.com/joshjhall/octarine/issues/467) and gives the rule to
apply to the next integration. It is the home-directory decision for every
child of [#468](https://github.com/joshjhall/octarine/issues/468) (LLM suite),
[#469](https://github.com/joshjhall/octarine/issues/469) (OTel deployment), and
the already-filed sibling-crate trackers (#465, #471, #472, #563).

## The rule

Apply in order; **first match wins**.

### R0 — Direction is non-negotiable

Dependencies point **toward** `octarine-core`, never away.

`octarine-core` may re-export only crates that do **not** depend on it. There
is no `octarine::llm`, `octarine::image`, or `octarine::dicom` path, and there
cannot be one under the current layout — see
[Why the re-export shim is impossible](#why-the-re-export-shim-is-impossible).

### R1 — Extends vs consumes

Does it need `pub(crate)` or module-internal access to existing octarine code?
→ **feature flag on `octarine-core`**.

Does it only touch the public API? → eligible for a sibling crate.

Never widen a module's visibility just to feed your own sibling crate. That
inverts the cascading-visibility rules in
[layer-architecture.md](./layer-architecture.md) and is a worse outcome than
keeping the code in the main crate.

### R2 — New runtime surface

Does it ship a binary or server, need its own Docker image or k8s manifests, or
link a non-Rust runtime (ONNX, image codecs, DICOM parsers, Tesseract)?
→ **sibling crate**.

A system-native toolchain dependency cannot be expressed as a Cargo feature —
enabling the feature would break the build for everyone without those system
libraries installed.

### R3 — Dep-family risk

Does it pull vendor SDKs with an independent release cadence, preview/unstable
SDKs, or deps that would raise the main crate's MSRV (currently
`rust-version = "1.97"`)? → **sibling crate**.

A sibling isolates both MSRV and version churn.

### R4 — Size floor

Under ~500 LOC of glue with no new dep family? → **feature flag**, even if R2
or R3 nominally fire. A crate has real fixed costs (see
[Sibling-crate registration checklist](#sibling-crate-registration-checklist)).

### R5 — Already shipped as a feature flag?

Do not retract it absent a functional reason. Tidiness is not one.

### R6 — Testing

A sibling may be a **`path`-only dev-dependency** of `octarine-core` for
doctests and examples. Cargo explicitly permits dev-dependency cycles. It must
never be a normal or build dependency.

Use `path` only, with no `version` key: a dev-dependency carrying both creates
a first-publish chicken-and-egg problem. `cargo publish` strips `path`-only
dev-dependencies.

## Applied to the filed work

| Integration | Layout | Rule |
|---|---|---|
| `llm` (#468) | **Sibling** `crates/octarine-llm` | R2 (axum proxy binary), R3 (four vendor SDKs) |
| `otel` (#469) | **Feature flags** `otel` / `otel-http` — already shipped | R5, R1 |
| `octarine-server` (#465) | **Sibling** | R2 — it *is* a binary |
| `octarine-image` (#472) | **Sibling** | R2 — image codecs, Tesseract/Leptonica C libs |
| `octarine-dicom` (#471) | **Sibling** | R2 — native DICOM parsers |
| `octarine-eval` (#563) | **Sibling** | R2/R3 — dev/CI-only, must never appear in a production dep graph |
| `octarine-derive` | **Below-facade** — re-exported | Proc-macro; depends on nothing |
| `octarine-problem` | **Below-facade** | Shared error type; sits under everything |

### LLM (#468) — sibling crate

`crates/octarine-llm` depends one-way on `octarine-core`. Users write
`use octarine_llm::...`. There is no re-export back.

Two conflicts in #468's draft tree are resolved here:

- **The token vault stays in `octarine-core`.** #468 sketches `vault/` inside
  `crates/octarine-llm/`, but `crates/octarine/src/anonymize/vault/` already
  exists (`store.rs`, `session.rs`, `backends/memory.rs`) and #474 owns it.
  `octarine-llm` consumes it. Redis and Postgres backends (#541, #542) are
  feature-gated in core alongside the existing `postgres`/`sqlite` features,
  matching the established `sqlx` gating.
- **Reserve the crates.io name before children start.** The bare `octarine`
  name was already squatted (#655, which is why the package publishes as
  `octarine-core` while the lib stays `octarine`). `octarine-llm` availability
  is unverified.

### OTel (#469) — stays as feature flags

OTel is **already shipped**, not greenfield: features `otel` and `otel-http` in
`crates/octarine/Cargo.toml`, ~954 LOC at
`crates/octarine/src/observe/tracing/otel.rs` (OTLP/gRPC), Prometheus text
export at `observe/metrics/export/prometheus.rs`, and W3C `traceparent`
propagation.

The decisive reason not to retract it into `octarine-otel` is **visibility, not
SemVer**. #469's remaining children — #527 (OTLP/HTTP), #529 (pipeline
metrics), #531 (correlation-id middleware), #532 (per-stage spans) — *extend*
`observe/` internals. A sibling crate sees only the `pub` surface, so retracting would
force widening `observe/`'s public API purely to serve our own sibling, which
R1 forbids.

Only #528 (axum `/metrics` handler) and #530 (OTel `LogProcessor` /
`SpanProcessor` redactor) are pure glue over the public API. Two children do not
justify a crate.

## Why the re-export shim is impossible

Issue #467 originally proposed **sibling crates plus feature-gated re-export
shims** on the main crate (`octarine::llm::openai::*`), pitched as "best of both". It
does not compile, and this is worth recording so it is not re-litigated.

`octarine-llm` must depend on `octarine-core`: #520 specifies `LLMRecognizer`
implementing a `Recognizer` trait returning
`Result<Vec<RecognizerResult>, Problem>`, and `RecognizerResult` is a `pub`
type **inside the main crate** at `crates/octarine/src/anonymize/types.rs:102`
(landed via #463). For `octarine-core` to then re-export `octarine-llm` is a
package cycle, which Cargo rejects at resolve time with
`cyclic package dependency`.

Two things that look like escape hatches and are not:

- **`optional = true` does not help.** Optional dependencies are edges in the
  manifest graph; the cycle is detected *before* feature resolution. Adding
  `llm = ["dep:octarine-llm"]` fails even with the feature disabled.
- **`#[doc(inline)] pub use` does not help.** It is a rustdoc rendering
  attribute on a `pub use` that still requires the dependency edge.

**This kills the shim for OTel too, not just LLM** — `octarine-otel` would need
`observe::Event`, producing the identical cycle.

### The `octarine-derive` precedent does not generalize

`pub use octarine_derive::Config;` (`crates/octarine/src/lib.rs:327`, gated
`#[cfg(feature = "derive")]`) works precisely because `octarine-derive` is a
proc-macro crate that needs **nothing** from the parent — the same shape as
`serde`/`serde_derive` and `tokio`/`tokio-macros`.

The precedent that *does* generalize is `octarine-problem`: a shared-types crate
strictly **below** the main crate, depended on by everything — the `sqlx-core`,
`axum-core`, `tracing-core` pattern. A re-export shim is available only to
crates below the facade, never to consumers of its types.

### If a unified import path is ever wanted

The only legal construction is a new facade crate **above** everything
(`rand`/`getrandom`, `tracing`, `sqlx`). That requires renaming the current
`[lib] name = "octarine"` (e.g. to `octarine_kernel`), touching every
`use octarine::` in the tree and every downstream import.

Revisit only when there are **≥3 shipped siblings**, and only at a major
version.

## Sibling-crate registration checklist

A new workspace crate is not just a directory. Each of these is hand-maintained:

- [ ] `Cargo.toml` — add to workspace `members`
- [ ] `Cargo.toml` — add to `[workspace.dependencies]` with **both** `path` and
      `version` (`cargo publish` requires the version; `just release` keeps it
      in sync)
- [ ] `justfile` — add to the `cargo machete` invocation
- [ ] `justfile` — add a version-sync check alongside the existing per-crate
      checks
- [ ] `.github/workflows/release.yml` — add a publish job **in dependency
      order** (crates that depend on `octarine-core` publish *after* it)
- [ ] `.conform.yaml` — add the commit scope, or the commit-msg hook rejects
      `feat(<scope>):`
- [ ] Reserve the name on crates.io
- [ ] Copy the `[lints.rust]` / `[lints.clippy]` blocks — lints are **not**
      inherited automatically

### Two inheritance caveats

- **MSRV.** `rust-version` is inherited via `rust-version.workspace = true`. A
  sibling that needs a newer toolchain must set its own — that is a reason to
  split (R3), not a problem to hide.
- **`unsafe_code = "forbid"`** is set both workspace-wide (`Cargo.toml`) and
  per-crate. A crate wrapping native bindings can relax this locally only as a
  sibling; it cannot be relaxed for one module of the main crate.

### `arch-check` does not follow siblings

`just arch-check` scans **`crates/octarine/src` only**
(`scripts/arch_check/cli.py`). Code in a sibling crate is outside layer-boundary
enforcement.

This is a genuine cost of splitting, and a reason to prefer a feature flag when
R1 is even arguably in play. It is acceptable for the siblings above because
each is a *consumer* of octarine's public API rather than a participant in its
layer graph.

### CI builds siblings too

CI runs `cargo nextest run --workspace --all-features`
(`.github/workflows/ci.yml`). A sibling is therefore **built and tested on every
run** — splitting does not reduce CI time.

Note the corollary, because #467's original framing had it backwards: optional
dependencies do not compile when their feature is off, but they *do* appear in
`Cargo.lock` either way, and `--all-features` compiles them regardless. The real
benefits of a split are independent versioning, MSRV isolation, its own
Dockerfile, and keeping a binary out of the library — **not** lockfile size or
CI speed.

## Rollout status

The decision above was applied to the already-filed tracking issues by comment
(not by editing their bodies), so each child issue points back at this document:

| Issue | Applied |
|---|---|
| #468 — LLM suite | Sibling crate confirmed; vault + #525 placement corrected |
| #469 — OTel deployment | Sibling-crate scaffolding superseded; stays feature flags |
| #465 — `octarine-server` | Sibling confirmed + registration checklist |
| #471 — `octarine-dicom` | Sibling confirmed + registration checklist |
| #472 — `octarine-image` | Sibling confirmed + registration checklist |
| #563 — `octarine-eval` | Sibling confirmed + registration checklist |

**No workspace `members` or `[workspace.dependencies]` entries are added by this
decision.** #467's acceptance criteria anticipated that a sibling-crate outcome
would add them, but there is nothing to register until a crate actually exists:
each sibling is created by its own child issue, which works the
[registration checklist](#sibling-crate-registration-checklist) at that point.
Adding empty members now would break `cargo metadata`.

## Related documents

- [Layer Architecture](./layer-architecture.md) — the three-layer rules and the
  feature-flag list
- [System Design](./system-design.md) — overall library architecture
- [CLAUDE.md](../../CLAUDE.md) — development guidelines
