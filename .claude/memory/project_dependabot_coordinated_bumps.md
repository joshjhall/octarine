---
name: dependabot-coordinated-bumps
description: Some crate families (e.g. opentelemetry suite) must be bumped together; Dependabot files them separately and they all fail CI individually
metadata:
  node_type: memory
  type: project
  originSessionId: 00b43c98-2408-43d8-8bf1-4ca50fe70a90
---

When Dependabot files multiple PRs touching crates from the same release cycle (e.g. `opentelemetry`, `opentelemetry_sdk`, `opentelemetry-otlp` — all part of the OpenTelemetry Rust workspace), each individual PR will fail CI with trait-coherence errors (`E0277`: `SpanExporter`/`TracerProvider` trait bound not satisfied, `E0308`: mismatched types).

**Why:** bumping one crate alone produces a duplicate transitive version of the shared base crate in the lockfile. Traits implemented in one version aren't satisfied by types from the other version.

**How to apply:** when you see multiple failing Dependabot PRs touching crates that share a version number or release cadence, don't try to merge them individually or rebase them — close them all as superseded and file ONE unified bump PR that updates all of them together. The trait errors disappear once the lockfile resolves to a single version, and typically no call-site changes are needed (the API across versions in a coordinated release is usually stable).

**Examples of coordinated families to watch for:**

- `opentelemetry*` (opentelemetry, opentelemetry_sdk, opentelemetry-otlp, opentelemetry-http, opentelemetry-proto)
- `tonic*` (tonic, tonic-build, tonic-types)
- `tracing*` (tracing, tracing-subscriber, tracing-core)
- `serde*` (serde, serde_json — usually OK, but serde_derive must match serde)

Verified in this codebase: PR #313 (unified bump 0.31→0.32) succeeded after closing failing #307/#308/#309 which Dependabot had filed as three separate PRs.
