---
name: presidio-audit-issue-namespace
description: "Presidio gap audit complete. 140 issues filed in `gap/presidio` namespace at"
metadata:
  node_type: memory
  type: project
  originSessionId: eb6cbc31-6d1d-4fad-aae1-759850ee8f3c
---

The Presidio audit produced 140 GitHub issues (#462-#601) covering every gap between octarine and Microsoft Presidio. They are all labeled `gap/presidio` and structured as 15 tracking issues with child issues attached via "Blocked by #N" Context lines.

## Tracking issues (umbrellas) — use as entry points for design discussion

- **#462** — Layer 3 `anonymize/` module (operator surface)
- **#463** — Shared operator/engine type system
- **#464** — Layer 3 `analyze/` module with explicit pipeline
- **#465** — `octarine-server` REST scaffold
- **#466** — `octarine` CLI scan + anonymize subcommands
- **#467** — Crate strategy: `octarine-llm` and `octarine-otel` split decision
- **#468** — First-class LLM integration suite
- **#469** — OpenTelemetry deployment story
- **#470** — Layer 3 `structured/` module (pandas/Polars/Parquet/SQL/JSON/CSV)
- **#471** — `octarine-dicom` crate — 4-phase DICOM PHI scrubbing roadmap
- **#472** — `octarine-image` crate scaffold
- **#473** — Surrogate operator archetype (biggest single operator-category gap)
- **#474** — Session-stable token vault
- **#475** — Deployment artifacts (Dockerfile + Helm + Terraform + release CI)
- **#563** — `octarine-eval` crate (evaluation framework + CI gates)

## Source of truth

The audit findings live in `docs/audits/presidio/`:

- `00-feature-master.md` — full Presidio inventory (sections A-Y, ~2000 lines)
- `00b-octarine-superset.md` — octarine's superset posture + asymmetric wins
- `01-08*.md` — per-area audit catalogs (recognizers, anonymizer, image+structured, engine, deployment, presidio-research, types-and-utilities, docs-cli-roadmap, samples-deep, tests-issues-prs, loose-ends)

Issue drafts at `docs/audits/presidio/issues-to-file/` were deleted after all batches were filed.

## How issues are organized

- **Tier 1 critical parity** (~34 issues): anonymizer ops #481-#487, engine pipeline #488-#498, identifiers #476-#480, REST #499-#504, CLI #505-#509
- **Tier 2 asymmetric wins** (~36 issues): anonymizer T2 #510-#513, engine polish #514-#519, LLM suite #520-#526, OTel adapters #527-#532, Surrogate backends #533-#538, Token vault #539-#545
- **Tier 3 specialized** (~17 issues): Structured #546-#554, DICOM #555-#559, Image #560-#562
- **Tier 4 eval framework** (~18 issues): #572-#589 (E-14 #585 is the CI regression gate — high-leverage)
- **Tier 5 deployment polish** (~8 issues): #564-#571
- **Speculative on-hold** (12 issues): #590-#601 — all carry `status/on-hold` label; un-hold criteria documented in each body

## Anti-patterns octarine should NOT inherit from Presidio

Captured in `00b-octarine-superset.md` §C. Highest-value items already baked into Tier 1 acceptance criteria:

- Two `InvalidParamError` classes that don't share a base (octarine: single `Problem` type)
- `ConflictResolutionStrategy.NONE` declared but not defined (octarine: enum has all variants)
- CLI exit-on-finding broken (octarine: ships working from day one)
- `--no-warnings` is a no-op (octarine: actually filters)
- Line-by-line CLI analysis misses multi-line entities (octarine: full-file)
- AES-CBC without auth, no KDF (octarine: wires to existing AEAD crypto in `crypto/encryption/`)
- `Custom.validate()` probe-calling user lambdas (octarine: no-probe-call discipline per Presidio bug #2024)
- Substring-mode context-matching default (octarine: defaults to whole_word)
- Single-space-only adjacency merge (octarine: configurable whitespace)

## Where octarine ALREADY beats Presidio (audit confirmed)

- Context-window math (`+0.35`, cap `0.95`) already in `primitives/identifiers/confidence/context.rs`
- `observe`'s correlation_id + tenant-scoped audit writers SUPERSET Presidio's `AppTracer`
- `crypto/encryption/{ephemeral,persistent}.rs` ships ChaCha20-Poly1305 + AES-256-GCM + HMAC + KDF
- OTel partially shipped: OTLP/gRPC, W3C `traceparent`, x-correlation-id, Prometheus text exposition
- axum / tower / tower-http / tower_governor already optional deps behind `http` feature
- runtime/cli/CliApp + OutputFormat { Text, Json, Quiet } already exist

## How to use this for new work

- `/next-issue` will pick the next unblocked issue — works as-is now that all 140 are filed
- Closing umbrellas: when all children of an umbrella close, the umbrella can close too (AC checklists track them)
- For design discussion on a new feature, find the corresponding tracking issue and discuss there
- The 12 on-hold issues stay out of the working pool until their un-hold criteria materialize
