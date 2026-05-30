---
name: project_ci_doc_job_strict
description: "CI Doc job runs `just doc` (rustdoc -D warnings) — stricter than `just test-docs`; run `just doc` locally before shipping"
metadata:
  node_type: memory
  type: project
  originSessionId: c532b636-dc1e-4ee7-9f0c-1cc58b7bfbfe
---

The CI **Doc** job runs `just doc` = `RUSTDOCFLAGS="-D warnings" cargo doc
--workspace --no-deps --all-features`. This fails on **broken intra-doc
links** (`rustdoc::broken_intra_doc_links`), which `just test-docs` (doctests
only) and `just preflight` do **not** catch.

Common trap: in a `mod.rs` whose module-level doc (`//!`) references a private
submodule (`` [`types`] `` where `mod types;` is private) or re-exported type
names — rustdoc can't resolve those in the module-doc scope and the build
fails under `-D warnings`. Fix: use plain code spans (`` `RecognizerResult` ``)
in the aggregating `mod.rs`; keep rich intra-doc links in the file where the
items are actually defined and in scope.

**How to apply:** Before `/next-issue-ship`, run `just doc` (not just
`just preflight`) when you've added or edited any `//!` / `///` doc comments,
especially new module files. `just preflight` does NOT include the doc-link
check.
