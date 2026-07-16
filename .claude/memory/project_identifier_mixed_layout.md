---
name: project_identifier_mixed_layout
description: Identifier source tree is mixed-layout (flat .rs vs split dir); audit-agent grep rules must be layout-agnostic
metadata:
  node_type: memory
  type: project
  originSessionId: f7033bcf-b7bd-47fd-92be-a7f30b091855
---

The `primitives/identifiers/{domain}/` tree mixes two layouts at each node
(`detection`, `validation`, `sanitization`, `builder`): 13 builder-bearing
domains are **flat** (`detection.rs`), 5 are **split** into directories
(`government`, `location`, `network`, `personal`, `token`).
`identifiers/shortcuts/` is always a per-domain directory now (not a flat
`shortcuts.rs`); `identifiers/builder/` mixes flat `{domain}.rs` with
`government/`/`token/` directories.

**Why:** an audit-agent Grep rule that hard-codes one layout silently returns
zero matches for the other — a false negative reading as "no violations." The
Grep tool passes `path` to ripgrep verbatim (no `*` expansion), and ripgrep
anchors slash-containing `--glob` to cwd, so a bare-basename glob leaks the
nested `builder/detection.rs` in split domains.

**How to apply:** resolve files **Glob-tool-first** with a flat-`.rs` +
split-`/*.rs` pattern pair (single `*` before the node dir excludes
`builder/`), or use a single Grep `glob="{**/x.rs,**/x/*.rs}"` string. Fixed
across the audit agents + checklist docs in #670 / PR #702. Related:
[[project_aggregate_redactor_gap]].
