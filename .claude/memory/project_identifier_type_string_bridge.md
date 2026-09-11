---
name: project-identifier-type-string-bridge
description: IdentifierType <-> SCREAMING_SNAKE_CASE labels live in primitives/identifiers/types/labels.rs; re-export needs all four chain links
metadata:
  type: project
---

`IdentifierType::as_str()` / `FromStr` (added for #521) live in
`crates/octarine/src/primitives/identifiers/types/labels.rs`, not in `core.rs`
with the enum — the 117-arm bidirectional table would have pushed `core.rs` past
the split threshold. Both directions use an exhaustive match with no wildcard,
so a new variant fails compilation until it is given a label (same guard as
`observe/pii/types/mapping.rs`).

Labels use **Presidio spellings** where one exists (`PERSON` not
`PERSONAL_NAME`, `US_SSN`, `IBAN_CODE`, `US_BANK_NUMBER`) so a config written
against Presidio transfers unchanged. A mechanical CamelCase→SNAKE derivation
gets these wrong.

`FromStr` is **strict**: an unknown label returns `UnknownIdentifierType`, never
`IdentifierType::Unknown`. Degrading a typo to `Unknown` would let a config load
clean and then silently detect nothing.

**Why:** exporting a new type from primitives needs FOUR re-export edits, and
missing any one fails only at `just doc` (private-intra-doc-links), not at
`cargo build` — see [[project_ci_doc_job_strict]].

**How to apply:** to surface a new `primitives/identifiers/types/` item
publicly, edit all four: `primitives/identifiers/types/mod.rs`,
`primitives/identifiers/mod.rs`, `identifiers/types/core.rs`,
`identifiers/types/mod.rs`, plus `identifiers/mod.rs` for the L3 public API.
Related: [[project_identifier_mixed_layout]].
