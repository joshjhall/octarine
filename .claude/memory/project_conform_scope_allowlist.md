---
name: project_conform_scope_allowlist
description: New octarine top-level modules must be registered in .conform.yaml scopes or commit-msg hook rejects the commit
metadata:
  node_type: memory
  type: project
  originSessionId: c532b636-dc1e-4ee7-9f0c-1cc58b7bfbfe
---

The `conform` commit-msg hook (lefthook) enforces a curated scope allowlist in
`.conform.yaml` (`policies[].spec.conventional.scopes`). Scopes are anchored Go
regexes (e.g. `^identifiers$`). A commit like `feat(anonymize): ...` is
**rejected** until `^anonymize$` is added to that list.

Convention: every octarine source module under `crates/octarine/src/*` is
registered as a scope (`auth`, `crypto`, `data`, `http`, `identifiers`, `io`,
`observe`, `primitives`, `runtime`, `security`, `testing`, and now
`anonymize`).

**How to apply:** When adding a NEW top-level Layer 3 module, register its name
in `.conform.yaml` scopes (alphabetically in the "octarine source modules"
block) as part of the same PR. The same allowlist gates PR titles via the
Commit Lint CI job. Until then, fall back to an existing scope like `types`.

Related: [[feedback_complete_provider_integration]]
