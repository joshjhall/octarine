---
name: project_conform_no_presidio_scope
description: `presidio` is not an allowed conform commit scope; use `identifiers` or `docs` for gap-analysis work
metadata:
  type: project
---

`.conform.yaml` has no `^presidio$` scope, so `docs(presidio): ...` is rejected
by the commit-msg hook with a bare `🥊 conform` line and exit 1 — no message
naming the offending scope. Hit on #427 (2026-09-11).

For presidio gap-analysis work use `identifiers` (code) or `docs` (doc-only).

**Why:** the failure output does not say which policy failed, so it reads like a
malformed header rather than a scope violation, and the obvious retry (rewording
the subject line) does not fix it.

**How to apply:** when conform rejects a commit whose header is conventional and
under 72 chars, check the scope against the `scopes:` list in `.conform.yaml`
before touching anything else. See [[project_conform_scope_allowlist]].
