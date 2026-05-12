---
name: pre-1-0-prefer-breaking-over-deprecation
description: "While pre-1.0, prefer direct breaking renames over `#[deprecated]` alias dances. Beta is for making changes."
metadata:
  node_type: memory
  type: feedback
  originSessionId: 2b6e3b9e-2ae9-4601-9fcd-e69d0373b101
---

While pre-1.0 (`0.x` line), do breaking renames directly — drop the old name in the same PR — rather than maintaining `#[deprecated]` aliases through a deprecation cycle.

**Why:** Octarine is at `0.3.0-beta.x`, not published to crates.io, and the SemVer policy explicitly says `0.X.0` minor bumps may include breaking changes. The whole point of the beta line is to absorb breakage cheaply. Carrying parallel old+new names doubles the public surface, splits documentation, and forces the cleanup to happen *twice* (rename, then later remove). Downstream callers in this state are few and updating callsites in one go is straightforward.

**How to apply:**
- When a naming/API change qualifies as "breaking" per the breaking-change catalog in [[octarine-release]] AND the project is on `0.x`: rename in place, delete the old symbol, and document the break under `### Changed` in CHANGELOG `[Unreleased]`.
- The version bump remains `minor` (which finalizes a beta to stable per `octarine-release` SKILL.md) — don't add a synthetic `#[deprecated]` step just because the change is breaking.
- After 1.0 ships, the calculus flips — deprecation cycles become the right tool. Reassess this guidance when crossing 1.0.
- This guidance doesn't apply when the rename targets a trait method that external implementers might rely on without us being able to update them — that's still a hard break worth flagging in the PR description, but the action is the same (just rename), not "add a deprecation alias."

Concrete example: instead of #314's original "add `#[deprecated]` aliases pointing at new names" plan, the follow-up should just rename `crypto::auth::hmac::verify_*` → `validate_*` / `is_*_valid`, delete the old names, bump minor.
