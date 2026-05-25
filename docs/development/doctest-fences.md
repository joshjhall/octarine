# Doctest Fences: `ignore` vs `no_run` vs plain `rust`

Rust doctests have three fence variants. Picking the right one keeps
examples accurate as the codebase evolves, and keeps `cargo test --doc`
honest about which examples are actually verified.

## Rule of thumb

| Fence            | rustdoc behavior              | Use when                                                                     |
| ---------------- | ----------------------------- | ---------------------------------------------------------------------------- |
| ` ```rust ` / ` ``` ` | Compiles **and** runs    | Pure functions, no I/O, no async runtime, no panics on the happy path        |
| ` ```no_run `    | Compiles, does **not** run    | Compiles cleanly but needs runtime state — network, filesystem, tokio reactor |
| ` ```ignore `    | Neither compiles nor runs     | Pseudo-code, intentionally incomplete, or a pre-existing example pending adaptation |

Prefer the leftmost fence that fits. A plain ` ```rust ` example is the
strongest guarantee — the doctest runs on every `just test-docs`, so the
example cannot quietly rot. ` ```no_run ` is the next-best — type and import
correctness are still verified at compile time. ` ```ignore ` is the escape
hatch.

## Why this matters

` ```ignore ` silently skips compilation. A reader cannot tell whether the
example "won't compile in principle," "shouldn't run in CI," or "the author
hadn't decided yet." Over time, undocumented `ignore` fences accumulate and
the example drifts out of sync with the API.

The [`doctest-ignores`](../../scripts/arch_check/checks/doctest_ignores.py)
arch-check enforces that every `ignore` fence in Layer 2/3 carries a
justification comment within the preceding 3 doc lines. It runs on every
`just arch-check` and gates CI as an ERROR.

## Picking the right fence

**Reach for ` ```rust ` (or bare ` ``` `) by default.** If the example is a
pure call like `let s = sanitize(input)?;`, it can run. See
`security/commands/shortcuts.rs` for five such examples on detection
shortcuts.

**Drop to ` ```no_run ` when compilation is the only honest guarantee.**
This applies to examples that:

- spawn or `.await` async work outside a runtime
- open files, sockets, or external processes
- depend on environment that the doctest harness does not provide

The compile step still catches renames, signature drift, and missing
imports — so prefer `no_run` over `ignore` whenever the example compiles.

**Use ` ```ignore ` only when compilation would fail.** Typical triggers:

- the example shows pseudo-code or a deliberately incomplete snippet
- the example uses items not in scope without elaborate import boilerplate
- the example exists as remediation backlog (an older `ignore` not yet
  rewritten — `runtime/config/builder.rs` has 16 such async-builder
  examples)

Every `ignore` MUST be preceded by a doc-comment line whose body contains
the substring `ignore` (case-insensitive). The arch-check is intentionally
generous about phrasing — the goal is to force authors to write
*something*, not to police wording.

## Suppression

Two ways to satisfy the arch-check:

1. **Inline justification** — any preceding ` /// ` or ` //! ` doc line
   within the last 3 lines whose text contains `ignore`. Examples:

   ```text
   /// Async builder — ignored because it requires a running tokio runtime.
   /// ```ignore
   /// ...
   /// ```
   ```

2. **Explicit directive** — for the rare cases where the word "ignore"
   does not naturally fit the justification:

   ```text
   // arch-check: allow doctest-ignores -- pseudo-code for documentation only
   /// ```ignore
   /// ...
   /// ```
   ```

## Examples from this codebase

- **Pure runnable** — `crates/octarine/src/security/commands/shortcuts.rs`
  (five bare ` ``` ` fences on detection shortcuts).
- **Justified `ignore`** — `crates/octarine/src/runtime/config/builder.rs`
  (16 async-builder examples preceded by a "Pre-existing example…" line).
- **Module-level `//!` doc** — `crates/octarine/src/data/text/shortcuts.rs`
  (one `ignore` fence in the module overview).
