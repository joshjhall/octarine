# Platform Compatibility Scanning Rules

Companion file for `audit-octarine-platforms.md`. Loaded on demand when
scanning a manifest or evaluating findings. Categories use
`octarine-platforms/<slug>` format.

## Rule Index

| # | Slug                       | Severity | Method        | Confidence |
| - | -------------------------- | -------- | ------------- | ---------- |
| 1 | cfg-without-else           | high     | deterministic | 0.90       |
| 2 | cfg-without-test           | medium   | heuristic     | 0.60       |
| 3 | unix-only-api              | high     | deterministic | 0.90       |
| 4 | hardcoded-path-separator   | medium   | heuristic     | 0.65       |
| 5 | platform-security-gap      | high     | heuristic     | 0.75       |
| 6 | missing-platform-doc       | low      | heuristic     | 0.60       |
| 7 | arch-assumption            | medium   | heuristic     | 0.60       |
| 8 | arch-specific-no-fallback  | medium   | deterministic | 0.85       |

The Certainty Assignment section in `audit-octarine-platforms.md` carries
the authoritative copy of these values and the notes explaining each
confidence level — consult it after applying a rule.

## Rules

### 1. cfg-without-else (severity: high)

Platform-conditional code with no fallback arm. A `#[cfg(unix)]` function
or block without a corresponding `#[cfg(not(unix))]` or `#[cfg(windows)]`
means the code silently vanishes on the uncovered platform.

Grep patterns:

```text
Grep pattern="#\[cfg\(unix\)\]" path="crates/octarine/src/"
Grep pattern="#\[cfg\(windows\)\]" path="crates/octarine/src/"
Grep pattern="#\[cfg\(target_os" path="crates/octarine/src/"
```

For each match:

1. Read the file and identify the cfg-gated item (function, impl block, or module)
2. Search the same file and parent `mod.rs` for a complementary cfg gate
   (`not(unix)`, `not(windows)`, `cfg_if!` with else)
3. If no complement found, flag as a finding

Exception: `#[cfg(test)]` blocks are not platform gates — skip them.

### 2. cfg-without-test (severity: medium)

Platform-conditional code with no test coverage on the non-default platform.
CI runs on ubuntu-latest/x86_64, so Windows and macOS paths are untested.

Grep patterns:

```text
Grep pattern="#\[cfg\(windows\)\]" path="crates/octarine/src/"
Grep pattern="#\[cfg\(target_os = \"macos\"\)\]" path="crates/octarine/src/"
Grep pattern="#\[cfg\(target_arch" path="crates/octarine/src/"
```

For each match, search the same file's `#[cfg(test)]` module for a test
that exercises or mocks the platform-specific path. Flag if no test exists.

Note: This rule has lower confidence because some platform code is
inherently untestable on other platforms.

### 3. unix-only-api (severity: high)

Public functions or methods that only exist on Unix with no cross-platform
alternative. Users calling these on Windows get a compile error.

Grep patterns:

```text
Grep pattern="#\[cfg\(unix\)\]\s*\n\s*pub fn" path="crates/octarine/src/" multiline=true
Grep pattern="#\[cfg\(unix\)\]\s*\n\s*pub(crate) fn" path="crates/octarine/src/" multiline=true
```

For each match:

1. Check if the function has a `#[cfg(not(unix))]` counterpart
2. Check if it is behind a feature gate (acceptable if documented)
3. Check if the parent module is entirely cfg-gated (acceptable — the
   whole module is platform-specific)

Flag only `pub fn` items that have no alternative on non-Unix platforms.

### 4. hardcoded-path-separator (severity: medium)

Literal `/` or `\\` used in path construction instead of `std::path::Path`,
`std::path::MAIN_SEPARATOR`, or `join()`. False positives include URL paths,
regex patterns, and documentation strings.

Grep patterns:

```text
Grep pattern='format!\(".*[/\\\\].*"' path="crates/octarine/src/"
Grep pattern='push_str\(".*[/\\\\]' path="crates/octarine/src/"
Grep pattern='\.to_string\(\) \+ "[/\\\\]' path="crates/octarine/src/"
```

For each match, read context to determine if:

- It is a filesystem path (flag) vs URL/URI path (skip)
- It is in a const/static string for display purposes (skip)
- It uses `format!` to build a filesystem path with literal separators (flag)

### 5. platform-security-gap (severity: high)

Security-critical functions that behave differently per platform without
documenting the difference. A permission check that works on Unix but is
a no-op on Windows is a security gap.

Grep patterns:

```text
Grep pattern="#\[cfg\(unix\)\]" path="crates/octarine/src/primitives/security/"
Grep pattern="#\[cfg\(unix\)\]" path="crates/octarine/src/security/"
Grep pattern="#\[cfg\(unix\)\]" path="crates/octarine/src/primitives/io/"
Grep pattern="#\[cfg\(unix\)\]" path="crates/octarine/src/io/"
Grep pattern="mode\(\)|permissions\(\)|set_permissions" path="crates/octarine/src/"
```

For each match:

1. Read the function and its cfg counterpart (if any)
2. Check if the Windows path provides equivalent security guarantees
3. Flag if the Windows arm is missing, a no-op, or weaker than the Unix arm

### 6. missing-platform-doc (severity: low)

Platform-conditional blocks without doc comments explaining the platform
behavior. Developers maintaining this code need to understand WHY
a block is platform-gated.

Grep patterns:

```text
Grep pattern="#\[cfg\((unix|windows|target_os|target_arch)" path="crates/octarine/src/"
```

For each match, check the 1-5 lines above for a doc comment (`///` or `//`)
explaining the platform-specific behavior. Flag if no comment present.

### 7. arch-assumption (severity: medium)

Code that assumes pointer size, endianness, or CPU features without a
`cfg(target_arch)` guard. Common violations:

- `as usize` on values that could overflow on 32-bit
- `mem::size_of::<usize>()` used as a constant (8 on 64-bit, 4 on 32-bit)
- Byte order assumptions without `cfg(target_endian)`

Grep patterns:

```text
Grep pattern="mem::size_of::<usize>\(\)" path="crates/octarine/src/"
Grep pattern="as usize.*>> (32|16)" path="crates/octarine/src/"
Grep pattern="\.to_be_bytes\(\)|\.to_le_bytes\(\)" path="crates/octarine/src/"
```

For each match, read context to determine if a `cfg(target_arch)` or
`cfg(target_endian)` guard is present. Flag if absent.

### 8. arch-specific-no-fallback (severity: medium)

Architecture-specific blocks (e.g., `#[cfg(target_arch = "x86_64")]`) without
a fallback for other architectures.

Grep patterns:

```text
Grep pattern="#\[cfg\(target_arch" path="crates/octarine/src/"
```

For each match, check for a complementary `#[cfg(not(target_arch = ...))]`
or a generic fallback. Flag if no fallback exists.
