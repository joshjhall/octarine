---
description: Cross-platform compatibility patterns for octarine. Use when writing cfg() attributes, platform-specific code, file permissions, signal handling, path operations, or targeting Windows, macOS, Linux, or ARM64.
---

# Octarine Platform Compatibility

## cfg() Pattern Selection

Choose the narrowest attribute that covers your use case:

| Scope | Attribute | Use When |
|-------|-----------|----------|
| OS family | `#[cfg(unix)]` / `#[cfg(windows)]` | Feature differs by POSIX vs Windows (permissions, signals) |
| Specific OS | `#[cfg(target_os = "linux")]` | OS-specific API (e.g., `/proc` filesystem) |
| Architecture | `#[cfg(target_arch = "...")]` | Endianness, SIMD, pointer-size-dependent logic |
| Negation | `#[cfg(not(unix))]` | Provide fallback (no-op or alternative) |
| Exhaustive | `#[cfg(not(any(unix, windows)))]` | Catch-all for unsupported platforms |

**Every `#[cfg(unix)]` block MUST have a `#[cfg(not(unix))]` counterpart** -- either a real implementation or an explicit no-op with a comment. See `primitives/io/file/permissions.rs` for the canonical pattern.

For functions needing three+ OS variants, use per-OS blocks with a `not(any(...))` fallback. See `primitives/io/file/pidlock.rs` (`is_process_alive`).

## Platform Branching Patterns

**Separate functions** (preferred for distinct implementations):

```rust
#[cfg(unix)]
fn set_mode(path: &Path, mode: FileMode) -> Result<(), Problem> { /* real */ }

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: FileMode) -> Result<(), Problem> { Ok(()) }
```

**Inline blocks** (for small divergences within one function):

```rust
pub fn escape_shell_arg(arg: &str) -> Result<String> {
    #[cfg(unix)]
    { Ok(escape_unix(arg)) }
    #[cfg(windows)]
    { Ok(escape_windows(arg)) }
    #[cfg(not(any(unix, windows)))]
    { Ok(escape_unix(arg)) }  // fallback to Unix
}
```

Prefix unused parameters with `_` in no-op variants to suppress warnings.

## File System Portability

- **Paths**: Always use `std::path::Path` / `PathBuf` -- never literal `/` or `\\` as separators
- **Case sensitivity**: NTFS and APFS (macOS default) are case-insensitive; ext4 is case-sensitive. Normalize to lowercase for cross-platform comparison
- **Permissions**: Unix mode bits (`0o644`) vs Windows read-only flag. Use `FileMode` from `primitives/io/file/permissions.rs` (no-op on non-Unix)
- **Symlinks**: Behavior varies (Windows requires privileges). Check with `path.is_symlink()` and gate with `follow_symlinks` option
- **Home directory**: Use `$HOME` / `$USERPROFILE` with fallback chains. See `data/paths/home/core.rs`

## Security: Defensive Cross-Platform Detection

Security detections MUST check for threats from ALL platforms, even when running on a single OS. A Unix server receiving user input may encounter Windows-style attacks:

```rust
// primitives/security/paths/detection.rs checks Windows backslash
// traversal even on Unix -- because input may come from Windows clients
#[cfg(not(windows))]
{
    if path.contains("..\\") { return true; }
}
```

This is intentional and required for all security detection functions.

## Signal Handling

Follow the pattern in `runtime/shutdown/signals.rs`:

- **Unix**: Handle `SIGTERM` + `SIGINT` via `tokio::signal::unix`
- **Windows**: Handle `ctrl_c()` via `tokio::signal`
- **Fallback**: `#[cfg(not(any(unix, windows)))]` waits for manual cancellation token

## Process Detection

Per-OS implementations required -- see `primitives/io/file/pidlock.rs` for the three-OS pattern (Linux `/proc`, macOS `ps`, Windows `tasklist`) with `not(any(...))` fallback.

## Testing Strategy

- Gate platform-specific tests with `#[cfg(unix)]` / `#[cfg(target_os = "...")]`
- Test no-op fallbacks explicitly -- verify they return `Ok(())` not errors
- Use `just test` (runs on current platform); CI matrix covers others
- Permission tests that set Unix modes need `#[cfg(unix)]` to avoid no-op assertions

```rust
#[cfg(unix)]
#[test]
fn test_set_mode_applies_permissions() { /* assert mode bits */ }

// No Windows equivalent needed if set_mode is a no-op there
```

## When to Use

- Adding `#[cfg(...)]` attributes to any code
- Writing file permission logic
- Implementing signal or process handling
- Writing path manipulation code
- Adding security detections that handle cross-platform input
- Reviewing code for missing platform fallbacks

## When NOT to Use

- Pure business logic with no OS interaction
- Code that already uses `std::path::Path` without platform branching
- Feature-flag `cfg` attributes (`#[cfg(feature = "...")]`) -- different concern
- Architecture decisions about module placement -- use `octarine-architecture`

## Verification

- `just clippy` -- catches dead code under cfg, missing imports
- `just test` -- verifies current-platform behavior
- Grep for lone `#[cfg(unix)]` without matching `#[cfg(not(unix))]` to find missing fallbacks
