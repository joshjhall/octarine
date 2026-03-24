# Security Guidelines

> **For vulnerability reporting and security policy**, see [SECURITY.md](../../SECURITY.md) in the repository root.

This document outlines critical security principles and anti-patterns discovered during development of the octarine security library.

## Table of Contents

- [Input Validation Principles](#input-validation-principles)
- [Known Vulnerabilities](#known-vulnerabilities)
- [Security Anti-Patterns](#security-anti-patterns)
- [Reporting Security Issues](#reporting-security-issues)

## Input Validation Principles

### 1. Never Bypass Validation for Convenience

**Rule**: Convenience features (tilde expansion, default values, shortcuts) must NEVER skip security validation.

**Vulnerability Pattern**: Functions that return input untouched based on a "safe" prefix or pattern.

**Examples of Dangerous Shortcuts**:

- Tilde paths (`~/`)
- "Safe" prefixes (`/opt/app/`, `C:\Program Files\`)
- Expected formats (URLs starting with `https://`)
- Default values (empty strings that skip validation)
- Special patterns (whitespace-only input treated as "safe")

**Mitigation**: Run ALL security checks FIRST, then apply convenience logic.

### 2. Defense in Depth

Apply multiple validation layers in this order:

1. **Early Rejection** (fail-fast on obvious attacks)

   - Command injection (`$(`, backticks)
   - Null byte injection (`\0`)
   - Control characters

1. **Format Validation**

   - Path traversal limits (OWASP: max 2 `../` sequences)
   - Length limits (prevent DoS)
   - Character whitelists/blacklists

1. **Sanitization** (only if strict validation passes)

   - Remove/replace dangerous characters
   - Normalize paths
   - Escape for specific contexts

1. **Fallback** (lenient functions only)

   - Use safe defaults
   - Log security events

### 3. Strict vs Lenient Pattern

Every security function has two versions:

- **Strict** (`_strict` suffix): Returns `Result<T>`, fails on suspicious input

  - Use in security-critical contexts
  - Fails fast, provides detailed error messages
  - Never silently sanitizes in strict mode

- **Lenient** (no suffix): Always returns a value, uses fallback for errors

  - Use in user-facing contexts
  - Sanitizes dangerous input
  - Falls back to safe defaults
  - Logs all transformations

## Known Vulnerabilities

### CVE-INTERNAL-2025-001: Tilde Path Bypass (CRITICAL)

**Discovered**: 2025-11-09
**Fixed**: 2025-11-09
**Severity**: CRITICAL (9.8/10)

#### Details

**Affected Function**: `normalize_ssh_directory_strict()`
**File**: `src/security/data/sanitization/paths/ssh.rs`
**Lines**: 325-346 (fix location)

#### Vulnerability

Paths starting with `~/` completely bypassed ALL security validation, allowing:

1. **Command Injection**:

   ```rust
   normalize_ssh_directory_strict("~/$(whoami)/.ssh")
   // Returned: "~/$(whoami)/.ssh" without validation
   // Would execute: whoami command during path expansion
   ```

1. **Path Traversal**:

   ```rust
   normalize_ssh_directory_strict("~/.ssh/../../../../etc/passwd")
   // Returned: "~/.ssh/../../../../etc/passwd" without validation
   // Could access: /etc/passwd or any system file
   ```

#### Root Cause

The function had a "convenience bypass" where tilde paths were returned as-is:

```rust
// VULNERABLE CODE (before fix)
let working_path = if path.starts_with("~/") {
    path.to_string()  // ❌ Bypasses ALL validation!
} else {
    sanitize_config_path_strict(path)?
};
```

#### Fix

Security checks now run BEFORE the tilde fast-path:

```rust
// SECURE CODE (after fix)
// Check for command injection BEFORE allowing tilde
if path.contains("$(") || path.contains('`') {
    return Err(Problem::validation("Directory contains command injection"));
}

// Check for excessive path traversal
let traversal_count = path.matches("../").count() + path.matches("..\\").count();
if traversal_count > 2 {
    return Err(Problem::validation("Excessive path traversal"));
}

// NOW safe to allow tilde (after validation)
let working_path = if path.starts_with("~/") {
    path.to_string()
} else {
    sanitize_config_path_strict(path)?
};
```

#### Impact

- **SSH credential paths**: Arbitrary command execution
- **SSH config paths**: System file access
- **SSH agent sockets**: Privilege escalation
- **Affected systems**: All systems using ssh.rs sanitization

#### Testing

Added comprehensive edge case tests:

- 24 new test categories
- 32 total tests (from 7)
- Validates the fix with real attack patterns

## Security Anti-Patterns

### Anti-Pattern #1: The Convenience Bypass

**Description**: Allowing "safe-looking" input to skip validation.

**Bad Example**:

```rust
fn validate_path(path: &str) -> Result<String> {
    // ❌ NEVER DO THIS
    if path.starts_with("~/") || path.starts_with("/opt/safe/") {
        return Ok(path.to_string());  // Bypasses all checks!
    }

    check_command_injection(path)?;
    check_path_traversal(path)?;
    Ok(path.to_string())
}
```

**Why It's Dangerous**:

- Attackers can craft input matching the "safe" pattern
- `~/$(malicious)` looks safe but contains command injection
- `/opt/safe/../../../etc/passwd` looks safe but escapes directory

**Good Example**:

```rust
fn validate_path(path: &str) -> Result<String> {
    // ✅ ALWAYS validate first
    check_command_injection(path)?;
    check_path_traversal(path)?;
    check_null_bytes(path)?;

    // THEN apply convenience logic
    if path.starts_with("~/") {
        return Ok(path.to_string());  // Safe after validation
    }

    normalize_path(path)
}
```

### Anti-Pattern #2: Incomplete Character Filtering

**Description**: Checking for some dangerous patterns but missing others.

**Bad Example**:

```rust
// ❌ Missing plain $ variable expansion
if input.contains("$(") || input.contains("${") {
    return Err(...);
}
// Allows: $VAR, which can still be dangerous
```

**Good Example**:

```rust
// ✅ Check all variations
if input.contains('$') || input.contains('`') || input.contains("$(") {
    return Err(...);
}
```

### Anti-Pattern #3: Silent Sanitization in Strict Mode

**Description**: Strict functions that sanitize instead of rejecting.

**Bad Example**:

```rust
fn sanitize_strict(input: &str) -> Result<String> {
    // ❌ Strict should ERROR, not sanitize
    Ok(input.replace('$', "").replace('`', ""))
}
```

**Good Example**:

```rust
fn sanitize_strict(input: &str) -> Result<String> {
    // ✅ Strict rejects dangerous input
    if input.contains('$') || input.contains('`') {
        return Err(Problem::validation("Dangerous characters"));
    }
    Ok(input.to_string())
}

fn sanitize_lenient(input: &str) -> String {
    // ✅ Lenient sanitizes
    input.replace('$', "").replace('`', "")
}
```

## Reporting Security Issues

If you discover a security vulnerability:

1. **DO NOT** open a public issue
1. Email security concerns to the maintainers
1. Include:
   - Affected function/file
   - Proof of concept
   - Severity assessment
   - Suggested fix (if any)

## References

- [OWASP Input Validation Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-78: OS Command Injection](https://cwe.mitre.org/data/definitions/78.html)
- [CWE-158: Improper Null Termination](https://cwe.mitre.org/data/definitions/158.html)

## Version History

- **2025-11-09**: Initial security guidelines document
- **2025-11-09**: CVE-INTERNAL-2025-001 documented and fixed
