# Error Handling Guide

## Core Principles

1. **Libraries return `Result`, applications handle errors**
1. **Fail fast at module boundaries, recover at application level**
1. **Rich error types with context, not string errors**
1. **Always log security-relevant errors**

## Result vs Option

### Use `Result<T, Problem>` when

- Operation can fail with meaningful error
- Caller needs to know why it failed
- Security events need logging
- Multiple failure modes exist

```rust
pub fn sanitize_path_strict(path: &str) -> Result<String, Problem> {
    if path.contains('\0') {
        Event::security("null_byte_attempt", path);
        return Err(Problem::validation("Path contains null bytes"));
    }
    Ok(sanitize_internal(path))
}
```

### Use `Option<T>` when

- Absence is a normal case, not an error
- Looking up values that may not exist
- No error context needed

```rust
pub fn find_config_value(key: &str) -> Option<String> {
    CONFIG.get(key).cloned()
}
```

### Never panic in library code

```rust
// BAD - panics in library
let value = map.get(key).unwrap();

// GOOD - return Result
let value = map.get(key)
    .ok_or_else(|| Problem::not_found("Key not found"))?;
```

## Error Propagation

### Use `?` operator liberally

```rust
pub fn process_file(path: &str) -> Result<String> {
    let safe_path = sanitize_path_strict(path)?;  // Propagate error
    let content = read_file(&safe_path)?;          // Propagate error
    let processed = transform_content(&content)?;   // Propagate error
    Ok(processed)
}
```

### Add context when propagating

```rust
pub fn load_config(path: &str) -> Result<Config> {
    read_file(path)
        .map_err(|e| Problem::config(format!("Failed to load config from {}: {}", path, e)))?
        .parse()
        .map_err(|e| Problem::parse(format!("Invalid config format: {}", e)))
}
```

## Dual Function Pattern

Every security operation has strict and lenient versions:

```rust
// Strict - returns Result, logs errors
pub fn operation_strict(input: &str) -> Result<String> {
    validate_input(input)?;
    let result = process(input)?;
    Event::success("operation", "Completed");
    Ok(result)
}

// Lenient - always succeeds with fallback
pub fn operation(input: &str) -> String {
    operation_strict(input).unwrap_or_else(|e| {
        Event::warn("operation", format!("Using fallback: {}", e));
        "safe_default".to_string()
    })
}
```

## Problem Types (from observe module)

Use specific Problem constructors for clarity:

```rust
Problem::validation("Invalid email format")     // Input validation failed
Problem::sanitization("Cannot sanitize input")  // Cannot make input safe
Problem::conversion("Cannot convert format")    // Type conversion failed
Problem::permission_denied("Unauthorized")      // Access control
Problem::not_found("Resource does not exist")   // Missing resource
Problem::config("Missing required setting")     // Configuration error
Problem::timeout("Operation timed out")         // Timeout
Problem::operation_failed("External API error") // Generic failure
```

## Recovery Strategies

### For lenient functions

1. **Safe defaults** - Return a safe, usable value
1. **Partial success** - Process what you can
1. **Graceful degradation** - Reduced functionality
1. **Retry with backoff** - For transient failures

```rust
pub fn read_config_lenient(path: &str) -> Config {
    read_config_strict(path).unwrap_or_else(|e| {
        Event::warn("config", format!("Using default config: {}", e));
        Config::default()  // Safe default
    })
}
```

## Security Error Handling

### Always log security errors

```rust
if input.contains("../") {
    Event::security("path_traversal", format!("Attempt from: {}", source));
    return Err(Problem::validation("Invalid path"));
}
```

### Never expose internal details

```rust
// BAD - exposes internal path
Err(format!("Failed to read /etc/app/secret.key: {}", e))

// GOOD - generic message
Err(Problem::config("Configuration error"))
```

## Testing Error Paths

Always test both success and failure:

```rust
#[test]
fn test_validates_input() {
    // Success case
    assert!(validate_email("user@example.com").is_ok());

    // Failure cases
    assert!(validate_email("not-an-email").is_err());
    assert!(validate_email("").is_err());
    assert!(validate_email("@example.com").is_err());
}
```

## See Also

- [`../../crates/octarine/src/observe/problem/`](../../crates/octarine/src/observe/problem/) - Problem type implementation
- [`security-patterns.md`](./security-patterns.md) - Security-specific error handling
- [`testing-strategy.md`](./testing-strategy.md) - Testing error conditions
