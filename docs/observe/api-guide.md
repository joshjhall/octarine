# Observe Module API Guide

This guide explains the two complementary APIs for observability in octarine and when to use each.

## Overview

The observe module provides **two APIs** for logging and error handling:

1. **Event API** - Simple, auto-context (1 argument)
1. **Shortcuts API** - Contextual, operation-aware (2 arguments)

Both APIs are valid and serve different purposes. Understanding when to use each will make your code cleaner and more maintainable.

______________________________________________________________________

## Event API (Simple, Auto-Context)

**Location**: `observe::event`
**Import**: `use crate::observe::event::{debug, info, warn, error};`
**Signature**: Single argument - just the message

### Event API: When to Use

✅ **Library internals** - runtime, common modules, internal utilities
✅ **Simple logging** - Quick status updates, debugging
✅ **When operation context is obvious** - The caller/module name is sufficient
✅ **High-frequency logging** - Minimal overhead, no extra string allocations

### Event API: Examples

```rust
use crate::observe::event::{debug, info, warn, error};

// Simple status updates
debug("Starting retry operation");
info("Connection established");
warn("Rate limit approaching");
error("Failed to connect to database");

// With formatted messages
info(format!("Processed {} items in {}ms", count, elapsed));
debug(format!("Cache hit rate: {:.2}%", hit_rate));
```

### How It Works

```rust
// Internal implementation (you don't write this, just understand it)
pub fn debug(message: impl Into<String>) {
    EventBuilder::new(message)
        .with_context(context_shortcuts::full())  // ← Auto-captures context!
        .debug();
}
```

**Context captured automatically**:

- Timestamp
- Thread/task ID
- Environment (dev/staging/prod)
- Tenant ID (if set in thread-local)
- User ID (if set in thread-local)

______________________________________________________________________

## Shortcuts API (Contextual, Operation-Aware)

**Location**: `observe` (root)
**Import**: `use crate::observe;`
**Signature**: Two arguments - operation name + message

### Shortcuts API: When to Use

✅ **Application/business logic** - Domain operations, workflows
✅ **Cross-cutting operations** - Operations that span multiple modules
✅ **When operation context is NOT obvious** - Need explicit operation tracking
✅ **Error handling** - Returns `Problem` types for propagation
✅ **Audit logging** - Security-sensitive operations needing explicit context

### Shortcuts API: Examples

#### Logging with Operation Context

```rust
use crate::observe;

// Explicit operation context
observe::debug("user_authentication", "Validating credentials");
observe::info("payment_processing", format!("Processing payment: ${}", amount));
observe::warn("rate_limiter", format!("User {} approaching limit", user_id));
```

#### Error Handling (Returns Problem)

```rust
use crate::observe;

// Returns observe::Problem for error propagation
fn validate_input(data: &str) -> observe::Result<String> {
    if data.is_empty() {
        return Err(observe::fail_validation("input", "Cannot be empty"));
    }

    if data.len() > 1000 {
        return Err(observe::fail("input_validation", "Input exceeds maximum length"));
    }

    Ok(data.to_string())
}

// Security-sensitive operations
fn check_permission(user: &str, resource: &str) -> observe::Result<()> {
    if !has_permission(user, resource) {
        return Err(observe::fail_permission("access_control", user, resource));
    }
    Ok(())
}
```

### Available Error Helpers

```rust
// Generic failure (logs error + returns Problem)
observe::fail("operation", "message") -> Problem

// Security failure (creates security audit event)
observe::fail_security("operation", "message") -> Problem

// Permission denied (includes user + resource context)
observe::fail_permission("operation", user, resource) -> Problem

// Validation failure (for input validation)
observe::fail_validation("field_name", "error message") -> Problem

// Unimplemented feature marker
observe::todo("feature_name") -> Problem
```

______________________________________________________________________

## Comparison Table

| Feature | Event API | Shortcuts API |
|---------|-----------|---------------|
| **Import** | `observe::event::debug` | `observe::debug` |
| **Arguments** | 1 (message only) | 2 (operation + message) |
| **Context** | Auto-captured | Operation explicit |
| **Returns** | `()` (logs only) | `()` for logs, `Problem` for errors |
| **Use Case** | Internal logging | Application logic |
| **Overhead** | Minimal | Slightly higher |
| **Best For** | Libraries, utilities | Business logic, APIs |

______________________________________________________________________

## Integration Patterns

### Pattern 1: Library Module (runtime example)

```rust
// src/runtime/retry.rs
use crate::observe::{self as observe, Result};
use crate::observe::event::{debug, info, warn};  // ← Event API (1-arg)

impl Retry {
    pub async fn execute<F, Fut, T>(&self, mut f: F) -> Result<T> {
        // Use event API for internal logging
        debug("Starting retry operation");

        for attempt in 0..max_attempts {
            match f().await {
                Ok(result) => {
                    info(format!("Retry succeeded on attempt {}", attempt + 1));
                    return Ok(result);
                }
                Err(err) => {
                    warn(format!("Attempt {} failed: {}", attempt + 1, err));
                }
            }
        }

        // Use shortcuts API for error (returns Problem)
        Err(observe::fail("retry", "All attempts exhausted"))
    }
}
```

### Pattern 2: Application/Business Logic

```rust
// src/application/payment.rs
use crate::observe::{self as observe, Result};

pub fn process_payment(user_id: &str, amount: f64) -> Result<PaymentId> {
    // Use shortcuts API for business operations
    observe::info("payment_processing", format!("Processing ${} for user {}", amount, user_id));

    // Validate
    if amount <= 0.0 {
        return Err(observe::fail_validation("amount", "Must be positive"));
    }

    // Check permissions
    if !has_permission(user_id, "make_payment") {
        return Err(observe::fail_permission("payment", user_id, "make_payment"));
    }

    // Process...
    let payment_id = charge_card(amount)?;

    observe::success("payment_processing", format!("Payment {} completed", payment_id));
    Ok(payment_id)
}
```

### Pattern 3: Security Module

```rust
// src/security/authentication.rs
use crate::observe::{self as observe, Result};

pub fn authenticate(username: &str, password: &str) -> Result<Session> {
    // Security operations use shortcuts API for audit logging
    observe::info("authentication", format!("Login attempt: {}", username));

    if !validate_credentials(username, password) {
        // Security failure - creates security audit event
        return Err(observe::fail_security(
            "authentication",
            format!("Invalid credentials for user: {}", username)
        ));
    }

    let session = create_session(username)?;

    // Log successful authentication
    observe::auth_success(username);

    Ok(session)
}
```

______________________________________________________________________

## Quick Reference

### Event API (1-arg, auto-context)

```rust
use crate::observe::event::{debug, info, warn, error};

debug("message");           // Debug level
info("message");            // Info level
warn("message");            // Warning level
error("message");           // Error level (logs only, no Problem)
trace("message");           // Trace level (minimal context)
success("message");         // Success event
```

### Shortcuts API (2-arg, explicit context)

```rust
use crate::observe;

// Logging
observe::debug("operation", "message");
observe::info("operation", "message");
observe::warn("operation", "message");
observe::error("operation", "message");
observe::success("operation", "message");

// Error handling (returns Problem)
observe::fail("operation", "message")
observe::fail_security("operation", "message")
observe::fail_permission("operation", user, resource)
observe::fail_validation("field", "message")
observe::todo("feature")
```

### Special Helpers

```rust
// Authentication
observe::auth_success(username);
observe::auth_failure(username, reason);

// Validation
observe::validation_success("message");

// Development
observe::debug_here("message");  // Quick debug, minimal context
```

______________________________________________________________________

## Best Practices

### ✅ DO

- Use **Event API** for library internals (runtime, common modules)
- Use **Shortcuts API** for application logic and error handling
- Let context be captured automatically when possible
- Use formatted messages for dynamic content: `format!("Processed {} items", count)`
- Return `observe::Result<T>` from functions that can fail
- Use specific error helpers: `fail_validation`, `fail_security`, `fail_permission`

### ❌ DON'T

- Mix both APIs in the same file (pick one pattern per module)
- Use `observe::fail()` and ignore the returned `Problem`
- Create custom error enums (use `observe::Problem` instead)
- Add operation context when it's redundant (module name is enough)
- Log sensitive data (passwords, tokens, secrets) - use redaction

______________________________________________________________________

## Migration Guide

### From Custom Errors to observe::Problem

**Before**:

```rust
#[derive(Debug, Error)]
pub enum MyError {
    #[error("Connection failed")]
    ConnectionFailed,
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

pub fn my_function() -> Result<(), MyError> {
    Err(MyError::ConnectionFailed)
}
```

**After**:

```rust
use crate::observe::{self as observe, Result};

pub fn my_function() -> Result<()> {
    Err(observe::fail("my_function", "Connection failed"))
}
```

### From Manual Logging to observe

**Before**:

```rust
println!("Processing item {}", id);
eprintln!("ERROR: Failed to process: {}", error);
```

**After**:

```rust
use crate::observe::event::{info, error};

info(format!("Processing item {}", id));
error(format!("Failed to process: {}", error));
```

______________________________________________________________________

## Architecture Notes

### Why Two APIs?

1. **Event API** - Optimized for simplicity and performance

   - Zero allocation for operation context (it's automatic)
   - Clean, minimal syntax for frequent logging
   - Perfect for library code where context is implicit

1. **Shortcuts API** - Optimized for explicitness and traceability

   - Explicit operation naming for audit logs
   - Returns `Problem` for error propagation
   - Perfect for business logic where operations are tracked

### Context Capture

Both APIs capture the same context, but differently:

- **Event API**: Uses `context_shortcuts::full()` automatically
- **Shortcuts API**: Uses operation name + `context_shortcuts::full()`

Result: Both have complete context, but shortcuts API adds explicit operation tracking.

______________________________________________________________________

## Related Documentation

- **Problem Types**: See `docs/observe/problem-types.md`
- **Event Builder**: See `docs/observe/event-builder.md`
- **Context Capture**: See `docs/observe/context-capture.md`
- **Security Integration**: See `docs/security/observability-integration.md`

______________________________________________________________________

## Summary

- **Event API** (`observe::event`) - Simple 1-arg logging with auto-context
- **Shortcuts API** (`observe`) - Contextual 2-arg logging + error handling
- Choose based on use case: library internals vs application logic
- Both APIs provide complete observability with full context capture
- Use `observe::Result<T>` as the standard error type throughout octarine
