# Error and Problem Architecture

## Overview

The octarine library uses a unified `Problem` type for error handling that automatically captures context, generates events, and maintains audit trails. This architecture separates the error (what went wrong) from the context (who/where/when) for better observability and compliance.

## Core Principles

1. **Separation of Concerns**: Errors describe what went wrong; context captures who/where/when
1. **Automatic Event Generation**: Every error automatically creates an audit event
1. **OWASP Compliance**: External errors are generic; internal logs have full details
1. **Progressive Disclosure**: More detail available as you drill deeper

## The Problem Type

The `Problem` type in the observe module is the primary error type:

```rust
use octarine::observe::problem::{Problem, ProblemSeverity};

// Simple creation with automatic context
return Err(Problem::validation("Invalid email format"));
return Err(Problem::not_found("user", "12345"));
return Err(Problem::permission_denied("admin access required"));

// With severity
return Err(Problem::system(
    "Database connection failed",
    ProblemSeverity::Critical
));
```

## Three-Layer Architecture

### Layer 1: Problem Creation (Developer-facing)

```rust
// Simple, clean API for developers
impl Problem {
    pub fn validation(msg: impl Into<String>) -> Self {
        Self::new(ProblemKind::Validation, msg)
    }

    pub fn not_found(resource: &str, id: &str) -> Self {
        Self::new(
            ProblemKind::NotFound,
            format!("{} {} not found", resource, id)
        )
    }

    pub fn security(msg: impl Into<String>) -> Self {
        Self::new(ProblemKind::Security, msg)
            .with_severity(ProblemSeverity::Warning)
    }
}
```

### Layer 2: Automatic Context Capture

```rust
// Context automatically captured when Problem is created
pub struct ProblemContext {
    // WHERE - Location in code
    module_path: String,     // via module_path!()
    file: String,           // via file!()
    line: u32,              // via line!()

    // WHEN - Temporal context
    timestamp: DateTime<Utc>,
    correlation_id: Uuid,

    // WHO - If available from observe::context
    tenant_id: Option<String>,
    user_id: Option<String>,
    environment: Option<String>,
}
```

### Layer 3: Event Generation

```rust
// Every Problem automatically generates an event
impl Problem {
    pub fn new(kind: ProblemKind, msg: impl Into<String>) -> Self {
        let problem = Self {
            kind,
            message: msg.into(),
            context: ProblemContext::capture(),
            severity: kind.default_severity(),
        };

        // Automatically generate event
        Event::problem(&problem).emit();

        problem
    }
}
```

## Problem Categories

Problems are categorized for better handling and reporting:

```rust
pub enum ProblemKind {
    // Input problems
    Validation,      // Invalid input format
    Sanitization,    // Input cannot be sanitized
    Conversion,      // Type conversion failed

    // Resource problems
    NotFound,        // Resource doesn't exist
    AlreadyExists,   // Duplicate resource
    Unavailable,     // Temporary unavailability

    // Security problems
    Authentication,  // Auth failed
    Authorization,   // Permission denied
    Security,        // Security policy violation
    RateLimit,       // Too many requests

    // System problems
    System,          // System error
    Configuration,   // Config error
    Integration,     // External service error
}
```

## Dual Function Pattern

Functions provide both strict (Result) and lenient (default) versions:

```rust
// Strict - returns Result
pub fn validate_email_strict(email: &str) -> Result<String, Problem> {
    if !email.contains('@') {
        return Err(Problem::validation("Invalid email format"));
    }
    Ok(email.to_string())
}

// Lenient - returns safe default
pub fn validate_email(email: &str) -> String {
    validate_email_strict(email)
        .unwrap_or_else(|_| "invalid@example.com".to_string())
}
```

## External vs Internal Messages

Problems provide different views for security:

```rust
impl Problem {
    /// Safe message for external consumers
    pub fn external_message(&self) -> String {
        match self.kind {
            ProblemKind::Validation => "Input validation failed",
            ProblemKind::Security => "Request denied",
            ProblemKind::NotFound => "Resource not found",
            _ => "An error occurred"
        }.to_string()
    }

    /// Full details for internal logging
    pub fn internal_details(&self) -> String {
        format!("{:?}: {} at {}:{}",
            self.kind,
            self.message,
            self.context.file,
            self.context.line
        )
    }
}
```

## Integration with Events

Problems automatically generate events for audit trails:

```rust
// When a problem occurs
let problem = Problem::security("Suspicious login attempt");

// This automatically emits an event:
// Event::Security {
//     action: "problem_reported",
//     severity: Warning,
//     details: problem.to_audit_entry()
// }
```

## Usage Examples

### In Security Module

```rust
use octarine::observe::problem::{Problem, ProblemSeverity};

pub fn sanitize_path_strict(path: &str) -> Result<String, Problem> {
    if path.contains("../") {
        return Err(Problem::security("Path traversal detected")
            .with_severity(ProblemSeverity::Warning));
    }
    Ok(path.to_string())
}
```

### In Application Code

```rust
// Problems flow naturally through the application
pub async fn create_user(data: UserData) -> Result<User, Problem> {
    // Validation
    let email = validate_email_strict(&data.email)?;

    // Check uniqueness
    if user_exists(&email).await? {
        return Err(Problem::already_exists("user", &email));
    }

    // Create user
    let user = User::create(data).await
        .map_err(|e| Problem::system(e.to_string()))?;

    Ok(user)
}
```

### At API Boundaries

```rust
// Convert Problem to HTTP response
impl From<Problem> for HttpResponse {
    fn from(problem: Problem) -> Self {
        // Log full details internally
        log::error!("{}", problem.internal_details());

        // Return safe error to client
        match problem.kind {
            ProblemKind::NotFound => {
                HttpResponse::NotFound()
                    .json(json!({ "error": problem.external_message() }))
            }
            ProblemKind::Validation => {
                HttpResponse::BadRequest()
                    .json(json!({ "error": problem.external_message() }))
            }
            _ => {
                HttpResponse::InternalServerError()
                    .json(json!({ "error": "Internal server error" }))
            }
        }
    }
}
```

## Performance Considerations

- Context capture is lazy - only on error creation
- Events are emitted asynchronously
- No performance impact on success path
- Minimal overhead on error path

## Compliance Features

| Requirement | Implementation |
|------------|---------------|
| **SOC2** - Audit Trail | Automatic event generation |
| **SOC2** - Context | Who/what/when/where captured |
| **HIPAA** - Minimum Necessary | External messages are generic |
| **OWASP** - No Info Leakage | Internal details never exposed |
| **GDPR** - Data Minimization | Configurable retention |

## Best Practices

1. **Use specific problem types** - `validation()` not `generic()`
1. **Include context** - What failed, not just that it failed
1. **Set appropriate severity** - Critical for data loss, Warning for validation
1. **Let problems bubble up** - Use `?` operator for clean error propagation
1. **Convert at boundaries** - Transform to appropriate external format

## Related Documentation

- [Error Handling Patterns](./error-handling.md)
- [Event System](../operations/audit-logging.md)
- [Observability Guide](../observe/integration.md)
