# System Design and Architecture

## Overview

octarine is a foundational security and observability library for Rust applications. It provides two main modules that work together to create secure, auditable, and maintainable applications.

## High-Level Architecture

```text
┌─────────────────────────────────────────────────────────┐
│                     Application Code                      │
└─────────────┬───────────────────────┬───────────────────┘
              │                       │
              ▼                       ▼
┌─────────────────────────┐ ┌─────────────────────────────┐
│    Security Module      │ │      Observe Module         │
│                         │ │                             │
│ • Input Validation      │ │ • Event System              │
│ • Input Sanitization    │ │ • Problem Types             │
│ • Input Conversion      │ │ • Context Propagation       │
│ • Access Control        │ │ • Writers (Console/File/DB) │
│ • File Security         │ │                             │
│ • Process Security      │ └─────────────────────────────┘
│ • Secret Management     │            ▲
│ • Pattern Detection     │            │
└─────────────────────────┘            │
              │                         │
              └─────────────────────────┘
                    Generates Events
```

## Core Modules

### 1. Security Module (`/src/security/`)

Provides comprehensive security primitives for safe input handling and system operations.

#### Input Security (`/src/security/data/`)

The input module organizes all input handling into nine security contexts based on OWASP categories:

1. **paths** - File system paths and directories
1. **network** - URLs, IPs, ports, protocols
1. **authentication** - Usernames, passwords, tokens, API keys
1. **formats** - JSON, XML, CSV, dates, structured data
1. **text** - Plain text, unicode, encoding
1. **commands** - Shell commands, OS execution
1. **queries** - SQL, NoSQL, GraphQL, LDAP
1. **crypto** - Keys, certificates, algorithms
1. **identifiers** - Email, phone, UUIDs, PII data

Each context has three operations:

- **Validation** - Check if input meets requirements
- **Sanitization** - Make input safe for use
- **Conversion** - Transform between formats

#### Other Security Components

- **access_control/** - Rate limiting and permissions
- **file_security/** - Secure file operations
- **process/** - Safe command execution
- **secrets/** - Secret management and encryption
- **detection/** - Pattern detection (secrets, PII)

### 2. Observe Module (`/src/observe/`)

Provides unified observability with automatic context capture and event generation.

#### Core Components

- **context/** - Automatic capture of tenant, user, environment
- **event/** - Business, security, and system event generation
- **problem/** - Error handling with automatic event creation
- **writers/** - Output destinations (console, file, database)

#### Event Flow

```text
Application Action
        │
        ▼
Problem or Event Created
        │
        ▼
Context Automatically Captured
        │
        ▼
Event Enriched with Metadata
        │
        ▼
Event Sent to Writers
        │
        ├──► Console (Development)
        ├──► File (Production)
        └──► Database (Compliance)
```

## Key Design Patterns

### Three-Layer Pattern

Every module follows this structure:

1. **Core Implementation** - Business logic (private)
1. **Builder Pattern** - Configuration and composition
1. **Simple Functions** - Convenience API with defaults

See [Module Patterns](./module-patterns.md) for details.

### Dual Function Pattern

Functions provide both strict and lenient versions:

```rust
// Strict - returns Result
pub fn validate_email_strict(email: &str) -> Result<String, Problem>

// Lenient - returns safe default
pub fn validate_email(email: &str) -> String
```

### Automatic Event Generation

All security-relevant operations automatically generate events:

```rust
// This automatically generates a security event if traversal detected
let safe_path = sanitize_path(user_input);

// Problems automatically generate events
let problem = Problem::validation("Invalid input");
```

## Data Flow Architecture

### Input Processing Pipeline

```text
Untrusted Input
      │
      ▼
┌──────────────┐
│  Detection   │ ← Identify input type
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Validation  │ ← Check constraints
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Sanitization │ ← Make safe
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Conversion  │ ← Transform format
└──────┬───────┘
       │
       ▼
Trusted Output → Application Use
```

### Context Propagation

Context flows through the application automatically:

```text
Request Start
      │
      ▼
Set Context (tenant, user, correlation_id)
      │
      ▼
All Operations Within Request
      │
      ├──► Events include context
      ├──► Problems include context
      └──► Audit logs include context
```

## Security Architecture

### Defense in Depth

Multiple independent security layers:

1. **Perimeter** - Rate limiting, authentication
1. **Input** - Validation and sanitization
1. **Processing** - Authorization, business rules
1. **Output** - Encoding, filtering
1. **Audit** - Comprehensive logging

### Zero Trust Principles

- **Never trust input** - All input is validated
- **Assume breach** - Design for compromised components
- **Verify continuously** - Re-validate cached data
- **Minimal privilege** - Least access necessary
- **Audit everything** - Complete audit trail

## Performance Considerations

### Optimization Strategies

1. **Lazy Evaluation** - Compute only when needed
1. **Short-circuit** - Fail fast on first error
1. **Caching** - Cache validated results (with TTL)
1. **Async Events** - Non-blocking event emission
1. **Batch Operations** - Group similar operations

### Resource Management

- **Memory** - Bounded buffers and queues
- **CPU** - Configurable worker threads
- **I/O** - Async operations where appropriate
- **Network** - Connection pooling for writers

## Extensibility

### Plugin Points

1. **Custom Validators** - Add domain-specific validation
1. **Custom Sanitizers** - Add specialized sanitization
1. **Custom Writers** - Send events to new destinations
1. **Custom Problem Types** - Domain-specific errors

### Extension Example

```rust
// Custom validator
impl Validator for MyCustomValidator {
    fn validate(&self, input: &str) -> Result<(), Problem> {
        // Custom validation logic
    }
}

// Register with builder
let sanitizer = InputSanitizer::builder()
    .add_validator(MyCustomValidator::new())
    .build();
```

## Integration Patterns

### Web Framework Integration

```rust
// Actix-web example
async fn handler(data: web::Data<AppState>) -> Result<HttpResponse> {
    // Context set by middleware
    Context::set()
        .tenant_id(&data.tenant)
        .user_id(&data.user)
        .apply();

    // Use security module
    let safe_input = sanitize_input(&data.input)?;

    // Process with automatic event generation
    let result = process(safe_input)?;

    Ok(HttpResponse::Ok().json(result))
}
```

### CLI Integration

```rust
// CLI application
fn main() -> Result<()> {
    // Initialize observe module
    let observe = ObserveBuilder::new()
        .add_writer(ConsoleWriter::new())
        .build();

    // Set context for CLI
    Context::set()
        .environment("cli")
        .apply();

    // Use security for args
    let args = sanitize_args(std::env::args())?;

    // Run with observability
    run_command(args)
}
```

## Deployment Considerations

### Environment-Specific Behavior

- **Development** - Verbose logging, detailed errors
- **Staging** - Production-like with extra metrics
- **Production** - Minimal logging, generic errors

### Configuration

```rust
// Via builder pattern
let observe = ObserveBuilder::new()
    .environment(Environment::from_env())
    .min_severity(EventSeverity::Warning)
    .add_writer(appropriate_writer())
    .build();
```

## Future Architecture

### Planned Enhancements

1. **WASM Support** - Run validators in sandbox
1. **Distributed Tracing** - OpenTelemetry integration
1. **ML Detection** - Anomaly detection via ML
1. **Policy Engine** - Declarative security policies

### Stability Guarantees

- Public API follows semantic versioning
- Internal structure may change between versions
- Migration guides for breaking changes
- Deprecation warnings before removal

## Related Documentation

- [Module Patterns](./module-patterns.md) - Three-layer architecture
- [Input Architecture](../security/patterns/input-architecture.md) - Security design
- [Event System](../operations/audit-logging.md) - Observability design
- [Refactor Plan](./refactor-plan.md) - Current refactor status
