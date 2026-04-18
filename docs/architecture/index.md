# Architecture Overview

This section covers the system design, patterns, and architectural decisions for octarine.

## Quick Links

- **Layer Architecture**: [`layer-architecture.md`](./layer-architecture.md) - **START HERE** - Four-layer dependency rules
- **Module Patterns**: [`module-patterns.md`](./module-patterns.md) - Three-layer pattern and builder pattern
- **System Design**: [`system-design.md`](./system-design.md) - Overall library architecture
- **Testing Patterns**: [`testing-patterns.md`](./testing-patterns.md) - Shared test infrastructure
- **Async + Observability Integration**: [`async-observability-integration.md`](./async-observability-integration.md) - Comprehensive async runtime instrumentation
- **Refactor Plan**: [`refactor-plan.md`](./refactor-plan.md) - Current status and roadmap
- **Full Plan**: [`../../src/refactor-plan.md`](../../src/refactor-plan.md) - Detailed refactor plan

## In This Section

### [Module Patterns](./module-patterns.md)

The three-layer pattern used throughout octarine:

- Core implementation layer (business logic)
- Builder pattern layer (configuration and composition)
- Simple function layer (convenience API with safe defaults)
- Dual function pattern (strict vs lenient versions)
- Complete implementation examples

### [System Design](./system-design.md)

Overall system architecture including:

- High-level architecture diagram
- Security and observe module interaction
- Data flow and processing pipelines
- Context propagation and event generation
- Integration patterns for web and CLI
- Performance and extensibility considerations

### [Refactor Plan](./refactor-plan.md)

Current refactoring status with:

- Module completion tracking
- Phase-based implementation strategy
- Links to detailed plan in source tree
- Contributing guidelines

## Key Architectural Principles

### 1. Separation of Concerns

- **Business Logic** - Isolated in core implementation files
- **API Design** - Handled by builders and shortcuts
- **Configuration** - Managed through builder pattern
- **Observability** - Automatic via observe module

### 2. Safety by Default

- **Input Validation** - All input validated before use
- **Safe Defaults** - Lenient functions return safe values
- **Error Handling** - Problems generate events automatically
- **Zero Trust** - Never trust any input source

### 3. Progressive Disclosure

- **Simple Cases** - Use simple functions
- **Complex Cases** - Use builder pattern
- **Power Users** - Access internals via pub(crate)
- **Extensibility** - Plugin points for custom logic

### 4. Consistent Patterns

- **Three Layers** - Same structure in every module
- **Nine Contexts** - All input organized consistently
- **Dual Functions** - Strict and lenient versions
- **Event Generation** - Automatic for all operations

## Architecture Decisions

### Why Three Layers?

- Separates concerns cleanly
- Provides multiple API levels
- Easy to test each layer
- Maintains flexibility

### Why Builder Pattern?

- Composable operations
- Type-safe configuration
- Prevents invalid states
- Self-documenting API

### Why Nine Security Contexts?

- Based on OWASP categories
- Covers all input types
- Consistent organization
- Easy to navigate

### Why Automatic Events?

- Can't forget to log
- Consistent audit trail
- Compliance ready
- Performance optimized

## Module Organization

```text
crates/octarine/src/
├── primitives/        # Layer 1 (pub(crate)): pure functions, no observe deps
│   ├── data/          # FORMAT concern (paths, network, text, ...)
│   ├── security/      # THREATS concern (commands, formats, network, paths, queries)
│   ├── identifiers/   # CLASSIFICATION concern (personal, financial, network, ...)
│   ├── crypto/        # Crypto primitives
│   ├── io/            # File-operation primitives
│   ├── runtime/       # Async utility primitives
│   └── types/         # Problem, Result, shared types
│
├── observe/           # Layer 2 (pub): observability — depends only on primitives
│   ├── audit/         # Audit-trail generation
│   ├── compliance/    # SOC2 / HIPAA / GDPR / PCI-DSS mapping
│   ├── context/       # Automatic WHO/WHAT/WHEN/WHERE capture
│   ├── event/         # Event generation
│   ├── metrics/       # Metrics collection
│   ├── pii/           # PII detection and redaction
│   ├── problem/       # Error handling with audit trails
│   ├── tracing/       # Distributed tracing
│   └── writers/       # Console, file, SQLite, PostgreSQL
│
├── data/              # Layer 3 (pub): primitives + observe instrumentation
├── security/          # Layer 3 (pub)
├── identifiers/       # Layer 3 (pub)
├── runtime/           # Layer 3 (pub)
├── crypto/            # Layer 3 (pub)
├── io/                # Layer 3 (pub)
├── auth/              # Layer 3 (pub)
├── http/              # Layer 3 (pub)
└── testing/           # Test infrastructure (feature = "testing")

docs/
├── architecture/      # This section
├── api/               # API documentation
├── security/          # Security patterns
└── operations/        # Deployment and ops
```

## Related Sections

- [Security Patterns](../security/patterns/) - Security implementation details
- [API Design](../api/) - Public API principles and error handling
- [Operations](../operations/) - Audit logging and monitoring
- [Development](../development/) - Development workflow and testing

## External References

- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/) - Rust community standards
- [Design Patterns](https://rust-unofficial.github.io/patterns/) - Rust design patterns
- [OWASP Guidelines](https://owasp.org/) - Security best practices
