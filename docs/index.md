# Rust-Core Documentation

Welcome to the octarine documentation. This library provides security primitives and observability tools for Rust applications.

## Quick Navigation

### 🏗️ [Architecture](./architecture/)

System design, patterns, and refactoring plans

- Module patterns (three-layer, builder)
- System architecture
- Active refactor plan

### 💻 [Development](./development/)

Getting started, workflow, testing, and debugging

- Environment setup
- Git workflow
- Testing strategy
- Benchmarking guide

### 📚 [API Design](./api/)

API principles, error handling, and usage examples

- Design principles
- Error handling patterns
- Async patterns
- Code examples

### 🔒 [Security](./security/)

Security patterns, OWASP compliance, and threat models

- OWASP Top 10 implementation
- Security patterns catalog
- Threat modeling
- Security checklist

### 🚀 [Operations](./operations/)

Audit logging and operational observability

- Audit logging
- Compliance trails

## Quick Start

```bash
# Clone and setup
git clone <repository>
cd octarine

# Build and test
just build
just test

# Run security checks
just deps-audit

# See all commands
just --list
```

## Project Links

- **Main README**: [`../README.md`](../README.md)
- **Security Policy**: [`../SECURITY.md`](../SECURITY.md)
- **Changelog**: [`../CHANGELOG.md`](../CHANGELOG.md)
- **Refactor Status**: [`./architecture/refactor-plan.md`](./architecture/refactor-plan.md)

## For AI Assistants

When working with this codebase, start with:

1. [`../CLAUDE.md`](../CLAUDE.md) - Project-specific AI instructions
1. [`./architecture/layer-architecture.md`](./architecture/layer-architecture.md) - Layer boundaries and dependency rules
1. [`./structure.md`](./structure.md) - Documentation organization
1. Relevant section index for the task at hand

## Documentation Standards

All documentation follows these principles:

- **Kebab-case** filenames (e.g., `error-handling.md`)
- **Index files** for navigation in each folder
- **Progressive disclosure** - overview → details → implementation
- **Cross-linking** between related topics
- **Practical examples** with working code

## Finding Information

Each section has an `index.md` that provides:

1. Overview of the section
1. Quick links to important documents
1. Brief descriptions of each document
1. Related sections and external resources

Start with the section index, then drill down to specific topics as needed.

## Contributing to Docs

See [`../CLAUDE.md`](../CLAUDE.md) for contributor and AI-assistant workflow,
and [`./architecture/testing-patterns.md`](./architecture/testing-patterns.md)
for testing conventions.
- Review process
