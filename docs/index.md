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

CI/CD, versioning, deployment, and monitoring

- CI/CD pipeline
- Semantic versioning
- Deployment guide
- Monitoring setup

### 🤝 [Contributing](./contributing/)

Contribution guidelines, code style, and review process

- How to contribute
- Code style guide
- Documentation standards
- Review process

### 📖 [Reference](./reference/)

Quick references, commands, and troubleshooting

- Common commands
- Troubleshooting guide
- Glossary of terms

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
- **Refactor Plan**: [`../src/refactor-plan.md`](../src/refactor-plan.md)

## For AI Assistants

When working with this codebase, start with:

1. [`../CLAUDE.md`](../CLAUDE.md) - Project-specific AI instructions
1. [`../src/refactor-plan.md`](../src/refactor-plan.md) - Current refactor plan
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

See [`contributing/documentation.md`](./contributing/documentation.md) for guidelines on:

- Writing style
- File organization
- Cross-referencing
- Code examples
- Review process
