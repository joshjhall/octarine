# Development Guide

Everything you need to develop, test, and contribute to octarine.

## Quick Start

1. **Setup**: [`getting-started.md`](./getting-started.md) - Environment setup
1. **Workflow**: [`workflow.md`](./workflow.md) - Git workflow and branching
1. **Testing**: [`testing.md`](./testing.md) - Running and writing tests
1. **Build**: `make build` or `cargo build`

## In This Section

### [Getting Started](./getting-started.md)

- Development environment setup
- Required tools installation
- First build and test run
- IDE configuration

### [Development Workflow](./workflow.md)

- Git branching strategy (main/develop)
- Commit message conventions
- Pull request process
- Code review guidelines

### [Testing Strategy](./testing.md)

- Unit tests (in-file)
- Integration tests (/tests)
- Benchmark tests (/benches)
- Security test cases
- Coverage requirements

### [Benchmarking Guide](./benchmarking.md)

- Setting up criterion
- Writing benchmarks
- Interpreting results
- Performance regression detection

### [Debugging Tips](./debugging.md)

- Common issues and solutions
- Debugging tools
- Logging and tracing
- Performance profiling

## Common Commands

```bash
# Development cycle
just default      # Check, clippy, and test (default recipe)
just preflight    # Full pre-push validation: fmt-check, clippy, tests

# Testing
just test                        # Run all workspace tests
just test-octarine               # Octarine crate only
just test-mod "module::path"     # Unit tests by module path
just test-filter PATTERN         # Filter by test name
just test-verbose                # Tests with output visible
just test-with-fixtures          # With testing feature enabled
just test-perf                   # Performance tests (ignored by default)

# Code quality
just fmt                         # Auto-format code
just fmt-check                   # Check formatting without fixing
just clippy                      # Run clippy

# Dependencies
just deps-check                  # Full dependency health check
just deps-audit                  # Security vulnerability audit
just deps-outdated               # Show outdated dependencies
```

## Development Principles

1. **Test First** - Write tests before implementation
1. **Security by Default** - Secure patterns from the start
1. **Document as You Go** - Update docs with code
1. **Refactor Continuously** - Keep code clean
1. **Review Everything** - All code gets reviewed

## Related Sections

- [Architecture](../architecture/) - System design patterns
- [API Design](../api/) - Public API guidelines
- [Contributing](../contributing/) - Contribution process

## Tools & Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Cargo Documentation](https://doc.rust-lang.org/cargo/)
- [Clippy Lints](https://rust-lang.github.io/rust-clippy/)
- [Rustfmt](https://github.com/rust-lang/rustfmt)
