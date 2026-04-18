# Development Guide

Guidance for developing, testing, and contributing to octarine.

## Start Here

- [`../../CLAUDE.md`](../../CLAUDE.md) — project conventions, layer rules,
  clippy lints, and AI-assistant workflow (canonical reference for contributors)
- [`../architecture/layer-architecture.md`](../architecture/layer-architecture.md) —
  three-layer architecture that governs module placement
- [`../architecture/testing-patterns.md`](../architecture/testing-patterns.md) —
  unit tests, integration tests, fixtures, and timing-resilient patterns
- [`../api/naming-conventions.md`](../api/naming-conventions.md) — prefix rules
  and API style

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
just arch-check                  # Architecture enforcement

# Dependencies
just deps-check                  # Full dependency health check
just deps-audit                  # Security vulnerability audit
just deps-outdated               # Show outdated dependencies
```

## Development Principles

1. **Test First** — write tests before implementation
1. **Security by Default** — secure patterns from the start
1. **Document as You Go** — update docs with code
1. **Refactor Continuously** — keep code clean
1. **Review Everything** — all code gets reviewed

## Related Sections

- [Architecture](../architecture/) — system design patterns
- [API Design](../api/) — public API guidelines

## External Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Cargo Documentation](https://doc.rust-lang.org/cargo/)
- [Clippy Lints](https://rust-lang.github.io/rust-clippy/)
- [Rustfmt](https://github.com/rust-lang/rustfmt)
