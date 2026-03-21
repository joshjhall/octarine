//! Shared Test Infrastructure
//!
//! This module provides reusable test utilities for rust-core and all consuming projects.
//! It is feature-gated behind `testing` and should only be used in `[dev-dependencies]`.
//!
//! ## Architecture
//!
//! The testing module is unique in rust-core's layer architecture:
//! - It's in Layer 1 (Foundation) alongside primitives
//! - Unlike primitives, it's publicly accessible (feature-gated)
//! - It can depend on ALL other layers (primitives, observe, security, runtime)
//! - NO production code may depend on it
//!
//! ```text
//! Normal flow:  Layer 3 → Layer 2 → Layer 1 (down only)
//! Testing flow: testing → ALL layers (it's a consumer, not a provider)
//! ```
//!
//! ## Quick Start
//!
//! ```toml
//! [dependencies]
//! rust-core = { version = "0.2", features = ["full"] }
//!
//! [dev-dependencies]
//! rust-core = { version = "0.2", features = ["testing"] }
//! ```
//!
//! ```rust,ignore
//! use octarine::testing::prelude::*;
//!
//! #[rstest]
//! fn test_with_temp_dir(temp_dir: TempDir) {
//!     let file = temp_dir.child("test.txt");
//!     file.write_str("hello").unwrap();
//!     file.assert(predicate::str::contains("hello"));
//! }
//! ```
//!
//! ## Module Overview
//!
//! - `fixtures` - Test fixtures (temp dirs, permissions, symlinks, NFS)
//! - `generators` - Data generators for property testing (attacks, PII, identifiers)
//! - `cli` - CLI testing utilities (command execution, interactive testing)
//! - `api` - API testing utilities (HTTP mocking, MCP protocol)
//! - `assertions` - Security-focused assertions (no PII, safe paths)
//!
//! ## Why a Shared Testing Module?
//!
//! 1. **Consistent patterns**: All projects using rust-core test the same way
//! 2. **Security-focused generators**: Attack patterns match our defenses
//! 3. **Reusable fixtures**: Don't reinvent temp dirs, permissions, etc.
//! 4. **Property testing**: Generators for fuzzing security-critical code
//!
//! See `/docs/architecture/testing-patterns.md` for complete documentation.

// Testing utilities are expected to panic on setup failures - that's their job.
// These lints are appropriate for production code but not for test infrastructure.
#![allow(clippy::expect_used)]
#![allow(clippy::panic)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::type_complexity)]

pub mod api;
pub mod assertions;
pub mod cli;
pub mod fixtures;
pub mod generators;

/// Prelude for convenient imports in tests
///
/// Import everything commonly needed for testing:
///
/// ```rust,ignore
/// use octarine::testing::prelude::*;
/// ```
pub mod prelude {
    // Re-export our modules
    pub use super::assertions::*;
    pub use super::cli::*;
    pub use super::fixtures::*;
    pub use super::generators::*;

    // Re-export external test crates for convenience
    pub use assert_fs::TempDir;
    pub use assert_fs::prelude::*;
    pub use predicates::prelude::*;
    pub use proptest::prelude::*;
    pub use rstest::*;
}
