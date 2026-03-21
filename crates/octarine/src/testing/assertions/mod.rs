//! Test Assertions
//!
//! Provides custom assertions and predicates for security testing.
//!
//! ## Security Assertions
//!
//! ```rust,ignore
//! use octarine::testing::assertions::*;
//!
//! #[test]
//! fn test_no_traversal() {
//!     let path = "/safe/path/file.txt";
//!     assert_no_path_traversal(path);
//! }
//!
//! #[test]
//! fn test_no_injection() {
//!     let input = "clean input";
//!     assert_no_command_injection(input);
//! }
//! ```
//!
//! ## Custom Predicates
//!
//! ```rust,ignore
//! use octarine::testing::assertions::predicates_security::*;
//! use predicates::prelude::*;
//!
//! let is_safe = is_safe_path();
//! assert!(is_safe.eval("/normal/path.txt"));
//! assert!(!is_safe.eval("../etc/passwd"));
//! ```

mod predicates;
mod security;

pub use self::predicates::*;
pub use security::*;
