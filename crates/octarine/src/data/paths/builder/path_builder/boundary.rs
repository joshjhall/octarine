//! Boundary delegators for [`PathBuilder`] that go beyond the simple
//! `boundary()` configuration setter (which lives in `builder/mod.rs`).
//!
//! Methods here read `self.boundary` and route through
//! [`BoundaryBuilder`].

use super::super::{BoundaryBuilder, PathBuilder};
use crate::observe::Problem;

impl PathBuilder {
    /// Check if within boundary
    #[must_use]
    pub fn is_within_boundary(&self, path: &str) -> bool {
        if let Some(ref boundary) = self.boundary {
            BoundaryBuilder::new(boundary).is_within(path)
        } else {
            true
        }
    }

    /// Resolve path in boundary
    pub fn resolve_in_boundary(&self, path: &str) -> Result<String, Problem> {
        if let Some(ref boundary) = self.boundary {
            let bb = BoundaryBuilder::new(boundary);
            if !bb.is_within(path) {
                return Err(Problem::validation("Path escapes boundary"));
            }
            Ok(bb.resolve(path))
        } else {
            Ok(path.to_string())
        }
    }
}
