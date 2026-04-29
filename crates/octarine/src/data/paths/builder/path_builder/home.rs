//! Home directory delegators for [`PathBuilder`].
//!
//! Methods that delegate to [`HomeBuilder`] for `~` expansion and
//! collapse.

use super::super::{HomeBuilder, PathBuilder};
use crate::observe::Problem;

impl PathBuilder {
    /// Check for home reference
    #[must_use]
    pub fn is_home_reference_present(&self, path: &str) -> bool {
        HomeBuilder::new().is_reference_present(path)
    }

    /// Expand home directory
    pub fn expand_home(&self, path: &str) -> Result<String, Problem> {
        HomeBuilder::new().expand(path)
    }

    /// Collapse home directory
    #[must_use]
    pub fn collapse_home(&self, path: &str) -> String {
        HomeBuilder::new().collapse(path)
    }
}
