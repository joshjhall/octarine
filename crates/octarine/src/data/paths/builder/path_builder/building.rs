//! Path-building delegators for [`PathBuilder`].
//!
//! Methods that delegate to [`ConstructionBuilder`] for assembling paths
//! from components and producing temp/config paths.

use super::super::{ConstructionBuilder, PathBuilder};
use crate::observe::Problem;

impl PathBuilder {
    /// Build path from components
    pub fn build_path(&self, base: &str, components: &[&str]) -> Result<String, Problem> {
        ConstructionBuilder::new().build(base, components)
    }

    /// Build absolute path
    pub fn build_absolute_path(&self, base: &str, components: &[&str]) -> Result<String, Problem> {
        ConstructionBuilder::new().build_absolute(base, components)
    }

    /// Build file path
    pub fn build_file_path(&self, directory: &str, filename: &str) -> Result<String, Problem> {
        ConstructionBuilder::new().build_file(directory, filename)
    }

    /// Build temp path
    #[must_use]
    pub fn build_temp_path(&self, filename: &str) -> String {
        ConstructionBuilder::new().temp(filename)
    }

    /// Build config path
    #[must_use]
    pub fn build_config_path(&self, directory: &str, environment: Option<&str>) -> String {
        ConstructionBuilder::new().config(directory, environment)
    }

    /// Join components
    pub fn join_components(&self, components: &[&str]) -> Result<String, Problem> {
        ConstructionBuilder::new().join(components)
    }
}
