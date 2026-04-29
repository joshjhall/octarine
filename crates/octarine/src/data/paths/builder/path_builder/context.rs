//! Context-specific path sanitization delegators for [`PathBuilder`].
//!
//! Methods that delegate to [`PathContextBuilder`] for env, SSH,
//! credential, certificate, keystore, secret, backup, and op-reference
//! path handling.

use super::super::{PathBuilder, PathContextBuilder};
use crate::observe::Problem;

impl PathBuilder {
    /// Check if env path
    #[must_use]
    pub fn is_env_path(&self, path: &str) -> bool {
        PathContextBuilder::new().is_env_path(path)
    }

    /// Sanitize env path
    pub fn sanitize_env_path(&self, path: &str) -> Result<String, Problem> {
        PathContextBuilder::new().sanitize_env(path)
    }

    /// Check if SSH path
    #[must_use]
    pub fn is_ssh_path(&self, path: &str) -> bool {
        PathContextBuilder::new().is_ssh_path(path)
    }

    /// Sanitize SSH path
    pub fn sanitize_ssh_path(&self, path: &str) -> Result<String, Problem> {
        PathContextBuilder::new().sanitize_ssh(path)
    }

    /// Check if credential path
    #[must_use]
    pub fn is_credential_path(&self, path: &str) -> bool {
        PathContextBuilder::new().is_credential_path(path)
    }

    /// Sanitize credential path
    pub fn sanitize_credential_path(&self, path: &str) -> Result<String, Problem> {
        PathContextBuilder::new().sanitize_credential(path)
    }

    /// Sanitize certificate path
    pub fn sanitize_certificate_path(&self, path: &str) -> Result<String, Problem> {
        PathContextBuilder::new().sanitize_certificate(path)
    }

    /// Sanitize keystore path
    pub fn sanitize_keystore_path(&self, path: &str) -> Result<String, Problem> {
        PathContextBuilder::new().sanitize_keystore(path)
    }

    /// Sanitize secret path
    pub fn sanitize_secret_path(&self, path: &str) -> Result<String, Problem> {
        PathContextBuilder::new().sanitize_secret(path)
    }

    /// Sanitize backup path
    pub fn sanitize_backup_path(&self, path: &str) -> Result<String, Problem> {
        PathContextBuilder::new().sanitize_backup(path)
    }

    /// Check if op reference
    #[must_use]
    pub fn is_op_reference(&self, path: &str) -> bool {
        PathContextBuilder::new().is_op_reference(path)
    }

    /// Sanitize op reference
    pub fn sanitize_op_reference(&self, path: &str) -> Result<String, Problem> {
        PathContextBuilder::new().sanitize_op(path)
    }
}
