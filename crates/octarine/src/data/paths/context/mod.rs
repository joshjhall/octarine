//! Context-specific path sanitization
//!
//! Provides sanitization for paths in specific contexts:
//! - Environment files (.env)
//! - SSH configuration (.ssh)
//! - Credential/secret files
//! - 1Password references (op://)

mod credential;
mod env;
mod op;
mod ssh;

// Internal API - only accessible within data/paths
pub(super) use credential::{
    is_credential_path, sanitize_backup_path, sanitize_certificate_path, sanitize_credential_path,
    sanitize_keystore_path, sanitize_secret_path,
};
pub(super) use env::{is_env_path, sanitize_env_path};
pub(super) use op::{is_op_reference, sanitize_op_reference};
pub(super) use ssh::{is_ssh_path, sanitize_ssh_path};
