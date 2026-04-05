//! Integration tests for the io module
//!
//! These tests verify end-to-end behavior across io components:
//! - Atomic writes with permission verification
//! - Secure temp file lifecycle (create → detect → validate → delete)
//! - Magic byte detection and extension spoofing
//! - SecureFileOps with different config presets

mod io;
