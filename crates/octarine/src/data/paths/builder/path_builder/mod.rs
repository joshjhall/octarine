//! `PathBuilder` extension impl blocks, organized by concern.
//!
//! `PathBuilder` is defined in the parent module (`builder/mod.rs`).
//! Each file here adds an `impl PathBuilder { ... }` block scoped to a
//! specific concern (file type detection, format conversion, etc.). This
//! mirrors the split-impl pattern used in `observe/builder/` and
//! `observe/context/builder/`.
//!
//! Methods that emit metrics directly stay in `builder/mod.rs` so the
//! `define_metrics!`-generated `metric_names` module remains in scope.

mod boundary;
mod building;
mod characteristic;
mod construction;
mod context;
mod filename;
mod filetype;
mod format;
mod home;
mod lenient;
mod security;
