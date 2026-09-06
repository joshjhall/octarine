//! Analysis surface over identifier detection (Layer 3).
//!
//! This module is octarine's parity surface for Presidio's `AnalyzerEngine`:
//! it takes the raw detections produced by the identifier primitives and
//! applies the engine-side passes that turn them into a coherent result set.
//!
//! # Components
//!
//! - [`ConflictResolution`](crate::analyze::ConflictResolution) — overlap
//!   reconciliation across detections, with Presidio-compatible same-type
//!   containment as the default and an opt-in cross-type strategy that closes
//!   a documented Presidio gap.
//!
//! The remaining pipeline passes — per-entity score thresholds, ad-hoc
//! recognizer injection, allow/deny lists, and the decision-process trace —
//! land as follow-up work under the `analyze/` umbrella.
//!
//! # Where dedup happens
//!
//! Individual detectors already deduplicate *within* their own domain before
//! their matches are drained.
//! [`ConflictResolution`](crate::analyze::ConflictResolution) therefore
//! operates on an already-partially-deduped set, and its job is
//! **cross-detector** reconciliation: the overlaps that only become visible
//! once every domain's matches share one buffer.
//!
//! All spans are half-open (`start` inclusive, `end` exclusive).
//!
//! # Examples
//!
//! ```
//! use octarine::analyze::ConflictResolution;
//! use octarine::identifiers::Identifiers;
//!
//! let text = "Contact: alice@example.com";
//! let matches = Identifiers::new().scan_text(text);
//!
//! // Default strategy mirrors Presidio's same-type containment dedup.
//! let resolved = ConflictResolution::default().resolve(text, matches);
//! # let _ = resolved;
//! ```

mod conflict;

pub use conflict::ConflictResolution;
