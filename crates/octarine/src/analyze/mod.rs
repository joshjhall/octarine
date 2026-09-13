//! Analysis surface over identifier detection (Layer 3).
//!
//! This module is octarine's parity surface for Presidio's `AnalyzerEngine`:
//! [`AnalyzerEngine`](crate::analyze::AnalyzerEngine) drives a set of pluggable [`Recognizer`](crate::analyze::Recognizer)s through an
//! explicit pipeline that scores detections, reconciles their overlaps, and
//! returns a coherent result set.
//!
//! # Quick start
//!
//! ```
//! use octarine::analyze::AnalyzerEngine;
//!
//! # tokio_test::block_on(async {
//! let engine = AnalyzerEngine::new();
//! let results = engine.analyze("Contact: user@example.com", "en").await?;
//!
//! for result in &results {
//!     println!("{} at {}..{} ({:.2})", result.entity_type, result.start, result.end, result.score);
//! }
//! # assert!(results.iter().any(|r| r.entity_type == "EMAIL_ADDRESS"));
//! # Ok::<(), octarine::observe::Problem>(())
//! # }).unwrap();
//! ```
//!
//! # Components
//!
//! - [`AnalyzerEngine`](crate::analyze::AnalyzerEngine) — the pipeline shell. Async, because a recognizer may
//!   be a network service.
//! - [`RecognizerRegistry`](crate::analyze::RecognizerRegistry) — the recognizer set, filtered per request.
//! - [`Recognizer`](crate::analyze::Recognizer) — the pluggable detection interface, implemented by
//!   detection sources beyond the built-in primitives (a remote PII service,
//!   an LLM, a customer's own pattern set).
//! - [`IdentifierRecognizer`](crate::analyze::IdentifierRecognizer) — the built-in adapter over octarine's identifier
//!   detection. Registered by default, so the engine is useful with no setup.
//! - [`ConflictResolution`](crate::analyze::ConflictResolution) — overlap reconciliation, with Presidio-compatible
//!   same-type containment as the default and an opt-in cross-type strategy
//!   that closes a documented Presidio gap.
//! - [`AnalyzeRequest`](crate::analyze::AnalyzeRequest) / [`AnalysisExplanation`](crate::analyze::AnalysisExplanation) — per-call knobs and the
//!   decision-process record.
//!
//! # The pipeline
//!
//! Each pass is a separate function, individually testable and individually
//! extensible. The order mirrors Presidio's because it is load-bearing:
//! context enhancement must precede thresholding, or a result the context
//! would have rescued is discarded before the rescue runs.
//!
//! 1. Resolve the recognizer set for the requested language and entities
//! 2. *NLP artifacts* — a documented seam; requires an NER model
//! 3. Run each recognizer and aggregate
//! 4. Stamp recognizer provenance into result metadata
//! 5. Raise scores for detections with a supportive keyword nearby
//! 6. *Allow-list filtering* — a documented seam
//! 7. Reconcile overlapping spans
//! 8. Drop results below the score threshold
//! 9. Strip explanations unless the caller asked to keep them
//!
//! Steps 2 and 6 are deliberately absent rather than stubbed. A knob that
//! parses but reaches no consumer is a silent no-op — callers set it, nothing
//! happens, and the only symptom is wrong output. Each lands with the pass
//! that reads it.
//!
//! # Where dedup happens
//!
//! Individual detectors already deduplicate *within* their own domain before
//! their matches are drained. [`ConflictResolution`](crate::analyze::ConflictResolution) therefore operates on an
//! already-partially-deduped set, and its job is **cross-detector**
//! reconciliation: the overlaps that only become visible once every domain's
//! matches share one buffer.
//!
//! All spans are half-open (`start` inclusive, `end` exclusive).

mod builder;
mod conflict;
mod identifiers;
mod pipeline;
mod recognizer;
mod registry;
mod shortcuts;
mod types;

pub use builder::AnalyzerEngine;
pub use conflict::ConflictResolution;
pub use identifiers::IdentifierRecognizer;
pub use recognizer::Recognizer;
pub use registry::RecognizerRegistry;
pub use shortcuts::{analyze, analyze_with_threshold};
pub use types::{AnalysisExplanation, AnalyzeRequest};
