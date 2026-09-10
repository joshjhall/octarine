//! The [`Recognizer`] trait — the pluggable detection interface.
//!
//! A recognizer answers one question: *what entities does this text contain?*
//! It is the extension point that lets detection sources beyond the built-in
//! identifier primitives — a remote PII service, an LLM, a customer's own
//! pattern set — return results the rest of the analyze pipeline can consume.
//!
//! # Why the trait is async
//!
//! The built-in identifier detectors are synchronous pure functions, and
//! nothing forces them to change. But the interesting implementations are not:
//! an LLM recognizer issues an HTTP request per call, and a remote recognizer
//! is a network round-trip by definition. Making [`Recognizer::analyze`] async
//! lets those be written directly, and costs a synchronous implementation
//! nothing but an `async fn` that never awaits.
//!
//! # Relationship to the rest of the pipeline
//!
//! A recognizer produces [`RecognizerResult`]s — the same canonical detection
//! type the anonymizer surface consumes, so results flow through without a
//! conversion step. Overlaps *between* recognizers are not the recognizer's
//! problem: reconciliation is
//! [`ConflictResolution`](crate::analyze::ConflictResolution)'s job, and a
//! recognizer is free to return spans that overlap another recognizer's.
//!
//! All spans are half-open (`start` inclusive, `end` exclusive), matching
//! [`RecognizerResult`].
//!
//! # Examples
//!
//! ```
//! use async_trait::async_trait;
//! use octarine::analyze::Recognizer;
//! use octarine::anonymize::RecognizerResult;
//! use octarine::observe::Result;
//! use octarine::identifiers::IdentifierType;
//!
//! /// A recognizer that finds one hard-coded marker.
//! struct MarkerRecognizer {
//!     supported: Vec<IdentifierType>,
//! }
//!
//! #[async_trait]
//! impl Recognizer for MarkerRecognizer {
//!     async fn analyze(
//!         &self,
//!         text: &str,
//!         _language: &str,
//!         _entities: &[IdentifierType],
//!     ) -> Result<Vec<RecognizerResult>> {
//!         let mut out = Vec::new();
//!         if let Some(start) = text.find("ACME-1234") {
//!             let end = start.saturating_add("ACME-1234".len());
//!             out.push(RecognizerResult::new("ACCOUNT_ID", start, end, 0.9)?);
//!         }
//!         Ok(out)
//!     }
//!
//!     fn name(&self) -> &str {
//!         "marker"
//!     }
//!
//!     fn supported_entities(&self) -> &[IdentifierType] {
//!         &self.supported
//!     }
//! }
//! ```

use async_trait::async_trait;

use crate::anonymize::RecognizerResult;
use crate::observe::Result;
use crate::primitives::identifiers::types::IdentifierType;

// Note: `IdentifierType` is re-exported publicly as `octarine::identifiers::IdentifierType`;
// internal code reaches it through the `pub(crate)` primitives path above.

/// A source of entity detections over text.
///
/// Implementations are shared across tasks, so the trait requires `Send + Sync`.
#[async_trait]
pub trait Recognizer: Send + Sync {
    /// Detects entities in `text`, returning one [`RecognizerResult`] per span.
    ///
    /// `language` is a BCP 47 tag (`"en"`, `"pt-BR"`). An implementation that
    /// handles only one language should return an empty vector for others
    /// rather than erroring — an unsupported language is not a failure, it is
    /// an absence of results, and erroring would fail the whole analysis run
    /// over one recognizer's narrowness.
    ///
    /// `entities` narrows what the caller is asking for. An **empty slice
    /// means "everything this recognizer supports"** — it is not a request for
    /// nothing. Otherwise, an implementation should restrict its work to the
    /// intersection of `entities` and
    /// [`supported_entities`](Recognizer::supported_entities); returning a type
    /// the caller did not ask for is not an error, but it wastes downstream
    /// filtering.
    ///
    /// Returned spans are byte offsets into `text`, half-open, and need not be
    /// sorted or mutually disjoint.
    ///
    /// # Errors
    ///
    /// Returns a [`Problem`](crate::observe::Problem) when detection could not
    /// be completed — a transport failure, an unparseable upstream response, or
    /// a span the source produced that is not valid for `text`. An empty result
    /// set is a success, not an error: "I found nothing" and "I could not look"
    /// are different answers and must not collapse into one.
    async fn analyze(
        &self,
        text: &str,
        language: &str,
        entities: &[IdentifierType],
    ) -> Result<Vec<RecognizerResult>>;

    /// A short, stable identifier for this recognizer.
    ///
    /// Used in logs, metrics labels, and
    /// [`RecognizerResult::recognition_metadata`] so a detection can be traced
    /// back to its source. Keep it stable across releases — it ends up in
    /// stored audit records.
    fn name(&self) -> &str;

    /// The entity types this recognizer can produce.
    ///
    /// Lets a registry skip a recognizer entirely when none of its types were
    /// requested, avoiding a pointless network call.
    fn supported_entities(&self) -> &[IdentifierType];
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    /// Finds every occurrence of a fixed needle. Deliberately returns
    /// overlapping-capable raw spans — reconciliation is not its job.
    struct NeedleRecognizer {
        needle: &'static str,
        supported: Vec<IdentifierType>,
    }

    #[async_trait]
    impl Recognizer for NeedleRecognizer {
        async fn analyze(
            &self,
            text: &str,
            language: &str,
            entities: &[IdentifierType],
        ) -> Result<Vec<RecognizerResult>> {
            if language != "en" {
                return Ok(Vec::new());
            }
            if !entities.is_empty() && !entities.iter().any(|e| self.supported.contains(e)) {
                return Ok(Vec::new());
            }

            let mut out = Vec::new();
            let mut from = 0usize;
            while let Some(offset) = text.get(from..).and_then(|rest| rest.find(self.needle)) {
                let start = from.saturating_add(offset);
                let end = start.saturating_add(self.needle.len());
                out.push(RecognizerResult::new("NEEDLE", start, end, 0.8)?);
                from = end;
            }
            Ok(out)
        }

        fn name(&self) -> &str {
            "needle"
        }

        fn supported_entities(&self) -> &[IdentifierType] {
            &self.supported
        }
    }

    fn needle_recognizer() -> NeedleRecognizer {
        NeedleRecognizer {
            needle: "xyz",
            supported: vec![IdentifierType::Email],
        }
    }

    #[tokio::test]
    async fn analyze_returns_a_span_per_occurrence_at_correct_offsets() {
        let rec = needle_recognizer();
        // Two occurrences at known, distinct offsets; the leading text is sized
        // so a wrong offset cannot coincidentally match.
        let results = rec
            .analyze("--xyz----xyz", "en", &[])
            .await
            .expect("detection succeeds");

        assert_eq!(results.len(), 2, "expected one span per occurrence");
        assert_eq!(
            results.first().map(|r| (r.start, r.end)),
            Some((2, 5)),
            "first span must cover exactly the first needle"
        );
        assert_eq!(
            results.get(1).map(|r| (r.start, r.end)),
            Some((9, 12)),
            "second span must cover exactly the second needle"
        );
    }

    #[tokio::test]
    async fn empty_entities_slice_means_all_supported_not_none() {
        let rec = needle_recognizer();
        let results = rec
            .analyze("--xyz", "en", &[])
            .await
            .expect("detection succeeds");

        assert_eq!(
            results.len(),
            1,
            "an empty `entities` slice must mean 'everything', not 'nothing'"
        );
    }

    #[tokio::test]
    async fn unsupported_entity_filter_yields_no_results() {
        let rec = needle_recognizer();
        // Text definitely contains the needle; only the filter should suppress it.
        let results = rec
            .analyze("--xyz", "en", &[IdentifierType::CreditCard])
            .await
            .expect("detection succeeds");

        assert!(
            results.is_empty(),
            "a filter naming only unsupported types must suppress results"
        );
    }

    #[tokio::test]
    async fn unsupported_language_is_empty_success_not_error() {
        let rec = needle_recognizer();
        // Same text that yields a hit in "en".
        let outcome = rec.analyze("--xyz", "fr", &[]).await;

        let results = outcome.expect("an unsupported language must not be an error");
        assert!(results.is_empty(), "unsupported language yields no results");
    }

    #[tokio::test]
    async fn is_object_safe_and_usable_behind_dyn() {
        let rec: Box<dyn Recognizer> = Box::new(needle_recognizer());
        let results = rec
            .analyze("--xyz", "en", &[])
            .await
            .expect("detection succeeds");

        assert_eq!(rec.name(), "needle");
        assert_eq!(rec.supported_entities(), &[IdentifierType::Email]);
        assert_eq!(results.len(), 1);
    }
}
