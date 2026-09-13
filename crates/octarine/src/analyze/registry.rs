//! The set of [`Recognizer`]s an [`AnalyzerEngine`] drives.
//!
//! [`RecognizerRegistry`] holds recognizers and answers one question per run:
//! *which of these is worth calling for the requested entity types?* Filtering
//! here rather than inside each recognizer avoids a pointless network round
//! trip to a remote recognizer that could not have produced a requested type.
//!
//! [`AnalyzerEngine`]: crate::analyze::AnalyzerEngine

use std::sync::Arc;

use crate::analyze::{IdentifierRecognizer, Recognizer};
use crate::primitives::identifiers::types::IdentifierType;

/// A collection of recognizers, filtered per request.
///
/// Recognizers are held behind [`Arc`] so a single instance — an LLM client
/// with a connection pool, say — can be shared across several engines without
/// being rebuilt.
///
/// # Examples
///
/// ```
/// use octarine::analyze::RecognizerRegistry;
/// use octarine::identifiers::IdentifierType;
///
/// // The default registry detects octarine's whole identifier catalog.
/// let registry = RecognizerRegistry::with_defaults();
/// assert_eq!(registry.len(), 1);
///
/// // The built-in recognizer advertises every type, so it is selected for
/// // any request.
/// let selected = registry.recognizers_for(&[IdentifierType::Ssn]);
/// assert_eq!(selected.len(), 1);
/// ```
#[derive(Clone, Default)]
pub struct RecognizerRegistry {
    recognizers: Vec<Arc<dyn Recognizer>>,
}

impl std::fmt::Debug for RecognizerRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.recognizers.iter().map(|r| r.name()).collect();
        f.debug_struct("RecognizerRegistry")
            .field("recognizers", &names)
            .finish()
    }
}

impl RecognizerRegistry {
    /// Creates an empty registry.
    ///
    /// An engine driving an empty registry returns no results — it is not an
    /// error, but it is almost never what a caller wants. Use
    /// [`with_defaults`](Self::with_defaults) unless you are deliberately
    /// assembling a registry from scratch.
    #[must_use]
    pub fn new() -> Self {
        Self {
            recognizers: Vec::new(),
        }
    }

    /// Creates a registry holding the built-in
    /// [`IdentifierRecognizer`](crate::analyze::IdentifierRecognizer).
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new().register(Arc::new(IdentifierRecognizer::new()))
    }

    /// Like [`with_defaults`](Self::with_defaults), but the built-in
    /// recognizer emits no observe events or metrics.
    ///
    /// Used by [`AnalyzerEngine::silent`](crate::analyze::AnalyzerEngine::silent),
    /// so silence reaches the layer that actually emits per match rather than
    /// stopping at the engine boundary.
    #[must_use]
    pub fn with_silent_defaults() -> Self {
        Self::new().register(Arc::new(IdentifierRecognizer::silent()))
    }

    /// Adds a recognizer.
    ///
    /// Registering two recognizers with the same
    /// [`name`](Recognizer::name) is allowed — both run, and both are
    /// distinguishable only by position. Names are used for metadata and
    /// metrics, not identity.
    #[must_use]
    pub fn register(mut self, recognizer: Arc<dyn Recognizer>) -> Self {
        self.recognizers.push(recognizer);
        self
    }

    /// Returns the recognizers worth calling for `requested`.
    ///
    /// Filtering goes through [`Recognizer::supports`], which encodes the
    /// empty-means-everything convention on **both** sides: an empty
    /// `requested` asks for everything, and a recognizer advertising an empty
    /// [`supported_entities`](Recognizer::supported_entities) handles
    /// everything. A naive set intersection would get this exactly backwards
    /// and skip the general-purpose recognizers.
    #[must_use]
    pub fn recognizers_for(&self, requested: &[IdentifierType]) -> Vec<Arc<dyn Recognizer>> {
        self.recognizers
            .iter()
            .filter(|r| r.supports(requested))
            .map(Arc::clone)
            .collect()
    }

    /// All registered recognizers, unfiltered.
    #[must_use]
    pub fn recognizers(&self) -> &[Arc<dyn Recognizer>] {
        &self.recognizers
    }

    /// The number of registered recognizers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.recognizers.len()
    }

    /// Whether the registry holds no recognizers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.recognizers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    use async_trait::async_trait;

    use crate::anonymize::RecognizerResult;
    use crate::observe::Result;

    /// Advertises exactly one entity type.
    struct NarrowRecognizer {
        label: &'static str,
        supported: Vec<IdentifierType>,
    }

    #[async_trait]
    impl Recognizer for NarrowRecognizer {
        async fn analyze(
            &self,
            _text: &str,
            _language: &str,
            _entities: &[IdentifierType],
        ) -> Result<Vec<RecognizerResult>> {
            Ok(Vec::new())
        }

        fn name(&self) -> &str {
            self.label
        }

        fn supported_entities(&self) -> &[IdentifierType] {
            &self.supported
        }
    }

    fn narrow(label: &'static str, supported: Vec<IdentifierType>) -> Arc<dyn Recognizer> {
        Arc::new(NarrowRecognizer { label, supported })
    }

    #[test]
    fn new_registry_is_empty() {
        let registry = RecognizerRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn with_defaults_registers_the_identifier_recognizer() {
        let registry = RecognizerRegistry::with_defaults();
        assert_eq!(registry.len(), 1);
        assert_eq!(
            registry.recognizers().first().map(|r| r.name()),
            Some("identifiers")
        );
    }

    #[test]
    fn filter_selects_only_the_matching_narrow_recognizer() {
        let registry = RecognizerRegistry::new()
            .register(narrow("ssn-only", vec![IdentifierType::Ssn]))
            .register(narrow("email-only", vec![IdentifierType::Email]));

        let selected = registry.recognizers_for(&[IdentifierType::Ssn]);
        let names: Vec<&str> = selected.iter().map(|r| r.name()).collect();
        assert_eq!(
            names,
            vec!["ssn-only"],
            "only the recognizer advertising the requested type should be selected"
        );
    }

    #[test]
    fn empty_request_selects_every_recognizer() {
        let registry = RecognizerRegistry::new()
            .register(narrow("ssn-only", vec![IdentifierType::Ssn]))
            .register(narrow("email-only", vec![IdentifierType::Email]));

        assert_eq!(
            registry.recognizers_for(&[]).len(),
            2,
            "an empty request asks for everything, so nothing may be filtered out"
        );
    }

    #[test]
    fn catch_all_recognizer_survives_a_narrow_request() {
        // The regression this guards: a bare set intersection never matches an
        // empty supported set, so it would skip exactly the recognizers that
        // handle everything.
        let registry = RecognizerRegistry::new()
            .register(narrow("catch-all", Vec::new()))
            .register(narrow("email-only", vec![IdentifierType::Email]));

        let selected = registry.recognizers_for(&[IdentifierType::Ssn]);
        let names: Vec<&str> = selected.iter().map(|r| r.name()).collect();
        assert_eq!(
            names,
            vec!["catch-all"],
            "a recognizer advertising everything must be kept for a narrow request"
        );
    }
}
