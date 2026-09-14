//! Convenience functions over a default [`AnalyzerEngine`].
//!
//! Each constructs a default engine per call. When analyzing many texts, build
//! one [`AnalyzerEngine`] and reuse it — the shortcut rebuilds the recognizer
//! registry every time.

use crate::analyze::AnalyzerEngine;
use crate::anonymize::RecognizerResult;
use crate::observe::Result;

/// Analyzes `text` with the default engine and every built-in recognizer.
///
/// # Errors
///
/// See [`AnalyzerEngine::analyze`].
///
/// # Examples
///
/// ```
/// use octarine::analyze::analyze;
///
/// # tokio_test::block_on(async {
/// let results = analyze("Contact: user@example.com", "en").await?;
/// assert!(results.iter().any(|r| r.entity_type == "EMAIL_ADDRESS"));
/// # Ok::<(), octarine::observe::Problem>(())
/// # }).unwrap();
/// ```
pub async fn analyze(text: &str, language: &str) -> Result<Vec<RecognizerResult>> {
    AnalyzerEngine::new().analyze(text, language).await
}

/// Analyzes `text`, keeping only results scoring at or above `threshold`.
///
/// # Errors
///
/// See [`AnalyzerEngine::analyze`].
///
/// # Examples
///
/// ```
/// use octarine::analyze::analyze_with_threshold;
///
/// # tokio_test::block_on(async {
/// // Only validated, high-confidence detections survive.
/// let results = analyze_with_threshold("Contact: user@example.com", "en", 0.8).await?;
/// assert!(results.iter().all(|r| r.score >= 0.8));
/// # Ok::<(), octarine::observe::Problem>(())
/// # }).unwrap();
/// ```
pub async fn analyze_with_threshold(
    text: &str,
    language: &str,
    threshold: f64,
) -> Result<Vec<RecognizerResult>> {
    AnalyzerEngine::new()
        .with_score_threshold(threshold)
        .analyze(text, language)
        .await
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[tokio::test]
    async fn shortcut_matches_a_hand_built_default_engine() {
        let text = "Contact: user@example.com";
        let via_shortcut = analyze(text, "en").await.expect("analysis succeeds");
        let via_engine = AnalyzerEngine::new()
            .analyze(text, "en")
            .await
            .expect("analysis succeeds");

        assert_eq!(
            via_shortcut
                .iter()
                .map(|r| (r.entity_type.clone(), r.start, r.end))
                .collect::<Vec<_>>(),
            via_engine
                .iter()
                .map(|r| (r.entity_type.clone(), r.start, r.end))
                .collect::<Vec<_>>(),
        );
    }

    #[tokio::test]
    async fn threshold_shortcut_excludes_weak_detections() {
        let text = "Contact: user@example.com";

        let unfiltered = analyze(text, "en").await.expect("analysis succeeds");
        let filtered = analyze_with_threshold(text, "en", 0.99)
            .await
            .expect("analysis succeeds");

        assert!(
            !unfiltered.is_empty(),
            "fixture must detect something, or the comparison below is vacuous"
        );
        assert!(
            filtered.len() < unfiltered.len(),
            "a 0.99 threshold must exclude detections the unfiltered run returned"
        );
    }
}
