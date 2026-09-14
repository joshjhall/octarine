//! Overlap reconciliation for identifier matches.
//!
//! Detection produces a raw set of [`IdentifierMatch`] spans that may overlap:
//! the same span found twice, a short match nested inside a longer one, or two
//! matches that partially intersect. [`ConflictResolution`] selects how those
//! conflicts are reconciled before the results reach redaction.
//!
//! The same four strategies apply to both span types the crate carries:
//! [`resolve`](ConflictResolution::resolve) over [`IdentifierMatch`] for direct
//! identifier scans, and
//! [`resolve_results`](ConflictResolution::resolve_results) over
//! [`RecognizerResult`] for the [`analyze`](crate::analyze) pipeline.

use std::cmp::Ordering;

use crate::anonymize::{PiiSpan, RecognizerResult};
use crate::primitives::identifiers::types::IdentifierMatch;

/// Strategy for reconciling overlapping [`IdentifierMatch`] spans.
///
/// # Confidence, not score
///
/// Presidio ranks detections by an `f64` score in `[0, 1]` and silently drops
/// entries scoring exactly `0` — a recognizer's "definitely not PII" sentinel.
/// Octarine ranks by [`DetectionConfidence`], an ordered three-level enum with
/// no such sentinel: `Low` is a genuine heuristic hit, not a rejection, so
/// dropping it would discard valid detections.
///
/// The zero-score drop therefore maps to the degenerate case octarine *does*
/// have — the **zero-width span**. A match with `start == end` covers no text,
/// so it can be neither redacted nor meaningfully reported. Every strategy
/// except [`None`](Self::None) drops zero-width matches. Priority ordering uses
/// `DetectionConfidence`'s derived `Ord` (`High > Medium > Low`) wherever
/// Presidio would compare scores.
///
/// [`DetectionConfidence`]: crate::primitives::identifiers::types::DetectionConfidence
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConflictResolution {
    /// Apply no reconciliation; return every match, sorted by `(start, end)`.
    ///
    /// Zero-width matches are **retained** — this strategy is a pass-through
    /// for callers that want the raw detection set.
    None,

    /// Drop duplicate and contained matches **of the same type only**.
    ///
    /// This is the default, and mirrors Presidio's engine-level dedup
    /// (`EntityRecognizer.remove_duplicates`): equal-span same-type duplicates
    /// are dropped, and a same-type match contained in a longer same-type match
    /// loses to the longer one. Matches of *different* types are left alone
    /// even when one contains the other — a `PhoneNumber` inside a `Url` keeps
    /// both, exactly as Presidio does.
    ///
    /// Because cross-type overlaps survive, this strategy's output may contain
    /// overlapping spans. Do not feed it straight into a splice-based redactor
    /// that assumes disjoint ranges — use
    /// [`CrossTypeContainment`](Self::CrossTypeContainment) or
    /// [`RemoveIntersections`](Self::RemoveIntersections) when downstream
    /// redaction requires them.
    #[default]
    SameTypeContainment,

    /// Drop duplicate and contained matches **regardless of type**.
    ///
    /// Everything [`SameTypeContainment`](Self::SameTypeContainment) does, plus
    /// cross-type containment: a `PhoneNumber` nested inside a `Url` is dropped
    /// so downstream redaction cannot double-redact the same span.
    ///
    /// # An asymmetric win over Presidio
    ///
    /// Presidio performs **no** cross-type overlap removal — its own analysis
    /// records that a PHONE inside a URL leaves both matches alive, and it
    /// offers no option to change that. Octarine ships the Presidio-compatible
    /// behavior as the default and makes this stricter reconciliation available
    /// as an opt-in, closing a documented gap rather than diverging silently.
    CrossTypeContainment,

    /// Trim partial overlaps instead of dropping whole matches.
    ///
    /// The highest-priority span is kept intact; each lower-priority span is
    /// shrunk to its longest sub-range not already covered by a kept span, and
    /// dropped only if nothing survives. A trimmed match has its
    /// `matched_text` re-sliced to match its new offsets.
    ///
    /// # A trimmed match yields at most one fragment
    ///
    /// When higher-priority spans block a candidate's *interior*, it is left
    /// with two or more disjoint free sub-ranges — and only the **longest**
    /// survives. The others are dropped, not emitted as additional matches, so
    /// that slice of text reaches no redactor. This mirrors the anonymize
    /// engine's identically-named helper, keeping the two engines' overlap
    /// behavior in step rather than silently diverging.
    ///
    /// It does mean this strategy can narrow PII coverage. Prefer
    /// [`CrossTypeContainment`](Self::CrossTypeContainment) when the goal is
    /// disjoint spans with no detection loss; reach for this one only when
    /// partial spans are genuinely wanted.
    RemoveIntersections,
}

impl ConflictResolution {
    /// Reconciles overlaps among `matches` found in `text`.
    ///
    /// Returns the surviving matches sorted by `(start, end)`.
    ///
    /// `text` is required because [`RemoveIntersections`](Self::RemoveIntersections)
    /// shrinks spans, and a shrunk match's `matched_text` must be re-sliced to
    /// stay consistent with its offsets: downstream sanitizers redact
    /// `matched_text` directly, so a stale value would splice a
    /// wrongly-sized replacement into the trimmed range.
    ///
    /// # Invariant
    ///
    /// `text` MUST be the exact string the matches were detected in — their
    /// offsets are interpreted against it. Passing normalized or otherwise
    /// transformed text is always a caller bug.
    ///
    /// **Only [`RemoveIntersections`](Self::RemoveIntersections) enforces
    /// this.** It is the sole strategy that reads `text` (it must re-slice
    /// `matched_text` after moving a span), so it is the only one positioned to
    /// notice a violation; a match whose span does not resolve is dropped and
    /// logged as `analyze_span_mismatch`. The other three strategies never
    /// touch `text` and pass an out-of-bounds span through untouched and
    /// unwarned. Validating there would mean *discarding* detections the caller
    /// never asked this strategy to inspect — a worse fail-open for a PII
    /// detector than passing them along — so bounds enforcement for the
    /// containment strategies belongs to whichever consumer slices with them.
    #[must_use]
    pub fn resolve(self, text: &str, matches: Vec<IdentifierMatch>) -> Vec<IdentifierMatch> {
        match self {
            Self::None => {
                let mut sorted = matches;
                sort_by_position(&mut sorted);
                sorted
            }
            Self::SameTypeContainment => drop_contained(matches, true),
            Self::CrossTypeContainment => drop_contained(matches, false),
            Self::RemoveIntersections => remove_intersections(text, matches),
        }
    }

    /// Reconciles overlaps among [`RecognizerResult`]s — the
    /// [`analyze`](crate::analyze) pipeline's dedup pass.
    ///
    /// Same strategies, same ordering rules as [`resolve`](Self::resolve), but
    /// over the type the pipeline actually carries. Running the pipeline
    /// through the [`IdentifierMatch`] form instead would mean converting in
    /// and back out, and [`IdentifierMatch`] has no `recognition_metadata` or
    /// `analysis_explanation` — the round trip would silently discard the
    /// provenance of every surviving detection, which is precisely what the
    /// decision-process trace is built on.
    ///
    /// # Ranking
    ///
    /// Where [`resolve`](Self::resolve) ranks by
    /// [`DetectionConfidence`](crate::primitives::identifiers::types::DetectionConfidence),
    /// this ranks by [`RecognizerResult::score`]. Scores are compared with
    /// [`f64::total_cmp`], so a `NaN` score sorts deterministically instead of
    /// poisoning the sort — it cannot arise through
    /// [`RecognizerResult::new`], which rejects non-finite scores, but a
    /// directly-constructed value could carry one.
    ///
    /// # Divergence from `resolve`
    ///
    /// [`RemoveIntersections`](Self::RemoveIntersections) trims **offsets
    /// only**. [`IdentifierMatch`] carries a `matched_text` copy that must be
    /// re-sliced when its span moves; [`RecognizerResult`] carries no text, so
    /// there is nothing to keep in sync and `text` is unused for every
    /// strategy here. It is still taken, so the two methods stay
    /// interchangeable at call sites and a future pass that needs the text —
    /// context re-evaluation after a trim, say — does not change the
    /// signature.
    #[must_use]
    pub fn resolve_results(
        self,
        text: &str,
        results: Vec<RecognizerResult>,
    ) -> Vec<RecognizerResult> {
        let _ = text;
        match self {
            Self::None => {
                let mut sorted = results;
                sort_results_by_position(&mut sorted);
                sorted
            }
            Self::SameTypeContainment => drop_contained_results(results, true),
            Self::CrossTypeContainment => drop_contained_results(results, false),
            Self::RemoveIntersections => remove_intersections_results(results),
        }
    }
}

/// Sorts results into reading order: by start, then by end.
fn sort_results_by_position(results: &mut [RecognizerResult]) {
    results.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| a.end.cmp(&b.end)));
}

/// [`RecognizerResult`] analogue of [`drop_contained`].
///
/// Ordering is longest-span-first so a container is always visited before
/// anything nested inside it — ranking by score first would let a
/// high-confidence *inner* span be kept before the span enclosing it was ever
/// tested, and both would survive.
fn drop_contained_results(
    results: Vec<RecognizerResult>,
    same_type_only: bool,
) -> Vec<RecognizerResult> {
    let mut by_span: Vec<RecognizerResult> =
        results.into_iter().filter(|r| r.end > r.start).collect();
    by_span.sort_by(|a, b| {
        let a_len = a.end.saturating_sub(a.start);
        let b_len = b.end.saturating_sub(b.start);
        b_len
            .cmp(&a_len)
            .then_with(|| b.score.total_cmp(&a.score))
            .then_with(|| a.start.cmp(&b.start))
    });

    let mut kept: Vec<RecognizerResult> = Vec::new();
    for candidate in by_span {
        let absorbed = kept.iter().any(|k| {
            let type_matches = !same_type_only || k.entity_type == candidate.entity_type;
            type_matches && candidate.contained_in(k)
        });
        if !absorbed {
            kept.push(candidate);
        }
    }

    sort_results_by_position(&mut kept);
    kept
}

/// [`RecognizerResult`] analogue of [`remove_intersections`], trimming offsets
/// only.
fn remove_intersections_results(results: Vec<RecognizerResult>) -> Vec<RecognizerResult> {
    let mut by_priority: Vec<RecognizerResult> =
        results.into_iter().filter(|r| r.end > r.start).collect();
    by_priority.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| a.start.cmp(&b.start))
            .then_with(|| a.end.cmp(&b.end))
    });

    let mut kept: Vec<RecognizerResult> = Vec::new();
    for mut candidate in by_priority {
        let mut blockers: Vec<(usize, usize)> = kept
            .iter()
            .filter(|k| k.intersects(&candidate))
            .map(|k| (k.start, k.end))
            .collect();
        blockers.sort_unstable();

        let Some((start, end)) = longest_free_subrange(candidate.start, candidate.end, &blockers)
        else {
            continue;
        };
        candidate.start = start;
        candidate.end = end;
        kept.push(candidate);
    }

    sort_results_by_position(&mut kept);
    kept
}

/// Sorts matches into reading order: by start, then by end.
fn sort_by_position(matches: &mut [IdentifierMatch]) {
    matches.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| a.end.cmp(&b.end)));
}

/// Descending priority: higher confidence first, then the earlier start, then
/// the earlier end.
///
/// Deliberately differs from the anonymize engine's `priority_cmp`, which
/// breaks confidence ties by preferring the *longer* span. Presidio's
/// documented `REMOVE_INTERSECTIONS` behavior adjusts the **second** entity's
/// boundary on a tie, so the tie-break here is positional: the earlier-starting
/// span is authoritative and the later one is the one trimmed, regardless of
/// length. Containment-by-length is already handled by the two containment
/// strategies.
///
/// [`IdentifierType`](crate::primitives::identifiers::types::IdentifierType)
/// has no `Ord`, so it cannot serve as a final tie-break; matches identical in
/// all three keys retain their input order via the stability of `sort_by`.
fn priority_cmp(a: &IdentifierMatch, b: &IdentifierMatch) -> Ordering {
    b.confidence
        .cmp(&a.confidence)
        .then_with(|| a.start.cmp(&b.start))
        .then_with(|| a.end.cmp(&b.end))
}

/// Drops every match that is contained in another surviving match.
///
/// When `same_type_only` is true, containment is only considered between
/// matches sharing an [`IdentifierType`](crate::primitives::identifiers::types::IdentifierType);
/// when false, any type may absorb any other. Zero-width matches are dropped in
/// both modes.
///
/// Candidates are ordered longest-span-first so a container is always visited
/// before anything nested inside it. Ordering by [`priority_cmp`] would rank a
/// high-confidence *inner* span ahead of the lower-confidence span enclosing
/// it; because the loop only asks whether a candidate falls inside something
/// already kept, the container would then never be tested against it and both
/// spans would survive — the documented "longer wins" contract silently
/// violated whenever confidence disagreed with size.
///
/// Equal spans are broken by descending confidence, so an exact duplicate is
/// absorbed by its highest-confidence copy.
fn drop_contained(matches: Vec<IdentifierMatch>, same_type_only: bool) -> Vec<IdentifierMatch> {
    let mut by_span: Vec<IdentifierMatch> = matches.into_iter().filter(|m| !m.is_empty()).collect();
    by_span.sort_by(|a, b| {
        b.len()
            .cmp(&a.len())
            .then_with(|| b.confidence.cmp(&a.confidence))
            .then_with(|| a.start.cmp(&b.start))
    });

    let mut kept: Vec<IdentifierMatch> = Vec::new();
    for candidate in by_span {
        let absorbed = kept.iter().any(|k| {
            let type_matches = !same_type_only || k.identifier_type == candidate.identifier_type;
            type_matches && candidate.contained_in(k)
        });
        if !absorbed {
            kept.push(candidate);
        }
    }

    sort_by_position(&mut kept);
    kept
}

/// Keeps the highest-priority match intact and trims each lower-priority match
/// to its longest sub-range not covered by an already-kept match.
///
/// A match whose range is entirely covered is dropped. Trimmed matches have
/// their `matched_text` re-sliced from `text`.
fn remove_intersections(text: &str, matches: Vec<IdentifierMatch>) -> Vec<IdentifierMatch> {
    let mut by_priority: Vec<IdentifierMatch> =
        matches.into_iter().filter(|m| !m.is_empty()).collect();
    by_priority.sort_by(priority_cmp);

    let mut kept: Vec<IdentifierMatch> = Vec::new();
    for candidate in by_priority {
        let mut blockers: Vec<(usize, usize)> = kept
            .iter()
            .filter(|k| k.intersects(&candidate))
            .map(|k| (k.start, k.end))
            .collect();
        blockers.sort_unstable();

        let Some((start, end)) = longest_free_subrange(candidate.start, candidate.end, &blockers)
        else {
            continue;
        };

        // Snap unconditionally: a caller-supplied span may itself straddle a
        // character, and an unsnapped span cannot be sliced to refresh
        // `matched_text`.
        //
        // Both failure arms mean `text` does not correspond to the offsets the
        // matches were computed against. Dropping the match is fail-open for a
        // PII detector, so warn rather than vanish silently.
        let Some((start, end)) = snap_to_boundaries(text, start, end) else {
            warn_span_mismatch(candidate.start, candidate.end);
            continue;
        };
        let Some(slice) = text.get(start..end) else {
            warn_span_mismatch(candidate.start, candidate.end);
            continue;
        };

        let mut resolved = candidate;
        if start != resolved.start || end != resolved.end {
            // The span moved, so `matched_text` must follow it.
            resolved.matched_text = slice.to_string();
            resolved.start = start;
            resolved.end = end;
        }
        kept.push(resolved);
    }

    sort_by_position(&mut kept);
    kept
}

/// Reports a match dropped because its span could not be resolved against the
/// supplied text.
///
/// Logs offsets only — never the matched text, which is PII by construction.
fn warn_span_mismatch(start: usize, end: usize) {
    crate::observe::warn(
        "analyze_span_mismatch",
        format!(
            "dropped a match: span [{start}, {end}) does not resolve against the supplied text; \
             `resolve` must be given the exact text the matches were detected in"
        ),
    );
}

/// Snaps `[start, end)` inward to the nearest UTF-8 character boundaries.
///
/// Trim boundaries are derived from other matches' offsets, which are already
/// character boundaries in practice; this is a defensive floor for
/// caller-supplied spans. Snapping only ever shrinks the range, so a snapped
/// span can never re-introduce an overlap with an already-kept span. Returns
/// `None` when nothing survives.
fn snap_to_boundaries(text: &str, start: usize, end: usize) -> Option<(usize, usize)> {
    let mut start = start;
    let mut end = end.min(text.len());
    while start < end && !text.is_char_boundary(start) {
        start = start.saturating_add(1);
    }
    while end > start && !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    (start < end).then_some((start, end))
}

/// Returns the longest sub-range of `[start, end)` not covered by any of the
/// sorted `blockers`, or `None` if the whole range is covered.
///
/// Mirrors the anonymize engine's helper of the same name, over plain offsets.
fn longest_free_subrange(
    start: usize,
    end: usize,
    blockers: &[(usize, usize)],
) -> Option<(usize, usize)> {
    let mut best: Option<(usize, usize)> = None;
    let mut cursor = start;

    let consider = |from: usize, to: usize, best: &mut Option<(usize, usize)>| {
        if to > from {
            let len = to.saturating_sub(from);
            let is_better = best.is_none_or(|(bs, be)| be.saturating_sub(bs) < len);
            if is_better {
                *best = Some((from, to));
            }
        }
    };

    for &(blocker_start, blocker_end) in blockers {
        let gap_end = blocker_start.min(end);
        consider(cursor, gap_end, &mut best);
        cursor = cursor.max(blocker_end);
        if cursor >= end {
            break;
        }
    }
    consider(cursor, end, &mut best);

    best
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::primitives::identifiers::types::{DetectionConfidence, IdentifierType};

    /// Builds a match over `[start, end)`, slicing `matched_text` from `text`.
    fn m(
        text: &str,
        start: usize,
        end: usize,
        identifier_type: IdentifierType,
        confidence: DetectionConfidence,
    ) -> IdentifierMatch {
        let matched = text.get(start..end).unwrap_or_default().to_string();
        IdentifierMatch::new(start, end, matched, identifier_type, confidence)
    }

    fn email(text: &str, start: usize, end: usize) -> IdentifierMatch {
        m(
            text,
            start,
            end,
            IdentifierType::Email,
            DetectionConfidence::High,
        )
    }

    #[test]
    fn test_default_is_same_type_containment() {
        assert_eq!(
            ConflictResolution::default(),
            ConflictResolution::SameTypeContainment
        );
    }

    // ---- None -----------------------------------------------------------

    #[test]
    fn test_none_passes_overlaps_through_sorted() {
        let text = "aaaaaaaaaaaaaaaaaaaa";
        let matches = vec![email(text, 5, 15), email(text, 0, 10)];
        let out = ConflictResolution::None.resolve(text, matches);
        assert_eq!(out.len(), 2);
        assert_eq!(out.first().map(|x| x.start), Some(0));
        assert_eq!(out.get(1).map(|x| x.start), Some(5));
    }

    #[test]
    fn test_none_retains_zero_width_matches() {
        let text = "aaaaaaaaaa";
        let matches = vec![email(text, 3, 3)];
        let out = ConflictResolution::None.resolve(text, matches);
        assert_eq!(out.len(), 1);
    }

    // ---- Zero-width drop -------------------------------------------------

    #[test]
    fn test_zero_width_matches_are_dropped() {
        let text = "aaaaaaaaaa";
        for strategy in [
            ConflictResolution::SameTypeContainment,
            ConflictResolution::CrossTypeContainment,
            ConflictResolution::RemoveIntersections,
        ] {
            let out = strategy.resolve(text, vec![email(text, 4, 4)]);
            assert!(out.is_empty(), "{strategy:?} kept a zero-width match");
        }
    }

    // ---- SameTypeContainment --------------------------------------------

    #[test]
    fn test_same_type_drops_equal_span_duplicate() {
        let text = "aaaaaaaaaaaaaaaaaaaa";
        let matches = vec![email(text, 0, 10), email(text, 0, 10)];
        let out = ConflictResolution::SameTypeContainment.resolve(text, matches);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn test_same_type_keeps_longer_of_two() {
        let text = "aaaaaaaaaaaaaaaaaaaa";
        let matches = vec![email(text, 2, 6), email(text, 0, 12)];
        let out = ConflictResolution::SameTypeContainment.resolve(text, matches);
        assert_eq!(out.len(), 1);
        assert_eq!(out.first().map(|x| (x.start, x.end)), Some((0, 12)));
    }

    #[test]
    fn test_equal_span_duplicate_keeps_highest_confidence() {
        // Asserting the count alone would pass even if the tie-break inverted;
        // pin which copy survives.
        let text = "aaaaaaaaaaaaaaaaaaaa";
        let weak = m(text, 0, 10, IdentifierType::Email, DetectionConfidence::Low);
        let strong = m(
            text,
            0,
            10,
            IdentifierType::Email,
            DetectionConfidence::High,
        );
        let out = ConflictResolution::SameTypeContainment.resolve(text, vec![weak, strong]);
        assert_eq!(out.len(), 1);
        assert_eq!(
            out.first().map(|x| x.confidence.clone()),
            Some(DetectionConfidence::High)
        );
    }

    #[test]
    fn test_cross_type_collapses_equal_span_of_different_types() {
        // "regardless of type" covers equal spans, not just strict nesting.
        let text = "aaaaaaaaaaaaaaaaaaaa";
        let email = m(text, 0, 10, IdentifierType::Email, DetectionConfidence::Low);
        let phone = m(
            text,
            0,
            10,
            IdentifierType::PhoneNumber,
            DetectionConfidence::High,
        );
        let out = ConflictResolution::CrossTypeContainment.resolve(text, vec![email, phone]);
        assert_eq!(out.len(), 1);
        assert_eq!(
            out.first().map(|x| x.identifier_type.clone()),
            Some(IdentifierType::PhoneNumber)
        );
    }

    #[test]
    fn test_same_type_drops_contained_even_when_inner_scores_higher() {
        // Containment must not depend on visit order: the inner span carries
        // HIGHER confidence than the span enclosing it, so a confidence-first
        // ordering would visit the inner one first and never test the outer
        // one as a container.
        let text = "aaaaaaaaaaaaaaaaaaaa";
        let inner = m(text, 2, 6, IdentifierType::Email, DetectionConfidence::High);
        let outer = m(text, 0, 12, IdentifierType::Email, DetectionConfidence::Low);
        let out = ConflictResolution::SameTypeContainment.resolve(text, vec![inner, outer]);
        assert_eq!(
            out.len(),
            1,
            "contained span survived a longer same-type span"
        );
        assert_eq!(out.first().map(|x| (x.start, x.end)), Some((0, 12)));
    }

    #[test]
    fn test_cross_type_drops_contained_even_when_inner_scores_higher() {
        let text = "https://example.com/555-0123/path";
        let phone = m(
            text,
            20,
            28,
            IdentifierType::PhoneNumber,
            DetectionConfidence::High,
        );
        let url = m(text, 0, 33, IdentifierType::Url, DetectionConfidence::Low);
        let out = ConflictResolution::CrossTypeContainment.resolve(text, vec![phone, url]);
        assert_eq!(out.len(), 1);
        assert_eq!(out.first().map(|x| (x.start, x.end)), Some((0, 33)));
    }

    #[test]
    fn test_same_type_keeps_cross_type_containment() {
        // Presidio parity: a PhoneNumber inside a Url keeps BOTH.
        let text = "https://example.com/555-0123/path";
        let url = m(text, 0, 33, IdentifierType::Url, DetectionConfidence::High);
        let phone = m(
            text,
            20,
            28,
            IdentifierType::PhoneNumber,
            DetectionConfidence::High,
        );
        let out = ConflictResolution::SameTypeContainment.resolve(text, vec![url, phone]);
        assert_eq!(
            out.len(),
            2,
            "same-type strategy must not dedup across types"
        );
    }

    // ---- CrossTypeContainment -------------------------------------------

    #[test]
    fn test_cross_type_drops_phone_inside_url() {
        let text = "https://example.com/555-0123/path";
        let url = m(text, 0, 33, IdentifierType::Url, DetectionConfidence::High);
        let phone = m(
            text,
            20,
            28,
            IdentifierType::PhoneNumber,
            DetectionConfidence::High,
        );
        let out = ConflictResolution::CrossTypeContainment.resolve(text, vec![url, phone]);
        assert_eq!(out.len(), 1);
        assert_eq!(
            out.first().map(|x| x.identifier_type.clone()),
            Some(IdentifierType::Url)
        );
    }

    #[test]
    fn test_cross_type_keeps_partial_overlap() {
        // Containment is not intersection: partial overlap survives.
        let text = "aaaaaaaaaaaaaaaaaaaa";
        let a = m(text, 0, 10, IdentifierType::Url, DetectionConfidence::High);
        let b = m(
            text,
            5,
            15,
            IdentifierType::PhoneNumber,
            DetectionConfidence::High,
        );
        let out = ConflictResolution::CrossTypeContainment.resolve(text, vec![a, b]);
        assert_eq!(out.len(), 2);
    }

    // ---- RemoveIntersections --------------------------------------------

    #[test]
    fn test_remove_intersections_trims_lower_confidence() {
        let text = "abcdefghijklmnopqrst";
        let strong = m(
            text,
            0,
            10,
            IdentifierType::Email,
            DetectionConfidence::High,
        );
        let weak = m(
            text,
            5,
            15,
            IdentifierType::PhoneNumber,
            DetectionConfidence::Low,
        );
        let out = ConflictResolution::RemoveIntersections.resolve(text, vec![strong, weak]);
        assert_eq!(out.len(), 2);
        assert_eq!(out.first().map(|x| (x.start, x.end)), Some((0, 10)));
        assert_eq!(out.get(1).map(|x| (x.start, x.end)), Some((10, 15)));
    }

    #[test]
    fn test_remove_intersections_reslices_matched_text() {
        let text = "abcdefghijklmnopqrst";
        let strong = m(
            text,
            0,
            10,
            IdentifierType::Email,
            DetectionConfidence::High,
        );
        let weak = m(
            text,
            5,
            15,
            IdentifierType::PhoneNumber,
            DetectionConfidence::Low,
        );
        let out = ConflictResolution::RemoveIntersections.resolve(text, vec![strong, weak]);
        for found in &out {
            assert_eq!(
                Some(found.matched_text.as_str()),
                text.get(found.start..found.end),
                "matched_text drifted from its span"
            );
        }
    }

    #[test]
    fn test_remove_intersections_tie_break_adjusts_second_entity() {
        // Equal confidence: the earlier span stays intact, the later is trimmed.
        let text = "abcdefghijklmnopqrst";
        let first = m(
            text,
            0,
            10,
            IdentifierType::Email,
            DetectionConfidence::High,
        );
        let second = m(
            text,
            5,
            15,
            IdentifierType::PhoneNumber,
            DetectionConfidence::High,
        );
        let out = ConflictResolution::RemoveIntersections.resolve(text, vec![second, first]);
        assert_eq!(out.first().map(|x| (x.start, x.end)), Some((0, 10)));
        assert_eq!(out.get(1).map(|x| (x.start, x.end)), Some((10, 15)));
    }

    #[test]
    fn test_remove_intersections_drops_fully_covered_span() {
        let text = "abcdefghijklmnopqrst";
        let outer = m(text, 0, 20, IdentifierType::Url, DetectionConfidence::High);
        let inner = m(
            text,
            5,
            10,
            IdentifierType::PhoneNumber,
            DetectionConfidence::Low,
        );
        let out = ConflictResolution::RemoveIntersections.resolve(text, vec![outer, inner]);
        assert_eq!(out.len(), 1);
        assert_eq!(out.first().map(|x| (x.start, x.end)), Some((0, 20)));
    }

    #[test]
    fn test_remove_intersections_handles_multibyte_text() {
        // "héllo wörld…" — the 'é' occupies bytes 1..3 and the 'ö' bytes 8..10,
        // so byte offsets 2 and 9 fall *inside* a character. A kept span ending
        // at byte 2 forces the trimmed span to start mid-character, exercising
        // the inward snap.
        let text = "héllo wörld and more";
        assert!(!text.is_char_boundary(2), "test premise: 2 is mid-char");

        let strong = m(text, 0, 2, IdentifierType::Email, DetectionConfidence::High);
        let weak = m(
            text,
            0,
            11,
            IdentifierType::PhoneNumber,
            DetectionConfidence::Low,
        );
        let out = ConflictResolution::RemoveIntersections.resolve(text, vec![strong, weak]);

        for found in &out {
            assert!(
                text.is_char_boundary(found.start) && text.is_char_boundary(found.end),
                "span [{}, {}) landed off a char boundary",
                found.start,
                found.end
            );
            assert_eq!(
                Some(found.matched_text.as_str()),
                text.get(found.start..found.end),
                "matched_text drifted from its span"
            );
        }
        // The kept span's off-boundary end (2) snapped back to 1, so the
        // trimmed span picks up from there rather than splitting the 'é'.
        assert_eq!(out.first().map(|x| (x.start, x.end)), Some((0, 1)));
        assert_eq!(out.get(1).map(|x| (x.start, x.end)), Some((1, 11)));
    }

    #[test]
    fn test_remove_intersections_drops_span_outside_text() {
        // Offsets that do not resolve against `text` (a caller passing the
        // wrong string) drop the match rather than panicking.
        let text = "short";
        let bogus = m(
            "a much longer original string",
            10,
            20,
            IdentifierType::Email,
            DetectionConfidence::High,
        );
        let out = ConflictResolution::RemoveIntersections.resolve(text, vec![bogus]);
        assert!(out.is_empty());
    }

    #[test]
    fn test_remove_intersections_keeps_only_the_longest_fragment() {
        // Two blockers split the candidate's interior into two free gaps.
        // Only the longer survives — the shorter is dropped outright, not
        // emitted as a second match. Pinned because it narrows PII coverage.
        let text = "abcdefghijklmnopqrst";
        let left = m(text, 0, 4, IdentifierType::Url, DetectionConfidence::High);
        let right = m(text, 8, 10, IdentifierType::Url, DetectionConfidence::High);
        let candidate = m(
            text,
            0,
            20,
            IdentifierType::PhoneNumber,
            DetectionConfidence::Low,
        );
        let out =
            ConflictResolution::RemoveIntersections.resolve(text, vec![left, right, candidate]);

        // Gaps are [4,8) (len 4) and [10,20) (len 10); the latter wins.
        assert_eq!(out.len(), 3);
        let trimmed: Vec<(usize, usize)> = out
            .iter()
            .filter(|x| x.identifier_type == IdentifierType::PhoneNumber)
            .map(|x| (x.start, x.end))
            .collect();
        assert_eq!(trimmed, vec![(10, 20)], "expected only the longest gap");
    }

    #[test]
    fn test_remove_intersections_walks_multiple_blockers() {
        // Exercises the cursor advance across more than one blocker: the only
        // free range is the middle gap.
        let text = "abcdefghijklmnopqrst";
        let head = m(text, 0, 5, IdentifierType::Url, DetectionConfidence::High);
        let tail = m(text, 15, 20, IdentifierType::Url, DetectionConfidence::High);
        let candidate = m(
            text,
            0,
            20,
            IdentifierType::PhoneNumber,
            DetectionConfidence::Low,
        );
        let out =
            ConflictResolution::RemoveIntersections.resolve(text, vec![head, tail, candidate]);
        let trimmed: Vec<(usize, usize)> = out
            .iter()
            .filter(|x| x.identifier_type == IdentifierType::PhoneNumber)
            .map(|x| (x.start, x.end))
            .collect();
        assert_eq!(trimmed, vec![(5, 15)]);
    }

    #[test]
    fn test_containment_strategies_pass_through_unresolvable_spans() {
        // The documented contract: only RemoveIntersections validates against
        // `text`. The other three pass an out-of-bounds span through untouched.
        let text = "short";
        let bogus = m(
            "a much longer original string",
            10,
            20,
            IdentifierType::Email,
            DetectionConfidence::High,
        );
        for strategy in [
            ConflictResolution::None,
            ConflictResolution::SameTypeContainment,
            ConflictResolution::CrossTypeContainment,
        ] {
            let out = strategy.resolve(text, vec![bogus.clone()]);
            assert_eq!(out.len(), 1, "{strategy:?} dropped an out-of-bounds span");
            assert_eq!(out.first().map(|x| (x.start, x.end)), Some((10, 20)));
        }
    }

    #[test]
    fn test_snap_to_boundaries_moves_inward() {
        let text = "héllo";
        // 2 is inside 'é' (bytes 1..3); snapping start moves forward to 3.
        assert_eq!(snap_to_boundaries(text, 2, 5), Some((3, 5)));
        // Snapping an end offset moves it backward to 1.
        assert_eq!(snap_to_boundaries(text, 0, 2), Some((0, 1)));
        // Already-aligned offsets are untouched.
        assert_eq!(snap_to_boundaries(text, 0, 5), Some((0, 5)));
        // An end past the text is clamped.
        assert_eq!(snap_to_boundaries(text, 0, 999), Some((0, text.len())));
        // Nothing survives a collapsed range.
        assert_eq!(snap_to_boundaries(text, 3, 3), None);
    }

    // =========================================================================
    // resolve_results — the RecognizerResult form used by the analyze pipeline
    // =========================================================================

    /// Builds a result carrying `recognizer` provenance, so a pass that drops
    /// metadata is visible rather than merely suspected.
    fn rr(entity_type: &str, start: usize, end: usize, score: f64) -> RecognizerResult {
        let mut metadata = std::collections::HashMap::new();
        metadata.insert(
            "recognizer_name".to_string(),
            serde_json::Value::String("test-recognizer".to_string()),
        );
        RecognizerResult::new(entity_type, start, end, score)
            .expect("test span and score are valid")
            .with_metadata(metadata)
    }

    fn spans(results: &[RecognizerResult]) -> Vec<(&str, usize, usize)> {
        results
            .iter()
            .map(|r| (r.entity_type.as_str(), r.start, r.end))
            .collect()
    }

    #[test]
    fn results_same_type_containment_keeps_only_the_longer_span() {
        let text = "user@example.com";
        let out = ConflictResolution::SameTypeContainment.resolve_results(
            text,
            vec![
                rr("EMAIL_ADDRESS", 0, 16, 0.8),
                rr("EMAIL_ADDRESS", 5, 12, 0.9),
            ],
        );

        assert_eq!(
            spans(&out),
            vec![("EMAIL_ADDRESS", 0, 16)],
            "the nested same-type span must lose to the longer one even though it scored higher"
        );
    }

    #[test]
    fn results_same_type_containment_keeps_a_nested_different_type() {
        // Presidio parity: a PHONE_NUMBER inside a URL keeps both.
        let text = "https://x.com/555-123-4567";
        let out = ConflictResolution::SameTypeContainment.resolve_results(
            text,
            vec![rr("URL", 0, 26, 0.8), rr("PHONE_NUMBER", 14, 26, 0.9)],
        );

        assert_eq!(
            spans(&out),
            vec![("URL", 0, 26), ("PHONE_NUMBER", 14, 26)],
            "cross-type containment must survive the same-type strategy"
        );
    }

    #[test]
    fn results_cross_type_containment_absorbs_the_nested_span() {
        let text = "https://x.com/555-123-4567";
        let out = ConflictResolution::CrossTypeContainment.resolve_results(
            text,
            vec![rr("URL", 0, 26, 0.8), rr("PHONE_NUMBER", 14, 26, 0.9)],
        );

        assert_eq!(
            spans(&out),
            vec![("URL", 0, 26)],
            "cross-type containment must drop the nested span regardless of type"
        );
    }

    #[test]
    fn results_dedup_preserves_recognition_metadata() {
        // The reason resolve_results exists: converting through
        // IdentifierMatch and back would silently drop this.
        let text = "user@example.com";
        let out = ConflictResolution::SameTypeContainment.resolve_results(
            text,
            vec![
                rr("EMAIL_ADDRESS", 0, 16, 0.8),
                rr("EMAIL_ADDRESS", 5, 12, 0.9),
            ],
        );

        let survivor = out.first().expect("one result should survive");
        let metadata = survivor
            .recognition_metadata
            .as_ref()
            .expect("recognition_metadata must survive the dedup pass");
        assert_eq!(
            metadata.get("recognizer_name").and_then(|v| v.as_str()),
            Some("test-recognizer"),
        );
    }

    #[test]
    fn results_none_preserves_every_span_sorted() {
        let text = "user@example.com";
        let out = ConflictResolution::None.resolve_results(
            text,
            vec![
                rr("EMAIL_ADDRESS", 5, 12, 0.9),
                rr("EMAIL_ADDRESS", 0, 16, 0.8),
            ],
        );

        assert_eq!(
            spans(&out),
            vec![("EMAIL_ADDRESS", 0, 16), ("EMAIL_ADDRESS", 5, 12)],
            "None is a pass-through that only sorts"
        );
    }

    #[test]
    fn results_zero_width_dropped_by_every_strategy_but_none() {
        let text = "user@example.com";
        let zero = vec![rr("EMAIL_ADDRESS", 4, 4, 0.9)];

        assert!(
            ConflictResolution::SameTypeContainment
                .resolve_results(text, zero.clone())
                .is_empty(),
            "a zero-width span covers no text and cannot be redacted"
        );
        assert_eq!(
            ConflictResolution::None.resolve_results(text, zero).len(),
            1,
            "None retains zero-width spans by contract"
        );
    }

    #[test]
    fn results_remove_intersections_trims_the_lower_scoring_span() {
        let text = "aaaaaaaaaaaaaaaaaaaa";
        let out = ConflictResolution::RemoveIntersections
            .resolve_results(text, vec![rr("A", 0, 10, 0.9), rr("B", 5, 15, 0.5)]);

        assert_eq!(
            spans(&out),
            vec![("A", 0, 10), ("B", 10, 15)],
            "the higher-scoring span stays intact; the lower one is trimmed off its overlap"
        );
    }
}
