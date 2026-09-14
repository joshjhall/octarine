//! Engine-level allow-listing for the Layer 3 `analyze` pipeline.
//!
//! An [`AllowList`] suppresses detections whose matched text the caller has
//! declared a known false positive — a documented sample SSN, a placeholder
//! email in a fixture, an internal identifier that merely *looks* like PII.
//!
//! # Why this is not "just disable the recognizer"
//!
//! The two blunt alternatives both cost something. Disabling a recognizer
//! throws away its real detections along with the false positive; post-filtering
//! the returned results throws away the decision-process trail that
//! [`AnalyzeRequest::with_decision_process`](crate::analyze::AnalyzeRequest::with_decision_process)
//! exists to provide. Allow-listing inside the pipeline keeps both: every other
//! detection is scored, enhanced, and reconciled exactly as before.
//!
//! # Case sensitivity
//!
//! [`AllowList::Exact`] matching is **case-sensitive**, matching Presidio. An
//! allow-list holding `"Test@Example.com"` does not suppress a detection of
//! `"test@example.com"`. A case-insensitive variant is deliberately absent
//! rather than guessed at.
//!
//! # Examples
//!
//! ```
//! use octarine::analyze::{AllowList, AllowDecision};
//!
//! let allow = AllowList::exact(["test@example.com"]);
//! assert_eq!(allow.is_allowed("test@example.com"), AllowDecision::Allowed);
//! assert_eq!(allow.is_allowed("real@corp.com"), AllowDecision::NotAllowed);
//! ```

use std::collections::HashSet;
use std::time::{Duration, Instant};

use regex::{Regex, RegexBuilder};

use crate::observe::{Problem, Result};

/// Presidio's `REGEX_TIMEOUT_SECONDS`, used when no budget is given.
const DEFAULT_REGEX_BUDGET: Duration = Duration::from_secs(60);

/// Compiled-program ceiling for an allow-list pattern.
///
/// A pattern that will not fit is rejected at construction, where the caller
/// can see it, rather than becoming a per-call cost on every analysis run.
const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// Whether a matched span is allow-listed, or whether the check ran out of budget.
///
/// The third state is the point of this type. A plain `bool` cannot distinguish
/// "this text is not on the allow-list" from "the check did not finish", and
/// those two demand opposite handling: the first suppresses the detection, the
/// second must **keep** it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowDecision {
    /// The text is allow-listed; the detection should be suppressed.
    Allowed,
    /// The text is not allow-listed; the detection stands.
    NotAllowed,
    /// The check exceeded its budget. The detection **must be kept**.
    BudgetExceeded,
}

/// A set of strings whose detections are suppressed.
///
/// Mirrors Presidio's `allow_list` + `allow_list_match` pair: [`Exact`] is set
/// membership, [`Regex`] is a single compiled pattern.
///
/// [`Exact`]: AllowList::Exact
/// [`Regex`]: AllowList::Regex
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use octarine::analyze::{AllowList, AllowDecision};
///
/// // Exact: set membership, case-sensitive.
/// let exact = AllowList::exact(["555-12-3456"]);
/// assert_eq!(exact.is_allowed("555-12-3456"), AllowDecision::Allowed);
///
/// // Regex: one compiled pattern, bounded by a time budget.
/// let pattern = AllowList::regex(r"^\d{3}-\d{2}-0000$", Duration::from_secs(1))?;
/// assert_eq!(pattern.is_allowed("123-45-0000"), AllowDecision::Allowed);
/// assert_eq!(pattern.is_allowed("123-45-6789"), AllowDecision::NotAllowed);
/// # Ok::<(), octarine::observe::Problem>(())
/// ```
#[derive(Debug, Clone, Default)]
pub enum AllowList {
    /// No allow-listing; every detection stands.
    #[default]
    None,
    /// Suppress a detection whose matched text is in this set, exactly.
    Exact(HashSet<String>),
    /// Suppress a detection whose matched text the pattern finds.
    Regex {
        /// The compiled pattern.
        regex: Box<Regex>,
        /// Wall-clock ceiling for one match attempt.
        budget: Duration,
    },
}

/// Compares by pattern source and budget.
///
/// [`Regex`](regex::Regex) is not [`PartialEq`], so the comparison is on the
/// pattern text — two `AllowList`s built from the same source with the same
/// budget are equal, which is what a caller comparing requests means.
impl PartialEq for AllowList {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::None, Self::None) => true,
            (Self::Exact(lhs), Self::Exact(rhs)) => lhs == rhs,
            (
                Self::Regex {
                    regex: lhs,
                    budget: lhs_budget,
                },
                Self::Regex {
                    regex: rhs,
                    budget: rhs_budget,
                },
            ) => lhs.as_str() == rhs.as_str() && lhs_budget == rhs_budget,
            _ => false,
        }
    }
}

impl AllowList {
    /// An allow-list that allows nothing.
    #[must_use]
    pub fn none() -> Self {
        Self::None
    }

    /// Builds an exact-match allow-list from `entries`.
    ///
    /// Matching is case-sensitive; see the module docs.
    #[must_use]
    pub fn exact<I, S>(entries: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::Exact(entries.into_iter().map(Into::into).collect())
    }

    /// Compiles `pattern` into a regex allow-list bounded by `budget`.
    ///
    /// The pattern is compiled **once**, here, rather than per analysis call.
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Validation`] if `pattern` is not a valid regex, or if
    /// its compiled program would exceed the size ceiling — a runaway pattern
    /// is rejected where the caller wrote it, not on every later run.
    pub fn regex(pattern: &str, budget: Duration) -> Result<Self> {
        let regex = RegexBuilder::new(pattern)
            .size_limit(REGEX_SIZE_LIMIT)
            .dfa_size_limit(REGEX_SIZE_LIMIT)
            .build()
            .map_err(|e| Problem::Validation(format!("Invalid allow-list regex pattern: {e}")))?;
        Ok(Self::Regex {
            regex: Box::new(regex),
            budget,
        })
    }

    /// Compiles `pattern` with Presidio's default 60-second budget.
    ///
    /// # Errors
    ///
    /// See [`regex`](Self::regex).
    pub fn regex_with_default_budget(pattern: &str) -> Result<Self> {
        Self::regex(pattern, DEFAULT_REGEX_BUDGET)
    }

    /// Whether this allow-list suppresses nothing.
    ///
    /// The pipeline uses this to skip the pass entirely.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match self {
            Self::None => true,
            Self::Exact(entries) => entries.is_empty(),
            Self::Regex { .. } => false,
        }
    }

    /// Decides whether `matched_text` is allow-listed.
    ///
    /// # The budget
    ///
    /// Rust's regex engine matches in time linear in the input, so catastrophic
    /// backtracking — the ReDoS shape a timeout usually guards — is not
    /// reachable here. The budget is a backstop for the remaining cost of a
    /// very large pattern over a very long span, and is checked around the
    /// match rather than inside it, because the crate exposes no interruptible
    /// deadline. A trip returns [`AllowDecision::BudgetExceeded`], and the
    /// caller **keeps** the detection.
    ///
    /// The comparison is `elapsed >= budget`, so a [`Duration::ZERO`] budget
    /// always trips — "no time allowed" is a meaningful setting, and making it
    /// deterministic keeps the guard from depending on clock resolution.
    #[must_use]
    pub fn is_allowed(&self, matched_text: &str) -> AllowDecision {
        match self {
            Self::None => AllowDecision::NotAllowed,
            Self::Exact(entries) => {
                if entries.contains(matched_text) {
                    AllowDecision::Allowed
                } else {
                    AllowDecision::NotAllowed
                }
            }
            Self::Regex { regex, budget } => {
                let started = Instant::now();
                let matched = regex.is_match(matched_text);
                // `>=`, not `>`: a zero budget means "no time allowed" and must
                // trip deterministically. With `>` it would depend on two
                // monotonic clock reads differing, which a coarse-resolution
                // platform can tie — turning the fail-closed guard into a
                // timing accident.
                if started.elapsed() >= *budget {
                    return AllowDecision::BudgetExceeded;
                }
                if matched {
                    AllowDecision::Allowed
                } else {
                    AllowDecision::NotAllowed
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn none_allows_nothing() {
        let allow = AllowList::none();
        assert_eq!(allow.is_allowed("anything"), AllowDecision::NotAllowed);
        assert_eq!(allow.is_allowed(""), AllowDecision::NotAllowed);
        assert!(allow.is_empty());
    }

    #[test]
    fn exact_matches_only_full_entries() {
        let allow = AllowList::exact(["test@example.com", "555-12-3456"]);

        assert_eq!(allow.is_allowed("test@example.com"), AllowDecision::Allowed);
        assert_eq!(allow.is_allowed("555-12-3456"), AllowDecision::Allowed);
        // A substring of an entry is not an entry.
        assert_eq!(allow.is_allowed("test@example"), AllowDecision::NotAllowed);
        // Nor is a superstring.
        assert_eq!(
            allow.is_allowed("not-test@example.com"),
            AllowDecision::NotAllowed
        );
    }

    #[test]
    fn exact_is_case_sensitive() {
        // Presidio parity: only an exact byte match suppresses. If this ever
        // becomes case-insensitive it must be a new variant, not a silent
        // widening of this one.
        let allow = AllowList::exact(["Test@Example.com"]);

        assert_eq!(allow.is_allowed("Test@Example.com"), AllowDecision::Allowed);
        assert_eq!(
            allow.is_allowed("test@example.com"),
            AllowDecision::NotAllowed,
            "a case-differing string must not be suppressed"
        );
        assert_eq!(
            allow.is_allowed("TEST@EXAMPLE.COM"),
            AllowDecision::NotAllowed
        );
    }

    #[test]
    fn empty_exact_set_suppresses_nothing() {
        let allow = AllowList::exact(Vec::<String>::new());
        assert!(allow.is_empty());
        assert_eq!(allow.is_allowed("anything"), AllowDecision::NotAllowed);
    }

    #[test]
    fn regex_suppresses_matches_and_spares_non_matches() {
        let allow =
            AllowList::regex(r"^\d{3}-\d{2}-0000$", Duration::from_secs(5)).expect("valid pattern");

        assert_eq!(allow.is_allowed("123-45-0000"), AllowDecision::Allowed);
        assert_eq!(
            allow.is_allowed("123-45-6789"),
            AllowDecision::NotAllowed,
            "a real SSN-shaped value must survive a reserved-block pattern"
        );
        assert!(!allow.is_empty());
    }

    #[test]
    fn regex_is_unanchored_unless_the_pattern_anchors_itself() {
        // The pass hands over exactly the matched span, so an unanchored
        // pattern matching a substring is the caller's choice, not a surprise.
        let allow = AllowList::regex("example", Duration::from_secs(5)).expect("valid pattern");
        assert_eq!(allow.is_allowed("user@example.com"), AllowDecision::Allowed);
        assert_eq!(allow.is_allowed("user@corp.com"), AllowDecision::NotAllowed);
    }

    #[test]
    fn an_invalid_pattern_is_rejected_at_construction() {
        let outcome = AllowList::regex("(unclosed", Duration::from_secs(1));
        assert!(
            outcome.is_err(),
            "a malformed pattern must fail where it is written, not at match time"
        );
    }

    #[test]
    fn an_oversized_pattern_is_rejected_at_construction() {
        // Deeply-nested bounded repetition blows past the compiled-size ceiling.
        let pattern = r"((((((((((a{100}){100}){100}){100}){100}){100}){100}){100}){100}){100})";
        let outcome = AllowList::regex(pattern, Duration::from_secs(1));
        assert!(
            outcome.is_err(),
            "a pattern exceeding the size limit must be rejected at construction"
        );
    }

    #[test]
    fn a_zero_budget_always_trips_regardless_of_clock_resolution() {
        // "No time allowed" must be a deterministic outcome, not a race against
        // clock granularity: `>=` makes a zero budget trip on every platform.
        // The pattern below WOULD match, so a dropped budget check flips this
        // to Allowed and the test goes red.
        let allow = AllowList::regex("^exact$", Duration::ZERO).expect("valid pattern");
        for _ in 0..100 {
            assert_eq!(
                allow.is_allowed("exact"),
                AllowDecision::BudgetExceeded,
                "a zero budget must trip every time, not merely usually"
            );
        }
    }

    #[test]
    fn a_generous_budget_does_not_trip() {
        // The mirror of the test above: `>=` must not make every check trip.
        let allow = AllowList::regex("^exact$", Duration::from_secs(3600)).expect("valid pattern");
        assert_eq!(allow.is_allowed("exact"), AllowDecision::Allowed);
        assert_eq!(allow.is_allowed("other"), AllowDecision::NotAllowed);
    }

    #[test]
    fn default_budget_pattern_compiles() {
        let allow = AllowList::regex_with_default_budget("^placeholder$").expect("valid pattern");
        assert_eq!(allow.is_allowed("placeholder"), AllowDecision::Allowed);
    }

    #[test]
    fn equality_compares_pattern_source_and_budget() {
        let one = AllowList::regex("^a$", Duration::from_secs(1)).expect("valid");
        let same = AllowList::regex("^a$", Duration::from_secs(1)).expect("valid");
        let other_pattern = AllowList::regex("^b$", Duration::from_secs(1)).expect("valid");
        let other_budget = AllowList::regex("^a$", Duration::from_secs(2)).expect("valid");

        assert_eq!(one, same);
        assert_ne!(one, other_pattern);
        assert_ne!(
            one, other_budget,
            "a differing budget is a differing allow-list"
        );
        assert_ne!(one, AllowList::None);
        assert_eq!(AllowList::None, AllowList::None);
    }

    #[test]
    fn default_is_none() {
        assert_eq!(AllowList::default(), AllowList::None);
    }
}
