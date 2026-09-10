//! Prompt construction for entity detection.
//!
//! The system prompt is deliberately **static for a given entity set**: it is
//! the portion marked cache-eligible, and prompt caching only pays off if the
//! prefix is byte-identical across calls. Anything varying per call — the text
//! under analysis — belongs in the user prompt.

use octarine::identifiers::IdentifierType;

/// Builds the cache-eligible system prompt for a set of entity types.
///
/// Passing an empty slice asks for every type the recognizer supports, matching
/// [`Recognizer::analyze`](octarine::analyze::Recognizer::analyze)'s contract.
///
/// The prompt asks for the matched **text** rather than character offsets.
/// Models are unreliable at counting positions but reliable at quoting what
/// they found, so offsets are recovered locally by
/// [`anchor`](super::parse::anchor) — a substring search that either succeeds
/// exactly or is discarded. A hallucinated offset would silently redact the
/// wrong span; a hallucinated quote simply fails to anchor.
#[must_use]
pub fn system_prompt(entities: &[IdentifierType]) -> String {
    let wanted = if entities.is_empty() {
        "every category of personally identifiable information you recognize".to_string()
    } else {
        entity_list(entities)
    };

    format!(
        "You are a precise PII detection engine. Identify occurrences of {wanted} \
in the text supplied by the user.\n\
\n\
Respond with a JSON object and nothing else — no prose, no markdown fences. \
The object has one key, \"entities\", whose value is an array. Each array item \
has exactly these keys:\n\
  \"type\":  a SCREAMING_SNAKE_CASE entity label, e.g. EMAIL_ADDRESS\n\
  \"text\":  the matched substring, copied VERBATIM from the input\n\
  \"score\": your confidence, a number between 0.0 and 1.0\n\
\n\
Rules:\n\
- \"text\" must be an exact substring of the input. Do not normalize case, \
trim punctuation, expand abbreviations, or correct apparent typos.\n\
- Report each occurrence separately, including repeats of the same value.\n\
- If you find nothing, return {{\"entities\": []}}.\n\
- Never include commentary, explanations, or the input text itself."
    )
}

/// Renders the requested entity types as a readable, stable list.
///
/// Order follows the caller's slice so the prompt stays byte-stable for a
/// given request, preserving cache hits.
fn entity_list(entities: &[IdentifierType]) -> String {
    let labels: Vec<String> = entities.iter().map(|e| format!("{e:?}")).collect();
    format!("the following PII categories: {}", labels.join(", "))
}

/// Builds the per-call user prompt.
///
/// The text is fenced by sentinel lines so the model can tell input from
/// instructions. This is a clarity aid, not a security boundary: text
/// containing the sentinel is still just analyzed, never executed, because the
/// only thing done with the response is a substring search back into this same
/// input.
#[must_use]
pub fn user_prompt(text: &str) -> String {
    format!("<<<BEGIN TEXT>>>\n{text}\n<<<END TEXT>>>")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    #[test]
    fn empty_entity_slice_asks_for_everything_not_nothing() {
        let prompt = system_prompt(&[]);
        assert!(
            prompt.contains("every category"),
            "an empty slice must broaden the request, not empty it"
        );
        assert!(
            !prompt.contains("the following PII categories"),
            "must not render an empty explicit list"
        );
    }

    #[test]
    fn named_entities_appear_in_the_prompt() {
        let prompt = system_prompt(&[IdentifierType::Email, IdentifierType::CreditCard]);
        assert!(prompt.contains("Email"), "requested type must be named");
        assert!(
            prompt.contains("CreditCard"),
            "requested type must be named"
        );
        assert!(
            !prompt.contains("every category"),
            "an explicit list must not also request everything"
        );
    }

    #[test]
    fn prompt_is_byte_stable_for_the_same_entity_set() {
        // Cache hits depend on this exactly.
        let a = system_prompt(&[IdentifierType::Email, IdentifierType::Ssn]);
        let b = system_prompt(&[IdentifierType::Email, IdentifierType::Ssn]);
        assert_eq!(a, b, "identical input must produce identical bytes");
    }

    #[test]
    fn prompt_asks_for_verbatim_text_not_offsets() {
        // The anchoring strategy depends on the model quoting, not counting.
        let prompt = system_prompt(&[IdentifierType::Email]);
        assert!(prompt.contains("VERBATIM"));
        assert!(
            !prompt.to_lowercase().contains("offset"),
            "asking for offsets would invite unverifiable hallucinated positions"
        );
    }

    #[test]
    fn json_braces_survive_format_escaping() {
        // `{{` / `}}` in the format string must render as real braces.
        let prompt = system_prompt(&[]);
        assert!(
            prompt.contains(r#"{"entities": []}"#),
            "the empty-result example must render as literal JSON"
        );
    }

    #[test]
    fn user_prompt_fences_the_text_and_preserves_it_exactly() {
        let text = "Contact: alice@example.com";
        let prompt = user_prompt(text);
        assert!(prompt.contains("<<<BEGIN TEXT>>>"));
        assert!(prompt.contains("<<<END TEXT>>>"));
        assert!(
            prompt.contains(text),
            "the analyzed text must pass through unmodified"
        );
    }
}
