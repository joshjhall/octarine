//! Turning a model's response into anchored [`RecognizerResult`]s.
//!
//! Two problems to solve, in order.
//!
//! # 1. Getting JSON out of the response
//!
//! Providers with a structured-output mode return a bare JSON object. Providers
//! without one return the object wrapped in prose, a markdown fence, or both.
//! [`extract_json`] handles all three so the recognizer does not need to know
//! which kind of provider it is talking to.
//!
//! # 2. Getting offsets the model never gave us
//!
//! The prompt asks for the matched *text*, not offsets — models quote reliably
//! and count unreliably. [`anchor`] recovers positions by searching the original
//! input for each quoted string.
//!
//! This is what makes hallucination safe to handle: a value the model invented
//! is not present in the input, so it fails to anchor and is **dropped**. Had we
//! trusted model-supplied offsets, the same hallucination would have redacted a
//! real, unrelated span. Anchoring converts a correctness hazard into a
//! recall miss.

use octarine::anonymize::RecognizerResult;
use octarine_problem::{Problem, Result};
use serde::Deserialize;

/// One entity as reported by the model, before anchoring.
#[derive(Debug, Clone, Deserialize)]
pub struct RawEntity {
    /// Entity label, e.g. `"EMAIL_ADDRESS"`.
    #[serde(rename = "type")]
    pub entity_type: String,
    /// The matched substring, expected to appear verbatim in the input.
    pub text: String,
    /// Model confidence. Defaults to `0.5` when omitted — neither trusted nor
    /// discarded, since the model declining to score is not evidence either way.
    #[serde(default = "default_score")]
    pub score: f64,
}

/// Score assigned when the model omits one.
fn default_score() -> f64 {
    0.5
}

/// The response envelope the prompt asks for.
#[derive(Debug, Clone, Deserialize)]
struct DetectionEnvelope {
    #[serde(default)]
    entities: Vec<RawEntity>,
}

/// Extracts the JSON object from a model response.
///
/// Accepts, in order of preference: a bare JSON document, a ```json fenced
/// block, or an object embedded in surrounding prose (located by brace
/// matching). Returns the raw JSON text.
///
/// # Errors
///
/// Returns [`Problem::Parse`] when no balanced JSON object can be located.
pub fn extract_json(content: &str) -> Result<&str> {
    let trimmed = content.trim();
    if trimmed.starts_with('{') {
        return Ok(trimmed);
    }
    find_balanced_object(trimmed).ok_or_else(|| {
        Problem::Parse(format!(
            "no JSON object found in model response: {}",
            trimmed.chars().take(120).collect::<String>()
        ))
    })
}

/// Finds the first balanced `{...}` region, ignoring braces inside strings.
///
/// String-awareness matters: a naive brace count is thrown off by a payload
/// like `{"text": "}"}`, which is exactly the shape a PII detector sees when the
/// analyzed text contains punctuation.
fn find_balanced_object(text: &str) -> Option<&str> {
    let start = text.find('{')?;
    let mut depth = 0usize;
    let mut in_string = false;
    let mut escaped = false;

    for (offset, ch) in text.char_indices().skip_while(|(i, _)| *i < start) {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '{' => depth = depth.saturating_add(1),
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    let end = offset.saturating_add(ch.len_utf8());
                    return text.get(start..end);
                }
            }
            _ => {}
        }
    }
    None
}

/// Parses a model response into raw, un-anchored entities.
///
/// # Errors
///
/// Returns [`Problem::Parse`] when no JSON object is present or the object does
/// not match the expected envelope.
pub fn parse_entities(content: &str) -> Result<Vec<RawEntity>> {
    let json = extract_json(content)?;
    let envelope: DetectionEnvelope = serde_json::from_str(json)
        .map_err(|e| Problem::Parse(format!("model response was not valid detection JSON: {e}")))?;
    Ok(envelope.entities)
}

/// Anchors raw entities to byte offsets in `text`, dropping those that do not
/// appear in it.
///
/// Repeated occurrences of the same value anchor to successive positions rather
/// than all collapsing onto the first: the model reports each occurrence
/// separately, so consuming them left to right keeps the count honest.
///
/// Returns the anchored results and the number dropped for failing to anchor —
/// the caller records that count as a hallucination signal.
///
/// # Errors
///
/// Returns [`Problem::Validation`] if a score is outside `[0.0, 1.0]` or an
/// entity type is empty, surfaced by [`RecognizerResult::new`].
pub fn anchor(text: &str, raw: Vec<RawEntity>) -> Result<(Vec<RecognizerResult>, usize)> {
    // Per distinct value, where to resume searching, so N reported occurrences
    // map onto N distinct positions.
    let mut cursors: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    let mut anchored = Vec::new();
    let mut unanchored = 0usize;

    for entity in &raw {
        if entity.text.is_empty() {
            unanchored = unanchored.saturating_add(1);
            continue;
        }
        let from = cursors.get(entity.text.as_str()).copied().unwrap_or(0);
        let Some(found) = text.get(from..).and_then(|rest| rest.find(&entity.text)) else {
            // Either a hallucinated value, or more occurrences claimed than
            // exist. Both are safely dropped.
            unanchored = unanchored.saturating_add(1);
            continue;
        };

        let start = from.saturating_add(found);
        let end = start.saturating_add(entity.text.len());
        cursors.insert(entity.text.as_str(), end);

        // Clamp rather than reject: a model returning 1.4 is expressing high
        // confidence in a malformed way, and failing the whole batch over it
        // would discard the other, well-formed detections.
        let score = entity.score.clamp(0.0, 1.0);
        anchored.push(RecognizerResult::new(
            &entity.entity_type,
            start,
            end,
            score,
        )?);
    }

    Ok((anchored, unanchored))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    fn raw(entity_type: &str, text: &str, score: f64) -> RawEntity {
        RawEntity {
            entity_type: entity_type.to_string(),
            text: text.to_string(),
            score,
        }
    }

    // ---- extract_json ------------------------------------------------------

    #[test]
    fn extracts_a_bare_json_object() {
        let json = extract_json(r#"{"entities": []}"#).expect("bare object");
        assert_eq!(json, r#"{"entities": []}"#);
    }

    #[test]
    fn extracts_json_from_a_markdown_fence() {
        let content = "Here you go:\n```json\n{\"entities\": []}\n```\nHope that helps!";
        let json = extract_json(content).expect("fenced object");
        assert_eq!(
            json, r#"{"entities": []}"#,
            "the fence and surrounding prose must be stripped"
        );
    }

    #[test]
    fn brace_matching_ignores_braces_inside_strings() {
        // A naive depth counter terminates at the '}' inside the string and
        // returns a truncated, unparseable document.
        let content = r#"prose {"entities": [{"type": "X", "text": "}", "score": 1.0}]} tail"#;
        let json = extract_json(content).expect("balanced object");
        assert!(
            json.ends_with("}]}"),
            "must consume the whole object, got: {json}"
        );
        let parsed: DetectionEnvelope = serde_json::from_str(json).expect("valid JSON");
        assert_eq!(parsed.entities.len(), 1);
    }

    #[test]
    fn response_without_json_is_a_parse_error_not_an_empty_result() {
        // Silently returning [] would report "no PII" for a failed call.
        let outcome = extract_json("I'm sorry, I can't help with that.");
        assert!(outcome.is_err(), "no-JSON must not look like a clean scan");
    }

    // ---- parse_entities ----------------------------------------------------

    #[test]
    fn parses_entities_with_all_fields() {
        let entities =
            parse_entities(r#"{"entities":[{"type":"EMAIL","text":"a@b.com","score":0.9}]}"#)
                .expect("valid");
        let first = entities.first().expect("one entity");
        assert_eq!(first.entity_type, "EMAIL");
        assert_eq!(first.text, "a@b.com");
        assert_eq!(first.score, 0.9);
    }

    #[test]
    fn missing_score_defaults_to_neutral_not_zero_or_one() {
        let entities =
            parse_entities(r#"{"entities":[{"type":"EMAIL","text":"a@b.com"}]}"#).expect("valid");
        assert_eq!(
            entities.first().map(|e| e.score),
            Some(0.5),
            "an omitted score is an absence of evidence, not zero confidence"
        );
    }

    #[test]
    fn empty_entities_array_parses_as_a_clean_empty_result() {
        let entities = parse_entities(r#"{"entities": []}"#).expect("valid");
        assert!(entities.is_empty());
    }

    #[test]
    fn malformed_envelope_errors() {
        assert!(parse_entities(r#"{"entities": "not an array"}"#).is_err());
    }

    // ---- anchor ------------------------------------------------------------

    #[test]
    fn anchors_to_the_exact_offsets_of_the_quoted_text() {
        let text = "Mail alice@example.com now";
        let (results, dropped) =
            anchor(text, vec![raw("EMAIL", "alice@example.com", 0.9)]).expect("anchors");

        assert_eq!(dropped, 0);
        let first = results.first().expect("one result");
        assert_eq!((first.start, first.end), (5, 22));
        assert_eq!(
            text.get(first.start..first.end),
            Some("alice@example.com"),
            "the span must cover exactly the reported value"
        );
    }

    #[test]
    fn hallucinated_text_is_dropped_rather_than_mispositioned() {
        // This is the core safety property.
        let text = "Mail alice@example.com now";
        let (results, dropped) = anchor(
            text,
            vec![
                raw("EMAIL", "alice@example.com", 0.9),
                raw("SSN", "123-45-6789", 0.95),
            ],
        )
        .expect("anchors");

        assert_eq!(results.len(), 1, "only the real value survives");
        assert_eq!(dropped, 1, "the invented value is counted as dropped");
        assert_eq!(
            results.first().map(|r| r.entity_type.as_str()),
            Some("EMAIL"),
            "the surviving span must be the one that was actually present"
        );
    }

    #[test]
    fn repeated_values_anchor_to_successive_occurrences() {
        // Both collapsing onto offset 0 would under-redact the second instance.
        let text = "a@b.com and a@b.com";
        let (results, dropped) = anchor(
            text,
            vec![raw("EMAIL", "a@b.com", 0.9), raw("EMAIL", "a@b.com", 0.9)],
        )
        .expect("anchors");

        assert_eq!(dropped, 0);
        assert_eq!(results.len(), 2);
        assert_eq!(results.first().map(|r| (r.start, r.end)), Some((0, 7)));
        assert_eq!(
            results.get(1).map(|r| (r.start, r.end)),
            Some((12, 19)),
            "the second occurrence must anchor past the first"
        );
    }

    #[test]
    fn more_claimed_occurrences_than_exist_are_dropped() {
        let text = "only one a@b.com here";
        let (results, dropped) = anchor(
            text,
            vec![raw("EMAIL", "a@b.com", 0.9), raw("EMAIL", "a@b.com", 0.9)],
        )
        .expect("anchors");

        assert_eq!(results.len(), 1, "only the real occurrence anchors");
        assert_eq!(dropped, 1);
    }

    #[test]
    fn anchors_correctly_after_multibyte_characters() {
        // Byte offsets, not char offsets — "café " is 6 bytes, not 5.
        let text = "café alice@example.com";
        let (results, _) =
            anchor(text, vec![raw("EMAIL", "alice@example.com", 0.9)]).expect("anchors");

        let first = results.first().expect("one result");
        assert_eq!(first.start, 6, "offset must be in bytes");
        assert_eq!(text.get(first.start..first.end), Some("alice@example.com"));
    }

    #[test]
    fn out_of_range_scores_are_clamped_not_rejected() {
        let text = "a@b.com x@y.com";
        let (results, dropped) = anchor(
            text,
            vec![raw("EMAIL", "a@b.com", 1.4), raw("EMAIL", "x@y.com", -0.2)],
        )
        .expect("clamped, not failed");

        assert_eq!(dropped, 0);
        assert_eq!(
            results.first().map(|r| r.score),
            Some(1.0),
            "an over-range score clamps to the ceiling"
        );
        assert_eq!(
            results.get(1).map(|r| r.score),
            Some(0.0),
            "an under-range score clamps to the floor"
        );
    }

    #[test]
    fn empty_reported_text_is_dropped() {
        let text = "nothing here";
        let (results, dropped) = anchor(text, vec![raw("EMAIL", "", 0.9)]).expect("anchors");
        assert!(results.is_empty(), "an empty match must not anchor at 0");
        assert_eq!(dropped, 1);
    }
}
