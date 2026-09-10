//! A minimal Server-Sent Events parser for streaming completions.
//!
//! Hand-rolled rather than pulled from a crate: no SSE dependency exists
//! anywhere in the octarine tree, and the subset the LLM providers actually use
//! is small — `data:` lines, a `[DONE]` sentinel, and blank-line event
//! separation. Adding a dependency for that would mean a new entry in the
//! license and advisory review for very little code.
//!
//! # What this implements
//!
//! Per the WHATWG event-stream grammar, restricted to what providers emit:
//!
//! - A stream is a sequence of events separated by blank lines.
//! - `data: <payload>` contributes a line to the current event's payload;
//!   multiple `data:` lines within one event are joined with `\n`.
//! - A single optional space after the colon is part of the syntax and is
//!   stripped; further spaces are payload.
//! - Lines beginning with `:` are comments (used as keep-alives) and ignored.
//! - `event:`, `id:`, and `retry:` are accepted and ignored — none of the five
//!   providers rely on them for completion deltas.
//!
//! # Why it is a push parser
//!
//! Network chunks split anywhere, including mid-line and mid-UTF-8-sequence.
//! [`SseDecoder`] buffers across [`push`](SseDecoder::push) calls and yields
//! only complete events, so callers can feed it raw
//! `reqwest::Response::bytes_stream` chunks without pre-framing them.

use bytes::{Bytes, BytesMut};

/// The `data:` payload of one complete SSE event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    /// Joined `data:` lines, without the trailing newline.
    pub data: String,
}

/// Incremental SSE decoder.
///
/// Feed it bytes with [`push`](SseDecoder::push); it returns the events that
/// became complete as a result. Partial trailing data is retained for the next
/// call.
#[derive(Debug, Default)]
pub struct SseDecoder {
    /// Bytes received but not yet forming a complete line.
    buffer: BytesMut,
    /// `data:` lines accumulated for the event currently being assembled.
    pending: Vec<String>,
    /// Set once the `[DONE]` sentinel is seen; further input is ignored.
    done: bool,
}

/// The sentinel OpenAI-family providers send to close a stream.
const DONE_SENTINEL: &str = "[DONE]";

impl SseDecoder {
    /// Creates an empty decoder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the `[DONE]` sentinel has been observed.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Feeds a chunk and returns any events completed by it.
    ///
    /// Chunk boundaries are irrelevant — a chunk may end mid-line or split a
    /// multi-byte character.
    pub fn push(&mut self, chunk: &Bytes) -> Vec<SseEvent> {
        if self.done {
            return Vec::new();
        }
        self.buffer.extend_from_slice(chunk);

        let mut events = Vec::new();
        while let Some(line) = self.take_line() {
            if let Some(event) = self.consume_line(&line) {
                events.push(event);
            }
            if self.done {
                break;
            }
        }
        events
    }

    /// Flushes any event left un-terminated by a missing final blank line.
    ///
    /// Real streams end with a blank line, but a truncated connection may not.
    /// Dropping a fully-received event just because its terminator was lost
    /// would discard usable output, so callers should invoke this once the
    /// stream ends.
    pub fn finish(&mut self) -> Option<SseEvent> {
        self.flush_pending()
    }

    /// Splits one complete line off the buffer, handling both `\n` and `\r\n`.
    ///
    /// Returns `None` when no complete line is buffered yet.
    fn take_line(&mut self) -> Option<String> {
        let newline = self.buffer.iter().position(|&b| b == b'\n')?;
        let line_bytes = self.buffer.split_to(newline);
        // Discard the '\n' itself.
        let _ = self.buffer.split_to(1);

        // Lossy conversion is deliberate: a provider emitting invalid UTF-8 is
        // a broken provider, and replacing the bad bytes lets the rest of the
        // stream through instead of aborting the run.
        let line = String::from_utf8_lossy(&line_bytes);
        Some(line.strip_suffix('\r').unwrap_or(&line).to_string())
    }

    /// Processes one line, returning an event if the line terminated one.
    fn consume_line(&mut self, line: &str) -> Option<SseEvent> {
        // Blank line: dispatch whatever has accumulated.
        if line.is_empty() {
            return self.flush_pending();
        }
        // Comment / keep-alive.
        if line.starts_with(':') {
            return None;
        }

        let (field, raw_value) = match line.split_once(':') {
            Some((field, value)) => (field, value),
            // A field with no colon has an empty value per the spec.
            None => (line, ""),
        };
        // Exactly one leading space is syntax; the rest is payload.
        let value = raw_value.strip_prefix(' ').unwrap_or(raw_value);

        if field == "data" {
            if value.trim() == DONE_SENTINEL {
                self.done = true;
                // A pending event before [DONE] is still real output.
                return self.flush_pending();
            }
            self.pending.push(value.to_string());
        }
        // `event:`, `id:`, `retry:` and anything else are ignored.
        None
    }

    /// Emits the accumulated event, if any, and resets the accumulator.
    fn flush_pending(&mut self) -> Option<SseEvent> {
        if self.pending.is_empty() {
            return None;
        }
        let data = self.pending.join("\n");
        self.pending.clear();
        Some(SseEvent { data })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;

    fn push(decoder: &mut SseDecoder, text: &str) -> Vec<SseEvent> {
        decoder.push(&Bytes::from(text.to_string()))
    }

    fn data_of(events: &[SseEvent]) -> Vec<&str> {
        events.iter().map(|e| e.data.as_str()).collect()
    }

    #[test]
    fn parses_consecutive_events_in_order() {
        let mut d = SseDecoder::new();
        let events = push(&mut d, "data: first\n\ndata: second\n\n");
        assert_eq!(
            data_of(&events),
            vec!["first", "second"],
            "both events, in stream order"
        );
    }

    #[test]
    fn reassembles_an_event_split_across_chunk_boundaries() {
        let mut d = SseDecoder::new();
        // Split mid-word, mid-line, and before the terminator.
        assert!(push(&mut d, "data: he").is_empty(), "no complete line yet");
        assert!(push(&mut d, "llo wo").is_empty(), "still no newline");
        assert!(push(&mut d, "rld\n").is_empty(), "line done, event is not");

        let events = push(&mut d, "\n");
        assert_eq!(
            data_of(&events),
            vec!["hello world"],
            "the payload must survive being split at arbitrary points"
        );
    }

    #[test]
    fn reassembles_a_multibyte_char_split_across_chunks() {
        let mut d = SseDecoder::new();
        // "é" is 0xC3 0xA9 — split between the two bytes.
        let _ = d.push(&Bytes::from_static(b"data: caf\xc3"));
        let events = d.push(&Bytes::from_static(b"\xa9\n\n"));
        assert_eq!(
            data_of(&events),
            vec!["café"],
            "a UTF-8 sequence split across chunks must not corrupt"
        );
    }

    #[test]
    fn joins_multiple_data_lines_within_one_event_with_newlines() {
        let mut d = SseDecoder::new();
        let events = push(&mut d, "data: line1\ndata: line2\n\n");
        assert_eq!(
            data_of(&events),
            vec!["line1\nline2"],
            "multi-line payloads join with \\n and stay ONE event"
        );
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn strips_exactly_one_space_after_the_colon() {
        let mut d = SseDecoder::new();
        // Two spaces: one is syntax, one is payload. Also covers no-space form.
        let events = push(&mut d, "data:  padded\n\ndata:tight\n\n");
        assert_eq!(
            data_of(&events),
            vec![" padded", "tight"],
            "only the first space is syntax"
        );
    }

    #[test]
    fn handles_crlf_line_endings() {
        let mut d = SseDecoder::new();
        let events = push(&mut d, "data: windows\r\n\r\n");
        assert_eq!(
            data_of(&events),
            vec!["windows"],
            "the \\r must not survive into the payload"
        );
    }

    #[test]
    fn ignores_comments_and_non_data_fields() {
        let mut d = SseDecoder::new();
        let events = push(
            &mut d,
            ": keep-alive\nevent: message\nid: 42\nretry: 100\ndata: payload\n\n",
        );
        assert_eq!(
            data_of(&events),
            vec!["payload"],
            "only `data:` contributes to the payload"
        );
    }

    #[test]
    fn done_sentinel_sets_done_and_suppresses_later_input() {
        let mut d = SseDecoder::new();
        let events = push(&mut d, "data: real\n\ndata: [DONE]\n\n");
        assert_eq!(
            data_of(&events),
            vec!["real"],
            "the sentinel itself is not an event"
        );
        assert!(d.is_done());

        let after = push(&mut d, "data: ignored\n\n");
        assert!(after.is_empty(), "input after [DONE] must be ignored");
    }

    #[test]
    fn event_pending_when_done_arrives_is_still_emitted() {
        let mut d = SseDecoder::new();
        // No blank line between the payload and the sentinel.
        let events = push(&mut d, "data: last words\ndata: [DONE]\n\n");
        assert_eq!(
            data_of(&events),
            vec!["last words"],
            "a payload buffered when [DONE] lands must not be dropped"
        );
    }

    #[test]
    fn finish_flushes_an_event_missing_its_terminating_blank_line() {
        let mut d = SseDecoder::new();
        let streamed = push(&mut d, "data: truncated\n");
        assert!(streamed.is_empty(), "not dispatched without a blank line");

        let flushed = d.finish().expect("a complete line must survive finish()");
        assert_eq!(flushed.data, "truncated");
        assert!(d.finish().is_none(), "finish() must not repeat the event");
    }

    #[test]
    fn blank_lines_without_data_produce_no_events() {
        let mut d = SseDecoder::new();
        let events = push(&mut d, "\n\n: comment\n\n");
        assert!(
            events.is_empty(),
            "separators alone must not fabricate empty events"
        );
    }

    #[test]
    fn json_payload_with_colons_and_braces_survives_intact() {
        let mut d = SseDecoder::new();
        // The realistic case: the payload itself contains ':' characters.
        let events = push(
            &mut d,
            "data: {\"choices\":[{\"delta\":{\"a\":\"b:c\"}}]}\n\n",
        );
        assert_eq!(
            data_of(&events),
            vec![r#"{"choices":[{"delta":{"a":"b:c"}}]}"#],
            "only the FIRST colon delimits the field name"
        );
    }
}
