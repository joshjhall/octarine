//! Provider conformance against a mock HTTP server.
//!
//! Every provider is exercised end-to-end — real `HttpClient`, real serde
//! round-trip, real HTTP — against [`wiremock`] rather than a live vendor.
//! No test here needs credentials or a network, so the suite runs in CI
//! unchanged.
//!
//! The mock also lets the tests assert things a live endpoint could not
//! reliably reproduce: that a 429 is actually retried, that the Anthropic
//! request really carries a `cache_control` block, and that a malformed body is
//! surfaced as an error rather than as an empty detection set.

#![allow(clippy::panic, clippy::expect_used, clippy::indexing_slicing)]

use octarine::analyze::Recognizer;
use octarine_llm::provider::{
    AnthropicProvider, AzureOpenAiProvider, OllamaProvider, OpenAiCompatibleProvider,
    OpenAiProvider,
};
use octarine_llm::recognizer::parse;
use octarine_llm::sse::MAX_LINE_BYTES;
use octarine_llm::{LLMRecognizer, LlmProvider, LlmRequest};
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, Request, ResponseTemplate};

/// The text every detection test analyzes.
const SAMPLE_TEXT: &str = "Reach alice@example.com about invoice 42";

/// The value the mock providers claim to have found in `SAMPLE_TEXT`.
const SAMPLE_EMAIL: &str = "alice@example.com";

/// A detection payload naming a value that really is in `SAMPLE_TEXT`.
fn detection_json() -> String {
    json!({"entities": [{"type": "EMAIL_ADDRESS", "text": SAMPLE_EMAIL, "score": 0.95}]})
        .to_string()
}

/// An OpenAI-format success body wrapping `content`.
fn openai_body(content: &str) -> Value {
    json!({
        "model": "mock-model",
        "choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 20,
                  "prompt_tokens_details": {"cached_tokens": 64}}
    })
}

/// A detection request with a fixed, recognizable prompt.
fn request() -> LlmRequest {
    LlmRequest::for_detection("system instructions", SAMPLE_TEXT, String::new(), 512)
}

/// Asserts a result set is exactly the one email span, anchored into `text`.
fn assert_found_the_email(results: &[octarine::anonymize::RecognizerResult], text: &str) {
    assert_eq!(results.len(), 1, "expected exactly one detection");
    let found = &results[0];
    assert_eq!(found.entity_type, "EMAIL_ADDRESS");
    assert_eq!(
        text.get(found.start..found.end),
        Some(SAMPLE_EMAIL),
        "the span must cover the email in the original text"
    );
}

// ---------------------------------------------------------------------------
// Per-provider happy path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn openai_detects_end_to_end() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(header("authorization", "Bearer sk-test"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_body(&detection_json())))
        .expect(1)
        .mount(&server)
        .await;

    let provider =
        OpenAiProvider::with_base_url("sk-test", "gpt-4o", &server.uri()).expect("provider builds");
    let results = LLMRecognizer::new(provider)
        .silent()
        .analyze(SAMPLE_TEXT, "en", &[])
        .await
        .expect("detection succeeds");

    assert_found_the_email(&results, SAMPLE_TEXT);
}

#[tokio::test]
async fn anthropic_detects_end_to_end() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/messages"))
        .and(header("x-api-key", "sk-ant-test"))
        .and(header("anthropic-version", "2023-06-01"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "model": "claude-sonnet-5",
            "content": [{"type": "text", "text": detection_json()}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 12, "output_tokens": 8,
                      "cache_creation_input_tokens": 0, "cache_read_input_tokens": 900}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let provider =
        AnthropicProvider::with_base_url("sk-ant-test", "claude-sonnet-5", &server.uri())
            .expect("provider builds");
    let results = LLMRecognizer::new(provider)
        .silent()
        .analyze(SAMPLE_TEXT, "en", &[])
        .await
        .expect("detection succeeds");

    assert_found_the_email(&results, SAMPLE_TEXT);
}

#[tokio::test]
async fn ollama_detects_end_to_end() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "model": "llama3",
            "message": {"role": "assistant", "content": detection_json()},
            "done_reason": "stop",
            "prompt_eval_count": 200,
            "eval_count": 15
        })))
        .expect(1)
        .mount(&server)
        .await;

    let provider = OllamaProvider::with_base_url("llama3", &server.uri()).expect("builds");
    let results = LLMRecognizer::new(provider)
        .silent()
        .analyze(SAMPLE_TEXT, "en", &[])
        .await
        .expect("detection succeeds");

    assert_found_the_email(&results, SAMPLE_TEXT);
}

#[tokio::test]
async fn openai_compatible_detects_end_to_end() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(header("authorization", "Bearer gsk-test"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_body(&detection_json())))
        .expect(1)
        .mount(&server)
        .await;

    let provider =
        OpenAiCompatibleProvider::new("groq", &server.uri(), "gsk-test", "llama-3.3-70b")
            .expect("builds");
    assert_eq!(
        provider.name(),
        "groq",
        "metrics must attribute to the vendor"
    );

    let results = LLMRecognizer::new(provider)
        .silent()
        .analyze(SAMPLE_TEXT, "en", &[])
        .await
        .expect("detection succeeds");

    assert_found_the_email(&results, SAMPLE_TEXT);
}

#[tokio::test]
async fn azure_openai_detects_end_to_end_on_a_deployment_scoped_path() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        // The deployment name, not the model, selects the endpoint.
        .and(path("/openai/deployments/gpt4o-deploy/chat/completions"))
        .and(query_param("api-version", "2024-10-21"))
        .and(header("api-key", "azure-key"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_body(&detection_json())))
        .expect(1)
        .mount(&server)
        .await;

    let provider = AzureOpenAiProvider::with_api_key(&server.uri(), "azure-key", "gpt4o-deploy")
        .expect("builds");
    let results = LLMRecognizer::new(provider)
        .silent()
        .analyze(SAMPLE_TEXT, "en", &[])
        .await
        .expect("detection succeeds");

    assert_found_the_email(&results, SAMPLE_TEXT);
}

#[tokio::test]
async fn openai_compatible_without_auth_sends_no_credential() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_body(&detection_json())))
        .expect(1)
        .mount(&server)
        .await;

    let provider = OpenAiCompatibleProvider::without_auth("vllm", &server.uri(), "llama3")
        .expect("a local endpoint needs no key");
    let results = LLMRecognizer::new(provider)
        .silent()
        .analyze(SAMPLE_TEXT, "en", &[])
        .await
        .expect("detection succeeds");

    assert_found_the_email(&results, SAMPLE_TEXT);
}

// ---------------------------------------------------------------------------
// Retry behaviour
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rate_limited_request_is_retried_and_then_succeeds() {
    let server = MockServer::start().await;
    // First response 429, then success. `up_to_n_times` + priority makes the
    // ordering deterministic without any sleeping.
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(429).set_body_string("slow down"))
        .up_to_n_times(1)
        .with_priority(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_body(&detection_json())))
        .with_priority(2)
        .expect(1)
        .mount(&server)
        .await;

    let provider =
        OpenAiProvider::with_base_url("sk-test", "gpt-4o", &server.uri()).expect("builds");
    let results = LLMRecognizer::new(provider)
        .silent()
        .analyze(SAMPLE_TEXT, "en", &[])
        .await
        .expect("the retry must recover the call");

    assert_found_the_email(&results, SAMPLE_TEXT);
    // Both mocks assert `.expect(1)`, verified on drop: the 429 was consumed
    // AND a second request was actually issued.
}

#[tokio::test]
async fn server_error_is_retried_and_then_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(503).set_body_string("unavailable"))
        .up_to_n_times(1)
        .with_priority(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_body(&detection_json())))
        .with_priority(2)
        .expect(1)
        .mount(&server)
        .await;

    let provider =
        OpenAiProvider::with_base_url("sk-test", "gpt-4o", &server.uri()).expect("builds");
    let results = LLMRecognizer::new(provider)
        .silent()
        .analyze(SAMPLE_TEXT, "en", &[])
        .await
        .expect("a 5xx must be retried");

    assert_found_the_email(&results, SAMPLE_TEXT);
}

#[tokio::test]
async fn auth_failure_is_not_retried() {
    let server = MockServer::start().await;
    // `.expect(1)` is the assertion: a retry would make this 2 and fail on drop.
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string("invalid key"))
        .expect(1)
        .mount(&server)
        .await;

    let provider =
        OpenAiProvider::with_base_url("sk-bad", "gpt-4o", &server.uri()).expect("builds");
    let outcome = LLMRecognizer::new(provider)
        .silent()
        .analyze(SAMPLE_TEXT, "en", &[])
        .await;

    let problem = outcome.expect_err("a 401 must surface as an error");
    assert!(
        problem.to_string().contains("401") || problem.to_string().contains("Authentication"),
        "the error must identify an auth failure, got: {problem}"
    );
}

// ---------------------------------------------------------------------------
// Response handling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn json_wrapped_in_prose_and_fences_is_still_parsed() {
    let server = MockServer::start().await;
    let wrapped = format!(
        "Sure! Here's what I found:\n```json\n{}\n```\nLet me know if you need more.",
        detection_json()
    );
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_body(&wrapped)))
        .mount(&server)
        .await;

    let provider =
        OpenAiProvider::with_base_url("sk-test", "gpt-4o", &server.uri()).expect("builds");
    let results = LLMRecognizer::new(provider)
        .silent()
        .analyze(SAMPLE_TEXT, "en", &[])
        .await
        .expect("a provider without structured mode must still parse");

    assert_found_the_email(&results, SAMPLE_TEXT);
}

#[tokio::test]
async fn hallucinated_entity_is_dropped_while_the_real_one_survives() {
    let server = MockServer::start().await;
    let body = json!({"entities": [
        {"type": "EMAIL_ADDRESS", "text": SAMPLE_EMAIL, "score": 0.95},
        {"type": "US_SSN", "text": "123-45-6789", "score": 0.99}
    ]})
    .to_string();
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_body(&body)))
        .mount(&server)
        .await;

    let provider =
        OpenAiProvider::with_base_url("sk-test", "gpt-4o", &server.uri()).expect("builds");
    let results = LLMRecognizer::new(provider)
        .silent()
        .analyze(SAMPLE_TEXT, "en", &[])
        .await
        .expect("detection succeeds");

    // The SSN is not in SAMPLE_TEXT, so it cannot anchor and must be dropped
    // rather than pointed at an arbitrary offset.
    assert_found_the_email(&results, SAMPLE_TEXT);
}

#[tokio::test]
async fn unparseable_response_errors_rather_than_reporting_no_pii() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(openai_body("I'm sorry, I can't help with that.")),
        )
        .mount(&server)
        .await;

    let provider =
        OpenAiProvider::with_base_url("sk-test", "gpt-4o", &server.uri()).expect("builds");
    let outcome = LLMRecognizer::new(provider)
        .silent()
        .analyze(SAMPLE_TEXT, "en", &[])
        .await;

    assert!(
        outcome.is_err(),
        "a refusal must not be indistinguishable from a clean scan finding nothing"
    );
}

// ---------------------------------------------------------------------------
// Streaming
// ---------------------------------------------------------------------------

/// Builds an SSE body whose `content` deltas concatenate to `full`.
///
/// Splits at a deliberately awkward point — mid-JSON — so a decoder that
/// treated each frame as a standalone document would fail.
fn sse_stream(full: &str, split_at: usize) -> String {
    let (head, tail) = full.split_at(split_at);
    let frame = |delta: &str| {
        format!(
            "data: {}\n\n",
            json!({"model": "mock-model", "choices": [{"delta": {"content": delta}}]})
        )
    };
    let final_frame = json!({
        "choices": [{"delta": {}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 100, "completion_tokens": 20}
    });
    format!(
        "{}: keep-alive\n\n{}data: {final_frame}\n\ndata: [DONE]\n\n",
        frame(head),
        frame(tail),
    )
}

#[tokio::test]
async fn streamed_deltas_reassemble_into_a_complete_detection() {
    let server = MockServer::start().await;
    let detection = detection_json();
    // Split inside the JSON so no single frame is parseable on its own.
    let body = sse_stream(&detection, detection.len() / 2);

    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .and(header("accept", "text/event-stream"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(body, "text/event-stream")
                .append_header("content-type", "text/event-stream"),
        )
        .expect(1)
        .mount(&server)
        .await;

    let provider =
        OpenAiProvider::with_base_url("sk-test", "gpt-4o", &server.uri()).expect("builds");
    let response = provider
        .complete_streaming(&request())
        .await
        .expect("the stream must reassemble");

    assert_eq!(
        response.content, detection,
        "concatenated deltas must equal the original document"
    );
    assert_eq!(response.finish_reason, octarine_llm::FinishReason::Stop);
    assert_eq!(
        response.usage.completion_tokens, 20,
        "usage from the final frame must survive"
    );

    // And the reassembled document still drives detection end-to-end.
    let sent: Value =
        serde_json::from_slice(&server.received_requests().await.expect("recorded")[0].body)
            .expect("body is JSON");
    assert_eq!(
        sent["stream"],
        json!(true),
        "the streaming path must actually request a stream"
    );
}

#[tokio::test]
async fn streamed_content_yields_the_same_anchored_span_as_a_buffered_body() {
    let server = MockServer::start().await;
    let detection = detection_json();
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(sse_stream(&detection, 10), "text/event-stream")
                .append_header("content-type", "text/event-stream"),
        )
        .mount(&server)
        .await;

    let provider =
        OpenAiProvider::with_base_url("sk-test", "gpt-4o", &server.uri()).expect("builds");
    let streamed = provider
        .complete_streaming(&request())
        .await
        .expect("stream succeeds");

    // Drive the reassembled content through the same parse+anchor path
    // `analyze` uses, and assert it lands on the identical span.
    let raw = parse::parse_entities(&streamed.content).expect("reassembled content parses");
    let (results, unanchored) = parse::anchor(SAMPLE_TEXT, raw).expect("anchors");

    assert_eq!(unanchored, 0);
    assert_found_the_email(&results, SAMPLE_TEXT);
}

#[tokio::test]
async fn streaming_request_asks_for_usage_in_the_final_chunk() {
    // Without stream_options.include_usage, real OpenAI and Azure omit `usage`
    // from every chunk, so the accumulator silently reports zero tokens for
    // every streaming call. The mock always sends usage, so only inspecting the
    // outgoing request can catch this.
    let server = MockServer::start().await;
    let detection = detection_json();
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(sse_stream(&detection, 10), "text/event-stream")
                .append_header("content-type", "text/event-stream"),
        )
        .mount(&server)
        .await;

    let provider =
        OpenAiProvider::with_base_url("sk-test", "gpt-4o", &server.uri()).expect("builds");
    let _ = provider
        .complete_streaming(&request())
        .await
        .expect("stream succeeds");

    let sent: Value =
        serde_json::from_slice(&server.received_requests().await.expect("recorded")[0].body)
            .expect("body is JSON");

    assert_eq!(sent["stream"], json!(true));
    assert_eq!(
        sent["stream_options"]["include_usage"],
        json!(true),
        "usage is only streamed back when explicitly requested"
    );
}

#[tokio::test]
async fn streaming_error_status_is_surfaced_not_swallowed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(401).set_body_string("invalid key"))
        .mount(&server)
        .await;

    let provider =
        OpenAiProvider::with_base_url("sk-bad", "gpt-4o", &server.uri()).expect("builds");
    let outcome = provider.complete_streaming(&request()).await;

    assert!(
        outcome.is_err(),
        "a 401 on the streaming path must error, not yield empty content"
    );
}

#[tokio::test]
async fn a_content_free_stream_errors_rather_than_returning_empty_content() {
    let server = MockServer::start().await;
    // A well-formed stream that carries no delta content at all.
    let body = format!(
        "data: {}\n\ndata: [DONE]\n\n",
        json!({"choices": [{"delta": {}, "finish_reason": "stop"}]})
    );
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(body, "text/event-stream")
                .append_header("content-type", "text/event-stream"),
        )
        .mount(&server)
        .await;

    let provider =
        OpenAiProvider::with_base_url("sk-test", "gpt-4o", &server.uri()).expect("builds");
    let outcome = provider.complete_streaming(&request()).await;

    let problem = outcome.expect_err("empty content must not look like a clean completion");
    assert!(
        problem.to_string().contains("openai"),
        "the error must name the provider, got: {problem}"
    );
}

#[tokio::test]
async fn an_undecodable_data_frame_is_skipped_not_fatal() {
    // fold_chunk documents that a `data:` line failing to parse as ChatChunk is
    // tolerated. The existing tests only cover SSE *comment* lines, which the
    // decoder filters before fold_chunk ever runs.
    let server = MockServer::start().await;
    let detection = detection_json();
    let (head, tail) = detection.split_at(12);
    let frame = |delta: &str| {
        format!(
            "data: {}\n\n",
            json!({"choices": [{"delta": {"content": delta}}]})
        )
    };
    // The bad frames must genuinely FAIL to decode as ChatChunk. An object of
    // unknown keys would not: every ChatChunk field is `#[serde(default)]` and
    // serde ignores unrecognized keys, so it decodes to an empty chunk and
    // takes the Ok path — passing this test for the wrong reason. A syntax
    // error and a non-map both really hit the `else { return }` branch.
    let body = format!(
        "{}data: {{not valid json\n\ndata: [1,2,3]\n\n{}data: {}\n\ndata: [DONE]\n\n",
        frame(head),
        frame(tail),
        json!({"choices": [{"delta": {}, "finish_reason": "stop"}]})
    );

    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(body, "text/event-stream")
                .append_header("content-type", "text/event-stream"),
        )
        .mount(&server)
        .await;

    let provider =
        OpenAiProvider::with_base_url("sk-test", "gpt-4o", &server.uri()).expect("builds");
    let response = provider
        .complete_streaming(&request())
        .await
        .expect("a garbage frame must not fail the stream");

    assert_eq!(
        response.content, detection,
        "the surrounding real frames must still reassemble exactly"
    );
}

#[tokio::test]
async fn an_oversized_unterminated_sse_line_aborts_the_request() {
    // The decoder's cap is unit-tested; this asserts the provider layer
    // translates it into a hard error rather than a silently short read.
    let server = MockServer::start().await;
    // One `data:` line with no terminator, past the 1 MiB cap.
    let flood = format!("data: {}", "x".repeat(MAX_LINE_BYTES + 1024));
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(flood, "text/event-stream")
                .append_header("content-type", "text/event-stream"),
        )
        .mount(&server)
        .await;

    let provider =
        OpenAiProvider::with_base_url("sk-test", "gpt-4o", &server.uri()).expect("builds");
    let outcome = provider.complete_streaming(&request()).await;

    let problem = outcome.expect_err("an oversized line must abort, not truncate");
    let rendered = problem.to_string();
    assert!(
        rendered.contains("openai"),
        "the error must name the provider, got: {rendered}"
    );
    assert!(
        rendered.contains("buffer limit"),
        "the error must explain why, got: {rendered}"
    );
}

#[tokio::test]
async fn a_provider_without_streaming_falls_back_to_the_buffered_path() {
    // Ollama does not override `complete_streaming`, so the default trait
    // implementation must still return a usable response.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": {"content": detection_json()},
            "done_reason": "stop"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let provider = OllamaProvider::with_base_url("llama3", &server.uri()).expect("builds");
    let response = provider
        .complete_streaming(&request())
        .await
        .expect("the default fallback must work");

    assert_eq!(response.content, detection_json());
}

// ---------------------------------------------------------------------------
// Request shape
// ---------------------------------------------------------------------------

#[tokio::test]
async fn anthropic_request_carries_an_ephemeral_cache_control_block() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "content": [{"type": "text", "text": detection_json()}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 12, "output_tokens": 8,
                      "cache_creation_input_tokens": 0, "cache_read_input_tokens": 900}
        })))
        .mount(&server)
        .await;

    let provider = AnthropicProvider::with_base_url("sk-ant", "claude-sonnet-5", &server.uri())
        .expect("builds");
    let response = provider.complete(&request()).await.expect("call succeeds");

    // The request actually sent, as the server received it.
    let received: &Request = &server.received_requests().await.expect("requests recorded")[0];
    let sent: Value = serde_json::from_slice(&received.body).expect("body is JSON");

    assert_eq!(
        sent["system"][0]["cache_control"]["type"],
        json!("ephemeral"),
        "without this marker Anthropic performs no prompt caching at all"
    );
    assert_eq!(sent["system"][0]["text"], json!("system instructions"));
    assert_eq!(
        sent["messages"][0]["role"],
        json!("user"),
        "the system prompt must not also appear as a message"
    );

    // And the saving is visible on the way back.
    assert_eq!(response.usage.cache_read_tokens, Some(900));
    assert!(
        response.usage.is_cache_hit(),
        "cached tokens must register as a hit"
    );
}

#[tokio::test]
async fn openai_request_is_deterministic_and_requests_structured_output() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(openai_body(&detection_json())))
        .mount(&server)
        .await;

    let provider =
        OpenAiProvider::with_base_url("sk-test", "gpt-4o", &server.uri()).expect("builds");
    let _ = provider.complete(&request()).await.expect("call succeeds");

    let received: &Request = &server.received_requests().await.expect("recorded")[0];
    let sent: Value = serde_json::from_slice(&received.body).expect("body is JSON");

    assert_eq!(
        sent["temperature"],
        json!(0.0),
        "detection must be deterministic"
    );
    assert_eq!(sent["response_format"]["type"], json!("json_object"));
    assert_eq!(
        sent["model"],
        json!("gpt-4o"),
        "the provider's configured model, not the request's empty field"
    );
    assert_eq!(sent["messages"][0]["role"], json!("system"));
    assert_eq!(sent["messages"][1]["role"], json!("user"));
}

#[tokio::test]
async fn ollama_request_disables_streaming_and_nests_its_options() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "message": {"content": detection_json()},
            "done_reason": "stop"
        })))
        .mount(&server)
        .await;

    let provider = OllamaProvider::with_base_url("llama3", &server.uri()).expect("builds");
    let _ = provider.complete(&request()).await.expect("call succeeds");

    let received: &Request = &server.received_requests().await.expect("recorded")[0];
    let sent: Value = serde_json::from_slice(&received.body).expect("body is JSON");

    assert_eq!(
        sent["stream"],
        json!(false),
        "streaming on would return NDJSON the decoder cannot parse"
    );
    assert_eq!(sent["format"], json!("json"));
    assert_eq!(
        sent["options"]["num_predict"],
        json!(512),
        "max_tokens is Ollama's options.num_predict"
    );
}
