//! LLM-backed PII recognizers for octarine.
//!
//! Implements [`octarine::analyze::Recognizer`] on top of a language model, so
//! an LLM can sit in the analyzer registry alongside the built-in regex and
//! heuristic detectors and catch PII they miss — a name in an unusual format, an
//! account number described rather than written, PII embedded in prose.
//!
//! Native Rust throughout: no Python runtime, no per-vendor SDK, no
//! docker-compose sidecar. Five backends are supported:
//!
//! | Provider | Type | Notes |
//! |---|---|---|
//! | [`OpenAiProvider`] | Cloud | Chat completions; automatic prompt caching |
//! | [`AnthropicProvider`] | Cloud | Messages API; explicit `cache_control` caching |
//! | [`AzureOpenAiProvider`] | Cloud | Deployment-scoped URLs; key or Entra ID auth |
//! | [`OllamaProvider`] | Local | `localhost:11434`, no credential |
//! | [`OpenAiCompatibleProvider`] | Either | vLLM, LM Studio, Together, Groq, OpenRouter, Mistral, Perplexity, DeepInfra |
//!
//! # Crate layout
//!
//! This is a **sibling crate**: it depends on `octarine-core` one-way and is
//! not re-exported from it. There is no `octarine::llm` path and there cannot
//! be one — a re-export would make the two crates cyclic, which Cargo rejects
//! at resolve time. Import from `octarine_llm` directly. See
//! `docs/architecture/crate-layout.md`.
//!
//! # Streaming: transport only, not incremental detection
//!
//! [`LlmProvider::complete_streaming`] consumes an SSE response incrementally
//! and reassembles it, which bounds memory and avoids idle timeouts on a long
//! generation. It does **not** deliver partial `RecognizerResult`s as deltas
//! arrive, and [`LLMRecognizer`]'s `analyze` does not use it — `analyze` calls
//! [`LlmProvider::complete`].
//!
//! That is a property of the task, not an omission: detection output is a
//! single JSON document, and a fragment of a JSON document yields no spans. A
//! partial result could only be produced by incrementally parsing truncated
//! JSON, which would emit detections that a later delta might contradict.
//!
//! So streaming is available for **direct provider use** — call
//! `complete_streaming` yourself against a slow local model — while the
//! recognizer stays on the buffered path. Issue #520 anticipated partial
//! `RecognizerResult` delivery; that is not shipped here, and whether it should
//! be is tracked in issue #755 along with live-backend CI verification.
//!
//! # Hallucination safety
//!
//! Models are asked for the matched **text**, never for character offsets.
//! Offsets are recovered locally by searching the analyzed input for each
//! quoted value. A value the model invented is not found, so it is dropped
//! rather than anchored to an arbitrary position — a hallucination costs recall,
//! never a wrongly-redacted span. Dropped spans are counted in the
//! `llm.recognizer.spans_unanchored` metric.
//!
//! # Examples
//!
//! ```no_run
//! use octarine::analyze::Recognizer;
//! use octarine_llm::{LLMRecognizer, provider::AnthropicProvider};
//!
//! # async fn run() -> Result<(), octarine_problem::Problem> {
//! let provider = AnthropicProvider::new("sk-ant-...", "claude-sonnet-5")?;
//! let recognizer = LLMRecognizer::new(provider);
//!
//! let found = recognizer
//!     .analyze("Wire the deposit to Alice Chen, account 4471-2200.", "en", &[])
//!     .await?;
//!
//! for result in &found {
//!     println!("{} at {}..{}", result.entity_type, result.start, result.end);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! Against a local model, with no credential:
//!
//! ```no_run
//! use octarine_llm::{LLMRecognizer, provider::OllamaProvider};
//!
//! # fn main() -> Result<(), octarine_problem::Problem> {
//! let recognizer = LLMRecognizer::new(OllamaProvider::new("llama3")?);
//! # let _ = recognizer;
//! # Ok(())
//! # }
//! ```

pub mod error;
pub mod metrics;
pub mod provider;
pub mod recognizer;
pub mod sse;
pub mod types;

pub use provider::{
    AnthropicProvider, AzureOpenAiProvider, OllamaProvider, OpenAiCompatibleProvider,
    OpenAiProvider,
};
pub use recognizer::LLMRecognizer;
pub use recognizer::config::{
    ConfidenceConfig, ConfidencePolicy, FewShotEntity, FewShotExample, PromptConfig,
    RecognizerConfig, RecognizerFile,
};
pub use recognizer::loader::{ConfigSet, LoadedRecognizer, ReloadHandle};
pub use sse::{SseDecoder, SseEvent};
pub use types::{FinishReason, LlmProvider, LlmRequest, LlmResponse, TokenUsage};
