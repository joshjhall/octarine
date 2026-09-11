//! The declarative TOML schema for an LLM recognizer.
//!
//! One file describes one recognizer completely — provider, model, sampling
//! parameters, system prompt, few-shot examples, entity mapping, and confidence
//! policy. Presidio splits the equivalent across a YAML config plus a Python
//! class; keeping it in one file is what makes a recognizer something you can
//! drop into a directory rather than something you write code for.
//!
//! # Layout
//!
//! This module holds the schema — the serde structs a TOML file deserializes
//! into. The rules those structs must satisfy live in the private `validation`
//! submodule, which is where [`RecognizerConfig::validate`] is implemented.
//!
//! # Validation
//!
//! [`RecognizerConfig::validate`] is deliberately strict and reports the **TOML
//! field path** of whatever it rejects:
//!
//! ```text
//! recognizer.few_shot_examples[2].output[0].entity_type: unknown IdentifierType "PERSEN"
//! ```
//!
//! The path matters more than it looks. A config file is edited by hand, often
//! by someone who did not write the schema, and `invalid value` with no
//! location is a message you have to bisect the file to act on.
//!
//! Strictness matters for the same reason: an unrecognized `entity_type` is a
//! load-time **error**, never a silent degrade to `IdentifierType::Unknown`. A
//! typo that loads clean and then detects nothing is the worst outcome
//! available — the config looks healthy while coverage has silently dropped.

mod validation;

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub use validation::ResolvedConfig;

/// Sampling temperature used when a config omits one.
///
/// Detection wants determinism, matching
/// [`LlmRequest::for_detection`](crate::LlmRequest::for_detection).
const DEFAULT_TEMPERATURE: f32 = 0.0;

/// Generated-token ceiling used when a config omits one.
const DEFAULT_MAX_TOKENS: u32 = 2048;

/// Nucleus-sampling default.
const DEFAULT_TOP_P: f32 = 1.0;

/// The top-level shape of a recognizer TOML file.
///
/// The whole document is one `[recognizer]` table, so a file is unambiguous
/// about what it declares and the loader can reject a file that merely happens
/// to be TOML.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RecognizerFile {
    /// The single `[recognizer]` table.
    pub recognizer: RecognizerConfig,
}

/// A complete LLM recognizer definition.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RecognizerConfig {
    /// Instance name, unique within a config directory.
    ///
    /// Named `class_name` to match Presidio's key (their PR #2018 uses it to
    /// spin multiple instances from one class). Here it is purely an instance
    /// identifier: it becomes the recognizer's
    /// [`name`](octarine::analyze::Recognizer::name), so it lands in metrics
    /// labels and audit records.
    pub class_name: String,

    /// Which backend to talk to: `openai`, `anthropic`, `azure_openai`,
    /// `ollama`, or `openai_compatible`.
    pub provider: String,

    /// Model identifier in the provider's own namespace (`gpt-4o-mini`,
    /// `claude-sonnet-5`, `llama3`).
    pub model: String,

    /// Generated-token ceiling.
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,

    /// Sampling temperature.
    #[serde(default = "default_temperature")]
    pub temperature: f32,

    /// Nucleus sampling parameter.
    ///
    /// **Not yet forwarded to any provider.** [`LlmRequest`](crate::LlmRequest)
    /// has no `top_p` field, so wiring this means threading it through all five
    /// provider wire formats — tracked separately. It is validated and rejected
    /// out of range so a config written today stays correct once it is honored,
    /// but setting it currently has no effect on the request.
    #[serde(default = "default_top_p")]
    pub top_p: f32,

    /// Whether the loader should build this recognizer at all.
    ///
    /// Defaults to `true`: a file present in the config directory is meant to
    /// be used unless it says otherwise. `enabled = false` lets an operator
    /// park a config without deleting it.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// BCP 47 tags this recognizer handles. Empty means every language.
    ///
    /// Enforced: the built recognizer returns an empty result for a language
    /// outside this set rather than calling the provider.
    #[serde(default)]
    pub supported_languages: Vec<String>,

    /// Optional ISO 3166-1 alpha-2 country this recognizer is scoped to.
    ///
    /// **Advisory metadata only.** Unlike
    /// [`supported_languages`](RecognizerConfig::supported_languages), which the
    /// built recognizer enforces, nothing filters on this today — country-aware
    /// dispatch belongs to the analyzer registry (#464), which does not exist
    /// yet. It is carried so a config can record intent.
    #[serde(default)]
    pub country_code: Option<String>,

    /// Name of the environment variable holding this provider's credential.
    ///
    /// The **name**, never the key itself: a config file is committed, diffed,
    /// and pasted into issues, so a schema that accepts an inline secret
    /// guarantees one eventually gets checked in. Defaults to the provider's
    /// conventional variable (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
    /// `AZURE_OPENAI_API_KEY`). Ignored by `ollama`, which needs no credential.
    #[serde(default)]
    pub api_key_env: Option<String>,

    /// Overrides the provider's base URL.
    ///
    /// Required for `openai_compatible` (vLLM, Together, Groq, …) and for an
    /// `ollama` instance that is not on `localhost`. Ignored by the others,
    /// whose endpoints are fixed.
    #[serde(default)]
    pub base_url: Option<String>,

    /// Azure resource endpoint. Required when `provider = "azure_openai"`.
    #[serde(default)]
    pub endpoint: Option<String>,

    /// Azure API version. Optional; the provider's default is used when absent.
    #[serde(default)]
    pub api_version: Option<String>,

    /// Provider-specific knobs (`seed`, `stop`, …).
    ///
    /// Deliberately untyped: every provider has parameters the others do not,
    /// and enumerating them here would mean a schema change each time a vendor
    /// adds one.
    ///
    /// **Not yet forwarded to any provider.** Passing these through requires an
    /// extension field on [`LlmRequest`](crate::LlmRequest) plus per-provider
    /// serialization, tracked separately. The values round-trip through the
    /// schema but currently reach no request.
    #[serde(default)]
    pub language_model_params: HashMap<String, toml::Value>,

    /// Prompt configuration.
    pub prompt: PromptConfig,

    /// Few-shot examples appended to the system prompt.
    #[serde(default)]
    pub few_shot_examples: Vec<FewShotExample>,

    /// Maps the model's entity labels onto octarine types.
    #[serde(default)]
    pub entity_mapping: HashMap<String, String>,

    /// How to score detections.
    #[serde(default)]
    pub confidence: ConfidenceConfig,
}

/// The prompt handed to the model.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PromptConfig {
    /// The system prompt. Replaces the built-in detection prompt entirely when
    /// present, so a config can specialize a recognizer to one entity type or
    /// one document shape.
    pub system: String,

    /// Optional JSON schema for providers with a structured-output mode.
    ///
    /// **Not yet forwarded to any provider.** Detection currently requests
    /// generic JSON mode (`response_format: json_object` on OpenAI), not a
    /// caller-supplied schema; honoring this means a new
    /// [`LlmRequest`](crate::LlmRequest) field and per-provider handling,
    /// tracked separately.
    #[serde(default)]
    pub json_schema: Option<toml::Value>,
}

/// One few-shot example: an input and the entities a model should find in it.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FewShotExample {
    /// The example input text.
    pub input: String,
    /// The entities expected in `input`.
    pub output: Vec<FewShotEntity>,
}

/// One expected entity within a few-shot example.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FewShotEntity {
    /// Entity label, resolved against
    /// [`IdentifierType`](octarine::identifiers::IdentifierType) at load time.
    pub entity_type: String,
    /// The matched substring.
    pub text: String,
    /// Optional start offset, for documentation inside the example.
    #[serde(default)]
    pub start: Option<usize>,
    /// Optional end offset.
    #[serde(default)]
    pub end: Option<usize>,
}

/// How a detection's score is produced.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConfidenceConfig {
    /// `constant` pins every detection to [`value`](ConfidenceConfig::value);
    /// `from_model` keeps the score the model reported.
    #[serde(default = "default_confidence_mode")]
    pub mode: String,

    /// The constant score, required when `mode = "constant"`.
    #[serde(default)]
    pub value: Option<f64>,
}

impl Default for ConfidenceConfig {
    /// Trusts the model's own score.
    ///
    /// The alternative default — a constant — would silently overwrite every
    /// score a model reported with a number nobody chose.
    fn default() -> Self {
        Self {
            mode: "from_model".to_string(),
            value: None,
        }
    }
}

/// The scoring policy, after validation has resolved the string `mode`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConfidencePolicy {
    /// Every detection scores exactly this value.
    Constant(f64),
    /// Keep whatever the model reported.
    FromModel,
}

fn default_max_tokens() -> u32 {
    DEFAULT_MAX_TOKENS
}

fn default_temperature() -> f32 {
    DEFAULT_TEMPERATURE
}

fn default_top_p() -> f32 {
    DEFAULT_TOP_P
}

fn default_enabled() -> bool {
    true
}

fn default_confidence_mode() -> String {
    "from_model".to_string()
}
