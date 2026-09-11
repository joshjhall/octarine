//! The rules a [`RecognizerConfig`] must satisfy, and the resolution its
//! validation performs.
//!
//! Split from the schema in [`super`] so the structs a file deserializes into
//! stay readable separately from the rules they must satisfy — the same
//! separation the identifier primitives use between `types` and `validation`.
//!
//! Every rejection here names the **TOML field path** it came from, built up as
//! the walk descends rather than reconstructed afterwards, so an indexed path
//! like `recognizer.few_shot_examples[2].output[0].entity_type` points at
//! exactly one line of exactly one file.

use std::collections::HashMap;
use std::str::FromStr;

use octarine::identifiers::IdentifierType;
use octarine_problem::{Problem, Result};

use super::{ConfidencePolicy, FewShotEntity, RecognizerConfig};

/// Builds a `Problem::Config` naming the TOML field path and the complaint.
///
/// Every rejection in this module goes through here so the message shape is
/// uniform and a caller can rely on the path being present.
fn invalid(path: &str, detail: impl std::fmt::Display) -> Problem {
    Problem::Config(format!("{path}: {detail}"))
}

/// Resolves an entity label, attributing any failure to `path`.
fn resolve_entity(path: &str, raw: &str) -> Result<IdentifierType> {
    IdentifierType::from_str(raw).map_err(|e| invalid(path, e))
}

/// The provider names the loader knows how to construct.
const KNOWN_PROVIDERS: [&str; 5] = [
    "openai",
    "anthropic",
    "azure_openai",
    "ollama",
    "openai_compatible",
];

impl RecognizerConfig {
    /// Validates the config and resolves everything string-typed.
    ///
    /// Runs to a **resolved** form rather than returning `()`: the entity
    /// mapping and confidence policy are parsed here, so the loader cannot
    /// forget to and no later stage re-parses a string that was already checked.
    ///
    /// # Errors
    ///
    /// Returns [`Problem::Config`] naming the offending TOML field path for an
    /// empty required field, an unknown provider, an out-of-range sampling
    /// parameter, an unknown `entity_type`, or an incoherent confidence policy.
    pub fn validate(&self) -> Result<ResolvedConfig> {
        if self.class_name.trim().is_empty() {
            return Err(invalid("recognizer.class_name", "must not be empty"));
        }
        if self.model.trim().is_empty() {
            return Err(invalid("recognizer.model", "must not be empty"));
        }
        if !KNOWN_PROVIDERS.contains(&self.provider.as_str()) {
            return Err(invalid(
                "recognizer.provider",
                format!(
                    "unknown provider {:?} (known: {})",
                    self.provider,
                    KNOWN_PROVIDERS.join(", ")
                ),
            ));
        }
        if self.prompt.system.trim().is_empty() {
            return Err(invalid("recognizer.prompt.system", "must not be empty"));
        }
        if self.max_tokens == 0 {
            return Err(invalid("recognizer.max_tokens", "must be greater than 0"));
        }
        if !(0.0..=2.0).contains(&self.temperature) {
            return Err(invalid(
                "recognizer.temperature",
                format!("{} is outside [0.0, 2.0]", self.temperature),
            ));
        }
        if !(0.0..=1.0).contains(&self.top_p) {
            return Err(invalid(
                "recognizer.top_p",
                format!("{} is outside [0.0, 1.0]", self.top_p),
            ));
        }

        self.validate_provider_fields()?;

        let entity_mapping = self.resolve_entity_mapping()?;
        self.validate_few_shot_examples()?;
        let confidence = self.resolve_confidence()?;

        Ok(ResolvedConfig {
            entity_mapping,
            confidence,
        })
    }

    /// Checks the fields a specific provider cannot be constructed without.
    ///
    /// Caught here rather than at construction so the message names the TOML
    /// field, not an internal argument.
    fn validate_provider_fields(&self) -> Result<()> {
        match self.provider.as_str() {
            "azure_openai" if self.endpoint.is_none() => Err(invalid(
                "recognizer.endpoint",
                "is required when provider = \"azure_openai\"",
            )),
            "openai_compatible" if self.base_url.is_none() => Err(invalid(
                "recognizer.base_url",
                "is required when provider = \"openai_compatible\"",
            )),
            _ => Ok(()),
        }
    }

    /// The environment variable this config reads its credential from.
    ///
    /// `None` for `ollama`, which authenticates nothing.
    #[must_use]
    pub fn credential_env(&self) -> Option<&str> {
        if self.provider == "ollama" {
            return None;
        }
        Some(
            self.api_key_env
                .as_deref()
                .unwrap_or(match self.provider.as_str() {
                    "anthropic" => "ANTHROPIC_API_KEY",
                    "azure_openai" => "AZURE_OPENAI_API_KEY",
                    _ => "OPENAI_API_KEY",
                }),
        )
    }

    /// Resolves every `entity_mapping` value to an [`IdentifierType`].
    ///
    /// Keys are the model's own labels and stay strings — a model may emit
    /// anything, and mapping it is the point. Values name octarine types and
    /// must resolve.
    fn resolve_entity_mapping(&self) -> Result<HashMap<String, IdentifierType>> {
        let mut resolved = HashMap::with_capacity(self.entity_mapping.len());
        for (from, to) in &self.entity_mapping {
            let path = format!("recognizer.entity_mapping.{from}");
            resolved.insert(from.clone(), resolve_entity(&path, to)?);
        }
        Ok(resolved)
    }

    /// Checks every few-shot example, with an indexed path per entity.
    ///
    /// Offsets, when given, must describe a real span of the example input.
    /// An example that teaches the model a span the text does not contain
    /// teaches it to hallucinate.
    fn validate_few_shot_examples(&self) -> Result<()> {
        for (i, example) in self.few_shot_examples.iter().enumerate() {
            let example_path = format!("recognizer.few_shot_examples[{i}]");
            if example.input.trim().is_empty() {
                return Err(invalid(
                    &format!("{example_path}.input"),
                    "must not be empty",
                ));
            }
            for (j, entity) in example.output.iter().enumerate() {
                let entity_path = format!("{example_path}.output[{j}]");
                resolve_entity(&format!("{entity_path}.entity_type"), &entity.entity_type)?;
                if entity.text.is_empty() {
                    return Err(invalid(&format!("{entity_path}.text"), "must not be empty"));
                }
                if !example.input.contains(&entity.text) {
                    return Err(invalid(
                        &format!("{entity_path}.text"),
                        format!(
                            "{:?} does not appear in the example input; an example \
that quotes absent text teaches the model to hallucinate",
                            entity.text
                        ),
                    ));
                }
                Self::validate_offsets(&entity_path, entity, &example.input)?;
            }
        }
        Ok(())
    }

    /// Validates an example entity's optional offsets against the input.
    fn validate_offsets(path: &str, entity: &FewShotEntity, input: &str) -> Result<()> {
        let (Some(start), Some(end)) = (entity.start, entity.end) else {
            // Offsets are optional and only meaningful as a pair; one alone
            // describes nothing, so there is nothing to check.
            return Ok(());
        };
        if start >= end {
            return Err(invalid(
                &format!("{path}.start"),
                format!("{start} is not before end {end}"),
            ));
        }
        if end > input.len() {
            return Err(invalid(
                &format!("{path}.end"),
                format!(
                    "{end} is past the end of the example input ({})",
                    input.len()
                ),
            ));
        }
        match input.get(start..end) {
            Some(slice) if slice == entity.text => Ok(()),
            Some(slice) => Err(invalid(
                &format!("{path}.start"),
                format!(
                    "offsets {start}..{end} select {slice:?}, not the declared text {:?}",
                    entity.text
                ),
            )),
            // Offsets are byte indices; landing mid-character is as wrong as
            // landing out of range, and `get` is how we find out without panicking.
            None => Err(invalid(
                &format!("{path}.start"),
                format!("offsets {start}..{end} do not fall on character boundaries"),
            )),
        }
    }

    /// Resolves the confidence policy.
    fn resolve_confidence(&self) -> Result<ConfidencePolicy> {
        match self.confidence.mode.as_str() {
            "from_model" => {
                // A stray `value` here would look like it does something.
                if self.confidence.value.is_some() {
                    return Err(invalid(
                        "recognizer.confidence.value",
                        "is set but mode is \"from_model\", which ignores it; \
use mode = \"constant\" or remove the value",
                    ));
                }
                Ok(ConfidencePolicy::FromModel)
            }
            "constant" => {
                let value = self.confidence.value.ok_or_else(|| {
                    invalid(
                        "recognizer.confidence.value",
                        "is required when mode = \"constant\"",
                    )
                })?;
                if !(0.0..=1.0).contains(&value) {
                    return Err(invalid(
                        "recognizer.confidence.value",
                        format!("{value} is outside [0.0, 1.0]"),
                    ));
                }
                Ok(ConfidencePolicy::Constant(value))
            }
            other => Err(invalid(
                "recognizer.confidence.mode",
                format!("unknown mode {other:?} (known: constant, from_model)"),
            )),
        }
    }

    /// Whether this recognizer handles `language`.
    ///
    /// An empty `supported_languages` means every language, matching the
    /// empty-means-everything convention
    /// [`Recognizer`](octarine::analyze::Recognizer) uses for entity types.
    #[must_use]
    pub fn supports_language(&self, language: &str) -> bool {
        self.supported_languages.is_empty()
            || self
                .supported_languages
                .iter()
                .any(|l| l.eq_ignore_ascii_case(language))
    }
}

/// The parts of a config that validation resolved from strings.
///
/// Handed to the loader so the resolution done during validation is reused
/// rather than repeated.
#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    /// Model label → octarine type.
    pub entity_mapping: HashMap<String, IdentifierType>,
    /// How detections are scored.
    pub confidence: ConfidencePolicy,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    // The schema items these tests build live in the parent module; validation
    // only adds the rules.
    use crate::recognizer::config::{
        ConfidenceConfig, DEFAULT_MAX_TOKENS, DEFAULT_TEMPERATURE, DEFAULT_TOP_P, FewShotExample,
        PromptConfig, RecognizerFile, default_max_tokens, default_temperature, default_top_p,
    };

    /// A minimal valid config, mutated per-test.
    fn base() -> RecognizerConfig {
        RecognizerConfig {
            class_name: "person_finder".to_string(),
            provider: "openai".to_string(),
            model: "gpt-4o-mini".to_string(),
            max_tokens: default_max_tokens(),
            temperature: default_temperature(),
            top_p: default_top_p(),
            enabled: true,
            supported_languages: Vec::new(),
            country_code: None,
            api_key_env: None,
            base_url: None,
            endpoint: None,
            api_version: None,
            language_model_params: HashMap::new(),
            prompt: PromptConfig {
                system: "Extract PERSON entities.".to_string(),
                json_schema: None,
            },
            few_shot_examples: Vec::new(),
            entity_mapping: HashMap::new(),
            confidence: ConfidenceConfig::default(),
        }
    }

    fn example(input: &str, entity_type: &str, text: &str) -> FewShotExample {
        FewShotExample {
            input: input.to_string(),
            output: vec![FewShotEntity {
                entity_type: entity_type.to_string(),
                text: text.to_string(),
                start: None,
                end: None,
            }],
        }
    }

    /// Asserts the message names both the field path and the offending value.
    /// Checking only `is_err()` would pass against any unrelated rejection.
    fn assert_rejected_at(err: &Problem, path: &str, value: &str) {
        let msg = err.to_string();
        assert!(
            msg.contains(path),
            "message must name the field path {path}: {msg}"
        );
        assert!(
            msg.contains(value),
            "message must quote the offending value {value}: {msg}"
        );
    }

    #[test]
    fn a_minimal_config_validates() {
        assert!(base().validate().is_ok());
    }

    // ---- entity_mapping ----------------------------------------------------

    #[test]
    fn an_unknown_entity_type_in_the_mapping_names_its_path_and_value() {
        let mut config = base();
        config
            .entity_mapping
            .insert("PERSON".to_string(), "PERSEN".to_string());

        let err = config.validate().expect_err("PERSEN is not a type");
        assert_rejected_at(&err, "recognizer.entity_mapping.PERSON", "PERSEN");
    }

    #[test]
    fn a_valid_mapping_resolves_to_the_octarine_type() {
        let mut config = base();
        config
            .entity_mapping
            .insert("PERSON".to_string(), "PERSON".to_string());
        config
            .entity_mapping
            .insert("LOCATION".to_string(), "NAMED_LOCATION".to_string());

        let resolved = config.validate().expect("valid mapping");
        assert_eq!(
            resolved.entity_mapping.get("PERSON"),
            Some(&IdentifierType::PersonalName)
        );
        assert_eq!(
            resolved.entity_mapping.get("LOCATION"),
            Some(&IdentifierType::NamedLocation),
            "the mapping must resolve the VALUE, not echo the key"
        );
    }

    // ---- few-shot examples -------------------------------------------------

    #[test]
    fn an_unknown_entity_type_in_an_example_names_its_indexed_path() {
        let mut config = base();
        config.few_shot_examples = vec![
            example("Alice met Bob", "PERSON", "Alice"),
            example("Carol called", "PERSON", "Carol"),
            example("Dave waited", "PERSEN", "Dave"),
        ];

        let err = config.validate().expect_err("PERSEN is not a type");
        // The index must point at the third example, not the first.
        assert_rejected_at(
            &err,
            "recognizer.few_shot_examples[2].output[0].entity_type",
            "PERSEN",
        );
    }

    #[test]
    fn an_example_quoting_absent_text_is_rejected() {
        // Such an example teaches the model that inventing spans is correct.
        let mut config = base();
        config.few_shot_examples = vec![example("Alice met Bob", "PERSON", "Charlie")];

        let err = config.validate().expect_err("Charlie is not in the input");
        assert_rejected_at(
            &err,
            "recognizer.few_shot_examples[0].output[0].text",
            "Charlie",
        );
    }

    #[test]
    fn example_offsets_must_select_the_declared_text() {
        let mut config = base();
        config.few_shot_examples = vec![FewShotExample {
            input: "Alice met Bob".to_string(),
            output: vec![FewShotEntity {
                entity_type: "PERSON".to_string(),
                text: "Alice".to_string(),
                // "Alice" is at 0..5; 10..13 is "Bob".
                start: Some(10),
                end: Some(13),
            }],
        }];

        let err = config
            .validate()
            .expect_err("offsets select the wrong span");
        let msg = err.to_string();
        assert!(
            msg.contains("recognizer.few_shot_examples[0].output[0].start"),
            "must name the offset path: {msg}"
        );
        assert!(
            msg.contains("Bob"),
            "must show what the offsets actually selected: {msg}"
        );
    }

    #[test]
    fn correct_example_offsets_are_accepted() {
        let mut config = base();
        config.few_shot_examples = vec![FewShotExample {
            input: "Alice met Bob".to_string(),
            output: vec![FewShotEntity {
                entity_type: "PERSON".to_string(),
                text: "Alice".to_string(),
                start: Some(0),
                end: Some(5),
            }],
        }];
        assert!(config.validate().is_ok());
    }

    #[test]
    fn offsets_past_the_end_are_rejected_rather_than_panicking() {
        let mut config = base();
        config.few_shot_examples = vec![FewShotExample {
            input: "Alice".to_string(),
            output: vec![FewShotEntity {
                entity_type: "PERSON".to_string(),
                text: "Alice".to_string(),
                start: Some(0),
                end: Some(9_999),
            }],
        }];
        let err = config.validate().expect_err("9999 is past the end");
        assert!(err.to_string().contains("past the end"));
    }

    #[test]
    fn offsets_splitting_a_multibyte_character_are_rejected() {
        // Byte offsets that land mid-character must not panic on slicing.
        let mut config = base();
        config.few_shot_examples = vec![FewShotExample {
            input: "café au lait".to_string(),
            output: vec![FewShotEntity {
                entity_type: "PERSON".to_string(),
                text: "café".to_string(),
                start: Some(0),
                // 'é' occupies bytes 3..5, so 4 is mid-character.
                end: Some(4),
            }],
        }];
        let err = config
            .validate()
            .expect_err("a mid-character offset is not valid");
        assert!(err.to_string().contains("character boundaries"), "{err}");
    }

    // ---- confidence --------------------------------------------------------

    #[test]
    fn constant_mode_requires_a_value() {
        let mut config = base();
        config.confidence = ConfidenceConfig {
            mode: "constant".to_string(),
            value: None,
        };
        let err = config.validate().expect_err("constant needs a value");
        assert!(err.to_string().contains("recognizer.confidence.value"));
    }

    #[test]
    fn constant_mode_resolves_to_its_value() {
        let mut config = base();
        config.confidence = ConfidenceConfig {
            mode: "constant".to_string(),
            value: Some(0.85),
        };
        let resolved = config.validate().expect("valid");
        assert_eq!(resolved.confidence, ConfidencePolicy::Constant(0.85));
    }

    #[test]
    fn a_value_under_from_model_mode_is_rejected_rather_than_ignored() {
        // Silently ignoring it would leave the operator believing the score
        // was pinned when it is not.
        let mut config = base();
        config.confidence = ConfidenceConfig {
            mode: "from_model".to_string(),
            value: Some(0.9),
        };
        let err = config.validate().expect_err("value is meaningless here");
        assert!(err.to_string().contains("recognizer.confidence.value"));
    }

    #[test]
    fn an_out_of_range_constant_is_rejected() {
        for bad in [-0.1, 1.1] {
            let mut config = base();
            config.confidence = ConfidenceConfig {
                mode: "constant".to_string(),
                value: Some(bad),
            };
            assert!(
                config.validate().is_err(),
                "{bad} is outside [0.0, 1.0] and must be rejected"
            );
        }
    }

    #[test]
    fn an_unknown_confidence_mode_names_the_value() {
        let mut config = base();
        config.confidence = ConfidenceConfig {
            mode: "vibes".to_string(),
            value: None,
        };
        let err = config.validate().expect_err("vibes is not a mode");
        assert_rejected_at(&err, "recognizer.confidence.mode", "vibes");
    }

    #[test]
    fn the_default_confidence_policy_trusts_the_model() {
        // A constant default would silently overwrite every reported score.
        let resolved = base().validate().expect("valid");
        assert_eq!(resolved.confidence, ConfidencePolicy::FromModel);
    }

    // ---- scalar fields -----------------------------------------------------

    #[test]
    fn an_unknown_provider_names_the_value_and_lists_the_known_ones() {
        let mut config = base();
        config.provider = "sk-magic".to_string();
        let err = config.validate().expect_err("not a provider");
        assert_rejected_at(&err, "recognizer.provider", "sk-magic");
        assert!(
            err.to_string().contains("ollama"),
            "listing the known providers is what makes the error actionable: {err}"
        );
    }

    #[test]
    fn empty_required_fields_are_rejected_by_name() {
        type Mutation = fn(&mut RecognizerConfig);
        let cases: [(&str, Mutation); 4] = [
            ("recognizer.class_name", |c| c.class_name = "  ".to_string()),
            ("recognizer.model", |c| c.model = String::new()),
            ("recognizer.prompt.system", |c| {
                c.prompt.system = "\n".to_string();
            }),
            ("recognizer.max_tokens", |c| c.max_tokens = 0),
        ];
        for (path, mutate) in cases {
            let mut config = base();
            mutate(&mut config);
            let err = config.validate().expect_err("must reject");
            assert!(
                err.to_string().contains(path),
                "rejection must name {path}: {err}"
            );
        }
    }

    #[test]
    fn out_of_range_sampling_parameters_are_rejected() {
        let mut hot = base();
        hot.temperature = 2.5;
        assert!(hot.validate().is_err(), "temperature 2.5 is out of range");

        let mut wide = base();
        wide.top_p = 1.5;
        assert!(wide.validate().is_err(), "top_p 1.5 is out of range");
    }

    // ---- language scoping --------------------------------------------------

    #[test]
    fn an_empty_language_list_means_every_language() {
        let config = base();
        assert!(config.supports_language("en"));
        assert!(
            config.supports_language("pt-BR"),
            "empty means everything, not nothing"
        );
    }

    #[test]
    fn a_language_list_scopes_the_recognizer() {
        let mut config = base();
        config.supported_languages = vec!["en".to_string(), "es".to_string()];
        assert!(config.supports_language("en"));
        assert!(
            config.supports_language("ES"),
            "matching is case-insensitive"
        );
        assert!(!config.supports_language("de"), "de was not listed");
    }

    // ---- TOML round-trip ---------------------------------------------------

    #[test]
    fn the_documented_toml_shape_deserializes() {
        // The schema in the issue and in docs/llm/recognizer-config.md must
        // actually parse, or the documentation is fiction.
        let toml_src = r#"
[recognizer]
class_name = "person_finder_openai"
provider = "openai"
model = "gpt-4o-mini"
max_tokens = 512
temperature = 0.0
top_p = 1.0
enabled = true
supported_languages = ["en", "es"]
country_code = "US"

[recognizer.language_model_params]
seed = 42

[recognizer.prompt]
system = "Extract PERSON entities from the user text."

[[recognizer.few_shot_examples]]
input = "Alice met Bob in NYC"
output = [{ entity_type = "PERSON", text = "Alice", start = 0, end = 5 }]

[recognizer.entity_mapping]
PERSON = "PERSON"
LOCATION = "NAMED_LOCATION"

[recognizer.confidence]
mode = "constant"
value = 0.85
"#;
        let file: RecognizerFile = toml::from_str(toml_src).expect("documented shape must parse");
        let resolved = file
            .recognizer
            .validate()
            .expect("documented shape is valid");

        assert_eq!(file.recognizer.class_name, "person_finder_openai");
        assert_eq!(file.recognizer.max_tokens, 512);
        assert_eq!(resolved.confidence, ConfidencePolicy::Constant(0.85));
        assert_eq!(
            resolved.entity_mapping.get("LOCATION"),
            Some(&IdentifierType::NamedLocation)
        );
        assert_eq!(
            file.recognizer.language_model_params.get("seed"),
            Some(&toml::Value::Integer(42)),
            "provider-specific params must pass through untouched"
        );
    }

    #[test]
    fn omitted_optional_fields_take_their_documented_defaults() {
        let toml_src = r#"
[recognizer]
class_name = "minimal"
provider = "ollama"
model = "llama3"

[recognizer.prompt]
system = "Find PII."
"#;
        let file: RecognizerFile = toml::from_str(toml_src).expect("minimal shape must parse");
        assert_eq!(file.recognizer.max_tokens, DEFAULT_MAX_TOKENS);
        assert_eq!(file.recognizer.temperature, DEFAULT_TEMPERATURE);
        assert_eq!(file.recognizer.top_p, DEFAULT_TOP_P);
        assert!(
            file.recognizer.enabled,
            "a config present in the directory is meant to be used"
        );
        assert!(file.recognizer.validate().is_ok());
    }
}
