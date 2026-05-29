# Presidio — Docs Concepts, CLI, and Roadmap Signals

## Source files reviewed

- `mkdocs.yml` (canonical nav) — https://github.com/microsoft/presidio/blob/main/mkdocs.yml
- `CHANGELOG.md` — https://raw.githubusercontent.com/microsoft/presidio/main/CHANGELOG.md
- `presidio-cli/presidio_cli/cli.py` — https://github.com/microsoft/presidio/blob/main/presidio-cli/presidio_cli/cli.py
- `presidio-cli/presidio_cli/config.py` — https://github.com/microsoft/presidio/blob/main/presidio-cli/presidio_cli/config.py
- `presidio-cli/presidio_cli/analyzer.py` — https://github.com/microsoft/presidio/blob/main/presidio-cli/presidio_cli/analyzer.py
- `presidio-cli/presidio_cli/__init__.py` — https://github.com/microsoft/presidio/blob/main/presidio-cli/presidio_cli/__init__.py
- `presidio-cli/presidio_cli/__main__.py` — https://github.com/microsoft/presidio/blob/main/presidio-cli/presidio_cli/__main__.py
- `presidio-cli/.presidiocli` — https://github.com/microsoft/presidio/blob/main/presidio-cli/.presidiocli
- `presidio-cli/presidio_cli/conf/default.yaml`
- `presidio-cli/presidio_cli/conf/limited.yaml`
- `presidio-cli/README.md`
- Docs site pages (selection):
  - https://microsoft.github.io/presidio/
  - https://microsoft.github.io/presidio/learn_presidio/concepts/
  - https://microsoft.github.io/presidio/analyzer/
  - https://microsoft.github.io/presidio/analyzer/adding_recognizers/
  - https://microsoft.github.io/presidio/analyzer/developing_recognizers/
  - https://microsoft.github.io/presidio/analyzer/recognizer_registry_provider/
  - https://microsoft.github.io/presidio/analyzer/analyzer_engine_provider/
  - https://microsoft.github.io/presidio/analyzer/customizing_nlp_models/
  - https://microsoft.github.io/presidio/analyzer/nlp_engines/spacy_stanza/
  - https://microsoft.github.io/presidio/analyzer/nlp_engines/transformers/
  - https://microsoft.github.io/presidio/analyzer/nlp_engines/gpu_usage/
  - https://microsoft.github.io/presidio/analyzer/decision_process/
  - https://microsoft.github.io/presidio/anonymizer/
  - https://microsoft.github.io/presidio/anonymizer/adding_operators/
  - https://microsoft.github.io/presidio/image-redactor/
  - https://microsoft.github.io/presidio/image-redactor/evaluating_dicom_redaction/
  - https://microsoft.github.io/presidio/structured/
  - https://microsoft.github.io/presidio/evaluation/
  - https://microsoft.github.io/presidio/ahds_integration/
  - https://microsoft.github.io/presidio/faq/
  - https://microsoft.github.io/presidio/supported_entities/
  - Tutorial pages `00`–`13` under https://microsoft.github.io/presidio/tutorial/
  - Quick-start pages under https://microsoft.github.io/presidio/getting_started/

## Docs site — pages and concepts taught

The mkdocs nav has six top-level sections: **Presidio**, **Quick start**, **Learn Presidio**, **Resources**, **Recipes**, **Samples**. Page titles below are quoted verbatim from `mkdocs.yml`.

### Presidio (top-level intro)

- **Home** (`index.md`) — Library overview, building blocks, install/Docker entry points.
- **Installation** (`installation.md`) — pip / Docker / source install matrix; spaCy model download step.
- **FAQ** (`faq.md`) — Customization paths, NLP framework support, false positive/negative tradeoffs, explicit "no built-in authentication by design" stance, "Microsoft Presidio is not an official Microsoft product" disclaimer, pseudonymization defined as reversible fake-data substitution.

### Quick start

- **Home** (`getting_started.md`) — Index of the three modality starters.
- **Text** (`getting_started/getting_started_text.md`) — pip + spaCy model + transformers (`dslim/bert-base-NER`) + Docker REST flow. Notes "Apple Silicon MPS is currently not supported" for cupy install.
- **Images** (`getting_started/getting_started_images.md`) — ImageRedactor pip + Tesseract + Docker.
- **Semi/Structured data** (`getting_started/getting_started_structured.md`) — Pandas/JSON quickstart for presidio-structured.

### Learn Presidio

- **Home** (`learn_presidio/index.md`) — Index page.
- **Concepts** (`learn_presidio/concepts.md`) — Teaches the vocabulary: **Entity, Context, Recognizer, Analyzer, Predefined recognizer, Custom recognizer, ad-hoc recognizer, Deny list, Allow list**, plus the object inventory: `EntityRecognizer`, `RecognizerResult`, `RecognizerRegistry`, `NlpEngine`, `AnalyzerEngine`, `BatchAnalyzerEngine`, `AnonymizerEngine`, `DeanonymizerEngine`, `Operator`, `BatchAnonymizerEngine`, `ImageRedactorEngine`, `StructuredEngine`. Evaluation: **Precision, Recall**.

#### Tutorial pages

| Page | Concept taught |
|---|---|
| Getting started | `AnalyzerEngine()`, `analyzer.analyze(text=, language="en")` |
| Deny-list recognizers | `PatternRecognizer(supported_entity=, deny_list=)`, then `analyzer.registry.add_recognizer(...)` |
| Regex recognizers | `Pattern(name=, regex=, score=)` + `PatternRecognizer(supported_entity=, patterns=[...])` |
| Rule-based recognizers | Subclass `EntityRecognizer`, implement `load()` + `analyze(text, entities, nlp_artifacts)`, use `NlpArtifacts.tokens` and spaCy attrs like `token.like_num` |
| Additional models/languages | Two-level: `NlpEngine` per language + `EntityRecognizer.supported_language` per recognizer. Engine-level `supported_languages=["en","es"]` |
| External services | Wrap a remote service or non-spaCy ML framework (Flair, HF transformers, CRF) by subclassing `EntityRecognizer`/`RemoteRecognizer` and converting outputs to `RecognizerResult` |
| Context enhancement | `LemmaContextAwareEnhancer` with tunable `context_similarity_factor` (default 0.35) and `min_score_with_context_similarity` (default 0.4). Per-call `context=[...]` parameter on `analyze()` for column-name hints |
| Decision process | `AnalyzerEngine(log_decision_process=True)` for stdout logs, or `analyze(..., return_decision_process=True)` to attach `analysis_explanation` to results. Optional `correlation_id` (returned via `x-correlation-id` HTTP header). Exposed fields: `recognizer`, `pattern_name`, `pattern`, `original_score`, `score`, `score_context_improvement`, `supportive_context_word`, `textual_explanation`, `validation_result` |
| No-code recognizers | Three YAML files: `default_analyzer.yaml`, `default_recognizers.yaml`, `default.yaml` (NLP). Loaded via `AnalyzerEngineProvider(analyzer_engine_conf_file=...).create_engine()` |
| Ad-hoc recognizers | Per-request JSON-defined recognizers via `ad_hoc_recognizers` field on the `/analyze` REST endpoint. Supports `patterns`, `deny_list`, `supported_entity`, `supported_language`, `context`. Scope: single request only |
| Simple anonymization | `AnonymizerEngine.anonymize(text, analyzer_results, operators={...})`. `OperatorConfig` per entity type. Built-in `DEFAULT` key. `mask` operator params: `masking_char`, `chars_to_mask`, `from_end`. Result has `.text` and `.to_json()` |
| Custom anonymization | `OperatorConfig("custom", {"lambda": fake_name})` — callable receives the matched text and returns a string. Use case: pseudonymization with `Faker` |
| Encryption/Decryption | AES-CBC, 16-char symmetric key. `OperatorConfig("encrypt", {"key": k})` and `OperatorConfig("decrypt", {"key": k})`. Direct operator use: `Decrypt().operate(text=..., params={"key": k})`. Output exposes `.text` + `.items` so only entities are decrypted |
| Allow-lists | `analyzer.analyze(..., allow_list=["bing.com"])` — tokens NEVER flagged regardless of recognizer |

#### Text de-identification — Analyzer

- **Home** (`analyzer/index.md`) — Class hierarchy: `RecognizerResult`, `EntityRecognizer`, `PatternRecognizer`, `AnalyzerEngine`, `RecognizerRegistry`, `NlpEngine`, `ContextAwareEnhancer`. Two ways to add NER: via `NlpEngine` (shared) or separate `EntityRecognizer` (composable, multiple in parallel).
- **Developing PII recognizers — Tutorial** (`analyzer/adding_recognizers.md`) — Hierarchy: `EntityRecognizer` → `LocalRecognizer` / `RemoteRecognizer` → `PatternRecognizer`. Lists nine extension patterns including **Azure AI Language**, **Azure Health Data Services (AHDS)**, **Language Model-based detection (LangExtract + Ollama)**, and **ad-hoc recognizers** via `/analyze` JSON.
- **Developing PII recognizers — Best practices** (`analyzer/developing_recognizers.md`) — Performance budget quoted: "Anything above 100ms per request with 100 tokens is probably not good enough." Three recognizer categories: deny lists, pattern-based, ML/rule-based. Isolate model deps via `RemoteRecognizer` to avoid conflicts.
- **Developing PII recognizers — Recognizer registry from file** (`analyzer/recognizer_registry_provider.md`) — `RecognizerRegistryProvider(conf_file=...).create_recognizer_registry()`. YAML keys: `global_regex_flags`, `supported_languages`, `recognizers[]` with `name`, `type` (predefined|custom), `supported_languages` (per-language `context`), `supported_entity`, `patterns`, `deny_list`, `deny_list_score`, `enabled`, `class_name`, `model_name`, `aggregation_strategy`, `device`. Tip: disable `SpacyRecognizer` for agglutinative languages (e.g., Korean) and rely on `HuggingFaceNerRecognizer`.
- **Filtering recognizers by country** (`analyzer/filtering_by_country.md`) — New page (unreleased, see CHANGELOG). `countries=["us","uk"]` kwarg on `RecognizerRegistry.load_predefined_recognizers()`; YAML top-level `supported_countries`; per-recognizer `country_code:` field; `EntityRecognizer.COUNTRY_CODE` ClassVar; runtime introspection via `country_code()` and `is_country_specific()` plus `RecognizerRegistry.get_country_codes()`. (Page returned 404 — still in the unreleased docs build.)
- **Multi-language support** (`analyzer/languages.md`) — `AnalyzerEngine(supported_languages=[...])` vs per-recognizer `supported_language`. Routing: `analyze(..., language="en")` dispatches only to matching recognizers and selects the matching NLP model. YAML config via `NlpEngineProvider(conf_file=...)`.
- **Customizing the NLP model — Home** (`analyzer/customizing_nlp_models.md`) — Two purposes: "NER based PII identification, and feature extraction for downstream rule based logic". `NlpEngineProvider` accepts dict or YAML. `ner_model_configuration` knobs: `labels_to_ignore`, `model_to_presidio_entity_mapping`, `low_confidence_score_multiplier`, `low_score_entity_names`.
- **Customizing the NLP model — Spacy/Stanza** (`analyzer/nlp_engines/spacy_stanza.md`) — `SpacyNlpEngine`, `SpacyRecognizer`, `NlpArtifacts`. Pattern for **reusing a pre-loaded spaCy pipeline** by subclassing `SpacyNlpEngine` and setting `self.nlp = {"en": loaded_model}`.
- **Customizing the NLP model — Transformers** (`analyzer/nlp_engines/transformers.md`) — `TransformersNlpEngine` wraps HF model inside a spaCy pipeline. Config: `aggregation_strategy` ("simple"|"first"|"average"|"max"), `stride`, `alignment_mode` ("strict"|"contract"|"expand"). Reference models: `StanfordAIMI/stanford-deidentifier-base`, `obi/deid_roberta_i2b2`, `dslim/bert-base-NER-uncased`.
- **Customizing the NLP model — GPU Acceleration** (`analyzer/nlp_engines/gpu_usage.md`) — `PRESIDIO_DEVICE` env var (`cpu`/`cuda`/`cuda:0`/`mps`). Supported engines: `TransformersNlpEngine`, GLiNER, Stanza, spaCy-transformers. Warning: `en_core_web_lg` (non-transformer spaCy) NOT recommended for GPU. cupy/CUDA driver mismatch fails silently.
- **Tracing the decision process** (`analyzer/decision_process.md`) — see Tutorial 07 row above. Caveat: only explains why PII WAS detected, never why it WASN'T.
- **Configure from file** (`analyzer/analyzer_engine_provider.md`) — `AnalyzerEngineProvider` takes single-file or split (analyzer + NLP + registry) configs. Top-level YAML keys: `supported_languages`, `default_score_threshold`, `nlp_configuration`, `recognizer_registry`. Recognizers omitted are silently dropped EXCEPT the NLP recognizer which always loads (toggle with `enabled: false`).

#### Text de-identification — Anonymizer

- **Home** (`anonymizer/index.md`) — Anonymizers vs Deanonymizers. Built-ins: `replace`, `redact`, `hash` (salted by default since 2.2.361, sha256/sha512), `mask`, `encrypt`, `custom`, `surrogate_ahds`, `keep`. Deanonymizer: `decrypt`. Overlap-resolution rules: higher score wins on full overlap; larger span wins on containment; partial intersections concatenate.
- **Developing PII anonymization operators** (`anonymizer/adding_operators.md`) — Subclass `Operator`, implement `operate()`, `validate()`, `operator_name()`, `operator_type()` (returns Anonymize|Deanonymize). Register via `AnonymizerEngine.add_anonymizer` or `DeanonymizeEngine.add_deanonymizer`.

#### AHDS integration

- **Azure Health Data Services de-identification service integration** (`ahds_integration.md`) — Two components: **AHDS Recognizer** (analyzer side) and **AHDS Surrogate Operator** (anonymizer side, `OperatorConfig("surrogate", {...})`). Surrogate params: `endpoint` (env fallback `AHDS_ENDPOINT`), `entities`, `input_locale`, `surrogate_locale`. Production credential chain: `EnvironmentCredential` + `WorkloadIdentityCredential` + `ManagedIdentityCredential`. `ENV=development` switches to `DefaultAzureCredential` (allows browser/CLI login). Extras: `pip install presidio-analyzer[ahds]`.

#### Image de-identification

- **Home** (`image-redactor/index.md`) — Engines: `ImageRedactorEngine`, `DicomImageRedactorEngine`, `ImageAnalyzerEngine`, `DocumentIntelligenceOCR` (Azure backend), Tesseract (default). DICOM caveat: pixel data only, NOT metadata. `redact_and_return_bbox()` returns image + bbox list.
- **Evaluating DICOM redaction** (`image-redactor/evaluating_dicom_redaction.md`) — `DicomImagePiiVerifyEngine.verify_dicom_instance()` and `.eval_dicom_instance()`. Ground-truth JSON schema: `label`, `left`, `top`, `width`, `height`. Tunables: `padding_width`, ground-truth matching tolerance, `ocr_kwargs={"ocr_threshold": 50}`.

#### Structured

- **Home** (`structured/index.md`) — `StructuredEngine`, `PandasAnalysisBuilder`, `JsonAnalysisBuilder`, `JsonDataProcessor`, `StructuredAnalysis` (manual mapping for nested JSON). `generate_analysis(selection_strategy=...)` modes: "most_common" (default), "highest_confidence", "mixed" with `mixed_strategy_threshold`. Stated limitation: "Nesting objects in lists is not supported in JsonAnalysisBuilder for now." Roadmap mentions: **PySpark**, **K-Anonymity**, **Differential Privacy**, **sensitive column-name detection**.

#### PII detection evaluation

- **Home** (`evaluation/index.md`) — Metrics: Precision, Recall, Fβ. Recommends β=2 to weight recall. Points at separate `microsoft/presidio-research` repo with five evaluation notebooks (data generator, EDA, train/test split with leakage avoidance, vanilla eval, tuned eval claiming ~30% F-score gain).

### Resources

- **Supported entities** (`supported_entities.md`) — Region groups: Global, USA, UK, Spain, Italy, Poland, Singapore, Australia, India, Finland, Korea, Nigeria, Thai, Medical/Clinical.
- **Community** (`community.md`)
- **Change log** — external link to GitHub.
- **Setting up a development environment** (`development.md`)
- **Build and release process** (`build_release.md`)
- **Changes from V1 to V2** (`presidio_V2.md`)
- **Python API reference**: Home, Analyzer, Anonymizer, Image Redactor, Structured — auto-generated via mkdocstrings (sphinx-style docstrings).
- **REST API reference** — external link to `api-docs.html`.

### Recipes

- **Home** (`recipes/index.md`), **Contributing** (`recipes/CONTRIBUTING.md`), **Template** (`recipes/template.md`) — Community contribution scaffolding (effectively empty cookbook).

### Samples (notable beyond first-pass audit)

Notebooks of interest not previously catalogued:
- `samples/python/pseudonymization.ipynb` — Pseudonymization pattern using `InstanceCounterAnonymizer` (custom operator).
- `samples/python/no_code_config.ipynb` — YAML-driven setup end-to-end.
- `samples/python/synth_data_with_openai.ipynb` — Synthetic PII generation.
- `samples/python/gliner.md` — GLiNER as external PII model.
- `samples/python/ahds/` — AHDS remote recognizer.
- `samples/python/keep_entities.ipynb` — The `keep` operator.
- `samples/python/getting_entity_values.ipynb` — Custom operator capturing original entity values.
- `samples/python/example_pdf_annotation.ipynb` — PDF support via separate notebook (NOT a built-in engine).
- `samples/deployments/redacting-telemetry/` — Pattern for redacting OpenTelemetry data.
- `samples/docker/litellm.md` — LiteLLM proxy integration for masking LLM API calls.

## Concepts taught (extracted)

Each item below is a first-class concept Presidio teaches and that octarine would need a corresponding feature for.

- **Entity / Entity type** — Strongly-typed PII category (`PERSON`, `CREDIT_CARD`, `US_SSN`, …). Returned in `RecognizerResult.entity_type`.
- **Recognizer** — Pluggable detector. Hierarchy: `EntityRecognizer` (abstract) → `LocalRecognizer` / `RemoteRecognizer` → `PatternRecognizer` (regex + deny-list base).
- **Predefined vs Custom recognizer** — Predefined ships in the repo; custom is user-supplied. `type: predefined|custom` in YAML.
- **Ad-hoc recognizer** — Per-request, JSON-encoded in `/analyze` body. Scope: single call only. Lets you add detection logic to a running service without redeploying.
- **Persistent recognizer** — In code or YAML; survives across calls.
- **Deny list** — List of literal tokens treated as PII via `PatternRecognizer(deny_list=...)`.
- **Allow list** — List of literal tokens NEVER treated as PII regardless of recognizer (per-call `allow_list=` kwarg).
- **Score / Confidence score** — Per-result `score` ∈ [0,1].
- **Score threshold** — `default_score_threshold` in YAML, `--threshold` semantic in `.presidiocli` (`threshold` key). Filters results below threshold.
- **Context / Context word** — Surrounding words that boost a match's score. Per-recognizer `context=[...]` list and per-call `analyze(context=[...])` parameter.
- **Context-aware enhancement** — `LemmaContextAwareEnhancer` with `context_similarity_factor` (default 0.35) and `min_score_with_context_similarity` (default 0.4). Custom enhancer pluggable via `context_aware_enhancer=` kwarg. As of 2.2.362 also supports `context_matching_mode="whole_word"` to avoid `lic` matching `duplicate`.
- **Decision process / Decision trace** — Explainability layer. `return_decision_process=True` and `log_decision_process=True`. Returns an `analysis_explanation` object with fields: `recognizer`, `pattern_name`, `pattern`, `original_score`, `score`, `score_context_improvement`, `supportive_context_word`, `textual_explanation`, `validation_result`. Caveat: only explains positives, not false negatives.
- **Correlation ID** — Optional `correlation_id` argument to `analyze()`, also returned as `x-correlation-id` HTTP header.
- **No-code configuration** — Entire pipeline (analyzer + NLP + registry) driven by YAML. Triple of files (`default_analyzer.yaml`, `default_recognizers.yaml`, `default.yaml`) or single combined file. Loaded via `AnalyzerEngineProvider` and `RecognizerRegistryProvider`.
- **`global_regex_flags`** — Single regex-flags integer applied across all patterns, settable per-recognizer or registry-wide.
- **Country filtering / Country-specific recognizer** — New (unreleased). `country_code` field; `countries=` filter on registry; class-level `EntityRecognizer.COUNTRY_CODE`; `is_country_specific()`.
- **`enabled: false` toggle** — Selectively disable predefined recognizers. As of 2.2.359, country-specific English-default recognizers (SgFin, AuAbn/Acn/Tfn/Medicare, InPan/Aadhaar/VehicleReg/Passport/Voter, EsNif) ship as **`enabled: false`** to reduce false positives.
- **`labels_to_ignore`** — NER label filter. Note from 2.2.359: "Don't set a default for LABELS_TO_IGNORE if not specified."
- **`model_to_presidio_entity_mapping`** — Bridge model labels → Presidio entity types (e.g., `PER: PERSON`).
- **`low_confidence_score_multiplier` / `low_score_entity_names`** — Per-entity score adjustment knob.
- **NLP engine** — `SpacyNlpEngine`, `StanzaNlpEngine`, `TransformersNlpEngine`. Provides tokens, lemmas, NER entities, NLP artifacts.
- **`NlpEngineProvider`** — Builds engine from dict or YAML config file.
- **`HuggingFaceNerRecognizer`** — Direct HF NER without requiring spaCy as wrapper (new in 2.2.362).
- **`MedicalNERRecognizer`** — Subclass of `HuggingFaceNerRecognizer` for clinical entity detection.
- **GLiNER recognizer** — Open-vocabulary NER via `GLiNERRecognizer`. ONNX backend supported (`load_onnx_model=True`) for CPUs lacking AVX2.
- **LangExtract recognizer** — Configurable LLM-based PII detection. YAML config drives any LLM provider; Azure OpenAI managed-identity auth supported.
- **`HuggingFaceNerRecognizer` / `TransformersRecognizer`** — Two parallel paths into HF models: as the NlpEngine, or as a standalone Recognizer for parallel models.
- **Remote recognizer** — Subclass `RemoteRecognizer`. Wrap external HTTP service. Endpoints implied: `detect`, `supported_entities`.
- **GPU device control** — `PRESIDIO_DEVICE` env var.
- **Custom NLP engine** — Subclass `SpacyNlpEngine` to reuse pre-loaded models without double-loading.
- **`NerModelConfiguration`** — Configuration container for the NER step (aggregation strategy, stride, alignment mode, label mapping).
- **Multi-language support** — `supported_languages=[...]` on engine + `supported_language` per recognizer; language-keyed NLP model dict.
- **`BatchAnalyzerEngine` / `BatchAnonymizerEngine`** — Batch APIs. REST batch endpoints landed in 2.2.361. Tunable `n_process` and `batch_size` (2.2.358).
- **Operator** — Anonymizer plugin. Two types: `Anonymize`, `Deanonymize`.
- **Operator: `replace`** — Constant string substitution; defaults to `<ENTITY_TYPE>`.
- **Operator: `redact`** — Removes the entity entirely.
- **Operator: `mask`** — `masking_char`, `chars_to_mask`, `from_end`.
- **Operator: `hash`** — sha256 (default), sha512. **Salted by default since 2.2.361 (BREAKING)**; min 16 bytes. MD5 deprecated since 2.2.358.
- **Operator: `encrypt` / `decrypt`** — AES-CBC, 16-char symmetric key. Cryptography backend (cryptography ≥46.0.4).
- **Operator: `custom`** — User lambda receiving the value, returning string. Fix in unreleased: validate() no longer calls lambda with dummy `"PII"`.
- **Operator: `surrogate_ahds`** — Azure Health Data Services surrogate generation. Cross-reference consistency: same entity → same surrogate within document.
- **Operator: `keep`** — Pass-through; entity left in text.
- **`DEFAULT` operator key** — Catch-all override for unspecified entity types.
- **Pseudonymization** — Reversible replacement pattern. Built using `custom` operator + state-bearing lambda. Distinct from anonymization (irreversible).
- **`InstanceCounterAnonymizer`** — Sample pattern: assign monotonically increasing tokens per entity type.
- **OperatorResult** — Per-entity item in the anonymized output. Allows partial decryption.
- **Conflict resolution / Overlap handling** — Higher score wins on full overlap; larger span wins on containment; partial intersections concatenated.
- **`StructuredEngine` selection strategy** — `"most_common"` (default), `"highest_confidence"`, `"mixed"` with `mixed_strategy_threshold`.
- **`PandasAnalysisBuilder` / `JsonAnalysisBuilder`** — Column-name → entity-type inference for tabular and JSON inputs.
- **`StructuredAnalysis`** — Manual entity-mapping dict for nested JSON.
- **DICOM redaction** — Pixel-data PHI scrubbing distinct from metadata scrubbing. `_make_phi_list` uses both `is_patient` and `is_name` (since 2.2.361).
- **OCR engines** — Tesseract (default) and Azure Document Intelligence (`DocumentIntelligenceOCR`).
- **`ImageAnalyzerEngine`** — Wraps OCR component to feed text into analyzer.
- **`redact_and_return_bbox`** — Variant returning bounding boxes alongside redacted image (2.2.361).
- **`DicomImagePiiVerifyEngine`** — Eval engine for DICOM redaction (precision/recall against ground truth JSON).
- **PII detection evaluation framework** — Precision, Recall, Fβ (recommend β=2 for PII). Separate `microsoft/presidio-research` repo with PII data generator + train/test split with leakage avoidance.
- **LLM-as-a-judge evaluation** — New in 2.2.362 — LLM evaluates PII detection quality.
- **Sampling support in evaluation framework** — New in 2.2.362.
- **Dataset interface for evaluation framework** — New in 2.2.362.
- **REST batch API** — Array-in/array-out on `/analyze` with backward compatibility.
- **Regex execution timeout** — `REGEX_TIMEOUT_SECONDS` env var (default 60s) to prevent catastrophic backtracking. New in 2.2.362.
- **No-auth-by-design stance** — Presidio explicitly does NOT ship authentication; expected at gateway layer.
- **`presidio` meta-package** — `pip install presidio` now installs analyzer + anonymizer (2.2.362). Distinct from `presidio-cli`.
- **DeviceDetector singleton** — 4–10× perf boost for GLiNER/Transformers/Stanza (2.2.361).
- **Pydantic-based YAML validation** — `ConfigurationValidator` class for config error reporting (2.2.361).
- **Multiple recognizer instances from same class** — `class_name` parameter (2.2.361).
- **Disable NLP recognizer entirely** — Via config flag (2.2.359). Useful for pure-pattern pipelines.

## presidio-cli — complete command-line surface

### Executable and entry point

- **Executable name**: `presidio` (set by `SHELL_NAME = "presidio"` in `presidio_cli/__init__.py`).
- **Entry point**: `presidio_cli.cli:run` (also invocable via `python -m presidio_cli` → `__main__.py`).
- **Distribution**: `presidio-cli` on PyPI (separate from the meta-package `presidio`).
- **Python support**: 3.10, 3.11, 3.12, 3.13.

### Top-level flags (argparse, full surface)

| Flag | Type | Default | Help text |
|---|---|---|---|
| `-v` / `--version` | flag (action=version) | — | Prints `v{APP_VERSION}` and exits. |
| (positional) `FILE_OR_DIR` | `nargs="*"` | `()` | "files to check" — list of files and/or directories. Mutually exclusive with `-`. **Required** unless `-` is given. |
| `-` | flag (action=store_true → `stdin`) | False | "read from standard input". Mutually exclusive with positional files. |
| `-c` / `--config-file` | str | None | "path to a custom configuration" (YAML file path). Mutually exclusive with `-d`. |
| `-d` / `--config-data` | str | None | "custom configuration (as YAML source)" — inline YAML string. If string has no `:`, auto-prefixed with `extends:` to allow `-d default`. Mutually exclusive with `-c`. |
| `-f` / `--format` | choice | `"auto"` | "format for parsing output". Choices: `standard`, `github`, `auto`, `colored`, `parsable`. |
| `--no-warnings` | flag | False | "output only error level problems" (filters out `level != "error"`). |
| `-h` / `--help` | flag | — | argparse default help. |

There are NO subcommands. The tool is a single-shot scanner.

### Config-file precedence (when no `-c`/`-d` given)

1. `-d <yaml>` if provided.
2. `-c <path>` if provided.
3. `./.presidiocli` if it exists in cwd.
4. Built-in fallback: `extends: default` (loads `presidio_cli/conf/default.yaml`).

### Output formats

| Format | Description |
|---|---|
| `standard` | `  LINE:COL    SCORE    ENTITY_TYPE  (explanation?)` plain text; filename printed once at top of block. |
| `colored` | Same as `standard` but ANSI-colored. Score >=1 is red; <1 is yellow; line/col in dim; filename underlined. |
| `github` | GitHub Actions log workflow format. `::group::FILE` open, `::SCORE file=...,line=...,col=...::LINE:COL [TYPE]` per problem, `::endgroup::` close. |
| `parsable` | One JSON object per line from `RecognizerResult.to_dict()`. Fields: `entity_type`, `start`, `end`, `score`, `analysis_explanation`. |
| `auto` (default) | Resolves to `github` if `GITHUB_ACTIONS` AND `GITHUB_WORKFLOW` env vars are set; else `colored` if stdout is a TTY and platform supports ANSI; else `standard`. |

### Config file (`.presidiocli` / any YAML)

YAML keys (parsed by `PresidioCLIConfig.parse`):

| Key | Type | Default | Notes |
|---|---|---|---|
| `language` | string | `"en"` | Passed to `analyzer.analyze(language=...)`. |
| `entities` | list[str] | All supported entities | Validated against `AnalyzerEngine.get_supported_entities()`; unknown names raise `PresidioCLIConfigError`. |
| `ignore` | gitwildmatch string (multi-line) | None | `pathspec.PathSpec.from_lines("gitwildmatch", ...)`. Same syntax as `.gitignore`. |
| `allow` | list[str] | `[]` | Passed to `analyzer.analyze(allow_list=...)`. |
| `threshold` | float in [0, 1] | `0` | Filters results below threshold. Validation rejects out-of-range. |
| `locale` | string | None | Passed to `locale.setlocale(LC_ALL, ...)`. |
| `extends` | string | None | Path to base config OR name of bundled conf (`default`, `limited`) resolved via `presidio_cli/conf/{name}.yaml`. Extension semantics: union entities, base wins on language/ignore. |

The fallback `default.yaml` shipped with the package contains:
```yaml
language: en
ignore: |
  .git
```

The `limited.yaml` example contains the full schema including `entities`, `threshold`, `locale`, and commented `extends`.

The cwd `.presidiocli` (in the repo) defaults to language `en`, ignoring `.git`/`.pytest_cache`/`.vscode`, and the entity list: `CREDIT_CARD`, `CRYPTO`, `DATE_TIME`, `EMAIL_ADDRESS`, `IBAN_CODE`, `IP_ADDRESS`, `NRP`, `LOCATION`, `PERSON`, `PHONE_NUMBER`, `MEDICAL_LICENSE`.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No PII problems found across all processed files/stdin. |
| `1` | Either `PresidioCLIConfigError` raised during config load OR at least one PII problem was reported. |
| Other | Propagated from `EnvironmentError` on stdin read (also exits 1). |

**Note on the exit-code logic**: the CLI returns 1 if `prob_num > 0`, but `prob_num` is set from `show_problems()`'s `max_level` return value, which is initialized to 0 and **never modified** — so in practice exit 1 only fires when a config error is hit. (Likely a latent bug; worth noting.)

### Environment variables consumed

- `GITHUB_ACTIONS` and `GITHUB_WORKFLOW` — switch `--format auto` to `github`.
- `ANSICON`, `TERM` — used in the ANSI-support detection on Windows.
- Indirectly via presidio-analyzer: `PRESIDIO_DEVICE`, `AHDS_ENDPOINT`, `REGEX_TIMEOUT_SECONDS` (none read by the CLI itself).

### Shell integration

- File handling: walks directories recursively via `os.walk`; rejects binary files via UTF-8 decode + null-byte check (`set(range(0x20, 0x100)) - {0x7F}` heuristic, from a Stack Overflow snippet).
- Path stripping: leading `./` or `.\` removed from filenames in output.
- Stdin: read as a single buffer (no streaming); filename rendered as `"stdin"`.
- File glob support: NOT directly — the CLI relies on the shell to expand globs into positional args. Within a config, `ignore` supports gitwildmatch patterns.
- Encoding: opens files with `encoding="utf-8"`, `newline=""`.

### Notable internals

- `PIIProblem` wraps a `RecognizerResult` with line/column/score/type/explanation; line is 1-indexed, column = `start + 1`.
- `Line` chunking: splits on `\n`, strips trailing `\r`. Each line analyzed independently — multi-line entities won't be detected.
- `level != "error"` filtering exists in `show_problems` but `PIIProblem` never sets `level`, so `--no-warnings` is effectively a no-op against detected entities.

## CHANGELOG — Unreleased section + last 2 releases

### Unreleased — verbatim line items

**Anonymizer / Fixed**:
- "Custom operator `validate()` no longer calls the user-supplied lambda with a dummy `"PII"` value. Previously, stateful lambdas (e.g. those accumulating a token-to-original-value map for de-anonymization) would receive a spurious invocation during validation, inserting a junk entry (`{"TOKEN_1": "PII"}`) into the map and skewing all subsequent token counters. The return-type contract is now enforced in `operate()` when the lambda runs on real data. Fixes #2024."

**Analyzer / Added**:
- Country-filter feature: "Optional `countries` filter on `RecognizerRegistry.load_predefined_recognizers()` to scope predefined country-specific recognizers to a subset of locales (e.g. `countries=["us", "uk"]`)." Adds `supported_countries` YAML field, per-recognizer `country_code:`, `EntityRecognizer.COUNTRY_CODE` ClassVar, `country_code` constructor kwarg, `country_code()` / `is_country_specific()` instance methods, `to_dict()`/`from_dict()` round-trip, `RecognizerRegistry.get_country_codes()`, WARNING log for empty country matches. Fixes #1328.
- "Canadian SIN (`CA_SIN`) recognizer for the Canadian Social Insurance Number, using regex pattern matching, context words (English and French), and Luhn checksum validation. Disabled by default."
- "Swedish PII recognizers for `SE_PERSONNUMMER` to identify Swedish Personal ID Numbers using pattern match and checksum. The recognizer also supports Swedish coordination numbers (samordningsnummer)."
- "German PII recognizers for `DE_TAX_ID` (Steueridentifikationsnummer, §§ 139a–139e AO, ISO 7064 Mod 11,10 checksum), `DE_TAX_NUMBER` (Steuernummer), `DE_PASSPORT` (Reisepassnummer, ICAO Doc 9303), `DE_ID_CARD` (Personalausweisnummer), `DE_SOCIAL_SECURITY` (Rentenversicherungsnummer), `DE_HEALTH_INSURANCE` (Krankenversicherungsnummer/KVNR), `DE_KFZ` (KFZ-Kennzeichen), `DE_HANDELSREGISTER` (Handelsregisternummer HRA/HRB), and `DE_PLZ` (Postleitzahl, very low base confidence, context-only)."
- "Added recognizer for Swedish Organisationsnummer."
- "Added recognizer for Spanish Passport (`ES_PASSPORT`)."
- "Added Korean Resident Registration Number (RRN) recognizer (KrRrnRecognizer)."
- "Added Thai National ID Number (TNIN) recognizer (ThTninRecognizer)."
- "Added `supported_entity` parameter to `PhoneRecognizer`. Previously, this recognizer hard-coded `[\"PHONE_NUMBER\"]`."
- "Turkish PII recognizer for `TR_NATIONAL_ID` (TCKN)" — pattern + context + NVI checksum.
- "Turkish phone number detection via configurable `PhoneRecognizer` with `supported_regions=[\"TR\"]`."
- "Turkish PII recognizer for `TR_LICENSE_PLATE` (plaka)" — pattern + province code (01-81).
- "Added PH_MOBILE_NUMBER recognizer for Philippine mobile phone numbers."

**Analyzer / Fixed**:
- "CreditCardRecognizer regex could incorrectly identify 13-digit Unix timestamps as credit card numbers."
- "Enhance NlpEngineProvider with validation methods for NLP engines, configuration, and conf file path."
- "Fixed `PhoneRecognizer._get_recognizer_result` to use the constructor-provided `supported_entity` instead of the hard-coded `\"PHONE_NUMBER\"` string."
- "Fixed incorrect Prüfziffer algorithm in `DeHealthInsuranceRecognizer` (KVNR)."
- "Fixed incorrect check-digit weights in `DeSocialSecurityRecognizer` (RVNR)."
- "Fixed incorrect check-digit algorithm in `DeLanrRecognizer`."
- "Enforced post-2016 BZSt repetition rule in `DeTaxIdRecognizer`."
- "Registered `DeLanrRecognizer`, `DeBsnrRecognizer`, `DeVatIdRecognizer` and `DeFuehrerscheinRecognizer` in the default registry (previously imported but missing from `conf/default_recognizers.yaml`, so they were unreachable)."

**Analyzer / Added (continued)**:
- "ISO 7064 Mod 11,10 structural checksum in `DeVatIdRecognizer`."
- "ICAO Doc 9303 MRZ checksum validation in `DePassportRecognizer` and `DeIdCardRecognizer`."
- "Structural validation improvements in `DeBsnrRecognizer` per KBV Arztnummern-Richtlinie Anlage 1."

### Release 2.2.362 — 2026-03-15 — verbatim line items

**General / Added**:
- "Published `presidio` as a PyPI meta-package that installs `presidio-analyzer` and `presidio-anonymizer`, making `pip install presidio` work as expected. (#1889)"

**General / Changed**:
- "Pinned all CI/CD GitHub Actions and Docker base images to commit SHAs to mitigate supply chain attacks (#1861)"
- "Pinned `ruff` and `build` pip installs with SHA256 hashes for OSSF scorecard compliance (#1864)"
- "Updated GitHub Actions dependencies … and base Python Docker images" (many PR numbers)
- "Updated README to clarify Presidio's no-authentication-by-design stance with security guidance (#1903)"

**General / Fixed**:
- "Broken documentation links (#1856)"

**General / Security**:
- "Fixed CVE-2024-47874 and CVE-2025-54121 (Starlette vulnerabilities) (#1860)"
- "Fixed CVE-2025-2953 and CVE-2025-3730 (#1859)"

**Analyzer / Added**:
- "UK Driving Licence Number (UK_DRIVING_LICENCE) recognizer with pattern matching and context support"
- "`HuggingFaceNerRecognizer` for direct NER model inference using HuggingFace pipelines without requiring spaCy (#1834)"
- "Transformer-based `MedicalNERRecognizer` as a subclass of `HuggingFaceNerRecognizer` for clinical entity detection (#1853)"
- "US NPI (National Provider Identifier) recognizer with Luhn checksum validation and context support (#1847)"
- "UK Postcode (UK_POSTCODE) recognizer with pattern matching and context support (#1858)"
- "UK Passport (UK_PASSPORT) and Vehicle Registration (UK_VEHICLE_REGISTRATION) recognizers (#1862)"
- "Nigerian National Identification Number (NG_NIN) recognizer with Verhoeff checksum validation and Nigerian Vehicle Registration (NG_VEHICLE_REGISTRATION) recognizer (#1863)"
- "ONNX Runtime backend support for `GLiNERRecognizer` via `load_onnx_model=True` parameter, resolving crashes on CPUs without AVX2 support (#1884)"
- "Configurable regex execution timeout (default 60 seconds) via `REGEX_TIMEOUT_SECONDS` environment variable to prevent catastrophic backtracking (#1904)"
- "GPU device control via environment variable for explicit GPU/CPU selection (#1844)"
- "LLM-as-a-judge evaluation integration for assessing PII detection quality (#1900)"
- "Sampling support for the evaluation framework (#1894)"
- "Dataset interface for the evaluation framework (#1893)"

**Analyzer / Fixed**:
- "Erroneous anchor in Italian driver license regex that caused missed matches (#1899)"
- "`validation_result` type annotation in API docs and type hints (#1869)"
- "Bare `except` clauses replaced with `except Exception` for proper exception handling (#1881)"
- "Context enhancement substring matching bug where context words were incorrectly matched as substrings (#1827)"

**Image Redactor / Fixed**:
- "`_process_names` unconditionally treating all DICOM metadata as PHI; now correctly filters using both `is_patient` and `is_name` checks (#1855)"

### Release 2.2.361 — 2026-02-12 — verbatim line items

**Analyzer / Changed**:
- "Fixed context enhancement substring matching bug … Added configurable `context_matching_mode` parameter to `LemmaContextAwareEnhancer` with two options: \"substring\" (default, maintains backward compatibility for compound words like \"creditcard\"), and \"whole_word\" (prevents false positives like 'lic' matching 'duplicate') (#1061)"

**Analyzer / Added**:
- "US_MBI recognizer for Medicare Beneficiary Identifier with pattern matching and context support (#1821)"
- "MAC address recognizer for detecting MAC addresses in various formats (#1829)"
- "Korean Business Registration Number (KR_BRN) recognizer (#1822)"
- "Korean Foreigner Registration Number (KR_FRN) recognizer (#1825)"
- "Korean Driver License (KR_DRIVER_LICENSE) recognizer (#1820)"
- "Korean Passport (KR_PASSPORT) recognizer (#1814)"
- "Thai National ID Number (TH_TNIN) recognizer with format and checksum validation (#1713)"
- "Configurable LangExtract recognizer supporting any LLM provider with custom YAML configurations (#1815)"
- "Azure OpenAI support for LangExtract recognizer with managed identity authentication for GPT-4o, GPT-4, etc. (#1801)"
- "Batch processing support in REST API - accepts arrays of texts and returns arrays of results with backward compatibility (#1806)"
- "GPU device control via `PRESIDIO_DEVICE` environment variable for explicit GPU/CPU selection (#1843)"
- "Support for multiple recognizer instances from same class via `class_name` parameter (#1819)"
- "Pydantic-based YAML configuration validation with ConfigurationValidator class for improved reliability and error reporting (#1780)"
- "Japanese and Chinese mobile number test cases for PhoneRecognizer (#1808)"

**Analyzer / Changed**:
- "GPU optimizations with DeviceDetector singleton providing 4-10x performance improvements for GLiNER, Transformers, and Stanza engines (#1812)"
- "Configurable extraction parameters for LangExtract recognizers via YAML (max_char_buffer, timeout, num_ctx, fence_output, use_schema_constraints) (#1811)"
- "Lazy initialization for device detector singleton (#1831)"
- "Simplified IBAN regex pattern from 8 to 3 capture groups for better performance (#1818)"
- "Improved Korean RRN regex pattern with negative lookahead/lookbehind and gender digit validation (#1807)"

**Analyzer / Fixed**:
- "GLiNER GPU inference by properly passing map_location parameter (#1813)"
- "GLiNER text truncation issue during processing (#1805)"
- "IBAN regex trailing character handling to prevent false matches (#1818)"
- "Python 3.10 build compatibility by pinning onnxruntime <1.24.1 for Python 3.10 (#1848)"
- "TypeError in third-party recognizers by removing invalid **kwargs from __init__ methods (#1800)"
- "Pattern recognizer example language specification (#1835)"

**Anonymizer / Changed**:
- "**BREAKING CHANGE**: Hash operator now uses random salt by default to prevent brute-force and dictionary attacks. Same PII values will produce different hashes unless a `salt` parameter is explicitly provided. Users requiring referential integrity must provide their own salt. Minimum salt length: 16 bytes. (#1846)"
- "Updated cryptography dependency to >=46.0.4 to address CVE-2025-15467 security vulnerability (#1841)"

**General / Added**:
- "GPU acceleration documentation guide with setup and usage instructions (#1826)"
- "Telemetry redaction sample demonstrating PII removal from telemetry data (#1824)"

**General / Changed**:
- "Migrated CI workflows (lint, dependency review, release) to ubuntu-slim runners for improved efficiency (#1840)"
- "Updated actions/cache from v4 to v5 with Node.js 24 runtime support (#1817)"

**Image Redactor / Changed**:
- "DICOM: use_metadata will now use both is_patient and is_name to generate the PHI list of words via change to _make_phi_list."
- "Image Redactor: Added redact_and_return_bbox method to ImageRedactorEngine, which returns both the redacted image and the detected bounding boxes for redacted regions."

### Inferred direction — what the team is prioritizing

1. **Coverage expansion to non-English locales** is the dominant theme. Recent and unreleased recognizers: Canadian, Swedish (2), German (10), Spanish, Korean (5), Thai, Nigerian (2), Turkish (3), Philippine, Italian fixes, UK (5). Country-filtering machinery (the `countries=` kwarg, `COUNTRY_CODE` ClassVar, `country_code` YAML field) is now first-class.
2. **Checksum-based validation everywhere** — Luhn (CA SIN, US NPI, Credit Card), Verhoeff (NG NIN), ISO 7064 Mod 11,10 (DE Tax ID, DE VAT ID), ICAO Doc 9303 MRZ (DE Passport, DE ID Card), NVI (TR National ID), bespoke (KVNR, RVNR, LANR, BSNR). Strong direction toward reducing false positives via structural validation.
3. **LLM-as-a-judge and dataset/sampling for evaluation** — Presidio is investing in evaluation tooling that handles LLM-era detection quality.
4. **LLM-based detection itself** — LangExtract recognizer with any LLM provider + Azure OpenAI w/ managed identity. GLiNER (open-vocabulary NER) with ONNX backend for CPUs without AVX2.
5. **GPU + performance** — `PRESIDIO_DEVICE`, DeviceDetector singleton (4-10× speedup), regex timeout for ReDoS prevention.
6. **Security hardening** — SHA-pinned GitHub Actions, random salt for hash operator (breaking), MD5 deprecated, cryptography lib bumped for CVE.
7. **No-code / YAML-driven config** — Pydantic validation on YAML (`ConfigurationValidator`), `class_name` support for multiple instances of the same class, default-disabled country recognizers (safer defaults).
8. **PyPI meta-package `presidio`** — UX win addressing the long-standing "why do I need to install two packages?" friction.
9. **Anonymizer is quieter than analyzer** — Only meaningful Anonymizer changes recently: salted hash (BREAKING), MD5 deprecation, cryptography backend swap (pycryptodome → cryptography), AHDS surrogate operator, and the unreleased custom-validate fix.
10. **Roadmap promised but not delivered** (per Structured docs): PySpark backend, K-Anonymity, Differential Privacy, sensitive column-name detection. None present in any recent CHANGELOG.

## Anything notable / unusual

- **CLI has a latent exit-code bug**: `show_problems` returns `max_level` which is initialized to 0 and never modified, so the CLI's `if prob_num > 0: return_code = 1` only fires from config errors, not from finding PII. This means `presidio . && echo clean` may print "clean" even when PII was found. Worth noting if octarine's CLI follows a similar pattern — design return-on-finding from the start.
- **`--no-warnings` is a no-op** for actual detected PII because `PIIProblem` never sets `level`. Code path exists but unreachable.
- **Line-by-line analysis** in the CLI means multi-line PII entities won't be detected. Each line is sent to `analyzer.analyze` independently.
- **Heuristic binary-file detection** uses a Stack Overflow snippet (UTF-8 decode + null-byte check on first 1024 bytes). Brittle for some text formats.
- **Config `extends` is recursive** and resolves bundled names (`default`, `limited`) from the package's `conf/` directory before treating the value as a filesystem path. Nice ergonomic pattern.
- **The CLI is NOT in the main mkdocs nav** — it lives in its own `presidio-cli` subdirectory with its own README, never linked from the docs site. Easy to miss when surveying Presidio's surface.
- **No explicit CLI for the anonymizer or image redactor** — `presidio-cli` only wraps the analyzer. Anonymization, image redaction, and structured data have no CLI surface.
- **No batch CLI flag** despite `BatchAnalyzerEngine` existing — the CLI processes line by line per file.
- **The "Recipes" section is essentially empty** — community scaffolding only (Home/Contributing/Template). Suggests an intended-but-unrealized cookbook surface.
- **The Decision Process docs are explicit about a limitation**: it explains why PII WAS detected, never why it WASN'T. This is a known asymmetry octarine should consider.
- **Predefined country recognizers ship disabled by default since 2.2.359** — A documented direction-shift to reduce false positives. The `countries=` filter in the unreleased section makes this configurable per deployment.
- **`presidio-cli` Python compatibility (3.10–3.13) is narrower than presidio-analyzer/anonymizer's** — onnxruntime pin in 2.2.361 was specifically for Python 3.10 compat.
- **The unreleased section is HUGE for Anonymizer/Analyzer combined** — 13+ new recognizers, 8+ bug fixes, plus a major new country-filter subsystem. Suggests a substantial 2.2.363 release is imminent.
- **Country code `country_code` constructor kwarg + YAML field + class ClassVar** is a three-way reconciliation that octarine's identifier registry needs a parallel design for. Cross-checked at load time with `ValueError` on conflict.
- **Operator `validate()` previously called user lambdas with a dummy `"PII"` string** — A subtle bug that broke stateful operators like `InstanceCounterAnonymizer`. Octarine should avoid analogous "test the callable with dummy data" patterns in custom-operator validation.
- **Presidio explicitly does not ship authentication**: "Presidio API endpoints do not include built-in authentication by design." Auth is expected at gateway/proxy/mesh layer. Octarine likely takes the same posture for its primitives but should be explicit in docs.
