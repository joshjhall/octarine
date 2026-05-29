# Presidio - Types, Exceptions, and Utilities

A catalog of Microsoft Presidio's internal type system, exceptions, helper utilities,
and config objects across all four packages. This is the supporting type system that
downstream / wrapper code has to import and instantiate — distinct from the engine
classes documented in earlier audit notes.

## Source files reviewed

Analyzer (`presidio-analyzer/presidio_analyzer/`):

- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/__init__.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/analysis_explanation.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/recognizer_result.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/dict_analyzer_result.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/analyzer_request.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/pattern.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/entity_recognizer.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/analyzer_engine.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/context_aware_enhancers/context_aware_enhancer.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/nlp_engine/nlp_artifacts.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/nlp_engine/ner_model_configuration.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/input_validation/schemas.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/input_validation/language_validation.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/input_validation/yaml_recognizer_models.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/recognizer_registry/recognizers_loader_utils.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/app.py>

Anonymizer (`presidio-anonymizer/presidio_anonymizer/`):

- <https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/__init__.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/entities/__init__.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/entities/invalid_exception.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/entities/conflict_resolution_strategy.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/entities/engine/operator_config.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/entities/engine/pii_entity.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/entities/engine/recognizer_result.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/entities/engine/dict_recognizer_result.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/entities/engine/result/engine_result.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/entities/engine/result/operator_result.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/services/validators.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/services/app_entities_convertor.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/core/engine_base.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/core/text_replace_builder.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/operators/operator.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/operators/aes_cipher.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/operators/custom.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/operators/operators_factory.py>
- (plus encrypt.py, decrypt.py, hash.py, mask.py, replace.py, redact.py, keep.py, deanonymize_keep.py, ahds_surrogate.py)
- <https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/app.py>

Image Redactor (`presidio-image-redactor/presidio_image_redactor/`):

- <https://github.com/microsoft/presidio/blob/main/presidio-image-redactor/presidio_image_redactor/__init__.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-image-redactor/presidio_image_redactor/entities/__init__.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-image-redactor/presidio_image_redactor/entities/image_recognizer_result.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-image-redactor/presidio_image_redactor/entities/invalid_exception.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-image-redactor/presidio_image_redactor/entities/api_request_convertor.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-image-redactor/presidio_image_redactor/ocr.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-image-redactor/presidio_image_redactor/bbox.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-image-redactor/presidio_image_redactor/image_processing_engine.py>

Structured (`presidio-structured/presidio_structured/`):

- <https://github.com/microsoft/presidio/blob/main/presidio-structured/presidio_structured/__init__.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-structured/presidio_structured/config/structured_analysis.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-structured/presidio_structured/data/data_processors.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-structured/presidio_structured/data/data_reader.py>

## Request / response objects

All of these are **plain Python classes** (not pydantic, not dataclasses) **unless
noted** as `[dataclass]` or `[pydantic]`. Most expose `to_dict()` / `from_json()` /
`from_dict()` for ad-hoc JSON round-tripping; very few inherit a common base.

| Class | Package | Kind | Fields | Purpose |
|---|---|---|---|---|
| `AnalyzerRequest` | analyzer | plain class | `text`, `language`, `entities`, `correlation_id`, `score_threshold`, `return_decision_process`, `ad_hoc_recognizers` (List[PatternRecognizer]), `context`, `allow_list`, `allow_list_match` (default `"exact"`), `regex_flags` (default `re.DOTALL \| re.MULTILINE \| re.IGNORECASE`) | DTO built from a request `Dict`. Used by Flask `app.py` to forward kwargs to `BatchAnalyzerEngine.analyze_iterator`. Ad-hoc recognizers are eagerly materialized via `PatternRecognizer.from_dict`. |
| `RecognizerResult` (analyzer) | analyzer | plain class | `entity_type: str`, `start: int`, `end: int`, `score: float`, `analysis_explanation: Optional[AnalysisExplanation]`, `recognition_metadata: Optional[Dict]` | Canonical analyzer output. Implements `__eq__`, `__hash__`, `__gt__`, `intersects`, `contains`, `contained_in`, `equal_indices`, `has_conflict`. `to_dict()` returns `self.__dict__`. `from_json` reads only `start/end/score/entity_type` (drops explanation and metadata). |
| `RecognizerResult` (anonymizer copy) | anonymizer | plain class subclass of `PIIEntity` | `entity_type`, `start`, `end`, `score` | "Exact copy" of analyzer's `RecognizerResult` but inherits from `PIIEntity` so it can flow through the operator pipeline. Validates `score` is non-None. No `analysis_explanation`, no `recognition_metadata`. |
| `AnalysisExplanation` | analyzer | plain class | `recognizer: str`, `original_score: float`, `score: float` (mutable), `pattern_name: Optional[str]`, `pattern: Optional[str]`, `validation_result: Optional[bool]`, `textual_explanation: Optional[str]`, `regex_flags: Optional[int]`, `score_context_improvement: float = 0`, `supportive_context_word: str = ""` | Per-result tracing. Mutators: `set_improved_score(score)` (updates `score_context_improvement`), `set_supportive_context_word(word)`, `append_textual_explanation_line(text)`. |
| `DictAnalyzerResult` | analyzer | `[dataclass]` | `key: str`, `value: Union[str, List[str], dict]`, `recognizer_results: Union[List[RecognizerResult], List[List[RecognizerResult]], Iterator["DictAnalyzerResult"]]` | Output of analyzer's `analyze_dict`. Recursive — values that are dicts produce an `Iterator[DictAnalyzerResult]` rather than `List[RecognizerResult]`. |
| `DictRecognizerResult` | anonymizer | `[dataclass]` | Same shape as `DictAnalyzerResult` but typed against anonymizer's local `RecognizerResult` | The anonymizer's parallel structure for handling dict inputs. |
| `PIIEntity` | anonymizer | `abc.ABC` plain class | `start: int`, `end: int`, `entity_type: str` | Abstract base for `RecognizerResult` and `OperatorResult`. Implements `__gt__` (by `start`), `__eq__`, validates `start`/`end` >= 0 and `start <= end` in `__validate_fields`. |
| `OperatorConfig` | anonymizer | plain class | `operator_name: str`, `params: Dict` (defaulted to `{}`) | Per-entity configuration. `from_json({"type": ..., **params})` strips `"type"`. `__validate_fields` only requires `operator_name` non-empty. `params` is mutable — `EngineBase` defensively copies it and **injects `entity_type`** before calling `operator.validate()`. |
| `OperatorResult` | anonymizer | plain class subclass of `PIIEntity` | `start`, `end`, `entity_type`, `text: Optional[str]`, `operator: Optional[str]` | Per-entity result from anonymize/deanonymize. `to_dict()` returns `self.__dict__`. `from_json` reads `start/end/entity_type/text/operator`. |
| `EngineResult` | anonymizer | plain class | `text: Optional[str]`, `items: List[OperatorResult]` | Top-level anonymizer/deanonymizer result. Mutators: `set_text`, `add_item`, `normalize_item_indexes` (re-anchors indices end→start). `to_json()` = `json.dumps(self, default=lambda x: x.__dict__)` — the only built-in JSON serializer in the codebase. |
| `ImageRecognizerResult` | image-redactor | plain class subclass of analyzer's `RecognizerResult` | `entity_type`, `start`, `end`, `score`, `left: int`, `top: int`, `width: int`, `height: int` | Adds pixel bbox to a text-style `RecognizerResult`. Inherits `to_dict` from parent. |
| `StructuredAnalysis` | structured | `[dataclass]` | `entity_mapping: Dict[str, str]` | Single-field DTO: column/key path → entity type (e.g. `"person.address": "LOCATION"`). |
| `NlpArtifacts` | analyzer | plain class | `entities: List[spacy.Span]`, `tokens: spacy.Doc`, `tokens_indices: List[int]`, `lemmas: List[str]`, `nlp_engine: NlpEngine`, `language: str`, `scores: List[float]` (defaults to `[0.85] * len(entities)`), `keywords: List[str]` (computed via `set_keywords`) | Output of an NLP pipeline pass. `to_json()` strips `nlp_engine` (not serializable) and converts spaCy spans/tokens to strings. |
| `OCR.perform_ocr` return | image-redactor | `dict` | `{"text": [...], "left": [...], "top": [...], "width": [...], "height": [...], "conf": [...]}` (Tesseract-style parallel lists) | Abstract `OCR` defines only the dict shape; `BboxProcessor.get_bboxes_from_ocr_results` consumes it. |

No `to_dict` / `from_dict` exists on `AnalyzerRequest`, `EngineResult`, or
`OperatorConfig` consistently — each class invents its own pattern.

## Enum types

| Enum | Package | Members | Purpose |
|---|---|---|---|
| `OperatorType` | anonymizer (`operators/operator.py`) | `Anonymize = 1`, `Deanonymize = 2` | Discriminator used by `OperatorsFactory.create_operator_class` to look up by class and direction. Module also exposes `types = [OperatorType.Anonymize, OperatorType.Deanonymize]`. |
| `ConflictResolutionStrategy` | anonymizer (`entities/conflict_resolution_strategy.py`) | `MERGE_SIMILAR_OR_CONTAINED = "merge_similar_or_contained"`, `REMOVE_INTERSECTIONS = "remove_intersections"` | Default is `MERGE_SIMILAR_OR_CONTAINED`. Docstring also references a `NONE` member but **`NONE` is NOT defined in the enum** — a known doc/code mismatch. |

That's it — only two enums in the entire codebase. Everything else
("predefined" vs "custom" recognizer type, "exact" vs "loose" allow-list match,
operator names, hash algorithms) is plain `str` constants.

## Configuration objects

| Class | Package | Kind | Purpose |
|---|---|---|---|
| `Pattern` | analyzer (`pattern.py`) | plain class | `name`, `regex`, `score`. Validates regex compiles (with the `regex` lib, not stdlib `re`) and `0 <= score <= 1` in `__init__`. Has `compiled_regex` and `compiled_with_flags` slots set lazily by `PatternRecognizer`. `to_dict` / `from_dict` round-trip. |
| `OperatorConfig` | anonymizer | plain class | See request/response table above. |
| `NerModelConfiguration` | analyzer (`nlp_engine/ner_model_configuration.py`) | `[pydantic BaseModel]` | NER inference knobs. Fields: `labels_to_ignore` (Collection[str]), `aggregation_strategy` (default `"max"`, validated against `["simple","first","average","max"]`), `stride` (default `14`), `alignment_mode` (default `"expand"`, validated against `["strict","contract","expand"]`), `default_score` (default `0.85`, `0.0 <= x <= 1.0`), `model_to_presidio_entity_mapping` (defaults to `MODEL_TO_PRESIDIO_ENTITY_MAPPING` module constant — 19 entries), `low_score_entity_names` (defaults to empty set), `low_confidence_score_multiplier` (default `0.4`, `>= 0`). `model_config = ConfigDict(arbitrary_types_allowed=True)`. `to_dict()` = `model_dump(exclude_none=True)`. |
| `LanguageContextConfig` | analyzer (`input_validation/yaml_recognizer_models.py`) | `[pydantic]` | `language: str`, `context: Optional[List[str]]`. Validates language code via shared `validate_language_codes` helper. |
| `BaseRecognizerConfig` | analyzer (same file) | `[pydantic]` | Common fields: `name`, `class_name`, `enabled`, `type` (default `"predefined"`), `supported_language` (legacy single), `supported_languages` (list of strings OR `LanguageContextConfig`), `context`, `supported_entity` (legacy single), `supported_entities`. Cross-field validators reject `supported_language` + `supported_languages` together, `supported_entity` + `supported_entities` together, and forbid global `context` when more than one language is set. |
| `PredefinedRecognizerConfig` | analyzer (same file) | `[pydantic]` extends `BaseRecognizerConfig` | Adds `validate_predefined_recognizer_exists` model-validator that calls `RecognizerListLoader.get_existing_recognizer_cls` and raises `ValueError` wrapping `PredefinedRecognizerNotFoundError`. |
| `HuggingFaceRecognizerConfig` | analyzer (same file) | `[pydantic]` (`ConfigDict(extra="allow")`) | `model_name`, `tokenizer_name`, `label_mapping`, `threshold`, `aggregation_strategy`, `chunk_overlap`, `chunk_size`, `device` (`str` or `int`), `label_prefixes` (default `None` — overridden `model_dump` excludes None values so constructor defaults survive). |
| `GLiNERRecognizerConfig` | analyzer (same file) | `[pydantic]` (`ConfigDict(extra="allow")`) | `model_name`, `flat_ner`, `multi_label`, `threshold`, `map_location`, `load_onnx_model`, `onnx_model_file`, `entity_mapping`. Validator forbids `entity_mapping` + `supported_entities` together. |
| `CustomRecognizerConfig` | analyzer (same file) | `[pydantic]` extends `BaseRecognizerConfig` | `type` defaults to `"custom"`, `supported_entity` is **required**, `country_code` (lower/strip-normalized, optional ISO 3166-1 alpha-2), `patterns` (list of dicts validated to have `name`/`regex`/`score`), `deny_list`, `deny_list_score` (default `0.0`, range `[0,1]`). `check_predefined_name_conflict` (mode `"before"`) rejects custom names that collide with predefined recognizer class names. `validate_patterns_or_deny_list` requires at least one of those two. |
| `RecognizerRegistryConfig` | analyzer (same file) | `[pydantic]` (`ConfigDict(extra="forbid")`) | Top-level wrapper: `supported_languages: Optional[List[str]]`, `global_regex_flags: int = 26` (= `DOTALL \| MULTILINE \| IGNORECASE`), `recognizers: List[Union[Hugging, Predefined, Custom, str]]`. The `parse_recognizers` `before`-mode field validator selects between `HuggingFaceRecognizerConfig` / `GLiNERRecognizerConfig` / `PredefinedRecognizerConfig` / `CustomRecognizerConfig` via the module-level `CONFIG_MODEL_MAP = {"HuggingFaceNerRecognizer": ..., "GLiNERRecognizer": ...}`. |
| `ConfigurationValidator` | analyzer (`input_validation/schemas.py`) | static-methods class | Top-level validators for YAML inputs: `validate_language_codes`, `validate_file_path` (must exist + be file), `validate_score_threshold` (0-1), `validate_nlp_configuration` (requires `nlp_engine_name` + `models` with `lang_code`/`model_name`), `validate_recognizer_registry_configuration` (wraps `RecognizerRegistryConfig`), `validate_analyzer_configuration` (rejects unknown top-level keys, recurses into nested configs). |

## Exception hierarchy

There is **no shared Presidio base exception class**. The two `InvalidParamError`
classes are independent (one in anonymizer, one in image-redactor), both subclass
`Exception`, both store the message on `self.err_msg`. Everything else is a
generic `ValueError` or `TypeError`.

| Exception | Package | Defined in | Raised when |
|---|---|---|---|
| `InvalidParamError` | anonymizer | `entities/invalid_exception.py` | Any failed param validation in `services/validators.py`, operator `validate()` methods, `OperatorsFactory.create_operator_class` (unknown name/type), `OperatorsFactory.remove_*_operator` (not registered), `TextReplaceBuilder.__validate_position_in_text` (start/end out of range), `Custom.operate` (lambda returned non-string), `AppEntitiesConvertor.analyzer_results_from_json` (missing analyzer_results), `AHDSSurrogate` config errors, `PIIEntity.__validate_fields` (negative or inverted indices). Stores `self.err_msg`. |
| `InvalidParamError` | image-redactor | `entities/invalid_exception.py` | `api_request_convertor.get_json_data` (bad JSON), `color_fill_string_to_value` (malformed RGB triple). Independent class — **NOT** the same as the anonymizer one. |
| `PredefinedRecognizerNotFoundError` | analyzer | `recognizer_registry/recognizers_loader_utils.py` | `RecognizerListLoader.get_existing_recognizer_cls` when the name doesn't match a known predefined recognizer class. Used as a signal/look-before-you-leap exception inside pydantic validators (caught and rewrapped as `ValueError`). |
| `ValueError` | analyzer | `Pattern.__validate_regex`, `Pattern.__validate_score`, `EntityRecognizer._resolve_country_code` (blank or conflicting country code), all pydantic validators, `RecognizerRegistry.load_predefined_recognizers` ("No language provided", "No entities provided", "No matching recognizers were found to serve the request", "Input is not of type EntityRecognizer"), `BboxProcessor.remove_bbox_padding` (negative padding), structured `DataProcessorBase._generate_operator_mapping` ("Operator for entity X not found"), structured `PandasDataProcessor._process` (not a DataFrame), structured `JsonDataProcessor._process` (not dict/list). | Generic "bad input" — used everywhere outside operator land. |
| `TypeError` | analyzer | `EntityRecognizer._resolve_country_code` | `country_code` kwarg is not a str. Also caught in analyzer `app.py /analyze` and remapped to HTTP 400. |
| `BadRequest` (werkzeug) | anonymizer | `app.py` | Empty request body, custom operator submitted to REST endpoint (custom ops are explicitly NOT allowed over HTTP). |
| `OSError`, `yaml.YAMLError` | analyzer | `RecognizerRegistry` YAML loader | File read / parse failures. Re-raised after a `print` — yes, `print`, not `logger`. |

### HTTP error mapping (Flask `app.py`)

Anonymizer (`presidio-anonymizer/app.py`):

| Exception | HTTP status | Body |
|---|---|---|
| `InvalidParamError` | **422** Unprocessable Entity | `{"error": err.err_msg}` (logged at WARNING) |
| `HTTPException` (werkzeug — e.g. `BadRequest`) | passes `e.code` through | `{"error": e.description}` |
| any other `Exception` | **500** | `{"error": "Internal server error"}` (logged at ERROR; message NOT exposed to client) |

Analyzer (`presidio-analyzer/app.py`):

| Exception | HTTP status | Body |
|---|---|---|
| `TypeError` (in `/analyze` only) | **400** | `{"error": "Failed to parse /analyze request for AnalyzerEngine.analyze(). <args[0]>"}` |
| any other `Exception` in `/analyze`, `/recognizers`, `/supportedentities` | **500** | `{"error": e.args[0]}` — note the **raw exception message IS exposed** |
| `HTTPException` (werkzeug) | passes through | `{"error": e.description}` |

The analyzer service does NOT special-case any Presidio exception (no
`InvalidParamError` analog in analyzer; `ValueError` falls through to the 500
handler with the message exposed). The error contracts of the two services
differ.

## Utility / helper functions

### Anonymizer `services/validators.py`

All raise `InvalidParamError`. JSON-friendly type names: `str→"string"`, `bool→"boolean"`, `int→"number"`, `list→"array"`, `object→"object"`.

- `validate_parameter(value, name, type)` — None check + `validate_type`.
- `validate_type(value, name, type)` — `isinstance` check (but **silently passes** if `value` is falsy/empty — only checks when `parameter_value and not isinstance(...)`).
- `validate_parameter_exists(value, entity, name)` — only checks `is None`.
- `validate_parameter_not_empty(value, entity, name)` — `if not value` (empty string fails).
- `validate_parameter_in_range(values_range, value, name, type)` — `validate_parameter(value, name, object)` then `value not in values_range`.

These are the ONLY input-validation primitives in the anonymizer. Each operator
hand-codes its `validate()` against this small library.

### Analyzer `input_validation/`

- `validate_language_codes(languages)` — regex `^[a-z]{2}(-[A-Z]{2})?$`, raises `ValueError`. Compiled with the third-party `regex` lib, not stdlib `re`.
- `ConfigurationValidator` (static methods) — file path, score threshold, NLP config, registry config, analyzer config. Mix of `ValueError` (own checks) and rewrapped pydantic `ValidationError` (`raise ValueError("Invalid recognizer registry configuration") from e`).

### Image redactor

- `BboxProcessor` (static methods) — `get_bboxes_from_ocr_results`, `get_bboxes_from_analyzer_results`, `remove_bbox_padding` (mode-switches on which dict keys are present), `match_with_source` (matches detected PII against ground truth with a `tolerance: int = 50` pixel slack on `left`/`top`/`width`/`height`).
- `OCR.get_text_from_ocr_dict(ocr_result, separator=" ")` — static method on the abstract base; joins the parallel `text` list.
- `api_request_convertor` module functions: `get_json_data(data)` (single-quote `→` double-quote and `json.loads`; the single-quote rewrite is **lossy** for legitimate apostrophes in fields), `color_fill_string_to_value(json_params)` (parses `"1,1,1"` to `(1,1,1)` or `"5"` to `5`), `image_to_byte_array(image, format)`.

### Anonymizer operators

- `AESCipher` (static methods) — AES-CBC with PKCS#7 padding, random 16-byte IV prepended, base64-urlsafe encoded. `encrypt(key, text)`, `decrypt(key, text)`, `is_valid_key_size(key)` checks `len(key) * 8 in algorithms.AES.key_sizes` (i.e. 128, 192, 256 bits).
- `EntityRecognizer.sanitize_value(text, replacement_pairs)` — naive `for search, repl in pairs: text = text.replace(...)` chained loop. **Not present anywhere else** — most internal text manipulation goes through `TextReplaceBuilder`.
- `EntityRecognizer.remove_duplicates(results)` — sorts by `(-score, start, -length)`, drops `score == 0` results, applies "equals or contained-by-same-type" filtering.
- `EntityRecognizer._resolve_country_code(passed)` — classmethod that reconciles class-level `COUNTRY_CODE: ClassVar[Optional[str]]` with constructor kwarg. Lowercases, strips, raises `TypeError` for non-string, `ValueError` for blank or conflicting values.
- `EntityRecognizer.country_code() -> Optional[str]` instance method and `is_country_specific() -> bool` predicate.

### Anonymizer core

- `TextReplaceBuilder(original_text)` — `get_text_in_position(start, end)` (raises `InvalidParamError` if OOB), `replace_text_get_insertion_index(replacement, start, end)`. Operates end-to-start so that earlier indices stay valid through the loop, then `EngineResult.normalize_item_indexes` flips them back at the end.
- `AppEntitiesConvertor` (static methods) — `analyzer_results_from_json(list)`, `operators_config_from_json(dict)`, `deanonymize_entities_from_json(json)`, `check_custom_operator(dict)` (boolean — used by the REST handler to reject custom over HTTP).

## Constants

### Analyzer

- **Score bounds** on `EntityRecognizer`: `MIN_SCORE = 0`, `MAX_SCORE = 1.0`. Also duplicated as `ContextAwareEnhancer.MIN_SCORE = 0`, `ContextAwareEnhancer.MAX_SCORE = 1.0`.
- `EntityRecognizer.COUNTRY_CODE: ClassVar[Optional[str]] = None` — subclasses override to declare country tagging.
- **Recognition-metadata keys** on `RecognizerResult`:
  - `RECOGNIZER_NAME_KEY = "recognizer_name"`
  - `RECOGNIZER_IDENTIFIER_KEY = "recognizer_identifier"`
  - `IS_SCORE_ENHANCED_BY_CONTEXT_KEY = "is_score_enhanced_by_context"`
- `analyzer_engine.py` module-level: `REGEX_TIMEOUT_SECONDS = int(os.environ.get("REGEX_TIMEOUT_SECONDS", 60))`. Default 60s, env-var configurable.
- `recognizers_loader_utils.py`: `_COUNTRY_SPECIFIC_MODULE_SEGMENT = "country_specific"` (private — used to detect bundled country-specific recognizers by module path).
- `RecognizerListLoader.SUPPORTED_ENTITY = "supported_entity"`, `SUPPORTED_ENTITIES = "supported_entities"`.
- `ner_model_configuration.py`: `MODEL_TO_PRESIDIO_ENTITY_MAPPING` dict (19 keys mapping e.g. `PER→PERSON`, `LOC→LOCATION`, `GPE→LOCATION`, `NORP→NRP`, `HCW→PERSON`, etc.) and `LOW_SCORE_ENTITY_NAMES = set()` (empty default).
- `RecognizerRegistryConfig.global_regex_flags: int = 26` (= `re.DOTALL \| re.MULTILINE \| re.IGNORECASE`).
- `app.py`: `DEFAULT_PORT = "3000"`, `DEFAULT_BATCH_SIZE = "500"`, `DEFAULT_N_PROCESS = "1"`, `LOGGING_CONF_FILE = "logging.ini"`. Env-overridable: `LOG_LEVEL`, `BATCH_SIZE`, `N_PROCESS`, `PORT`, `ANALYZER_CONF_FILE`, `NLP_CONF_FILE`, `RECOGNIZER_REGISTRY_CONF_FILE`.

### Anonymizer

- `anonymizer_engine.py`: `DEFAULT = "replace"` — the operator name used when no per-entity operator and no `"DEFAULT"` entry are supplied.
- Operator-parameter key constants (string class attributes — not enums):
  - `Encrypt.KEY = "key"`, `Decrypt.NAME = "decrypt"`, `Decrypt.KEY = "key"`.
  - `Mask.CHARS_TO_MASK = "chars_to_mask"`, `Mask.FROM_END = "from_end"`, `Mask.MASKING_CHAR = "masking_char"`.
  - `Hash.HASH_TYPE = "hash_type"`, `Hash.SALT = "salt"`, `Hash.SHA256 = "sha256"`, `Hash.SHA512 = "sha512"`.
  - `Custom.LAMBDA = "lambda"`.
  - `Replace.NEW_VALUE = "new_value"`.
- Hash salt minimum: **16 bytes (128 bits)** if user-provided; auto-generates 32 random bytes via `os.urandom(32)` otherwise.
- `app.py`: `DEFAULT_PORT = "3000"`, `LOGGING_CONF_FILE = "logging.ini"`.

### Image redactor / structured

- No notable module-level constants. Image redactor uses a magic-string JSON key `color_fill` in REST payloads. Structured has no constants at all.

## Serialization

Presidio's serialization story is **ad-hoc and inconsistent**.

| Class | Mechanism | What's stripped / included |
|---|---|---|
| `RecognizerResult` (analyzer) | `to_dict() → self.__dict__`, `from_json(data)` | `from_json` only reads `entity_type/start/end/score`; ignores `analysis_explanation` and `recognition_metadata`. `to_dict` includes everything. |
| `AnalysisExplanation` | `to_dict() → self.__dict__` | No `from_*` method — one-way serialization. |
| `Pattern` | `to_dict()` → `{"name", "score", "regex"}` (explicit, excludes `compiled_regex` and `compiled_with_flags`), `from_dict(d)` | Hand-rolled allowlist. |
| `EntityRecognizer` | `to_dict()` → `{"supported_entities", "supported_language", "name", "version"}` (plus `"country_code"` if set), `from_dict(d) → cls(**d)` | Hand-rolled allowlist. The `is_loaded` flag, `_id`, `context`, and `_country_code` (except via the explicit branch) are NOT in `to_dict`. |
| `OperatorConfig` | `from_json({"type": ..., **params})` strips `"type"` | No `to_*` method — one-way deserialization. |
| `RecognizerResult` (anonymizer) | `from_json(data)` | Same as analyzer copy. |
| `OperatorResult` | `to_dict() → self.__dict__`, `__repr__` and `__str__` print the dict, `from_json(json)` | Includes `text` and `operator`. |
| `EngineResult` | `to_json() → json.dumps(self, default=lambda x: x.__dict__)` | The **only** built-in JSON encoder. Walks the whole object graph via `__dict__`. |
| `NlpArtifacts` | `to_json()` — deletes `nlp_engine` from the dict (not serializable), converts `tokens` and `entities` to their `.text`, casts `scores` to `float` | Explicit "exclude these" pattern. |
| `NerModelConfiguration` | pydantic `model_dump(exclude_none=True)`, `from_dict(d) → cls(**d)` | Pydantic v2 patterns. |
| `HuggingFaceRecognizerConfig` / `GLiNERRecognizerConfig` | override `model_dump` to default `exclude_none=True` so omitted YAML fields don't override constructor defaults with explicit `None` | A subtle but real footgun: forgetting this override would silently break HF/GLiNER kwargs. |
| `RecognizerRegistryConfig` | `model_dump(exclude_unset=False)` — includes default values | Used inside `ConfigurationValidator.validate_recognizer_registry_configuration`. |
| Analyzer `app.py` `/analyze` response | manual `json.dumps(results, default=lambda o: o.to_dict(), sort_keys=True)` and then strips `recognition_metadata` via `_exclude_attributes_from_dto` | Wire format intentionally drops the metadata dict (`recognition_metadata` is excluded from REST output). |
| Anonymizer `app.py` `/anonymize` response | `EngineResult.to_json()` | Whole `__dict__` walk. |

The **back-reference problem** is acknowledged in only one place
(`NlpArtifacts.to_json` deletes `nlp_engine`). Other potential cycles
(`Pattern.compiled_regex`, lambda inside `Custom`, file handles) rely on the
fact that the encoder is only called on safe types.

## Type / parameter validation patterns

1. **Operator params (anonymizer)** — go through `services/validators.py`, raise `InvalidParamError`. Operator `validate()` methods are called from `EngineBase.__operate_on_text` after defensively `params.copy()` and **injecting `entity_type` into the params dict** (a notable side-channel — `Replace` uses it to build the `<ENTITY_TYPE>` fallback).
2. **Engine inputs** — analyzer's `AnalyzerEngine.analyze` and the registry raise plain `ValueError("No language provided")` / `"No entities provided"` / `"No matching recognizers were found to serve the request."` etc. No use of `InvalidParamError`.
3. **YAML configs** — pydantic `BaseModel` subclasses with `field_validator` / `model_validator`. `ValidationError` is caught at `ConfigurationValidator.validate_recognizer_registry_configuration` and rewrapped as `ValueError`.
4. **Custom recognizer country code** — `EntityRecognizer._resolve_country_code` lowercases/strips, raises `TypeError` for non-string, `ValueError` for blank, and `ValueError` for conflict with the class-level `COUNTRY_CODE`. Mirrored in `CustomRecognizerConfig.validate_country_code` for YAML inputs.
5. **Image / DICOM** — almost entirely `ValueError` (e.g. `BboxProcessor.remove_bbox_padding` for negative width); `InvalidParamError` only fires on REST-boundary JSON parse failures.
6. **Structured** — only `ValueError` (no dedicated exception). `DataProcessorBase` raises `ValueError("Operator for entity {entity} not found")` when neither a specific nor a `"DEFAULT"` mapping is provided. Both processors guard the data type at the top of `_process`.
7. **NER configuration** — pydantic field-level validators. Unusual: `validate_stride` and `validate_alignment_mode` accept `None` and recover the field's default rather than raising — silent fallback.

## Anything notable / unusual

1. **`Custom` operator deliberately does NOT invoke the lambda during `validate()`** — the docstring explicitly references <https://github.com/microsoft/presidio/issues/2024>. Stateful lambdas (e.g. those that accumulate a token-to-original-value map for de-anonymization) would corrupt their state if called with a probe input. The return-type contract is therefore only enforced at `operate()` time, raising `InvalidParamError("Function return type must be a str")`.
2. **`validate_type` silently passes on falsy values** — `if parameter_value and not isinstance(...)`. An empty string or `0` bypasses the type check entirely. Callers must precede it with `validate_parameter_not_empty` if they care.
3. **Two `InvalidParamError` classes** — anonymizer and image-redactor each define their own, neither inherits from a shared base. `isinstance` checks won't cross packages.
4. **Two `RecognizerResult` classes** — one in `presidio-analyzer`, one in `presidio-anonymizer` (subclass of `PIIEntity`). The latter is described in the docstring as "an exact copy" but is structurally different (no `analysis_explanation`, no `recognition_metadata`, inherits a different `__gt__`). Round-tripping through JSON loses fields.
5. **`OperatorConfig.params` is mutated by the engine** — `EngineBase.__operate_on_text` copies before mutation, but if anyone calls `operator.validate()` or `operator.operate()` directly with their own `params` dict, `entity_type` gets injected.
6. **`AnalyzerRequest.regex_flags` default is `re.DOTALL | re.MULTILINE | re.IGNORECASE`** = 26, and the same value is hardcoded in `RecognizerRegistryConfig.global_regex_flags: int = 26`. Two sources of truth for the same default.
7. **`ConflictResolutionStrategy.NONE` is documented but missing** — the docstring lists three members; only two are defined.
8. **REST exception exposure is asymmetric** — anonymizer's 500 handler returns `"Internal server error"`, but analyzer's 500 handler returns `e.args[0]` (the raw exception message). The analyzer leaks more error detail than the anonymizer.
9. **`api_request_convertor.get_json_data` does `data.replace("'", '"')` before `json.loads`** — corrupts any JSON value containing an apostrophe. Done so that users can submit `{"color_fill":"1,1,1"}` as `{'color_fill':'1,1,1'}` from a shell without quoting nightmares.
10. **REST handler explicitly rejects `Custom` operators** via `AppEntitiesConvertor.check_custom_operator` → `raise BadRequest("Custom type anonymizer is not supported")`. Custom is library-only.
11. **`_exclude_attributes_from_dto` (analyzer `app.py`)** mutates the `RecognizerResult` instances in-place (`delattr(result, "recognition_metadata")`) before serialization. Side-effecting the engine's output to scrub the REST response.
12. **`Pattern` uses the third-party `regex` lib (PyPI `regex`), not stdlib `re`** — important for Unicode property classes (`\p{...}`) and for the configured `REGEX_TIMEOUT_SECONDS`. Stdlib `re` doesn't support timeouts.
13. **`AESCipher.decrypt` uses hardcoded `padding.PKCS7(128)`** instead of `algorithms.AES.block_size`. Functionally identical (AES block size IS 128), but the asymmetry with `encrypt` is unusual.
14. **`PIIEntity` and `RecognizerResult` (anonymizer) implement `__gt__` differently** — `PIIEntity` compares by `start` only; the anonymizer's `RecognizerResult` overrides to compare by `(start, end)`. Sorting a mixed list with `sorted(reverse=True)` would behave differently depending on declared types.
15. **`MODEL_TO_PRESIDIO_ENTITY_MAPPING` and `LOW_SCORE_ENTITY_NAMES` are module-level mutables** that `NerModelConfiguration` defaults to via `default_factory=lambda: ....copy()`. Reasonable defensive copy, but it means mutating the module constant has no effect on already-instantiated configs.
16. **No common base type for engine results** — `EngineResult` (anonymizer) is unrelated to `List[RecognizerResult]` (analyzer's output) and `List[DictAnalyzerResult]` (batch). A wrapper has to handle three separate shapes.
17. **`AHDS_AVAILABLE`** module-level boolean in `presidio_anonymizer.operators` — `True` iff `presidio_anonymizer.operators.ahds_surrogate` imports successfully (i.e. the optional `azure-health-deidentification` extra is installed). Re-exported from `__init__.py`. `OperatorsFactory` conditionally adds `AHDSSurrogate` to the `ANONYMIZERS` list based on this flag.
18. **`RecognizerListLoader.PredefinedRecognizerNotFoundError` is used as control flow** in `RecognizerRegistryConfig.parse_recognizers` and `CustomRecognizerConfig.check_predefined_name_conflict` — the validator deliberately catches it to mean "this name is available for a custom recognizer." This couples the YAML schema to recognizer discovery.
