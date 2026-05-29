# Presidio Analyzer — Engine, NLP, and Pipeline

Catalog of Microsoft Presidio's analyzer **engine** (orchestration, NLP
integration, context-aware enhancement, confidence scoring, multi-language
support, registry / configuration system) — i.e., everything that sits *around*
the individual recognizers. Compiled for comparison against octarine's
identifier pipeline.

## Source files reviewed

- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/analyzer_engine.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/analyzer_engine_provider.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/batch_analyzer_engine.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/entity_recognizer.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/pattern.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/pattern_recognizer.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/recognizer_result.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/analysis_explanation.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/remote_recognizer.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/recognizer_registry/recognizer_registry.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/recognizer_registry/recognizer_registry_provider.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/recognizer_registry/recognizers_loader_utils.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/context_aware_enhancers/context_aware_enhancer.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/context_aware_enhancers/lemma_context_aware_enhancer.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/nlp_engine/nlp_engine.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/nlp_engine/nlp_engine_provider.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/nlp_engine/nlp_artifacts.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/nlp_engine/spacy_nlp_engine.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/nlp_engine/stanza_nlp_engine.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/nlp_engine/transformers_nlp_engine.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/nlp_engine/ner_model_configuration.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/conf/default_analyzer.yaml>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/conf/default_analyzer_full.yaml>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/conf/default_recognizers.yaml>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/conf/example_recognizers.yaml>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/conf/transformers.yaml>
- <https://microsoft.github.io/presidio/analyzer/>
- <https://microsoft.github.io/presidio/analyzer/adding_recognizers/>
- <https://microsoft.github.io/presidio/analyzer/customizing_nlp_models/>
- <https://microsoft.github.io/presidio/analyzer/nlp_engines/transformers/>

## AnalyzerEngine features

### Constructor

```python
AnalyzerEngine(
    registry: RecognizerRegistry = None,
    nlp_engine: NlpEngine = None,
    app_tracer: AppTracer = None,
    log_decision_process: bool = False,
    default_score_threshold: float = 0,
    supported_languages: List[str] = None,        # defaults to ["en"]
    context_aware_enhancer: Optional[ContextAwareEnhancer] = None,
)
```

- Auto-builds defaults: `NlpEngineProvider()`, `AppTracer()`, a
  `RecognizerRegistry` via `RecognizerRegistryProvider`, and a
  `LemmaContextAwareEnhancer()`.
- Forces registry `supported_languages` to match the engine's; raises
  `ValueError` on mismatch.
- Calls `registry.load_predefined_recognizers(...)` when the registry is empty.

### `analyze()` API surface

```python
analyze(
    text: str,
    language: str,
    entities: Optional[List[str]] = None,
    correlation_id: Optional[str] = None,
    score_threshold: Optional[float] = None,
    return_decision_process: Optional[bool] = False,
    ad_hoc_recognizers: Optional[List[EntityRecognizer]] = None,
    context: Optional[List[str]] = None,
    allow_list: Optional[List[str]] = None,
    allow_list_match: Optional[str] = "exact",      # or "regex"
    regex_flags: Optional[int] = re.DOTALL | re.MULTILINE | re.IGNORECASE,
    nlp_artifacts: Optional[NlpArtifacts] = None,
) -> List[RecognizerResult]
```

Per-call knobs that are notable:

- **`entities`** — filter to a subset of entity types; `None` = all supported.
- **`correlation_id`** — passed to `AppTracer` for cross-event correlation.
- **`score_threshold`** — overrides the engine's `default_score_threshold`.
- **`return_decision_process`** — when `False` (default) the engine strips
  `analysis_explanation` from every result before returning.
- **`ad_hoc_recognizers`** — list of `EntityRecognizer` instances applied
  only to this request; survives one call, never registered.
- **`context`** — extra context words supplied at request time (in addition
  to whatever the recognizer carries).
- **`allow_list` + `allow_list_match`** — see below.
- **`nlp_artifacts`** — pre-computed artifacts; lets callers skip NLP work
  when re-analyzing the same text under a different config.

### Allow-list / deny-list handling

- **Allow-list** is engine-level (`analyze(allow_list=...)`):
  - `allow_list_match="exact"` — drops result if
    `text[result.start:result.end] in allow_list`.
  - `allow_list_match="regex"` — joins entries with `|`, compiles with the
    request `regex_flags`, searches each span with a configurable timeout
    (`REGEX_TIMEOUT_SECONDS` env var, default 60s). On timeout the result is
    *kept* and a warning is logged.
  - Any other mode raises `ValueError`.
- **Deny-list** is recognizer-level (`PatternRecognizer(deny_list=...)`).
  Each list of terms becomes a single regex pattern wrapped in
  `(?:^|(?<=\W))(...)(?:(?=\W)|$)` boundary lookarounds and scored at
  `deny_list_score` (default `1.0`).

### Pipeline order (single call)

1. Resolve target languages, recognizers for `language` (+ ad-hoc).
2. Run NLP engine `process_text(text, language)` → `NlpArtifacts` (skipped
   if caller supplied `nlp_artifacts`).
3. Trace artifacts when `log_decision_process=True`.
4. For each recognizer, call `recognizer.analyze(text, entities,
   nlp_artifacts)`; aggregate results.
5. Inject `recognizer_identifier` + `recognizer_name` into each result's
   `recognition_metadata`.
6. Per-recognizer self-enhancement via `recognizer.enhance_using_context(...)`
   (default no-op; overridable).
7. Global enhancement via
   `context_aware_enhancer.enhance_using_context(...)`.
8. Allow-list filtering.
9. Deduplication via `EntityRecognizer.remove_duplicates(results)` — see
   "Conflict resolution" below.
10. Low-score filter using `score_threshold ?? default_score_threshold`.
11. Strip `analysis_explanation` unless `return_decision_process=True`.

### Per-entity / per-call score thresholds

Only a single numeric `score_threshold` per request — there is **no
per-entity threshold map** in `analyze()`. Per-recognizer thresholds are not
a first-class concept either; recognizers express confidence via the
`Pattern.score`, deny-list score, and validator hooks.

### Decision-process tracing

- Optional `AppTracer` writes `"nlp artifacts: ..."` and the final results
  JSON, keyed by `correlation_id`.
- Independent of `return_decision_process` (which only controls what is
  returned to the caller).

## Batch / list analysis

### `BatchAnalyzerEngine`

Thin wrapper that delegates to an `AnalyzerEngine`. Two entry points:

```python
analyze_iterator(
    texts: Iterable[Union[str, bool, float, int]],
    language: str,
    batch_size: int = 1,
    n_process: int = 1,
    **kwargs,   # forwarded to AnalyzerEngine.analyze
) -> List[List[RecognizerResult]]

analyze_dict(
    input_dict: Dict[str, Union[Any, Iterable[Any]]],
    language: str,
    keys_to_skip: Optional[List[str]] = None,
    batch_size: int = 1,
    n_process: int = 1,
    **kwargs,
) -> Iterator[DictAnalyzerResult]
```

- `analyze_iterator` uses `nlp_engine.process_batch(...)` for spaCy/Stanza
  efficiency; then calls `analyzer_engine.analyze` per text.
- `analyze_dict` recurses into nested dicts, dispatches iterables to
  `analyze_iterator`, and **adds the current dict key to the `context`
  list** so e.g. `{"ssn": "..."}` gets the `ssn` context boost
  automatically. Skip keys propagate as `f"{key}.sub"` patterns.
- Empty values or `keys_to_skip` keys yield empty `DictAnalyzerResult`s.
- Non-primitive scalar values raise `ValueError("Lists of objects are
  not yet supported.")`.

## NLP engines

### Base abstraction

`NlpEngine` (ABC) requires:

- `load()`, `is_loaded()`
- `process_text(text, language) -> NlpArtifacts`
- `process_batch(texts, language, batch_size=1, n_process=1, **kwargs)`
  → `Iterator[Tuple[str, NlpArtifacts]]`
- `is_stopword(word, language) -> bool`
- `is_punct(word, language) -> bool`
- `get_supported_entities() -> List[str]`
- `get_supported_languages() -> List[str]`

### Bundled engines (`NlpEngineProvider` default tuple)

| Engine | `engine_name` | Default model(s) | NER source |
|---|---|---|---|
| `SpacyNlpEngine` | `spacy` | `[{lang_code: en, model_name: en_core_web_lg}]` | spaCy's built-in NER |
| `StanzaNlpEngine` | `stanza` | No hard default; user passes `[{lang_code: en, model_name: en}]`; runs Stanza inside a spaCy-blank `Language` wrapper via `PipelineAsTokenizer.v1` | Stanza pipeline (tokenize, pos, lemma, ner) |
| `TransformersNlpEngine` | `transformers` | spaCy `en_core_web_sm` for tokens/lemmas/POS + HuggingFace `obi/deid_roberta_i2b2` for NER | HF model via `spacy-huggingface-pipelines` (`hf_token_pipe`) |
| `SlimSpacyNlpEngine` | (slim) | Generic tokenizer mode | Lightweight spaCy variant |

`is_available` per class gates loading on installed optional deps.

### Bundled / recommended HuggingFace models

From docs and `conf/transformers.yaml`:

- `StanfordAIMI/stanford-deidentifier-base` (used in `transformers.yaml`)
- `obi/deid_roberta_i2b2` (default when no `models` passed)
- `dslim/bert-base-NER-uncased` (referenced in label-mapping docs)

Any HuggingFace token-classification model works in principle.

### Registering a custom NLP engine

Two paths:

1. **In code:** subclass `NlpEngine`, implement abstract methods, then
   instantiate `AnalyzerEngine(nlp_engine=my_engine,
   supported_languages=...)`.
2. **Via provider tuple:** pass
   `NlpEngineProvider(nlp_engines=(MySpacy, MyStanza, MyTransformers, MyOther))`.
   Each class must expose `engine_name` and `is_available`.

### NLP engine YAML

`NlpEngineProvider(conf_file=...)` accepts:

```yaml
nlp_engine_name: spacy            # required
models:                           # required
  - lang_code: en
    model_name: en_core_web_lg
  - lang_code: es
    model_name: es_core_news_md
ner_model_configuration:          # optional, NerModelConfiguration
  labels_to_ignore: [O]
  aggregation_strategy: max
  stride: 16
  alignment_mode: expand
  model_to_presidio_entity_mapping:
    PER: PERSON
    LOC: LOCATION
    # ...
  low_confidence_score_multiplier: 0.4
  low_score_entity_names: [ID]
generic_tokenizer: ...            # only for SlimSpacyNlpEngine
```

For transformers, `model_name` is a dict:

```yaml
model_name:
  spacy: en_core_web_sm
  transformers: StanfordAIMI/stanford-deidentifier-base
```

Default path: `presidio_analyzer/conf/default.yaml`.

### `NerModelConfiguration`

| Field | Default | Notes |
|---|---|---|
| `labels_to_ignore` | `[]` | NER labels to drop |
| `aggregation_strategy` | `"max"` | `simple`/`first`/`average`/`max` (subword aggregation) |
| `stride` | `14` | Token overlap for long inputs |
| `alignment_mode` | `"expand"` | `strict`/`contract`/`expand` (char-offset alignment) |
| `default_score` | `0.85` | Fallback when model lacks score |
| `model_to_presidio_entity_mapping` | `MODEL_TO_PRESIDIO_ENTITY_MAPPING` copy | See below |
| `low_score_entity_names` | empty set | Entities to discount |
| `low_confidence_score_multiplier` | `0.4` | Multiplier applied to `low_score_entity_names` |

Default model→Presidio mapping:

```
PER, PERSON, PATIENT, STAFF, HCW           -> PERSON
LOC, LOCATION, GPE                         -> LOCATION
ORG, HOSP, PATORG, HOSPITAL                -> ORGANIZATION
DATE, TIME                                 -> DATE_TIME
NORP                                       -> NRP
AGE                                        -> AGE
ID                                         -> ID
EMAIL                                      -> EMAIL
PHONE                                      -> PHONE_NUMBER
```

### `NlpArtifacts`

Per-text bundle produced by the NLP engine and passed to every recognizer:

| Field | Source / type |
|---|---|
| `entities` | spaCy `List[Span]` (NER hits) |
| `tokens` | spaCy `Doc` |
| `tokens_indices` | `List[int]` — character offsets per token |
| `lemmas` | `List[str]` |
| `nlp_engine` | back-reference (excluded from JSON) |
| `scores` | per-entity confidence; defaults `[0.85] * len(entities)` |
| `keywords` | computed from lemmas via `set_keywords(...)`; used by context enhancer |

`to_json()` strips `nlp_engine` and flattens `tokens` / `entities` / `scores`.

### Which entities depend on NER vs regex

- **NER (via spaCy / Stanza / Transformers)**: `PERSON`, `LOCATION`,
  `ORGANIZATION`, `DATE_TIME`, `NRP`, `AGE`, plus any custom mapping in
  `model_to_presidio_entity_mapping`. The default analyzer config in
  `default_analyzer_full.yaml` actually **drops `ORG`/`ORGANIZATION` via
  `labels_to_ignore`** with comment "has many false positives".
- **Regex / checksums (via PatternRecognizer subclasses)**: credit cards,
  IBAN, US SSN/ITIN/passport/license/bank, NHS, crypto wallets, email,
  IP, phone, URL, medical license, plus the disabled-by-default country
  packs (UK NINO, Singapore FIN, Australia ABN/ACN/TFN/Medicare, India
  PAN/Aadhaar/Vehicle/Passport/Voter/GSTIN).

## Context-aware enhancement

### `ContextAwareEnhancer` (abstract base)

Abstract `enhance_using_context(text, raw_results, nlp_artifacts,
recognizers, context=None)`. Constants `MIN_SCORE = 0`, `MAX_SCORE = 1.0`.
Constructor stores `context_similarity_factor`,
`min_score_with_context_similarity`, `context_prefix_count`,
`context_suffix_count` as instance attributes (no class-level constants).

### `LemmaContextAwareEnhancer` (default)

```python
LemmaContextAwareEnhancer(
    context_similarity_factor: float = 0.35,
    min_score_with_context_similarity: float = 0.4,
    context_prefix_count: int = 5,
    context_suffix_count: int = 0,
    context_matching_mode: str = "substring",   # or "whole_word"
)
```

- **Window**: 5 lemmas *before* the entity, 0 *after*. Driven by
  `_extract_surrounding_words` which uses `_add_n_words_backward` /
  `_add_n_words_forward` over `nlp_artifacts.keywords` (lemmas).
- **Matching modes**:
  - `"substring"` (default): case-insensitive substring containment
    (`"card"` matches `"creditcard"`).
  - `"whole_word"`: case-insensitive equality (prevents `"lic"` matching
    `"duplicate"`).
- **Scoring math** when a supportive word is found:

  ```text
  score += context_similarity_factor          # e.g., +0.35
  score = max(score, min_score_with_context_similarity)  # floor 0.4
  score = min(score, MAX_SCORE)               # cap 1.0
  ```

  So a regex hit with `score=0.01` and a found context word becomes
  `max(0.36, 0.4) = 0.4`. A `0.7` hit becomes `min(1.05, 1.0) = 1.0`.
- **Recognizer skip conditions**:
  - Missing `RECOGNIZER_IDENTIFIER_KEY` metadata → skip with debug log.
  - Recognizer's own `context` is empty → skip.
  - `IS_SCORE_ENHANCED_BY_CONTEXT_KEY` already set → skip (the recognizer
    already self-enhanced).
- **External context**: the `context` kwarg passed to `analyze()` is
  appended to the window lemmas (lowercased) before matching, so dict keys
  in `analyze_dict` boost scores.
- **Analysis explanation**: calls `set_supportive_context_word(word)` and
  `set_improved_score(new_score)` (which records the delta as
  `score_context_improvement`).

## Pattern recognizer features

### `Pattern`

Fields: `name: str`, `regex: str` (validated by `re.compile`),
`score: float` (0–1). Plus `compiled_regex` and `compiled_with_flags`
caches. JSON-serializable via `to_dict()` / `from_dict()` (compiled state
is not persisted).

Note: uses the third-party `regex` module (not stdlib `re`).

### `PatternRecognizer`

```python
PatternRecognizer(
    supported_entity: str,
    name: str = None,
    supported_language: str = "en",
    patterns: List[Pattern] = None,
    deny_list: List[str] = None,
    context: List[str] = None,
    deny_list_score: float = 1.0,
    global_regex_flags: int = re.DOTALL | re.MULTILINE | re.IGNORECASE,
    version: str = "0.0.1",
    country_code: Optional[str] = None,
)
```

- Requires either `patterns` or `deny_list` (else `ValueError`).
- Multiple patterns per entity: yes — passed as a list.
- Per-call `regex_flags` on `analyze(...)` override `global_regex_flags`.
- Recompiles each `Pattern` when uncompiled or flags changed.
- `re.finditer` runs under a per-call timeout (`REGEX_TIMEOUT_SECONDS`,
  default 60s). On timeout the pattern is logged and skipped.
- Skips empty regex matches.

### `validate_result(pattern_text)` / `invalidate_result(pattern_text)`

Both return `None` by default; subclasses override.

- `validate_result` returns:
  - `True` → score forced to `MAX_SCORE` (e.g., checksum passed).
  - `False` → score forced to `MIN_SCORE`.
  - `None` → leave score alone.
- `invalidate_result` returns truthy → score forced to `MIN_SCORE`
  (e.g., reject `"111-11-1111"` style same-digit SSNs).

Final list passes through `EntityRecognizer.remove_duplicates`.

### Context list

Stored on the recognizer and surfaced in `to_dict()`. The
`PatternRecognizer` itself does **not** consume context during matching —
the analyzer engine's `context_aware_enhancer` reads it later.

## EntityRecognizer base class features

```python
EntityRecognizer(
    supported_entities: List[str],
    name: str = None,                # defaults to class name
    supported_language: str = "en",
    version: str = "0.0.1",
    context: List[str] = None,
    country_code: Optional[str] = None,
)
```

Constants:

- `MIN_SCORE = 0`, `MAX_SCORE = 1.0`
- `COUNTRY_CODE: ClassVar[Optional[str]] = None` (class-level canonical
  ISO-3166 alpha-2 tag)

Attributes set: `_id = f"{name}_{id(self)}"`, `is_loaded`, `context`
(empty list if None), `_country_code` (resolved against class attribute).

**Abstract methods**: `load()`, `analyze(text, entities, nlp_artifacts)`.

**Concrete overridable**: `enhance_using_context(...)` (default returns
results unchanged — lets recognizers self-boost before global enhancement).

**Static helpers**:

- `remove_duplicates(results)` — deduplicates by equality, drops
  zero-score entries, and removes results "contained in" another result
  *of the same `entity_type`* (a longer hit wins over a shorter one when
  they're the same type).
- `sanitize_value(text, replacement_pairs)` — chained `str.replace`.

**Country-code resolution** (`_resolve_country_code` classmethod):
reconciles constructor kwarg with `COUNTRY_CODE` class attribute. Blank
string or mismatch with a set class attribute raises (prevents "a Polish
tax-ID recognizer being silently re-tagged as British").

**Note**: there is **no `score_threshold` field on `EntityRecognizer`** —
threshold is engine-level only.

**Subclass tree**: `EntityRecognizer` → `LocalRecognizer` (in-process) and
`RemoteRecognizer` (abstract; subclasses implement `analyze(...)` to call
out to a network service and translate the response back to
`List[RecognizerResult]`). `PatternRecognizer` extends `LocalRecognizer`.

## Recognizer registry

### `RecognizerRegistry`

```python
RecognizerRegistry(
    recognizers: Optional[Iterable[EntityRecognizer]] = None,
    global_regex_flags: int = re.DOTALL | re.MULTILINE | re.IGNORECASE,
    supported_languages: Optional[List[str]] = None,   # defaults to ["en"]
)
```

Methods:

- `load_predefined_recognizers(languages, nlp_engine, countries)` — loads
  built-ins via `RecognizerConfigurationLoader` + `RecognizerListLoader`,
  then adds the per-language NLP recognizer via `add_nlp_recognizer`.
- `add_recognizer(recognizer)` — append; type-checks.
- `remove_recognizer(recognizer_name, language=None)` — removes by name,
  optionally scoped to one language (so the same name in multiple
  languages can be disambiguated).
- `get_recognizers(language, entities=None, all_fields=False, ad_hoc_recognizers=None)`
  — strict `language == rec.supported_language` filter, plus entity
  filter; raises if result set is empty. Ad-hoc recognizers added to
  the candidate pool.
- `add_pattern_recognizer_from_dict(recognizer_dict)` — wraps
  `PatternRecognizer.from_dict(...)`.
- `add_recognizers_from_yaml(yml_path)` — reads YAML and loads each entry
  under the top-level `recognizers` key.
- `get_supported_entities(languages=None)` — union across languages.
- `get_country_codes()` — sorted unique lowercased country codes seen
  in loaded recognizers (excluding locale-agnostic).

### Multi-language behavior

- Each recognizer instance is **bound to a single language**
  (`supported_language: str`, not a list). For multi-language coverage,
  the loader instantiates one recognizer per language.
- `supported_languages` lives on the registry and on the engine; mismatch
  triggers `ValueError`.
- NLP recognizer is added per-language by `add_nlp_recognizer(nlp_engine)`
  using `nlp_engine.get_supported_languages()` (or the registry's list if
  no engine).
- `get_nlp_recognizer(nlp_engine)` picks the right NER recognizer class:
  Stanza → `StanzaRecognizer`, Transformers → `TransformersRecognizer`,
  else `SpacyRecognizer` (with warning for unknown engines).

### Loading recognizers — Python imports vs YAML

Both supported. Loader (`recognizers_loader_utils.py`) splits YAML entries
into two buckets via a `type` field:

| `type` | Behavior |
|---|---|
| `predefined` (or string-only entry) | Class is resolved by walking all `EntityRecognizer` subclasses; instantiated with the YAML kwargs |
| `custom` (default when `type` is absent) | `PatternRecognizer.from_dict(conf)` |

Custom recognizers are also fan-out per language: if no
`supported_language` is set, one recognizer instance is created per entry
in `supported_languages`. Legacy entries with a singular
`supported_language` produce a single recognizer and skip the fan-out.

After construction, `global_regex_flags` is set on every
`PatternRecognizer`.

Filtering steps:

1. **`enabled` flag** — `enabled: false` skips instantiation. Key is
   stripped before passing to `__init__`.
2. **Per-recognizer language check** — drops recognizers whose
   `supported_language` isn't in the registry's `supported_languages`
   (warn-logged).
3. **`supported_countries` filter** — keeps locale-agnostic recognizers
   always; country-specific ones only if their `country_code` is in the
   filter; empty list `[]` keeps only locale-agnostic; `None` (default)
   loads everything.

### YAML schema for recognizers

Top-level (`recognizers.yaml`):

```yaml
supported_languages: [en, es, it, pl]
global_regex_flags: 26     # re.DOTALL | re.MULTILINE | re.IGNORECASE
supported_countries: [us, uk]   # optional, filters predefined
recognizers:
  # ---- Predefined: name + type ----
  - name: CryptoRecognizer
    type: predefined

  # ---- Predefined with per-language context ----
  - name: CreditCardRecognizer
    supported_languages:
      - language: en
        context: [credit, card, visa, mastercard, cc, amex, ...]
      - language: es
        context: [tarjeta, credito, ...]
      - language: it
      - language: pl
    type: predefined

  # ---- Predefined, disabled, country-tagged ----
  - name: UsMbiRecognizer
    supported_languages: [en]
    type: predefined
    enabled: false
    country_code: us

  # ---- External config path (BasicLangExtractRecognizer) ----
  - name: BasicLangExtractRecognizer
    supported_languages: [en]
    type: predefined
    enabled: false
    config_path: presidio_analyzer/conf/langextract_config_basic.yaml

  # ---- Custom (PatternRecognizer-built) ----
  - name: "Zip code Recognizer"
    supported_language: en
    supported_entity: ZIP
    patterns:
      - name: "zip code (weak)"
        regex: "(\\b\\d{5}(?:\\-\\d{4})?\\b)"
        score: 0.01
    context: [zip, code]

  # ---- Custom with deny_list ----
  - name: "Mr Recognizer"
    supported_language: en
    supported_entity: TITLE
    deny_list: ["Mr", "Mr.", "Mister"]
```

Recognizer-entry keys recognized by the loader:

| Key | Notes |
|---|---|
| `name` | Display name / class name (for predefined) |
| `class_name` | Optional override when `name` is a custom display label |
| `type` | `predefined` or `custom` (default custom) |
| `enabled` | Bool; default true |
| `supported_languages` | List of codes **or** list of `{language, context}` dicts |
| `supported_language` | Singular, legacy single-language entry |
| `supported_entity` / `supported_entities` | Entity type(s) |
| `patterns` | List of `{name, regex, score}` |
| `deny_list` | List of literals |
| `context` | List of context words (when not per-language) |
| `country_code` | ISO-3166 alpha-2, must match class `COUNTRY_CODE` if both set |
| `config_path` | External per-recognizer config (used by langextract) |

### `AnalyzerEngineProvider` — full YAML

```yaml
supported_languages: [en]
default_score_threshold: 0
nlp_configuration:                  # inline NLP engine config
  nlp_engine_name: spacy
  models:
    - lang_code: en
      model_name: en_core_web_lg
  ner_model_configuration:
    labels_to_ignore: [O, ORG, ORGANIZATION, CARDINAL, EVENT, ...]
    model_to_presidio_entity_mapping: {...}
    low_confidence_score_multiplier: 0.4
    low_score_entity_names: []
recognizer_registry:                # inline registry config
  recognizers:
    - name: CreditCardRecognizer
      type: predefined
    - ...
```

Precedence: inline section in analyzer YAML → per-section file (passed via
`AnalyzerEngineProvider(nlp_engine_conf_file=..., recognizer_registry_conf_file=...)`)
→ defaults. The provider does **not** wire `context_aware_enhancer` — left
to `AnalyzerEngine`'s own default.

### Adding recognizers at runtime

- Direct: `analyzer.registry.add_recognizer(my_recognizer)`.
- Per-request: `analyze(..., ad_hoc_recognizers=[...])` — single-shot,
  not persisted. JSON-equivalent for the REST API exists.

### Removing / updating

`remove_recognizer(name, language=None)` is the only first-class
mechanism. No "update in place" API — remove and re-add.

## Analysis explanation / decision process

### `AnalysisExplanation`

| Field | Type | Notes |
|---|---|---|
| `recognizer` | `str` | Which component fired |
| `original_score` | `float` | Initial recognizer confidence |
| `pattern_name` | `str = None` | For `PatternRecognizer` |
| `pattern` | `str = None` | Regex source |
| `validation_result` | `bool = None` | e.g., checksum outcome |
| `textual_explanation` | `str = None` | Free-form notes |
| `regex_flags` | `int = None` | Flags used |
| `score` | `float` | Mutates from `original_score` |
| `score_context_improvement` | `float = 0` | Delta from context boost |
| `supportive_context_word` | `str = ""` | Which word triggered the boost |

Methods: `set_improved_score`, `set_supportive_context_word`,
`append_textual_explanation_line`, `to_dict`.

### Decision process flow

1. Recognizer instantiates `AnalysisExplanation(recognizer, original_score,
   pattern_name, pattern, validation_result, textual_explanation,
   regex_flags)`.
2. `validate_result` / `invalidate_result` may force the score to
   `MAX_SCORE` / `MIN_SCORE`.
3. Engine sets `recognition_metadata = {RECOGNIZER_NAME_KEY: ...,
   RECOGNIZER_IDENTIFIER_KEY: ...}` on every result.
4. Per-recognizer `enhance_using_context` may flip
   `IS_SCORE_ENHANCED_BY_CONTEXT_KEY` to mark "already enhanced".
5. Global `LemmaContextAwareEnhancer` records `supportive_context_word`
   and calls `set_improved_score(new_score)` (which stamps
   `score_context_improvement`).
6. `AppTracer` writes artifacts and result JSON if
   `log_decision_process=True`.
7. Engine returns explanations only when
   `return_decision_process=True`; otherwise sets every
   `analysis_explanation = None`.

## Result objects

### `RecognizerResult`

Fields: `entity_type: str`, `start: int`, `end: int`, `score: float`,
`analysis_explanation: AnalysisExplanation = None`, `recognition_metadata:
Dict = None`.

Metadata key constants:

```python
RECOGNIZER_NAME_KEY = "recognizer_name"
RECOGNIZER_IDENTIFIER_KEY = "recognizer_identifier"
IS_SCORE_ENHANCED_BY_CONTEXT_KEY = "is_score_enhanced_by_context"
```

Span methods:

- `intersects(other) -> int` — overlap character count (0 when disjoint).
- `contained_in(other) -> bool`
- `contains(other) -> bool`
- `equal_indices(other) -> bool`

### Conflict resolution

Two-tier:

1. **Per-result** `has_conflict(other)`:

   ```python
   def has_conflict(self, other):
       if self.equal_indices(other):
           return self.score <= other.score   # same span, lower score loses
       return other.contains(self)            # contained in larger span loses
   ```

2. **Engine-level** dedup via `EntityRecognizer.remove_duplicates(results)`:
   - Drops zero-score entries.
   - Drops results equal to another result.
   - Drops results "contained in another result **of the same
     `entity_type`**" — so a `PHONE` hit fully contained inside another
     `PHONE` hit dies, but a `PHONE` inside a `URL` survives.

So the conflict policy is: **same-type, same span → higher score wins;
same-type, contained span → longer wins; different types → both survive
(no cross-type overlap removal)**.

Ordering: `RecognizerResult.__gt__` orders by `start`, ties broken by
`end`. No explicit "first wins" tie-break — score and span containment
do all the work.

## Confidence scoring

### Score range and semantics

- Floor / ceiling: `EntityRecognizer.MIN_SCORE = 0`, `MAX_SCORE = 1.0`.
- `Pattern.score` is validated to lie in `[0, 1]`.
- Examples from the docs:
  - Weak regex hit: `0.01` (e.g., the ZIP example).
  - Deny-list hit default: `1.0`.
  - NER default fallback: `0.85` (`NerModelConfiguration.default_score`).
  - Low-score multiplier: `0.4` applied to `low_score_entity_names`.
- Score 0 results are silently dropped.

### Combining regex + context

```text
final = clamp(pattern.score + context_similarity_factor,
              min=min_score_with_context_similarity,
              max=MAX_SCORE)
```

Defaults: `+0.35` boost, floor `0.4`, cap `1.0`.

### Combining NER + context

For NER-derived results: the model's score (or `default_score`) is the
starting point; same enhancement math applies if the NER recognizer has a
context list, then label-specific `low_confidence_score_multiplier` is
applied. (The mapping/multiplier happens in
`SpacyNlpEngine._doc_to_nlp_artifact` *before* the recognizer wraps the
entities into `RecognizerResult`s.)

### Per-recognizer self-enhancement

Recognizers can override `enhance_using_context` to apply their own
domain-specific score adjustments. When they do, they set
`recognition_metadata[IS_SCORE_ENHANCED_BY_CONTEXT_KEY] = True` so the
global `LemmaContextAwareEnhancer` skips the result. This prevents
double-counting.

### Validator-driven overrides

`PatternRecognizer.validate_result` returning `True/False` clamps the score
to `MAX_SCORE`/`MIN_SCORE` regardless of pattern score — checksum-strong
hits get full confidence even if the regex was weak; checksum-failures get
nuked even if the regex looked strong. `invalidate_result` truthy → score
forced to `MIN_SCORE` and the result is dropped.

## Anything notable / unusual

- **Regex timeout out of the box.** Every regex run (pattern matching
  *and* allow-list regex mode) wraps in a `REGEX_TIMEOUT_SECONDS`
  guard (env-tunable, default 60s). Octarine doesn't have this safety
  net — a pathological pattern would hang the scanner.
- **Third-party `regex` module**, not stdlib `re`. Lets patterns use
  Unicode property escapes (`\p{...}`) and atomic groups.
- **Context window is asymmetric.** Default is 5 lemmas **before** the
  entity and **0 after**. Tuning suffix > 0 is an explicit choice; the
  default biases toward English-style left-context indicators ("SSN: ...").
- **Dict analysis auto-promotes keys to context words.** Calling
  `BatchAnalyzerEngine.analyze_dict({"ssn": "..."})` injects `"ssn"` as
  context, so a weak `0.01` SSN regex becomes a `0.4`+ hit. This is a
  killer feature for structured-data scanning.
- **Two enhancement passes per call**: each recognizer's own
  `enhance_using_context` runs first (and can self-flag to opt out of
  the global pass), then the engine's enhancer runs. Lets domain
  recognizers (e.g., medical license) apply richer scoring while still
  getting the cheap lemma-based boost for free.
- **Decision-process tracing is independent of the API response.**
  `log_decision_process=True` writes to `AppTracer` regardless of
  `return_decision_process`; the latter only controls what's returned to
  the caller. So you can have audit-level logging without paying the
  serialization cost on the response.
- **YAML configs are layered.** `AnalyzerEngineProvider` supports a
  single analyzer YAML *or* three separate files (analyzer + NLP +
  registry). Inline sections in the analyzer YAML override per-section
  files — explicit rationale in the source is that a Docker default
  pointing to a single file shouldn't be silently overridden.
- **`enabled: false` for individual recognizers in YAML.** Lets ops
  disable noisy recognizers (UK NINO, Singapore FIN, the India pack)
  without code changes. The default `default_analyzer_full.yaml` disables
  about a dozen country-specific recognizers out of the box.
- **`labels_to_ignore: [ORG, ORGANIZATION]` in the default config**
  with the inline comment "has many false positives" — Microsoft
  considers spaCy's ORG detection unreliable enough to drop entirely.
- **`country_code` reconciliation.** `EntityRecognizer._resolve_country_code`
  raises if YAML and class-level `COUNTRY_CODE` disagree, preventing a
  recognizer being mislabeled.
- **No per-entity confidence threshold.** Engine has a single
  `default_score_threshold` and a single per-call `score_threshold`.
  Octarine could differentiate by offering per-entity thresholds
  (e.g., "SSN must be > 0.8, but PERSON > 0.5").
- **No cross-type conflict resolution.** Two recognizers producing
  results of different entity types at the same span both survive.
  Callers are responsible for downstream tie-breaking if they only want
  one type per span.
- **`AppTracer` is a built-in audit hook**, distinct from the standard
  Python logger. Useful prior art for octarine's audit-trail
  integration with `observe`.
- **`RemoteRecognizer` is a first-class abstraction** for delegating
  detection to an external service (just implement `analyze(...)` and
  `get_supported_entities`). Octarine doesn't have this — all
  detection is in-process.
- **Country filtering at load time** lets the registry be tuned to a
  deployment region (`supported_countries: [us, uk]`) without writing
  Python.
- **`SlimSpacyNlpEngine`** is a low-dep alternative — generic tokenizer,
  no full spaCy pipeline. Suggests a Presidio escape hatch for
  environments where spaCy is too heavy.
