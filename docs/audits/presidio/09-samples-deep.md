# Presidio — Samples Deep Catalog

Deep-dive over every sample, script, notebook, and deployment under
`docs/samples/` in `microsoft/presidio`. Section K of the master doc
enumerated names; this file catalogs each sample's **actual content** —
what pattern it teaches, what class names appear, what parameters it
takes, what dependencies it pulls in, and what it does that is NOT
already present in the upstream `presidio-analyzer` / `presidio-anonymizer`
libraries.

## Source files reviewed

GitHub: `microsoft/presidio` @ `main`, under `docs/samples/`:

- `python/*.ipynb` (18 notebooks) + `python/*.py` (8 scripts) + `python/gliner.md`
- `python/streamlit/` (7 files including the Dockerfile)
- `python/transformers_recognizer/` (3 files)
- `python/langextract/index.md`
- `python/ahds/` (index.md + example_ahds_surrogate.py)
- `python/text_analytics/index.md`
- `docker/` (postman collections + litellm.md)
- `deployments/app-service/` (index + ARM templates)
- `deployments/k8s/` (Helm chart, KIND scripts)
- `deployments/data-factory/` (three template variants)
- `deployments/spark/` (Databricks notebooks + ARM + scripts)
- `deployments/redacting-telemetry/` (FastAPI app + OTel collector + Grafana)
- `deployments/openai-anonymaztion-and-deanonymaztion-best-practices/`
  ("Invisio" reference — FastAPI API, Textual client, Bicep IaC, K8s manifests)
- `fabric/` (env_setup, presidio_and_spark.ipynb)

---

## Python notebooks — `docs/samples/python/`

### Group A: Customization / authoring recognizers

#### `customizing_presidio_analyzer.ipynb`

The canonical "everything you can do to AnalyzerEngine" tour. Eight
worked examples:

1. Deny-list recognizer: `PatternRecognizer(supported_entity="TITLE", deny_list=titles_list)`
2. Regex recognizer: `Pattern(name, regex, score)` + `PatternRecognizer(patterns=[...])`
3. Custom `EntityRecognizer` subclass using `nlp_artifacts.tokens` with
   `token.like_num`
4. Remote recognizer pointer (references `example_remote_recognizer.py`)
5. Multi-language NLP via `NlpEngineProvider` with `{lang_code, model_name}`
6. Context boosting via `context=["zip"]` on the recognizer and at
   `analyze(context=[...])` call time. Configurable through
   `LemmaContextAwareEnhancer(context_similarity_factor=0.45, min_score_with_context_similarity=0.4)`
7. `return_decision_process=True` produces `result.analysis_explanation`
   with `score_context_improvement`, `supportive_context_word`, original pattern
8. `analyzer.analyze(..., allow_list=["bing.com", "google.com"])` —
   per-call allow list

Key classes: `AnalyzerEngine`, `PatternRecognizer`, `EntityRecognizer`,
`Pattern`, `RecognizerResult`, `RecognizerRegistry`, `NlpEngineProvider`,
`SpacyNlpEngine`, `LemmaContextAwareEnhancer`, `AnalysisExplanation`.

#### `ner_model_configuration.ipynb`

The "wire any NER backend into Presidio" deep dive. Imports
`NerModelConfiguration` from `presidio_analyzer.nlp_engine` and
shows the three backends with **identical surface**:

```python
ner_model_configuration = NerModelConfiguration(
    model_to_presidio_entity_mapping=entity_mapping,
    aggregation_strategy="simple",   # transformers
    stride=14,                       # transformers
    default_score=0.6,
)
```

`model_to_presidio_entity_mapping` translates raw NER tags (`PER`, `LOC`,
`GPE`, `PATIENT`, `STAFF`, `HCW`, `HOSP`, `PATORG`, `HOSPITAL`, `FACILITY`,
`AGE`, `ID`, `EMAIL`, `PHONE`, `DATE`, `TIME`, `NORP`) to canonical
Presidio names. Backends shown:

- `SpacyNlpEngine` with `en_core_web_lg`
- `StanzaNlpEngine` (Stanford)
- `TransformersNlpEngine` — hybrid: spaCy companion (`en_core_web_sm`)
  plus a transformers model (`obi/deid_roberta_i2b2`) for predictions

#### `no_code_config.ipynb`

YAML-driven configuration. Three default file targets:
`default_analyzer.yaml`, `default_recognizers.yaml`, `default.yaml`.
Loaded via:

```python
analyzer_engine = AnalyzerEngineProvider(
    analyzer_engine_conf_file=temp_file_path
).create_engine()
```

Recognizer YAML supports `type: predefined`, per-language `context`,
deny lists, and `recognizers` list. NLP engine YAML supports
`nlp_engine_name: transformers`, per-`lang_code` model maps, full
`ner_model_configuration` block with `labels_to_ignore`, `aggregation_strategy`,
`stride`, `alignment_mode`, `model_to_presidio_entity_mapping`,
`low_confidence_score_multiplier`, and `low_score_entity_names`.

This is the **only** sample showing how Presidio loads multi-language
multi-recognizer config from one YAML file — every other sample
uses Python wiring.

#### `Anonymizing known values.ipynb`

The unique pattern here is **ad-hoc per-record recognizers** —
recognizers instantiated inside a row loop and passed via the
`ad_hoc_recognizers` kwarg to `analyzer.analyze()`. Use case: a
structured row has `name` and `special_value` columns and a free-text
field to scrub against them. Two recognizers built per row, each a
`PatternRecognizer(supported_entity="name" / "special_value", deny_list=[row.name, row.special_value])`.
Also demonstrates that the same span can match multiple recognizers
(`PRESIDENT_FIRST_NAME` + built-in `PERSON`).

### Group B: Anonymization patterns

#### `pseudonymization.ipynb`

**Foundation** for the Invisio sample. Defines the
`InstanceCounterAnonymizer` and `InstanceCounterDeanonymizer` operators
that the production Invisio reference reuses verbatim.

Format: `"<{entity_type}_{index}>"`. Output:
`'PERSON': {'Heidi': '<PERSON_2>', 'Nicole': '<PERSON_0>', 'Peter': '<PERSON_1>'}`.
`OperatorConfig("entity_counter", {"entity_mapping": entity_mapping})` —
mapping is mutated externally (caller owns it). Notebook explicitly
notes: "The following logic is *not thread-safe*".

`AnonymizerEngine.add_anonymizer(InstanceCounterAnonymizer)` and
`DeanonymizeEngine.add_deanonymizer(InstanceCounterDeanonymizer)` are
the registration APIs (not in the main docs).

#### `encrypt_decrypt.ipynb`

`OperatorConfig("encrypt", {"key": crypto_key})` / `OperatorConfig("decrypt", {"key": crypto_key})`.
AES-CBC, 16-char key (`"WmZq4t7w!z%C&F)J"`). Demonstrates
`Decrypt().operate(text, params)` direct call as alternative.

#### `keep_entities.ipynb`

Single new pattern: `OperatorConfig("keep")` retains the original text
while still emitting an item in `result.items` with `operator: 'keep'` —
useful for audit trails. The example keeps `PERSON` while replacing
everything else via `DEFAULT`.

#### `getting_entity_values.ipynb`

Three ways to recover original PII spans from `RecognizerResult`s:

1. Slice the input text with `result.start:result.end`
2. `OperatorConfig("custom", {"lambda": lambda x: x})` — identity operator
3. `OperatorConfig("keep")` — built-in equivalent

The point: only `EngineResult.items` carries `.text`; `RecognizerResult`
only has offsets. The anonymizer also dedupes overlaps (URL inside email
gets dropped).

### Group C: External integration

#### `integrating_with_external_services.ipynb`

References `TextAnalyticsRecognizer` extending `RemoteRecognizer`.
Wires `TextAnalyticsEntityCategory` objects with `name` (Azure label),
`entity_type` (Presidio label), `subcategory`, `supported_languages=["en"]`.
Constructor takes `text_analytics_key`, `text_analytics_endpoint`.
No env var / Key Vault pattern shown — hardcoded placeholders.

#### `synth_data_with_openai.ipynb`

Pipeline: real text → Presidio analyze+anonymize to `<PERSON>` etc. →
OpenAI `client.chat.completions.create(model="gpt-3.5-turbo")` with
few-shot prompt → synthetic surrogate. Uses direct `OpenAI` (not Azure),
`OPENAI_API_KEY` via dotenv.

Few-shot prompt uses `[[TEXT STARTS]] / [[TEXT ENDS]]` delimiters with
three input/output exemplars. Templates from `presidio-research`
include both angle-bracket entities and double-brace Faker tokens
(`{{credit_card_number}}`, `{{first_name_male}}`, `{{nation_woman}}`,
`{{nation_plural}}` etc — ~35 templates listed).

Author flags four limitations: extra unwanted output, hallucinated PII,
cross-field contamination, missed coreferences.

### Group D: Structured / batch / streaming

#### `batch_processing.ipynb`

`BatchAnalyzerEngine(analyzer_engine=analyzer)` +
`BatchAnonymizerEngine()`. Two methods:

- `batch_analyzer.analyze_dict(input_dict, language="en")` — handles nested dicts
- `batch_analyzer.analyze_iterator(texts, language, n_process=4, batch_size=2)` — spaCy multiprocessing

DataFrame handling: `df.to_dict(orient="list")` → analyze → `pd.DataFrame(results)`.
Returns `DictAnalyzerResult(key, value, recognizer_results)`.

Key-skipping: flat (`keys_to_skip=["names"]`) or dotted (`keys_to_skip=["key_a.key_a1"]`).
**Limitation noted**: "JSON files with objects within lists are not yet supported."

#### `example_structured.ipynb`

Different module — `presidio_structured`. Classes: `StructuredEngine`,
`JsonAnalysisBuilder`, `PandasAnalysisBuilder`, `StructuredAnalysis`,
`CsvReader`, `JsonReader`, `JsonDataProcessor`, `PandasDataProcessor`.

Pattern is **per-column entity assignment**, not per-cell:
`StructuredAnalysis(entity_mapping={'name': 'PERSON', 'email': 'EMAIL_ADDRESS', 'address.city': 'LOCATION'})`.
Dot notation for JSON. `engine.anonymize(data, analysis, operators=None)` —
operators dict keyed by column-entity, supports lambda
(`OperatorConfig("custom", {"lambda": lambda x: fake.safe_email()})`).
Default null operator replaces with `<None>`.

Limitation: "Analyzer.analyze_iterator only works on primitive types
(int, float, bool, str). Lists of objects are not yet supported." —
workaround is manually defining `StructuredAnalysis`.

### Group E: Image and PDF

#### `example_dicom_image_redactor.ipynb`

Uses `presidio_image_redactor.DicomImageRedactorEngine`. Works on
`pydicom.dataset.FileDataset` from `pydicom.dcmread()`. Redacts
**pixel data** only — explicitly states "This module only redacts
pixel data and does not scrub text PHI which may exist in the DICOM
metadata." Points users to "Tools for Health Data Anonymization"
(separate Microsoft repo).

OCR via Tesseract, then Presidio detection, then overlay rectangles.
`engine.redact(dicom_instance, fill="contrast")`. Optionally takes a
custom `ImageAnalyzerEngine`.

Dataset: Pseudo-PHI-DICOM-Data (Rutherford et al., 2021, TCIA).

#### `example_dicom_redactor_evaluation.ipynb`

Uses `DicomImagePiiVerifyEngine.verify_dicom_instance()` to overlay
boxes for visual eval. Ground truth from
`sample_data/ground_truth.json`. Notebook itself does NOT show
explicit precision/recall computation in the snippet inspected —
references the "evaluating DICOM de-identification" docs page for
metric calculations.

#### `image_redaction_allow_list_approach.ipynb`

Demonstrates `allow_list` kwarg passed to `ImageRedactorEngine.redact()`
/ `DicomImageRedactorEngine.redact()`. Important caveat: "Always place
the `allow_list` argument last in your redact call as this is
considered a text analyzer kwarg."

Box-overlay parameters: `padding_width=3`, `fill="background"`
(blends with surrounding pixels). Workaround for "redact ALL text"
is a custom recognizer matching everything + `allow_list` for
exceptions.

#### `plot_custom_bboxes.ipynb`

Uses `ImagePiiVerifyEngine` and `DicomImagePiiVerifyEngine` to plot
user-supplied bounding boxes. PIL for image loading, matplotlib for
plotting, pydicom for DICOM. No OpenCV. Purpose: verify externally-
produced boxes against the image.

#### `example_pdf_annotation.ipynb`

Uses `pdfminer.six` (`extract_pages`, `LTTextContainer`, `LTChar`,
`LTTextLine`) for text + char-level bounding boxes, plus `pikepdf`
(`Pdf`, `Dictionary`, `Array`, `Name`, `AttachedFileSpec`) for
annotation objects. NOT PyMuPDF, NOT pdfplumber.

Builds **PDF highlight annotations** (not redactions): translucent
red overlay (`C=[1,0,0]`, `CA=0.5`) with `Subtype=Name.Highlight`
and proper four-point `QuadPoints`. Entity type stored in the `T`
(title) field for hover-display.

Custom `combine_rect(rectA, rectB)` merges char boxes into phrase
boxes. Notebook calls out limitations: no OCR for image text, no
extraction from PDF annotations themselves, hidden text from
incremental edits, ordering issues.

### Group F: Starter / utility

#### `presidio_notebook.ipynb`

Basic getting-started: install, analyze, custom `PatternRecognizer`
for `TITLE` (deny list) and `PRONOUN` (he/she/his), then anonymize
with **mixed operators in one call**:

```python
{
    "PHONE_NUMBER": OperatorConfig("mask", {"masking_char": "*", "chars_to_mask": 12, "from_end": True}),
    "TITLE": OperatorConfig("redact"),
    "DEFAULT": OperatorConfig("replace"),
}
```

Notebook explicitly states "the anonymizer provides 5 types of
anonymizers - replace, redact, mask, hash and encrypt" (though
`encrypt`/`hash` aren't demonstrated here).

---

## Python scripts (.py files) — `docs/samples/python/`

### `simple_anonymization_example.py`

Smallest possible E2E:

```python
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()
analyzer_results = analyzer.analyze(text=text, language="en")
anonymizer.anonymize(
    text=text,
    analyzer_results=analyzer_results,
    operators={"DEFAULT": OperatorConfig("replace", {"new_value": "<ANONYMIZED>"})},
)
```

### `custom_presidio.py`

Pairs the deny-list pattern (`TITLE` honorifics: Sir, Ma'am, Mr, Mrs,
Dr, Professor) with a regex pattern (`Pattern("numbers_pattern",
regex=r"\d+", score=0.5)` for `NUMBER`). Shows both registry-add
and direct `recognizer.analyze(text, entities=["NUMBER"])` (no
registration needed for one-shot use).

### `example_custom_lambda_anonymizer.py`

Two side-by-side functions:

- `anonymize_reverse_lambda` — `OperatorConfig("custom", {"lambda": lambda x: x[::-1]})`
- `anonymize_faker_lambda` — `OperatorConfig("custom", {"lambda": lambda x: fake.safe_email()})`

Pulls in `Faker("en_US")` with `fake.add_provider(internet)`.
Restricted to `EMAIL_ADDRESS` entity.

### `example_remote_recognizer.py`

Reference impl for `RemoteRecognizer` subclass. Two endpoints:
`/supported_entities` (discovery, called in `load()`) and `/detect`
(per-request, called in `analyze()`). Static helpers
`_recognizer_results_from_response` and
`_supported_entities_from_response` cleanly separate transport from
domain. Catches `requests.exceptions.RequestException` in `load()`
and degrades to empty supported entities — doesn't crash analyzer
startup.

`super().__init__(supported_entities=[], name=None, supported_language="en", version="1.0")`
— base class still requires placeholders even if discovery is deferred.

### `flair_recognizer.py`

Wrapper subclassing `EntityRecognizer` (not `RemoteRecognizer`).
Multi-language model registry:

```python
MODEL_LANGUAGES = {
    "en": "flair/ner-english-large",
    "es": "flair/ner-spanish-large",
    "de": "flair/ner-german-large",
    "nl": "flair/ner-dutch-large",
}
```

`PRESIDIO_EQUIVALENCES = {"PER": "PERSON", "LOC": "LOCATION", "ORG": "ORGANIZATION"}`.
Builds `CHECK_LABEL_GROUPS` (set-of-sets tuples) for fuzzy label
matching. Bundles `AnalysisExplanation` per result. Warning: "would
download a very large (+2GB) model on the first run."

### `span_marker_recognizer.py`

Similar wrapper for SpanMarker:
`DEFAULT_MODEL = "tomaarsen/span-marker-bert-base-fewnerd-fine-super"`.
`PRESIDIO_EQUIVALENCES = {"person-other": "PERSON", "location-GPE": "LOCATION", "organization-company": "ORGANIZATION"}`.
Comment flags caveat: "Not working properly for this recognizer"
on the `entities` parameter — single-recognizer routing limitation.

### `process_csv_file.py`

`CSVAnalyzer(BatchAnalyzerEngine)` subclass with one method
`analyze_csv(csv_full_path, language, keys_to_skip)`. Transposes rows
to column-oriented dict via `{header: list(map(str, values)) for header, *values in zip(*csv_list)}`,
then delegates to inherited `analyze_dict`. Pairs with
`BatchAnonymizerEngine().anonymize_dict(...)`.

### `gliner.md` (markdown reference)

GLiNER (bidirectional transformer for arbitrary entity types).
`pip install 'presidio-analyzer[gliner]'`. Built-in `GLiNERRecognizer`:

```python
gliner_recognizer = GLiNERRecognizer(
    model_name="urchade/gliner_multi_pii-v1",
    entity_mapping={"person": "PERSON", "organization": "ORGANIZATION", ...},
    flat_ner=False,
    multi_label=True,
    map_location="cpu",
)
analyzer_engine.registry.add_recognizer(gliner_recognizer)
analyzer_engine.registry.remove_recognizer("SpacyRecognizer")  # avoid duplicate NER
```

ONNX backend support via `load_onnx_model=True` for non-AVX2 CPUs.

`urchade/gliner_multi_pii-v1` supports 20+ entity types: person,
organization, phone, address, email, credit card, SSN, DOB, bank
account, medication, driver's license, IP, IBAN, username, passport,
CVV, license plate, postal code, **blood type**.

---

## Streamlit demo — `docs/samples/python/streamlit/`

Architecture (six files):

| File | Role |
|------|------|
| `presidio_streamlit.py` | UI shell |
| `presidio_helpers.py` | Cached engine factory + analyze/anonymize wrappers |
| `presidio_nlp_engine_config.py` | Five NLP-engine factory functions |
| `flair_recognizer.py` | Bundled Flair wrapper |
| `azure_ai_language_wrapper.py` | Azure Text Analytics adapter |
| `openai_fake_data_generator.py` | OpenAI completion-based synthesizer |
| `Dockerfile` | HF Spaces deployment image |
| `requirements.txt`, `test_streamlit.py`, `demo_text.txt` | misc |

### UI features (`presidio_streamlit.py`)

- Sidebar: model selector, threshold slider (0.0-1.0, default 0.35),
  decision-process checkbox, allow/deny list via `st_tags`, operator
  selectbox (7 options: `redact`, `replace`, `synthesize`, `highlight`,
  `mask`, `hash`, `encrypt`)
- `mask` reveals `number_of_chars` (0-100, default 15) and `Mask
  character` (default `*`)
- `encrypt` reveals AES key input (hardcoded default `"WmZq4t7w!z%C&F)J"`
  — security smell)
- `synthesize` branches on `OPENAI_TYPE` env var (Azure vs OpenAI) and
  exposes base URL / deployment / API version / key
- `highlight` renders via `annotated_text(*annotated_tokens)` from
  `streamlit-annotated-text`
- Main: two-column input/output, dataframe of findings
- No file uploader — `st_text` is the only input, pre-populated from
  `demo_text.txt`
- Microsoft Clarity tracking injected via `components.html`

### Engine factory (`presidio_helpers.py`)

- `@st.cache_resource` on `nlp_engine_and_registry`, `analyzer_engine`,
  `anonymizer_engine` (heavy objects)
- `@st.cache_data` on `get_supported_entities`, `analyze`, `call_openai_api`
- Dispatch on substring of `model_family.lower()`: `spacy`, `stanza`,
  `flair`, `huggingface`, `azure ai language`
- Ad-hoc recognizers injected at analyze time via `ad_hoc_recognizers`
  kwarg — not registered globally
- `get_supported_entities` appends a synthetic `"GENERIC_PII"` to the list

### NLP engine factory (`presidio_nlp_engine_config.py`)

Five factories: spaCy, Stanza, Transformers (hybrid with `en_core_web_sm`),
Flair (paired with spaCy + registers `FlairRecognizer`), Azure AI
Language (paired with spaCy + registers `AzureAIServiceWrapper`).
Always removes default `SpacyRecognizer` when adding Flair/Azure to
avoid duplicate NER. Hardcoded score multipliers:
`low_confidence_score_multiplier=0.4` for `ID` (transformers),
similar for `ORG`/`ORGANIZATION` (spacy).

### Azure wrapper (`azure_ai_language_wrapper.py`)

`AzureAIServiceWrapper(EntityRecognizer)` bridging
`TextAnalyticsClient.recognize_pii_entities`. `TA_SUPPORTED_ENTITIES`
derived from `PiiEntityCategory` enum. Maps `entity.offset` /
`offset + len(text)` to `RecognizerResult.start` / `end`. Wraps
`AzureKeyCredential(key)` for auth.

### OpenAI generator (`openai_fake_data_generator.py`)

```python
OpenAIParams = namedtuple("open_ai_params",
    ["openai_key", "model", "api_base", "deployment_id", "api_version", "api_type"])
```

Dispatch on `api_type.lower() == "azure"`: instantiates `AzureOpenAI`
or `OpenAI`. Uses **legacy Completions API** (`client.completions.create`),
not Chat Completions. Prompt has six lettered instructions and three
few-shot examples wrapped in `[[TEXT STARTS]] / [[TEXT ENDS]]`.
Handles both `<PLACEHOLDER>` and `{placeholder}` styles.

### Dockerfile

`python:3.10-slim` + non-root `user` (UID 1000), spaCy `en_core_web_sm`
and `en_core_web_lg` installed from HuggingFace Hub wheels, port 7860
(HF Spaces convention), healthcheck on `_stcore/health`.

---

## Transformers recognizer sample — `docs/samples/python/transformers_recognizer/`

Three files: `index.md`, `configuration.py`, `transformer_recognizer.py`.

### Pattern: Recognizer vs NLP Engine

Documentation explicitly distinguishes between:

- `TransformersRecognizer` — for **parallel** multi-NER setups (alongside spaCy)
- `TransformersNlpEngine` — when transformers IS the only NER

### `configuration.py`

Two named configurations as dicts:

| Field | `BERT_DEID_CONFIGURATION` | `STANFORD_CONFIGURATION` |
|-------|---------------------------|---------------------------|
| `MODEL_PATH` | `obi/deid_roberta_i2b2` | `StanfordAIMI/stanford-deidentifier-base` |
| `DEVICE` entity | NOT supported | supported |
| `HOSPITAL` mapping | `ORGANIZATION` | `LOCATION` |
| `MEDICALRECORD`/`IDNUM`/`ZIP` | mapped to `"O"` (ignored) | mapped to `"ID"`/`"ZIP"` |
| Shared | `CHUNK_OVERLAP_SIZE=40`, `CHUNK_SIZE=600`, `ID_SCORE_MULTIPLIER=0.4` | same |

Two mapping layers per config: `DATASET_TO_PRESIDIO_MAPPING` (annotation
labels → Presidio entities) and `MODEL_TO_PRESIDIO_MAPPING` (model output
tags → Presidio entities).

### `transformer_recognizer.py`

`TransformersRecognizer(EntityRecognizer)`. Init is lazy: real config
loaded via `load_transformer(**BERT_DEID_CONFIGURATION)`. Builds
`pipeline("ner", model=AutoModelForTokenClassification, tokenizer=AutoTokenizer)`.
GPU auto-detect (`device=0` vs `-1`). Long-text chunking via
`split_text_to_word_chunks(start, end)` static method with auto-correct
when overlap >= chunk length. Per-chunk inference offsets shifted by
`chunk_start` back to original coordinates, dedup via set of
dict-item tuples.

ID score reduction: if `entity == id_entity_name`, score multiplied by
`id_score_reduction=0.5`. Original score preserved on
`AnalysisExplanation.original_score`.

---

## LangExtract sample — `docs/samples/python/langextract/`

Index-only — no Python files.

### Class hierarchy

```
LMRecognizer (abstract)
└── LangExtractRecognizer (abstract, model-agnostic)
    ├── AzureOpenAILangExtractRecognizer (concrete)
    └── BasicLangExtractRecognizer (concrete, YAML-driven)
```

`BasicLangExtractRecognizer` is described as supporting "Ollama, OpenAI,
Gemini, and other providers" via YAML.

### YAML configuration model

Two sections:

```yaml
lm_recognizer:
  supported_entities: [...]
  labels_to_ignore: [...]
  enable_generic_consolidation: true  # collapse unknowns to GENERIC_PII_ENTITY
  min_score: 0.5

langextract:
  model:
    model_id: gpt-4
    temperature: 0.1
  prompt_file: ./prompt.txt
  examples_file: ./examples.json
  entity_mappings: {...}
  provider:
    name: ollama
    kwargs: { model_url: ... }
    extract_params: { use_schema_constraints: true, fence_output: true, temperature: ... }
    language_model_params: { timeout: ..., num_ctx: ... }
```

### Auth patterns

- Direct: `azure_endpoint`, `api_key`, `api_version`
- Env: `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY`
- **Managed Identity**: omit `api_key`; uses `ChainedTokenCredential`
  (Environment → Workload Identity → Managed Identity). Set
  `ENV=development` to use `DefaultAzureCredential` locally. Required
  Azure role: **"Cognitive Services OpenAI User"**

Default Ollama model: `qwen2.5:1.5b`. Recognizer is disabled by default
in `default_recognizers.yaml`.

---

## AHDS sample — `docs/samples/python/ahds/`

`AzureHealthDeidRecognizer` — built-in predefined recognizer.
`pip install "presidio-analyzer[ahds]"`. Env var: `AHDS_ENDPOINT`.

Same auth pattern as LangExtract: production uses limited
credential chain (Environment, WorkloadIdentity, ManagedIdentity);
`ENV=development` switches to `DefaultAzureCredential` for local
`az login`.

### `example_ahds_surrogate.py`

Demonstrates `"surrogate_ahds"` operator (anonymizer-side, not
analyzer-side):

```python
engine.anonymize(
    text=text,
    analyzer_results=results,  # PATIENT, DOCTOR, DATE
    operators={"DEFAULT": OperatorConfig("surrogate_ahds", {
        "entities": analyzer_results,
        "input_locale": "en-US",
        "surrogate_locale": "en-US",
    })}
)
```

Generates realistic-but-fake replacements (preserves natural document
shape) via Azure Health Data Services de-id surrogate API. Locale-aware.

---

## Text Analytics (Azure AI Language) sample — `docs/samples/python/text_analytics/`

Index-only.

`pip install "presidio-analyzer[azure-ai-language]"`. Env vars:
`AZURE_AI_KEY`, `AZURE_AI_ENDPOINT`. Predefined recognizer
`AzureAILanguageRecognizer`. Three-line wire-in:

```python
azure_ai_language = AzureAILanguageRecognizer()
analyzer = AnalyzerEngine()
analyzer.registry.add_recognizer(azure_ai_language)
```

---

## Docker samples — `docs/samples/docker/`

### Postman collections

`PresidioAnalyzer.postman_collection.json` exercises five endpoints on
`http://localhost:5002`:

| Method | Path | Body / Query |
|--------|------|---------------|
| GET | `/health` | — |
| GET | `/supportedentities` | `?language=en` |
| GET | `/recognizers` | `?language=en` |
| POST | `/analyze` | `{"text": "...", "language": "en"}` |
| POST | `/analyze` | adds `"score_threshold": 0.7` |

`PresidioAnonymizer.postman_collection.json` on `http://localhost:5001`:

| Method | Path | Body |
|--------|------|------|
| GET | `/health` | — |
| GET | `/anonymizers` | — |
| POST | `/anonymize` | `text`, `anonymizers` (map of entity→OperatorConfig), `analyzer_results` (array of spans) |

Example operator config shown in body:
`PHONE_NUMBER: {"type": "mask", "masking_char": "*", "chars_to_mask": 4, "from_end": true}`.

### `litellm.md`

Architecture: App ↔ LiteLLM Proxy + Presidio PII Masking ↔ LLM provider
(Anthropic / Gemini / Bedrock / etc.).

`config.yaml`:

```yaml
model_list:
  - model_name: my-openai-model
    litellm_params:
      model: gpt-3.5-turbo
litellm_settings:
  callbacks = ["presidio"]
```

Env vars wire to Presidio: analyzer port 5002, anonymizer port 5001,
plus provider API key.

Capabilities exposed via this proxy:

1. **Input masking** — tokens like `[PERSON]`, `[PHONE_NUMBER]`
2. **Output parsing** — `output_parse_pii: true` reverses tokens in
   the LLM response (`"Hey [PERSON]"` → `"Hey Jane Doe"`)
3. **Ad-hoc recognizers** — JSON file ref via
   `presidio_ad_hoc_recognizers` (example: Swiss AHV numbers)
4. **Per-key control** — `permissions: {"pii": false}` on virtual key
5. **Per-request control** — when key has `allow_pii_controls: true`,
   client sends `extra_body={"content_safety": {"output_parse_pii": False}}`
6. **Logging-only mode** — `presidio_logging_only: true` masks only
   in logs (Langfuse etc.), passes raw to LLM

This is one of two production references in the repo (the other being
Invisio).

---

## Deployment samples

### App Service — `docs/samples/deployments/app-service/`

Three deploy paths:

1. One-click ARM "Deploy to Azure" button
2. CLI shell (`az group create` + `az appservice plan create --is-linux
   --sku $APP_SERVICE_SKU` + `az webapp create -i $IMAGE_NAME`)
3. ARM via CLI (`az deployment group create --template-file
   presidio-services.json --parameters @values.json`)

Default image: `mcr.microsoft.com/presidio-analyzer`. Private registry
support via `-s $ACR_USER_NAME -w $ACR_USER_PASSWORD`.

IP access restrictions via `az webapp config access-restriction add`.
Two ARM templates: `presidio-app-service.json` (analyzer only),
`presidio-services.json` (both services + plumbing). VNet isolation
requires Isolated tier (noted but not provided in samples).

Log Analytics: documented as preview, not auto-provisioned.

### Kubernetes — `docs/samples/deployments/k8s/`

#### Helm chart (`charts/presidio/`)

`Chart.yaml`, `values.yaml`, `templates/` (9 files).

`values.yaml` parameterizes:

| Section | Defaults |
|---------|----------|
| `registry` | `mcr.microsoft.com` |
| `privateRegistry` | (off) |
| `tag` | `latest` |
| `ingress.enabled` | `true` |
| `ingress.class` | `nginx` (traefik/istio "wip") |
| `analyzer` | replicas=1, requests=1500Mi/1500m, limits=3000Mi/2000m |
| `anonymizer` | replicas=1, requests=128Mi/125m, limits=512Mi/500m |
| `anonymizerimage` (presidio-image-redactor) | replicas=1, same as analyzer |

All three components share container/service shape: `name`, `replicas`,
`imagePullPolicy=Always`, `service.type=ClusterIP`,
`service.externalPort=80`, `service.internalPort=8080`.

Caveat documented: replicas > 1 needs Linkerd/Istio for proper traffic
balancing (refs issue #304).

Templates use `{{ $fullname := presidio.analyzer.fullname }}` helpers,
`default .Chart.AppVersion` fallback for tag, conditional
`imagePullSecrets` when `.Values.privateRegistry` set.

#### KIND deployment (`deployment/`)

Two scripts:

- `deploy-presidio.sh` — wrapper for `helm install` against current cluster
- `run-with-kind.sh` — builds KIND from source, creates cluster, creates
  `presidio` namespace, runs deploy-presidio. **Single-shot — must
  `kind delete cluster` to retry.** Explicitly "NOT intended to be
  installed in this manner for any workload."

### Data Factory — `docs/samples/deployments/data-factory/`

Three documents covering two architecturally different patterns plus
the master overview:

#### `presidio-data-factory.md` (master)

The full sample with both backends side-by-side. Provisions:

- ADF (orchestrator)
- Key Vault (SAS token / storage key storage)
- Azure Storage (data persistence)
- Either App Service OR Databricks (Presidio runtime)

**SAS token mechanism**: ARM `listAccountSas()` → import into Key Vault.
Databricks variant adds `listKeys()` for storage account access key.

**Managed Identity flow**: ADF has `identity: SystemAssigned`; access
policy uses `reference(adfResource).identity.principalId` to grant
Key Vault access at deploy time.

#### `presidio-data-factory-template-gallery-http.md`

**Scale limit**: "up to 5000 files, each up to 200KB" (ADF lookup-activity
limit + network overhead). For larger workloads use the Databricks
variant.

Eight activities: `GetMetadata`, `Filter`, `GetSASToken`, `ForEach`,
`LoadFileContent`, `PresidioAnalyze`, `PresidioAnonymize`, `UploadBlob`.

Parameters: `SourceStore_Location`, `DestinationStore_Name`,
`DestinationStore_Location` (default `presidio`), `KeyVault_Name`,
`Analyzer_Url`, `Anonymizer_Url`.

#### `presidio-data-factory-template-gallery-databricks.md`

For larger CSV datasets. Three activities:
`AnonymizeSource` (Databricks notebook job) → `MergeAnonymizedToTarget`
(combines CSV parts to single file) → `DeleteAnonymized` (cleanup).

Linked services configured by hand: `PresidioStorage` (Azure Storage),
`PresidioDatabricks` (Databricks with auth token + `presidio_cluster`
target).

Four parameters: `SourceStore_Location`, `DestinationStore_Name`,
`SourceFile_Name`, `TextColumn_Name`.

### Spark / Databricks — `docs/samples/deployments/spark/`

ARM (`databricks.json`) provisions Databricks workspace + storage
account + container in a managed resource group named
`databricks-rg-<workspace>-<uniqueString>`. Outputs `workspaceId` and
`workspaceUrl`.

#### `configure_databricks.sh`

Heavyweight bootstrap script. Generates a Databricks PAT via two-token
exchange (AAD token for Databricks resource ID
`2ff814a6-3304-4ab8-85cb-cd0e6f879c1d` + management API token →
`/api/2.0/token/create`). Pulls storage key, creates `storage_scope`
secret scope, uploads init script to `dbfs:/FileStore/dependencies/
startup.sh`, imports notebooks to `/notebooks`, creates cluster from
`cluster.config.json` injecting `STORAGE_*` env vars, mounts storage
via `runs submit`, generates a second "For CLI" PAT.

#### `cluster.config.json`

```json
{
    "cluster_name": "presidio_cluster",
    "autoscale": {"min_workers": 2, "max_workers": 5},
    "spark_version": "7.5.x-scala2.12",
    "autotermination_minutes": 30,
    "node_type_id": "Standard_DS12_v2",
    "driver_node_type_id": "Standard_DS12_v2",
    "spark_env_vars": {
        "PYSPARK_PYTHON": "/databricks/python3/bin/python3",
        "STORAGE_MOUNT_NAME": "/mnt/files",
        ...
    },
    "init_scripts": [{"dbfs": {"destination": "dbfs:/FileStore/dependencies/startup.sh"}}]
}
```

#### Notebooks

`00_setup.py` — mounts blob container at `/mnt/files` using `wasbs://`
(not ABFS) with storage account key from `storage_scope` secret. Has
idempotent `sub_unmount()` helper using `dbutils.fs.mounts()` +
`dbutils.fs.refreshMounts()`.

`01_transform_presidio.py` — **the core pattern** (also reused in
the Fabric sample):

```python
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()
broadcasted_analyzer = sc.broadcast(analyzer)
broadcasted_anonymizer = sc.broadcast(anonymizer)

def anonymize_text(text: str) -> str:
    analyzer = broadcasted_analyzer.value
    anonymizer = broadcasted_anonymizer.value
    analyzer_results = analyzer.analyze(text=text, language="en")
    return anonymizer.anonymize(
        text=text, analyzer_results=analyzer_results,
        operators={"DEFAULT": OperatorConfig("replace", {"new_value": "<ANONYMIZED>"})},
    ).text

def anonymize_series(s: pd.Series) -> pd.Series:
    return s.apply(anonymize_text)

anonymize = pandas_udf(anonymize_series, returnType=StringType())
anonymized_df = input_df.withColumn(anonymized_column, anonymize(col(anonymized_column)))
```

Widgets: `file_format` (dropdown text/csv), `storage_input_path`,
`storage_output_folder`, `anonymized_column`. Tags each row with
provenance via `input_file_name()` + `regexp_replace` to strip the
mount prefix.

**Critical pattern**: engines broadcast once on driver — avoids
re-loading heavy spaCy models per executor task. Pandas UDF uses
Arrow-vectorized execution.

### Redacting telemetry — `docs/samples/deployments/redacting-telemetry/`

Demo: client-side PII masking in OpenTelemetry **before** export.

Architecture: App → Presidio (mask) → OTel Collector → Loki/Tempo →
Grafana.

`docker-compose.yml` orchestrates seven services on a `telemetry`
bridge network:

| Service | Image | Ports |
|---------|-------|-------|
| presidio-analyzer | `mcr.microsoft.com/presidio-analyzer:latest` | 5002:3000 |
| presidio-anonymizer | `mcr.microsoft.com/presidio-anonymizer:latest` | 5001:3000 |
| pii-demo-app | local build | 8000 |
| otel-collector | `otel/opentelemetry-collector-contrib:0.97.0` | 4317, 4318, 8888, 8889 |
| loki | `grafana/loki:2.9.3` | 3100 |
| tempo | `grafana/tempo:2.3.1` | 3200, 4317 |
| grafana | `grafana/grafana:10.2.3` | 3000 (anonymous Admin) |

`otel-collector-config.yaml`:
- Receivers: OTLP gRPC `:4317`, HTTP `:4318`
- Processors: `batch (10s)`, `attributes` (inserts `service_name` from
  `service.name` then promotes to Loki label via `loki.attribute.labels`)
- Exporters: `loki` (`http://loki:3100/loki/api/v1/push`), `otlp`
  (`tempo:4317`, `tls.insecure: true`), `logging` (debug)
- Traces pipeline: otlp → batch → otlp+logging
- Logs pipeline: otlp → attributes → batch → loki+logging

#### `app/main.py`

FastAPI app generating PII logs. Sets up dual pipelines:

```python
resource = Resource(attributes={SERVICE_NAME: "pii-demo-app",
                                "service.namespace": "pii-demo"})
trace.set_tracer_provider(TracerProvider(resource=resource))
otlp_span_exporter = OTLPSpanExporter(endpoint=otel_endpoint, insecure=True)
span_processor = BatchSpanProcessor(otlp_span_exporter)
trace.get_tracer_provider().add_span_processor(span_processor)
```

Same parallel pipeline for `LoggerProvider` + `BatchLogRecordProcessor`
+ `OTLPLogExporter` + `LoggingHandler` on the stdlib `logging`.

**Defensive `mask_pii` wrapper**:

```python
def mask_pii(pii: str) -> str:
    try:
        return presidio_mask_pii(pii)
    except Exception as e:
        logger.error(f"Error masking PII: {e}")
        return "[REDACTED]"  # fail-safe fallback
```

**Span redaction pattern**: PII is masked **at `set_attribute` time**,
before the span is flushed:

```python
span.set_attribute("user.name", mask_pii(name))
```

Notable inconsistency in sample: `user-registration` span sets
`user.name` and `user.email` raw — gap in coverage. The address-
update/support-ticket/error paths only log, no spans.

#### `app/presidio_client.py`

HTTP client with `ANALYZER_URL` and `ANONYMIZER_URL` from env
(defaults to in-cluster service names on port 3000). `mask_pii()`
convenience wraps `analyze_text()` → `anonymize_text()`. All HTTP
calls use 10s timeout, `raise_for_status()`, and degrade to original
text on exception — telemetry pipeline never breaks from Presidio failure.

### "Invisio" OpenAI best practices — `docs/samples/deployments/openai-anonymaztion-and-deanonymaztion-best-practices/`

The most production-shaped sample in the repo. Architecture:

```
Textual TUI Client  →  FastAPI API  →  Redis (session state)
                                     ↘  PythonPresidioService
                                        (or HttpPresidioService /
                                         HybridPresidioService)

Client → AzureOpenAI direct (separately)
```

Deploys to: AKS + ACR + Redis Cache (Bicep), with K8s manifests.

#### Session-stable pseudonymization — the unique pattern

The whole point of the sample. Within a session:

| Stage | Text |
|---|---|
| User | `Hello world, my name is Jane Doe. My number is: 034453334` |
| → LLM | `Hello world, my name is [PERSON]. My number is: [PHONE_NUMBER]` |
| ← LLM | `Hey [PERSON], nice to meet you!` |
| → User | `Hey Jane Doe, nice to meet you!` |

The mapping `{'PERSON': {'Jane Doe': '<PERSON_0>'}}` is built on first
turn, persists in Redis under `session_id`, and is used to (a) keep
later turns referencing the same `Jane Doe` mapped to `<PERSON_0>`
and (b) reverse the LLM's response on return.

#### `InstanceCounterAnonymizer` (full source)

```python
class InstanceCounterAnonymizer(Operator):
    REPLACING_FORMAT = "<{entity_type}_{index}>"

    def operate(self, text: str, params: Dict = None) -> str:
        entity_type: str = params["entity_type"]
        entity_mapping: Dict[Dict:str] = params["entity_mapping"]
        entity_mapping_for_type = entity_mapping.get(entity_type)
        if not entity_mapping_for_type:
            new_text = self.REPLACING_FORMAT.format(
                entity_type=entity_type, index=0)
            entity_mapping[entity_type] = {}
        else:
            if text in entity_mapping_for_type:
                return entity_mapping_for_type[text]   # ← stability point
            previous_index = self._get_last_index(entity_mapping_for_type)
            new_text = self.REPLACING_FORMAT.format(
                entity_type=entity_type, index=previous_index + 1)
        entity_mapping[entity_type][text] = new_text
        return new_text

    @staticmethod
    def _get_last_index(entity_mapping_for_type: Dict) -> int:
        def get_index(value: str) -> int:
            return int(value.split("_")[-1][:-1])  # parses "<TYPE_N>"
        indices = [get_index(v) for v in entity_mapping_for_type.values()]
        return max(indices)

    def operator_name(self) -> str: return "entity_counter"
    def operator_type(self) -> OperatorType: return OperatorType.Anonymize
```

The operator is **stateless** — the caller threads the same
`entity_mapping` dict through every call. That dict is the memory.

#### `InstanceCounterDeanonymizer` (full source)

```python
class InstanceCounterDeanonymizer(Operator):
    def operate(self, text: str, params: Dict = None) -> str:
        entity_type: str = params["entity_type"]
        entity_mapping: Dict[Dict:str] = params["entity_mapping"]
        if entity_type not in entity_mapping:
            raise ValueError(...)
        if text not in entity_mapping[entity_type].values():
            raise ValueError(...)
        return self._find_key_by_value(entity_mapping[entity_type], text)

    @staticmethod
    def _find_key_by_value(entity_mapping, value):
        for key, val in entity_mapping.items():
            if val == value:
                return key
        return None

    def operator_name(self) -> str: return "entity_counter_deanonymizer"
    def operator_type(self) -> OperatorType: return OperatorType.Deanonymize
```

Pure reverse lookup over the same dict. Reversal is O(n) per token —
fine for chat-sized state, but pathological at high entity counts.

#### `main.py` (FastAPI surface)

Two endpoints:

```python
class AnonymizeRequest(BaseModel):
    text: str
    session_id: Optional[str] = None
    language: Optional[str] = "en"

class AnonymizeResponse(BaseModel):
    session_id: str
    text: str

class DeanonymizeRequest(BaseModel):
    text: str
    session_id: str

class DeanonymizeResponse(BaseModel):
    text: str
```

`POST /anonymize` and `POST /deanonymize`. Distinguishes errors:
`ValueError` (missing session) → 404; everything else → 500.
Services bootstrapped at import time (singletons): `presidio_service`,
`state_service = RedisStateService()`, `toolkit_service`.

#### `toolkit_service.py`

Coordinator. Generates `session_id` via `uuid.uuid4()` if not
provided. Loads mappings via `state_service.get_state(session_id)`,
runs `presidio_service.anonymize_text(...)`, persists via
`state_service.set_state(...)`. Raises with explicit message:
"Deanonymization is not possible because the session is not found".

#### Three swappable `PresidioService` impls

`presidio_service.py` is the abstract base. The implementations:

**`python_presidio_service.py`** (default, active in `main.py`):

- spaCy NLP engine, **three languages**: `en` (`en_core_web_lg`),
  `nl` (`nl_core_news_sm`), `es` (`es_core_news_sm`)
- `AnalyzerEngine(supported_languages=["en", "nl", "es"])`
- `AnonymizerEngine.add_anonymizer(InstanceCounterAnonymizer)`
- `DeanonymizeEngine.add_deanonymizer(InstanceCounterDeanonymizer)`
- `deanonymize_text` rebuilds positions via `text.find` loop, returning
  `OperatorResult(start, end, entity_type, entity_value, entity_id)`
- Times analyze/anonymize/total phases per session_id

**`http_presidio_service.py`**:

- Both analyzer and anonymizer remote via REST (`/analyze`, `/anonymize`)
- Pre-processes analyzer results with `add_id_to_analyzer_result()`
  which **mints stable IDs by mutating `entity_type`** to `PERSON_0`,
  `PERSON_1` etc., reusing existing IDs when the same surface form is
  seen again. Seeds `entity_type_counts` by parsing trailing indices.
- Post-processes anonymizer response with `build_entity_mappgings`
  [typo preserved] — strips `<...>` brackets, splits trailing index
  via `rsplit('_', 1)[0]`
- Deanonymization is **pure local string replace** — no HTTP. Iterates
  `entity_mappings` and `deanonymized_text.replace(entity_id, entity_value)`
- No explicit HTTP timeout/retry/auth

**`hybrid_presidio_service.py`**:

- Analyzer remote (HTTP `/analyze`, response → `RecognizerResult.from_json`)
- Anonymizer + Deanonymizer in-process (so custom operators are
  registered locally)
- Best of both: heavy NLP model lives once on remote service; custom
  Python operator stays local

The three impls form a clean perf/architecture trade-off matrix.

#### State backends

`state_service.py` is the abstract base.

`inmemory_state_service.py` — `dict[session_id → entity_mappings]`,
trivial.

`redis_state_service.py` — connects with hostname, port, password,
SSL, db=0. `json.dumps`/`json.loads` round-trip. `get_state` returns
`None` on miss; logged.

#### Bicep IaC (`infrastructure/`)

`main.bicep`:

```bicep
targetScope = 'resourceGroup'
param location string = resourceGroup().location
param aksClusterName string = 'preshack'
param aksNodeCount int = 3
param redisCacheName string = 'preshack'
param redisCapacity int = 1
param acrName string = 'preshack'

// NOTE: ACR / AKS / role-assignment modules are commented out in main
module redisModule 'modules/redis.bicep' = { ... }
```

(Default project name `preshack` — likely "presidio hackathon".)

`modules/redis.bicep`: `Microsoft.Cache/Redis@2023-08-01`, Standard C
SKU, `enableNonSslPort: false`.

`modules/aks.bicep`: `Microsoft.ContainerService/managedClusters@2023-07-01`,
`identity: SystemAssigned`, single nodepool `nodepool1` with
`Standard_DS2_v2`, outputs `principalId` (for role binding to ACR).

`modules/acr.bicep`: `Microsoft.ContainerRegistry/registries@2023-01-01-preview`,
SKU Basic, `adminUserEnabled: false`, outputs `acrId`.

`modules/roles.bicep`: wires AKS managed identity to ACR pull.

`deploy.sh`: short wrapper for `az deployment group create`.

#### K8s manifests (`deployments/`)

`api/deployment.yaml`: single replica, container
`preshack.azurecr.io/preshack-api`, port 80, `envFrom` ConfigMap
`api-config`, `REDIS_KEY` secret-ref. ConfigMap + Service alongside.

`client/`: deployment + service + **loadbalancer.yaml** (LoadBalancer
type for external client access) + ConfigMap.

`redis/`: deployment + service (single-replica Redis for local/dev,
not the Azure Cache resource — the Bicep deploys Azure Cache but the
K8s manifest is for in-cluster testing).

#### Demo client (`src/client_app/`)

`client.py` — Textual TUI app `InputApp`. Two-column UI: "Human
view" / "LLM view". CLI args: `--mode {llm|manual}` (default `llm`),
`--language en` (default).

`get_llm_response(messages)`:
```python
client = AzureOpenAI(
    api_key=os.getenv("OPENAI_API_KEY"),
    api_version=os.getenv("OPENAI_API_VERSION"),
    azure_endpoint=os.getenv("OPENAI_ENDPOINT"),
)
response = client.chat.completions.create(
    model=OPENAI_DEPLOYMENT_NAME,
    messages=messages,
    max_tokens=100,
)
```

System prompt: `"You're a friendly assistant"`. Session ID propagated
across turns so entity mappings stay consistent.

`serve.py` — `textual_serve.server.Server` running
`"python client.py --mode llm"` on configurable host/port. Env vars:
`TEXTUAL_HOST`, `TEXTUAL_PORT`, `TEXTUAL_PUBLIC_URL`. Note: the docs
mention a Streamlit chat variant under `spikes/` but the active client
is Textual-based.

---

## Fabric notebooks — `docs/samples/fabric/`

### `env_setup.md`

Pinned versions:
- `presidio-analyzer==2.2.357`
- `presidio-anonymizer==2.2.357`
- `spacy==3.8.4`

Warning: newer versions "may introduce dependency conflicts with
Fabric notebook utilities such as `mssparkutils`."

`en_core_web_md` (<300MB) installable to environment directly.
`en_core_web_lg` exceeds the size limit → must upload `.whl` to
Lakehouse and `%pip install /lakehouse/default/Files/presidio/models/
en_core_web_lg-3.8.0-py3-none-any.whl` inside the notebook.

### `artifacts/presidio_and_spark.ipynb`

Differences from the regular Spark sample:

- **Lakehouse-attached notebook** — `default_lakehouse` in metadata
- Input from `Files/presidio/fabric_sample_data.csv` (Lakehouse path)
- Same broadcast pattern as Databricks sample
  (`spark.sparkContext.broadcast()`)
- **Synthetic scaling pattern**: `array()` + `explode()` +
  `monotonically_increasing_id()` to multiply 5000 rows × N → 100,000+
  rows for perf testing
- Explicit `repartition(partitions_number)` "to show parrallel
  processing" (noted as should-be-removed for high scale)
- Per-column UDF detection so detected entities retain their source
  column
- Operators: `replace` with `""` empty string for `user_query`
  anonymization; a parallel `pii_summary` column captures
  `ENTITY_TYPE: substring` pairs
- **Delta Lake write**: `df_test.write.format("delta").mode("overwrite").
  saveAsTable(table_namne)` (typo preserved). Optional via
  `is_write_to_delta` flag. No merge, time travel, partitioning, or
  schema evolution shown.
- `display()` renders via `Synapse.DataFrame` widget

### `data/fabric_sample_data.csv`

2.5KB sample CSV for the Fabric notebook.

---

## Patterns extracted (cross-cutting)

For each pattern, the one-liner is what an octarine parallel would
need to express. Patterns marked **sample-only** exist nowhere in the
shipping `presidio-analyzer` / `presidio-anonymizer` library — they
live only in these examples.

- **Session-stable counter-based pseudonymization** (sample-only) —
  `<PERSON_0>` reused across N calls within a session, via externally-
  threaded mapping dict. Octarine would need a session-scoped vault
  (Redis/in-memory) + counter-aware operator.

- **Reversible pseudonymization** (sample-only) — round-trip via
  pre-built reverse-lookup. Symmetric pair: anonymizer fills the dict,
  deanonymizer reads it. Useful for LLM downstream protection.

- **Faker-driven synthetic replacement** — `OperatorConfig("custom",
  {"lambda": lambda x: fake.safe_email()})`. Octarine needs a
  "custom operator that can call arbitrary code" surface.

- **OpenAI as a surrogate generator** — anonymize first, then
  prompt-generate replacements. Built on `OperatorConfig("custom",
  {"lambda": call_openai})`.

- **LLM as a recognizer (LangExtract)** — abstract `LMRecognizer` →
  `LangExtractRecognizer` → `BasicLangExtractRecognizer` (multi-provider)
  + `AzureOpenAILangExtractRecognizer`. YAML-driven prompt + examples
  files. Generic-consolidation: collapse unknowns to `GENERIC_PII_ENTITY`.

- **LLM downstream protection** — anonymize before send, deanonymize
  after receive (LiteLLM proxy callback model + Invisio FastAPI model).

- **Spark UDF for distributed PII masking** — broadcast engines once,
  apply via `pandas_udf` over `pd.Series`. Pattern shared between
  Databricks and Fabric samples.

- **Delta Lake write of anonymized output** — Fabric variant.
  `df.write.format("delta").mode("overwrite").saveAsTable(...)`.

- **ETL pipeline integration via Azure Data Factory** — Presidio
  as REST endpoint OR as Databricks notebook job; SAS token via
  Key Vault; ADF managed identity grants access.

- **Async/batched PII masking** — `BatchAnalyzerEngine.analyze_iterator(
  texts, n_process=4, batch_size=2)` for spaCy multiprocessing;
  `analyze_dict()` for nested-dict input.

- **OTel pre-emission redaction** — mask PII at `set_attribute()` time
  before `BatchSpanProcessor` flushes spans; same for log records via
  `LoggingHandler`.

- **HTTP/local hybrid Presidio** — three-implementation matrix
  (`PythonPresidioService` / `HttpPresidioService` / `HybridPresidioService`)
  trading off model load location for custom-operator locality.

- **Per-column entity classification (structured)** — `presidio_structured`
  picks ONE entity per column rather than per-cell, via
  `PandasAnalysisBuilder.generate_analysis()` and `StructuredAnalysis(
  entity_mapping={...})`.

- **DICOM pixel redaction (vs metadata)** — `DicomImageRedactorEngine`
  redacts burned-in text in pixels; explicitly NOT metadata.
  `fill="contrast"` or `fill="background"`. Companion
  `DicomImagePiiVerifyEngine` for ground-truth eval.

- **PDF highlight annotation overlay** (vs redaction) — pikepdf
  `Subtype=Name.Highlight` with `QuadPoints`. Entity type stored on
  the annotation for hover. Char-level bounding boxes from pdfminer.

- **Image redaction with allow-list** — `allow_list` kwarg passed
  last (it's a text-analyzer kwarg). Tesseract OCR + Presidio +
  rectangle overlay with `padding_width`, `fill` color.

- **Multi-NER ensemble** — register multiple `EntityRecognizer`s
  (Flair + spaCy + transformers + GLiNER) in one registry. Workflow:
  always `registry.remove_recognizer("SpacyRecognizer")` when adding
  Flair/Azure/GLiNER to avoid dup NER.

- **Allow-list / deny-list anti-detection** — `allow_list` arg
  (don't flag these), `deny_list` constructor arg (flag these),
  context boost via `context=[...]`.

- **No-code YAML config** — single-file config of analyzer +
  recognizers + NLP engine via `AnalyzerEngineProvider(conf_file=...)`.
  Octarine has nothing equivalent today.

- **Ad-hoc per-call recognizers** — `analyzer.analyze(...,
  ad_hoc_recognizers=[...])` lets per-record recognizers exist without
  global registration. Used in "anonymizing known values" and the
  streamlit demo for deny/regex.

- **Remote recognizer pattern** — `RemoteRecognizer` base class with
  `load()` (capability discovery) + `analyze()` (per-request HTTP).
  Separate `_results_from_response` / `_supported_entities_from_response`
  static helpers for transport isolation.

- **Chunked long-text NER** — `TransformersRecognizer.split_text_to_word_chunks`
  with `CHUNK_SIZE=600`, `CHUNK_OVERLAP_SIZE=40`. Auto-corrects overlap
  ≥ chunk length. Predictions de-duplicated by tuple-of-items.

- **Per-entity-type score reduction** — `low_confidence_score_multiplier=0.4`
  for `ID` (transformers), similar for `ORG` (spacy); applied at NLP
  engine config layer.

- **Decision-process audit trail** — `return_decision_process=True`
  populates `result.analysis_explanation` with original pattern,
  score, `score_context_improvement`, `supportive_context_word`.

- **Encrypt/decrypt round-trip** — AES-CBC built-in operator; key
  passed via `OperatorConfig("encrypt", {"key": ...})`. Decrypt path
  available via `DeanonymizeEngine` or direct `Decrypt().operate(...)`.

- **Surrogate via AHDS** — `OperatorConfig("surrogate_ahds", {
  "entities": ..., "input_locale": ..., "surrogate_locale": ...})`
  delegates to Azure HDS for realistic locale-aware replacements.

- **Telemetry-grade resilience** — `mask_pii` wrapper that catches
  ALL exceptions and falls back to `"[REDACTED]"` so a Presidio
  outage never leaks raw PII; HTTP client uses 10s timeout +
  `raise_for_status()` + graceful degrade.

- **Multi-provider config gateway (LiteLLM)** — Presidio as a
  callback in front of Anthropic/Gemini/Bedrock/etc. Per-key
  (`permissions: {"pii": false}`) and per-request
  (`extra_body={"content_safety": {"output_parse_pii": False}}`)
  toggles. Output reverse-mapping (`output_parse_pii: true`).
  Logging-only mode for Langfuse-style observers.

- **Streamlit-style exploration UI** — file-less, pre-populated demo
  text, allow/deny via `st_tags`, threshold slider, operator switch,
  annotated-text highlight rendering for inline overlay view.

---

## Anything notable / unusual

- **Hardcoded AES key in source**: `presidio_streamlit.py` uses
  `"WmZq4t7w!z%C&F)J"` as default — same string copied across
  `encrypt_decrypt.ipynb`. Trivial decrypt for anyone reading the
  repo unless overridden.

- **Typo accepted as production behavior**: `http_presidio_service.py`
  in the Invisio sample defines and calls `build_entity_mappgings`
  consistently — refactoring would be a behavior-breaking rename.
  Same notebook code has `table_namne` and `parrallel`.

- **Pre-1.0 / hackathon naming**: Invisio sample resources default to
  `preshack` — "Presidio hackathon". Suggests this is community-
  authored not Microsoft-canonical.

- **Inconsistent span redaction coverage** in the OTel sample: payment
  span goes through `mask_pii()`; registration span sets `user.name`
  / `user.email` raw. The pattern is right but the discipline is
  not enforced.

- **Microsoft Clarity tracking** injected unconditionally via
  `components.html` in the Streamlit demo — not opt-in.

- **DICOM eval notebook is incomplete** — sets up verification engine
  but doesn't show precision/recall computation; defers to docs.

- **The "spikes/" directory** is referenced by Invisio's `index.md`
  ("experimental code including a Streamlit chat variant") but is not
  in the active source paths inspected — likely gitignored or pre-PR.

- **Three identical configuration shapes** for the three Invisio
  Presidio backends (`python`, `http`, `hybrid`) and three NER backends
  in `ner_model_configuration.ipynb` (`spacy`, `stanza`, `transformers`)
  reveal Presidio's strict adapter-pattern discipline — a clear win
  for a Rust port to match.

- **Docker default port mapping inconsistency**: Postman collections
  reference 5002/5001 externally, but the redacting-telemetry
  docker-compose maps `5002:3000` and `5001:3000` — the containers
  listen on 3000 internally. Important for K8s manifests too.

- **K8s manifests in the Invisio sample define their own Redis** —
  not pointing at the Bicep-provisioned Azure Cache. Two deployment
  paths exist: in-cluster Redis for testing, Azure Cache for
  production.

- **Spark sample is pinned to Databricks runtime 8.1 / spark 3.1.1**
  — relatively old. Fabric sample is the actively maintained Spark
  reference.

- **`gliner.md` lists `urchade/gliner_multi_pii-v1` with `blood type`**
  among detected categories — likely the only sample touching
  medical biometric attributes beyond DICOM.

- **`LMRecognizer` / `LangExtractRecognizer` shows Presidio's
  recent move** to formalize LLM-as-recognizer as a first-class
  abstraction (not just a remote recognizer). This is a recognizer
  category octarine doesn't yet model.

- **The `keep` operator and the identity `custom` operator are
  semantically equivalent** for the value-extraction use case but
  `keep` produces cleaner audit trails (`operator: 'keep'` in items)
  — useful for compliance traceability.

- **Per-row ad-hoc recognizers** in the known-values notebook are a
  pattern unique to Presidio's flexibility — most PII libraries
  require global recognizer registration. Octarine would need a
  per-call recognizer-list parameter to match.
