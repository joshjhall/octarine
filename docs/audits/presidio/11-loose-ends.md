# Presidio — Loose Ends

Final mop-up of small surfaces that earlier audits glanced at but didn't open fully.
Comprehensiveness > narrative. Items that overlap with prior audits are flagged with
"(already in NN)" instead of restated.

## Source files reviewed

- https://github.com/microsoft/presidio/blob/main/docs/api-docs/api-docs.yml
- https://github.com/microsoft/presidio/blob/main/docs/samples/docker/PresidioAnalyzer.postman_collection.json
- https://github.com/microsoft/presidio/blob/main/docs/samples/docker/PresidioAnonymizer.postman_collection.json
- https://github.com/microsoft/presidio/blob/main/presidio-analyzer/entrypoint.sh
- https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/entrypoint.sh
- https://github.com/microsoft/presidio/blob/main/presidio-image-redactor/entrypoint.sh
- https://github.com/microsoft/presidio/blob/main/presidio-analyzer/Dockerfile
- https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/Dockerfile
- https://github.com/microsoft/presidio/blob/main/presidio-image-redactor/Dockerfile
- https://github.com/microsoft/presidio/blob/main/presidio-analyzer/logging.ini
- https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/logging.ini
- https://github.com/microsoft/presidio/blob/main/presidio-image-redactor/presidio_image_redactor/image_pii_verify_engine.py
- https://github.com/microsoft/presidio/blob/main/presidio-image-redactor/presidio_image_redactor/dicom_image_pii_verify_engine.py
- https://github.com/microsoft/presidio/blob/main/presidio-cli/presidio_cli/conf/limited.yaml
- https://github.com/microsoft/presidio/blob/main/presidio-cli/presidio_cli/conf/default.yaml
- https://github.com/microsoft/presidio/blob/main/presidio-cli/.presidiocli
- https://github.com/microsoft/presidio/blob/main/docs/samples/python/streamlit/presidio_streamlit.py
- https://github.com/microsoft/presidio/blob/main/docs/samples/python/streamlit/presidio_helpers.py
- https://github.com/microsoft/presidio/blob/main/docs/samples/python/streamlit/presidio_nlp_engine_config.py
- https://github.com/microsoft/presidio/blob/main/docs/samples/python/streamlit/flair_recognizer.py
- https://github.com/microsoft/presidio/blob/main/docs/samples/python/streamlit/azure_ai_language_wrapper.py
- https://github.com/microsoft/presidio/blob/main/docs/samples/python/streamlit/openai_fake_data_generator.py
- https://github.com/microsoft/presidio/blob/main/docs/samples/python/streamlit/requirements.txt
- https://github.com/microsoft/presidio/blob/main/docs/installation.md
- https://github.com/microsoft/presidio/blob/main/docs/development.md
- https://github.com/microsoft/presidio/blob/main/docs/build_release.md
- https://github.com/microsoft/presidio/blob/main/docs/presidio_V2.md
- https://github.com/microsoft/presidio/blob/main/docs/community.md
- https://github.com/microsoft/presidio/blob/main/docs/design.md
- https://github.com/microsoft/presidio/blob/main/docs/faq.md
- https://github.com/microsoft/presidio/blob/main/docs/text_anonymization.md
- https://github.com/microsoft/presidio/blob/main/docs/ahds_integration.md
- https://github.com/microsoft/presidio/blob/main/docs/api/analyzer_python.md
- https://github.com/microsoft/presidio/blob/main/presidio-analyzer/pyproject.toml
- https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/pyproject.toml
- https://github.com/microsoft/presidio/blob/main/presidio-image-redactor/pyproject.toml
- https://github.com/microsoft/presidio/blob/main/presidio-structured/pyproject.toml
- https://github.com/microsoft/presidio/blob/main/presidio-cli/pyproject.toml
- https://github.com/microsoft/presidio/blob/main/NOTICE
- https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/app_tracer.py
- https://github.com/microsoft/presidio-research/blob/master/presidio_evaluator/experiment_tracking/__init__.py
- https://github.com/microsoft/presidio-research/blob/master/presidio_evaluator/experiment_tracking/experiment_tracker.py

## OpenAPI spec — full surface

Source: `docs/api-docs/api-docs.yml` (783 lines, OpenAPI 3.0.0, version "2.0", MIT)

### Servers (per-operation)
- Analyzer ops: `https://presidio-analyzer-prod.azurewebsites.net`
- Anonymizer ops: `https://presidio-anonymizer-prod.azurewebsites.net`

### Operations

| Method | Path | Summary |
|--------|------|---------|
| POST | `/analyze` | Analyze Text |
| GET | `/recognizers?language=en` | List recognizer class names |
| GET | `/supportedentities?language=en` | List supported entity types |
| POST | `/anonymize` | Anonymize Text |
| GET | `/anonymizers` | List built-in anonymizer ops |
| POST | `/deanonymize` | Deanonymize Text |
| GET | `/deanonymizers` | List built-in deanonymizer ops |
| GET | `/health` | Healthcheck (returns text/plain "service is up") |

### AnalyzeRequest schema (all fields)

```
text: string | string[]           # batch supported via array
language: string                  # ISO-639-1, required
correlation_id: string            # appended to headers + traces
score_threshold: number(double)
entities: EntityTypes[]
return_decision_process: boolean  # toggles AnalysisExplanation in response
ad_hoc_recognizers: PatternRecognizer[]
context: string[]                 # extra context words to boost scores
```

Notable: `text` can be a **string OR array of strings** — the response shape is
`RecognizerResult[]` for a string input and `RecognizerResult[][]` for an array
input (a `oneOf` schema with two example payloads documented).

### AnalysisExplanation schema (all fields)

```
recognizer: string
pattern_name: string
pattern: string                   # the full regex
original_score: number
score: number
textual_explanation: string
score_context_improvement: number
supportive_context_word: string
validation_result: bool|null      # e.g. checksum pass/fail
```

### PatternRecognizer schema (used for ad-hoc)

```
name, supported_language, patterns: Pattern[],
deny_list: string[], context: string[], supported_entity: string
```

`Pattern` = `{ name, regex, score }` with score guidance: "0.01 if very noisy,
0.6–1.0 if very specific" (this guidance is documented inline in the schema).

### Anonymizer operator schemas

| Operator | Required fields | Optional |
|----------|-----------------|----------|
| Replace | `type`, `new_value` | — |
| Redact | `type` | — |
| Mask | `type`, `masking_char`, `chars_to_mask` | `from_end: bool` (default false) |
| Hash | `type` | `hash_type: enum[sha256,sha512]` (default sha256) |
| Encrypt | `type`, `key` | — (key = 128/192/256-bit string) |
| Decrypt | `type`, `key` | — |

`AnonymizeRequest.anonymizers` is a `{ENTITY_TYPE_or_DEFAULT: OneOf<operator>}`
map. Default if omitted: `{ "DEFAULT": { "type": "replace", "new_value": "<ENTITY_TYPE>" } }`.

### Error responses
- `400 BadRequest` → `{ "error": "Invalid request json" }`
- `422 UnprocessableEntity` → `{ "error": "Invalid input, text can not be empty" }`

### Auth scheme
**Explicit absence.** No `securitySchemes`, no `security:` entries. The
public demo endpoints are unauthenticated. This matches the README guidance
that Presidio is intended to run behind your own auth / network boundary.

### Features visible in OpenAPI not previously catalogued

- **Batch analyze via array of strings** in a single request body (returns
  array-of-arrays). (Mentioned in audit 04 but the request-body shape
  is worth pinning: it's the same `/analyze` endpoint, just `text: []`.)
- **`correlation_id`** field gets propagated into headers/traces — useful for
  request correlation, server-side logging.
- **`trace: bool`** appears in the V2 doc example payload but not in the
  schema (likely a doc lag).
- **`context: []`** at the request level (not just per-recognizer) — globally
  boost any detection's score based on these surrounding words.

## Postman collections

Source: `docs/samples/docker/PresidioAnalyzer.postman_collection.json`,
`PresidioAnonymizer.postman_collection.json`

### Analyzer collection (port 5002)

| Name | Method | URL | Body |
|------|--------|-----|------|
| Presidio Analyzer health | GET | `/health` | — |
| Simple Text Analysis | POST | `/analyze` | `{"text": "John Smith drivers license is AC432223", "language": "en"}` |
| Text Analysis set score threshold | POST | `/analyze` | adds `"score_threshold": 0.7` |
| Analyzer get supported entities | GET | `/supportedentities?language=en` | — |
| Analyzer get recognizers | GET | `/recognizers?language=en` | — |

### Anonymizer collection (port 5001)

| Name | Method | URL | Body |
|------|--------|-----|------|
| Presidio Anonymizer health | GET | `/health` | — |
| Get Anonymizers | GET | `/anonymizers` | — |
| Simple Anonymize request | POST | `/anonymize` | Multi-entity payload: `DEFAULT=replace` + `PHONE_NUMBER=mask` with `chars_to_mask=4, from_end=true`; analyzer_results contains 4 entities including overlapping `NAME`/`FIRST_NAME`/`LAST_NAME` |

**Non-obvious shape revealed**: the anonymize payload shows **overlapping entity
spans** (NAME 24–32 + FIRST_NAME 24–28 + LAST_NAME 29–32) being passed in
together — confirms the anonymizer resolves overlaps via score (already in
audit 02).

## Docker entrypoint.sh scripts

All three packages share **identical** one-liners:

```sh
#!/bin/sh
exec poetry run gunicorn -w "$WORKERS" -b "0.0.0.0:$PORT" "app:create_app()"
```

### Env vars (sourced from corresponding Dockerfiles)

| Var | Default | Source |
|-----|---------|--------|
| `PORT` | `3000` | Dockerfile ENV (all 3 services) |
| `WORKERS` | `1` | Dockerfile ENV (all 3 services) |
| `ANALYZER_CONF_FILE` | `presidio_analyzer/conf/default_analyzer.yaml` | analyzer + image |
| `RECOGNIZER_REGISTRY_CONF_FILE` | `presidio_analyzer/conf/default_recognizers.yaml` | analyzer + image |
| `NLP_CONF_FILE` | `presidio_analyzer/conf/default.yaml` | analyzer + image |
| `PIP_NO_CACHE_DIR` | `1` | all (build-time) |
| `POETRY_VIRTUALENVS_CREATE` | `false` | all (build-time) |

### Pre-flight checks
- **Healthcheck** (in Dockerfile, not entrypoint): `curl -f http://localhost:$PORT/health` every 30s, 3s timeout, 30s start-period, 3 retries.
- **Build-time NLP model download** (analyzer + image): `poetry run python install_nlp_models.py --conf_file $NLP_CONF_FILE --analyzer_conf_file $ANALYZER_CONF_FILE` runs before the COPY of source — so models are baked into the image, not downloaded at first request.
- **Image redactor extra**: `python -m spacy download en_core_web_lg` runs **as root** during build so the non-root runtime user can read it. Also installs `tesseract-ocr`, `ffmpeg`, `libsm6`, `libxext6` apt packages and runs `tesseract -v` as a build smoke test.

### Non-root user
All three Dockerfiles create user `presidio` (uid 1001), chown `/app`, then
`USER 1001`. This is a security-hardening detail worth matching in any
octarine container image we ship.

### Python base versions per service
- Analyzer: `python:3.12-slim` (pinned by SHA256)
- Anonymizer: `python:3.14-slim` (pinned by SHA256)
- Image redactor: `python:3.13.13-slim` (pinned by SHA256)

The version drift between services is intentional (anonymizer is pure-Python,
analyzer pulls spaCy which has tighter version constraints).

## Logging configuration (logging.ini)

Source: `presidio-analyzer/logging.ini`, `presidio-anonymizer/logging.ini`
(no `logging.ini` in image-redactor).

Both files are 23 lines, identical structure:

```ini
[loggers]                   keys=root,presidio-{analyzer|anonymizer}
[handlers]                  keys=consoleHandler
[formatters]                keys=simpleFormatter

[logger_root]               level=INFO, handlers=consoleHandler
[logger_presidio-X]         level=INFO, handlers=consoleHandler,
                            qualname=presidio-{analyzer|anonymizer}, propagate=0
[handler_consoleHandler]    class=StreamHandler, level=INFO,
                            formatter=simpleFormatter, args=(sys.stdout,)
[formatter_simpleFormatter] format=%(asctime)s - %(name)s - %(levelname)s - %(message)s
```

Single stdout console handler, INFO level, simple time-name-level-message format,
no JSON logging, no file rotation. **No `decision_process` logger declared in
either ini file.**

### The decision_process logger (analyzer-only)

Source: `presidio-analyzer/presidio_analyzer/app_tracer.py`

```python
class AppTracer:
    def __init__(self, enabled: bool = True):
        self.logger = logging.getLogger("decision_process")
        self.enabled = enabled

    def trace(self, request_id: str, trace_data: str) -> None:
        if self.enabled:
            self.logger.info("[%s][%s]", request_id, trace_data)
```

Key facts:
1. Logger name is the literal string `"decision_process"` — **created via
   `getLogger()` not declared in `logging.ini`**, so it inherits the root
   logger's stdout handler.
2. Triggered by `AnalyzerEngine(app_tracer=AppTracer(enabled=True))` and per
   request via the `trace: bool` flag in `AnalyzeRequest`.
3. Output format: `INFO [request_id][trace_data]` — `request_id` is the
   `correlation_id` from the request.
4. Used to dump decision rationale (which recognizers fired, scores, context
   improvements) for accuracy debugging — an octarine-relevant feature for
   audit-grade explanation traces. Already partly noted in audit 04 ("audit
   trail"), but the implementation is dirt-simple: one logger name + a tracer
   class wired through the request pipeline.

## Image PII Verify workflow

Source: `presidio-image-redactor/presidio_image_redactor/image_pii_verify_engine.py`
(105 lines) and `dicom_image_pii_verify_engine.py` (320 lines).

### Class hierarchy
```
ImageRedactorEngine
    └── ImagePiiVerifyEngine            (verify())
              └── DicomImagePiiVerifyEngine (verify_dicom_instance(), eval_dicom_instance())
                  also inherits DicomImageRedactorEngine
```

`DicomImagePiiVerifyEngine` uses **diamond inheritance** from
`ImagePiiVerifyEngine` + `DicomImageRedactorEngine`.

### ImagePiiVerifyEngine.verify() — parameters

```python
verify(
    image: PIL.Image,
    is_greyscale: bool = False,
    display_image: bool = True,           # controls whether to render the overlay
    show_text_annotation: bool = True,    # controls whether entity-type labels appear
    ocr_kwargs: Optional[dict] = None,    # passed to ocr.perform_ocr
    ad_hoc_recognizers: List[PatternRecognizer] | None = None,
    **text_analyzer_kwargs,
) -> PIL.Image
```

Steps: duplicate image → OCR with threshold filter → analyze (with optional
ad-hoc recognizers) → compute PII bboxes via `image_analyzer_engine.get_pii_bboxes()`
→ render overlay via `add_custom_bboxes()`.

### Matplotlib overlay rendering (red for PII / blue for non-PII)

The actual color logic lives in `image_analyzer_engine.add_custom_bboxes()`
(not in `image_pii_verify_engine.py` — that file just calls it). The verify
engine itself only computes which bboxes are PII vs non-PII and passes them
down. The grey/color decision is a single bool (`use_greyscale_cmap`).

### `verify_dicom_instance()` — params + return

```python
verify_dicom_instance(
    instance: pydicom.dataset.FileDataset,
    padding_width: int = 25,
    display_image: bool = True,
    show_text_annotation: bool = True,
    use_metadata: bool = True,           # use DICOM metadata text as extra PHI signal
    ocr_kwargs: Optional[dict] = None,
    ad_hoc_recognizers: List[PatternRecognizer] | None = None,
    **text_analyzer_kwargs,
) -> Tuple[Optional[PIL.Image], list, list]   # (verify_image, ocr_bboxes, analyzer_bboxes)
```

Steps: deepcopy instance → assert `.PixelData` present (else `AttributeError("Provided DICOM instance lacks pixel data.")`) → detect grayscale (`_check_if_greyscale`) → rescale pixel array → convert to PIL ('L' for grey, 'RGB' for color) → pad → OCR → analyze with `_get_analyzer_results(use_metadata=...)` → render.

### `eval_dicom_instance()` — params + return

```python
eval_dicom_instance(
    instance, ground_truth: dict,
    padding_width: int = 25,
    tolerance: int = 50,                 # pixel-distance tolerance for matching
    display_image: bool = False,
    use_metadata: bool = True,
    ocr_kwargs=None, ad_hoc_recognizers=None,
    **text_analyzer_kwargs,
) -> Tuple[Optional[PIL.Image], dict]
```

Return dict shape:
```python
{
    "all_positives": [...],   # detected PHI labeled with text via OCR/GT match
    "ground_truth": {...},    # echoed back
    "precision": float,
    "recall": float,
}
```

Internals:
- `_remove_duplicate_entities()` — keeps highest-score bbox when multiple
  detections overlap within `dup_pix_tolerance=5` pixels on all four dims.
- `_label_all_positives()` — maps each detection back to PHI text via
  `bbox_processor.match_with_source(gt)` then falls back to OCR text.
- `calculate_precision/recall` — `len(TP) / len(all_pos)` and `len(TP) / len(GT)`,
  both with `ZeroDivisionError → 0`. Static methods on the engine.

### Ground-truth JSON schema for evaluation

The code never declares the GT schema in this file. From the usage:
- `ground_truth` is a `List[dict]`, where each dict has `left`, `top`, `width`,
  `height` (the bbox dims used in `_remove_duplicate_entities`) plus
  presumably a text/label field (passed to `bbox_processor.match_with_source`).
- TP detection is `[i for i in all_pos if i in gt]` — exact dict equality
  after the OCR/GT label-mapping step. This is a fragile equality check
  (any field mismatch breaks it).

This is the simplest possible evaluation harness — useful to note but
not a high bar to match.

## presidio-cli/conf/limited.yaml

Source: `presidio-cli/presidio_cli/conf/limited.yaml`
(default is `presidio-cli/presidio_cli/conf/default.yaml`)

### Default config (default.yaml — 4 lines)
```yaml
language: en
ignore: |
  .git
```

### Limited config (limited.yaml)
Documents all the **optional** CLI config keys with comments:
```yaml
language: en                 # optional, default en
ignore: |                    # optional list of ignored files/folders
  .git
  *.cfg
entities:                    # optional limit on entity types
  - PERSON
  - CREDIT_CARD
  - EMAIL_ADDRESS
threshold: 0.8               # optional score floor for reported findings
locale: en_US.UTF-8          # optional locale
# extends: custom.yaml       # commented — config file inheritance
```

### Repo-root `.presidiocli`
The repository ships a `.presidiocli` at the CLI package root which is a
"realistic example" config (different from limited.yaml):

```yaml
language: en
entities:
  - CREDIT_CARD
  - CRYPTO
  - DATE_TIME
  - EMAIL_ADDRESS
  - IBAN_CODE
  - IP_ADDRESS
  - NRP
  - LOCATION
  - PERSON
  - PHONE_NUMBER
  - MEDICAL_LICENSE
ignore: |
  .git
  .pytest_cache
  .vscode
```

### What's "limited" for
**Not** a reduced-feature preset for low-resource deployment. It's a **template
config showing every available option** — `default.yaml` is the empty-fallback
("just enough to run"), `limited.yaml` is the "here's what you can set"
documentation file, and `.presidiocli` is the in-repo example actually used
to lint Presidio itself. The `extends:` key (commented in limited.yaml) is
worth noting — config file inheritance is a small feature octarine's CLI
doesn't have.

## docs/samples/python/streamlit/ — full feature set exposed

Files (in addition to the .py files reviewed): `Dockerfile`, `demo_text.txt`,
`index.md`, `requirements.txt`, `test_streamlit.py`.

### Streamlit UI controls exposed (from `presidio_streamlit.py`)

| Control | Options |
|---------|---------|
| NER model package | `spaCy/en_core_web_lg`, `flair/ner-english-large`, `HuggingFace/obi/deid_roberta_i2b2`, `HuggingFace/StanfordAIMI/stanford-deidentifier-base`, `stanza/en`, `Azure AI Language`, `Other` (gated by `ALLOW_OTHER_MODELS` env var) |
| Custom NER model | text input for arbitrary spaCy/stanza/Flair/HuggingFace model name |
| Azure AI Language | endpoint + key inputs (or via `TA_KEY` / `TA_ENDPOINT` env vars) |
| De-identification operator | `redact`, `replace`, `synthesize`, `highlight`, `mask`, `hash`, `encrypt` |
| Operator-specific knobs | mask: `number_of_chars` (0–100) + `mask_char` (1 char); encrypt: AES key text input |
| OpenAI synthesis | openai/azure-openai switch, deployment id, API version, model name (default `text-davinci-003`), key from `OPENAI_KEY` / `AZURE_OPENAI_KEY` env |
| Acceptance threshold | slider 0.0–1.0 (default 0.35) |
| Add analysis explanations | checkbox → toggles `return_decision_process=True` |
| Allowlist + denylist | tag inputs — denylist becomes an ad-hoc `PatternRecognizer(supported_entity="GENERIC_PII", deny_list=...)` |
| Entities to look for | multiselect populated dynamically from analyzer's `get_supported_entities()` + `GENERIC_PII` |

### Operator handling notes (from `presidio_helpers.py:anonymize()`)

- **`highlight`** is implemented as `operator="custom", lambda x: x` (identity
  function) — so the anonymizer returns the entities unchanged, then the UI
  renders them via `annotated_text`.
- **`synthesize`** rewrites operator to `"replace"` first, then sends the
  redacted output to an OpenAI completions prompt that asks for realistic
  fake replacements ("Use completely random numbers...realistic names from
  diverse genders, ethnicities and countries").
- Default OpenAI model is `text-davinci-003` (legacy completions endpoint,
  not chat) — the demo is outdated on this point.

### NLP engine config builders (`presidio_nlp_engine_config.py`)

Five factories: `create_nlp_engine_with_spacy`, `create_nlp_engine_with_stanza`,
`create_nlp_engine_with_transformers`, `create_nlp_engine_with_flair`,
`create_nlp_engine_with_azure_ai_language`.

Notable mapping configs:

- Transformers config includes a 19-entity mapping covering medical (`PATIENT`,
  `STAFF`, `HOSP`, `HCW`, `HOSPITAL`, `FACILITY`, `PATORG`) — the
  StanfordAIMI/obi deid models' label space. `low_confidence_score_multiplier:
  0.4` for `ID` entity. `labels_to_ignore: CARDINAL, EVENT, LANGUAGE, LAW,
  MONEY, ORDINAL, PERCENT, PRODUCT, QUANTITY, WORK_OF_ART`.
- spaCy config: `low_confidence_score_multiplier: 0.4` for `ORG`/`ORGANIZATION`
  — "trust spaCy on PERSON but discount org" pattern.
- Azure AI Language: `TA_SUPPORTED_ENTITIES = [r.value for r in PiiEntityCategory]`
  — the recognizer pulls the entity list from the Azure SDK enum at import time
  (so adding new Azure entity types requires no code change in Presidio).
- Flair: hardcoded mapping `PER→PERSON, LOC→LOCATION, ORG→ORGANIZATION`,
  `MISC` deliberately commented out as "probably not PII".

### Streamlit demo extras
- `st.cache_resource` / `st.cache_data` decorators on engine factories — pattern
  for caching expensive NLP-engine init across reruns.
- `components.html(...)` at the bottom injects a Microsoft Clarity analytics
  tag (`clarity.ms/tag/h7f8bp42n8`) into the demo. Worth noting if any
  octarine demo were to claim "pure local" — Presidio's hosted demo phones
  home for usage analytics.
- requirements.txt pins `torch>=2.8.0`, `flair>=0.15.0`, `streamlit>=1.37.0`.

## sub-page docs that may not be in mkdocs nav

### `docs/installation.md` (174 lines)
- Supported Python: 3.10, 3.11, 3.12, 3.13.
- Installation tabs (pip): spaCy (default), Transformers, Stanza.
  - Transformers path: `pip install "presidio_analyzer[transformers]"` +
    a small spaCy model (`en_core_web_sm`) is still needed for non-NER NLP
    artifacts. (Already in audit 05.)
- **GPU acceleration**: linux NVIDIA via `pip install "spacy[cuda12x]"`, Apple
  Silicon MPS is auto-detected. Links to a separate GPU usage doc.
- Docker pulls from `mcr.microsoft.com/presidio-{analyzer,anonymizer,image-redactor}`
  on port 3000 (container) → 500{2,1,3} (host) — confirms the port mapping
  convention used by the docker docs and entrypoint defaults.
- "Install from source" path: `docker-compose up --build` from repo root.

### `docs/development.md` (235 lines)
- **Test naming convention**: `test_when_[condition_to_test]_then_[expected_behavior]`.
- "Treat tests as production code", "one behavior per test", prefer mocks in
  unit tests, less in integration tests.
- E2E test markers: `@pytest.mark.integration` (cross-service), `@pytest.mark.api`
  (single-service API layer).
- Linting: ruff + ruff-format via pre-commit; uses `pep8-naming` and
  `flake8-docstrings` ruff rules.
- `poetry install --all-extras` is the canonical dev-bootstrap command.
- Two-maintainer approval requirement on PRs (governance signal — relevant
  for "compare to Presidio review process" claims).

### `docs/build_release.md` (75 lines)
- CI runs on **Azure DevOps YAML pipelines** + GitHub Actions for releases.
- Azure DevOps pipelines: PR Validation, CI (deploys to internal dev env),
  Release (manually triggered, releases to PyPI + MCR + Docker Hub + GitHub +
  updates the public demo).
- **PyPI publishing via OIDC trusted publishing** (`pypa/gh-action-pypi-publish@release/v1`,
  `id-token: write`) — no PyPI tokens stored. Azure DevOps pipeline still
  uses traditional token auth.
- CI/release env vars: `ACR_AZURE_SUBSCRIPTION`, `ACR_REGISTRY_NAME`,
  `*_DEV_APP_NAME`, `*_PROD_APP_NAME`, `*_AZURE_SUBSCRIPTION`,
  `*_RESOURCE_GROUP_NAME`. Public dev hostnames documented per service.

### `docs/presidio_V2.md` (191 lines) — the V1→V2 reset story
- **March 2021** reset.
- Key changes: gRPC → HTTP; pip-installable Python anonymizer (was Go-based
  in V1); Image Redactor renamed from "presidio-image-anonymizer" + rewritten
  in Python; **FPE replaced with AES** (so V2 encryption is non-format-preserving,
  format-preserving encryption is no longer a Presidio feature).
- Other V1 services "deprecated, may be migrated over time with community
  help" — confirms V1 had additional services (scheduler, datasink, etc.)
  that V2 doesn't.
- V1 branch still exists: `https://github.com/microsoft/presidio/tree/V1`.
- API surface comparison tables: legacy template-driven payload (with
  `AnalyzeTemplate`, `default_transformation`, `field_type_transformations`)
  → flat snake_case JSON.

### `docs/community.md` (29 lines) — Presidio ecosystem
Already partially in audit 08. Full list of integrations: HashiCorp Vault
Operator (`sahajsoft/presidio-vault`), Rasa, LangChain, LlamaIndex, LiteLLM,
Guardrails-ai, LLMGuard, Privy, Huggingface, KNIME, OpenMetadata, dataiku,
Obsei, data-describe, Azure Search Power Skills, DataOps for Modern Data
Warehouse, "Extending Power BI with Python and R", HebSafeHarbor (Hebrew
clinical notes), Presidio GitHub Action. **18 integrations total** — useful
to size the "ecosystem gap" for an octarine adoption story.

### `docs/design.md` (19 lines)
Pure image references. Five high-level diagrams: analyzer-design.png,
anonymizer-design.png, image-redactor-design.png, dicom-image-redactor-design.png.
No textual content — diagrams are the doc.

### `docs/faq.md` (148 lines)
Organized as ToC + Q&A. Notable claims:
- Presidio (Latin "praesidium": protection/garrison).
- Mentions Azure Health Data Services and Amazon Comprehend as comparable
  managed services. Positioning vs Azure: "Presidio is OSS + on-prem
  capable; Azure AI Language is a managed service".
- Covers pseudonymization, structured/tabular data, false-positive/negative
  handling, deployment options, contribution + vulnerability reporting.

### `docs/text_anonymization.md` (16 lines)
One-paragraph "analyzer + anonymizer pipeline" overview with a flow image.
Minimal — basically a forwarder to the analyzer/anonymizer module docs.

### `docs/ahds_integration.md` (190 lines)
Azure Health Data Services de-identification service integration. Two
components:
- **AHDS Recognizer** (in `presidio-analyzer[ahds]`) — detects PHI via the
  Azure de-identification service.
- **AHDS Surrogate Operator** (in `presidio-anonymizer[ahds]`) —
  `OperatorConfig("surrogate", {"entities": ..., "input_locale": "en-US",
  "surrogate_locale": "en-US"})` — generates **realistic, medically-plausible
  replacements** (e.g. "John Doe" → "Michael Johnson") while preserving
  document structure and entity cross-references.
- Auth: production mode uses a restricted credential chain
  (EnvironmentCredential + WorkloadIdentityCredential + ManagedIdentityCredential
  only); `ENV=development` env var widens to `DefaultAzureCredential`
  (AZ CLI / interactive / etc.). `AHDS_ENDPOINT` env var.
- Locales: `input_locale` + `surrogate_locale` params — surrogation is
  locale-aware.

This is a more sophisticated form of replacement than octarine's current
`Redact`/`Replace` operators — "consistent cross-references" (same entity
gets same surrogate throughout a document) is the killer feature for
preserving downstream analytics utility.

### Other docs not previously referenced
- `docs/api/{analyzer,anonymizer,image_redactor,structured}_python.md` —
  **mkdocstrings-driven** auto-generated Python API reference pages. Each
  file is a thin shell listing classes with `::: module.Class\n    handler: python`
  directives. mkdocs renders the docstrings of the listed classes inline.
  Confirms Presidio's "rendered API reference" is **not hand-maintained** —
  it's all auto-generated from docstrings via mkdocstrings.
- `docs/learn_presidio/{index,concepts}.md` — onboarding.
- `docs/recipes/` — community recipes (CONTRIBUTING.md, german-language-support,
  template.md). The "recipes" pattern is a single-folder approach to
  community-contributed how-tos.
- `docs/getting_started/`, `docs/tutorial/`, `docs/analyzer/`, `docs/anonymizer/`,
  `docs/image-redactor/`, `docs/structured/`, `docs/evaluation/` — already
  covered in audits 01–07.

## pyproject.toml `[project.optional-dependencies]` — complete enumeration

### presidio-analyzer (v2.2.362)

Base required deps: `spacy>=3.4.4,!=3.7.0`, `regex`, `tldextract`, `pyyaml`,
`phonenumbers`, `pydantic>=2.12.5`.

Extras groups:

| Extra | Members |
|-------|---------|
| `server` | flask, gunicorn (non-Windows), waitress (Windows) |
| `transformers` | transformers, accelerate, huggingface_hub, spacy_huggingface_pipelines |
| `stanza` | stanza |
| `azure-ai-language` | azure-ai-textanalytics, azure-core |
| `ahds` | azure-identity, azure-health-deidentification (1.1.0b1 — **beta dep**) |
| `gliner` | transformers, huggingface_hub, gliner, onnxruntime (version-pinned per Python version: <1.24.1 on 3.10, unbounded on 3.11+) |
| `langextract` | langextract, openai, azure-identity, more-itertools, jinja2 |

**Pinned beta**: `azure-health-deidentification (>=1.1.0b1,<2.0.0)` — Presidio
ships against a Microsoft-published preview SDK. The recognizer file checks
for this and skips gracefully if unavailable.

**`ner` group does not exist** — the audit prompt asked about it but the
actual extras are the seven above.

### presidio-anonymizer (v2.2.362)

Base required dep: `cryptography>=46.0.4` (only!).

| Extra | Members |
|-------|---------|
| `server` | flask, gunicorn (non-Windows), waitress (Windows) |
| `ahds` | azure-identity, azure-health-deidentification (1.1.0b1) |

### presidio-image-redactor (v0.0.58)

Base required deps (8 of them — not optional): pillow, pytesseract,
presidio-analyzer, matplotlib, pydicom, pypng, azure-ai-formrecognizer,
opencv-python, python-gdcm, spaCy (Py3.13-conditional).

| Extra | Members |
|-------|---------|
| `server` | flask, gunicorn (no Windows split — image redactor isn't supported on Windows) |

Notable: **`azure-ai-formrecognizer`** (Azure's document OCR/forms service)
is a **required** dep, not optional — meaning every image-redactor install
pulls the Azure SDK. This is the "Azure Document Intelligence" recognizer
machinery (already in audit 03).

### presidio-structured (v0.0.6)

Base required deps: `presidio-analyzer`, `presidio-anonymizer`, `pandas>=1.5.2`.
**No `[project.optional-dependencies]` declared** — single install path.

### presidio-cli (v0.0.9)

Base required deps: `presidio-analyzer`, `pyyaml`, `pathspec>=0.9.0`.
**No `[project.optional-dependencies]` declared**.
Entry point: `presidio = presidio_cli.cli:run` (the `presidio` CLI command).
Python upper bound `<3.14` (other packages allow `<4.0` or `<3.14` —
inconsistent across packages).

### Who-plugs-in-what — one-line summary

| Capability | Package + extra |
|------------|-----------------|
| HTTP server | `*-analyzer[server]`, `*-anonymizer[server]`, `*-image-redactor[server]` |
| HuggingFace transformer NER | `presidio-analyzer[transformers]` |
| Stanza NLP | `presidio-analyzer[stanza]` |
| Azure Text Analytics PII | `presidio-analyzer[azure-ai-language]` |
| AHDS PHI detection + surrogation | `presidio-analyzer[ahds]` + `presidio-anonymizer[ahds]` |
| GLiNER (generalist NER) | `presidio-analyzer[gliner]` |
| LangExtract (LLM-based extraction) | `presidio-analyzer[langextract]` |
| Structured/tabular | `presidio-structured` (no extras) |
| CLI | `presidio-cli` (installs `presidio` command, no extras) |

## NOTICE / LICENSE caveats

Source: `NOTICE` (top-level "THIRD-PARTY SOFTWARE NOTICES AND INFORMATION").

### Attributed libraries (20 sections, with one obvious typo)
1. `azuure-ai-formrecognizer` (sic — typo, should be `azure-`) MIT
2. `opencv-python` MIT
3. `transformers` (Hugging Face) Apache 2.0
4. `stanza` Apache 2.0
5. `spacy-huggingface-pipelines`
6. `azure-ai-formrecognizer` (the same library, attributed twice — once
   with typo, once correctly)
7. `opencv-python` (also attributed twice)
8. `spaCy`
9. `tldextract` BSD-style
10. `regex` (Matt Friedl's regex module — Python license, derived from CPython 2.6/3.1)
11. `numpy`
12. `pyyaml`
13. `cryptography`
14. `pillow`
15. `pytesseract`
16. `pydicom` ("a pure-python DICOM library")
17. `pypng`
18. `python-gdcm`
19. `gunicorn`
20. (and others below — file is ~thousands of lines)

### Unusual license boundaries / caveats

- **Double-attribution typos**: `azuure-ai-formrecognizer` and
  `opencv-python` each appear twice (once with the typo). Suggests this file
  is partially auto-generated and partially hand-maintained.
- **regex license**: derived from CPython 2.6/3.1's `re` module — falls under
  CNRI's Python 1.6 license + the regex author's own terms. The unusual
  CNRI/Python-1.6 boundary is real but well-tested in the OSS world.
- **python-gdcm** (Grassroots DICOM) is BSD with a Mathieu Malaterre copyright —
  a less common dep that's pulled in only for DICOM medical imaging support.
- **Apache 2.0 deps** (transformers, stanza) require attribution but no
  license change for the Presidio-side MIT redistribution. No GPL/LGPL/AGPL
  deps were found — Presidio is fully permissive-compatible.

### LICENSE — Presidio itself
Top-level `LICENSE` is MIT (Microsoft copyright). Each pyproject.toml
declares `license = "MIT"` with the matching classifier. No CLA mentioned
in the repo metadata, but `docs/development.md` references one indirectly
("contribute via PR + two maintainer approvals").

## Anything else that was glanced at but not opened

### `api-docs.html` rendered output
Not a separate hand-maintained file — `docs/api-docs/` contains the YAML
spec and a thin Redoc/Swagger-UI HTML wrapper that renders the YAML at
build time. No additional API surface beyond what's in the YAML.

### TextAnalyticsRecognizer
The streamlit demo's `AzureAIServiceWrapper`
(`docs/samples/python/streamlit/azure_ai_language_wrapper.py`) **is** the
TextAnalytics recognizer — there's no separate `TextAnalyticsRecognizer`
class in the main analyzer package. It's a sample/demo wrapper around
`azure.ai.textanalytics.TextAnalyticsClient.recognize_pii_entities()`, with
`TA_SUPPORTED_ENTITIES = [r.value for r in PiiEntityCategory]` pulled from
the Azure SDK enum. Production users wire it in as an ad-hoc `EntityRecognizer`
via `RecognizerRegistry.add_recognizer()`.

The official Azure-AI-Language **NlpEngine** integration (the `[azure-ai-language]`
extra in `presidio-analyzer/pyproject.toml`) is a different code path —
that one is a full NLP engine, not just a recognizer.

### Internal mkdocstrings-driven API reference pages
Confirmed: `docs/api/{analyzer,anonymizer,image_redactor,structured}_python.md`
are mkdocstrings shells (one `:::` directive per public class, `handler:
python`). The "real" API docs are the docstrings on the classes themselves,
rendered by mkdocs.

### `presidio_evaluator.experiment_tracking.__init__`

Source: `presidio-research/presidio_evaluator/experiment_tracking/__init__.py`
(23 lines).

```python
from .experiment_tracker import ExperimentTracker
try:
    from comet_ml import Experiment
except ImportError:
    Experiment = None

def get_experiment_tracker():
    framework = os.environ.get("tracking_framework", None)
    if not framework or not Experiment:
        return ExperimentTracker()
    elif framework == "comet":
        return Experiment(api_key=..., project_name=..., workspace=...)
```

Key facts:
- Selected by lowercase env var `tracking_framework`. Currently only `"comet"`
  is recognized; anything else falls back to the local tracker.
- Local `ExperimentTracker` (in `experiment_tracker.py`) writes a single
  `experiment_{YYYYMMDD-HHMMSS}.json` to `os.getcwd()` on `.end()`. Supports
  `log_parameter(s)`, `log_metric(s)`, `log_dataset_hash` (no-op),
  `log_dataset_info`, `log_confusion_matrix(matrix, labels)`.
- **Soft Comet dependency**: `comet_ml` import is wrapped in `try/except`,
  Comet env vars (`API_KEY`, `PROJECT_NAME`, `WORKSPACE`) — all uppercase,
  no `COMET_` prefix.

## Anything notable / unusual

1. **Single-line entrypoints** across all three Docker services. The entire
   "production startup" logic is one gunicorn invocation. Anything more
   elaborate would be a regression.

2. **Build-time NLP model bake-in**. The analyzer + image Dockerfiles run
   `install_nlp_models.py` during build so model downloads don't happen at
   first request. Octarine's offline-friendly story should match this —
   downloads happen at build time, runtime is sealed.

3. **The OpenAPI spec documents the public Azure-hosted demo** as the
   `servers` URL for every operation. Anyone using the spec as-is hits
   Microsoft's prod demo by default. There's no production-server template
   variable.

4. **No auth declared in OpenAPI**. Combined with the public demo URLs,
   this is a deliberate "Presidio is a library/server, you bring the auth
   layer" stance. Documenting it as an explicit non-feature (vs leaving the
   field empty) would be friendlier to OWASP-conscious adopters.

5. **decision_process logger** is wired via `logging.getLogger("decision_process")`
   in `app_tracer.py` but **never declared in `logging.ini`** — it inherits
   the root logger. Anyone wanting separate decision-trace handling has to
   configure it externally. Octarine's observe layer already does this
   substantially better (per-event types, structured fields).

6. **The "limited.yaml" misnomer**. Reads like a feature subset preset but
   is actually a "fully documented example config". The `extends: custom.yaml`
   commented-out line is a real CLI feature (config inheritance) that
   audit 08 did not flag.

7. **Image PII verify engine emits no overlay colors itself** — it just
   computes PII vs non-PII bboxes and passes them to `add_custom_bboxes()`
   on the analyzer engine, which is where the matplotlib red/blue choice
   lives. The "verify engine" is a thin coordinator, not a renderer.

8. **DICOM eval is dict-equality based**. `tp = [i for i in all_pos if i
   in gt]` — any field-shape drift between ground truth and detected
   silently zeroes precision/recall. Brittle but fine for the academic
   evaluation use case it's designed for.

9. **Inconsistent Python upper bounds** across pyproject.toml files:
   - analyzer: `<3.14`
   - anonymizer: `<4.0`
   - image-redactor: `<3.14`
   - structured: `<4.0`
   - cli: `<3.14`

   The `<4.0` ones will silently break when 3.14 cuts new APIs that pin
   spaCy/cryptography upper bounds — likely a maintenance lag.

10. **Pinned beta dep on AHDS** (`azure-health-deidentification (>=1.1.0b1,<2.0.0)`).
    Microsoft preview SDKs occasionally break; the recognizer guards by
    skipping if the import fails, but octarine should note that this
    integration is intentionally beta-shaped.

11. **Microsoft Clarity tracking** in the public Streamlit demo
    (`clarity.ms/tag/h7f8bp42n8`). Worth flagging that "use the public
    demo" is not a privacy-preserving recommendation despite Presidio being
    a privacy tool.

12. **GLiNER and LangExtract** are recent additions (visible via the
    `[gliner]` and `[langextract]` extras) — these are general-purpose
    NER models (GLiNER) and LLM-based structured extraction (LangExtract,
    from Google). They show Presidio is actively pulling in newer NER
    approaches as optional extras. Octarine's roadmap should consider
    similar pluggable-backend pattern.

13. **Surrogation as a distinct operator concept** (in `[ahds]`). Different
    from replace/redact/mask/hash/encrypt: surrogation produces
    *realistic-looking* substitutes with cross-document consistency
    ("John Doe" maps to the same fake name everywhere). This is the most
    important operator-category gap between Presidio and octarine that
    emerged from this pass. Audit 02 covered the basic operators but
    didn't pin the AHDS surrogate operator as a separate operator
    archetype.
