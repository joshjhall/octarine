# Presidio — Deployment, APIs, Integrations

## Source files reviewed

- Top-level repo + manifest files:
  - `https://github.com/microsoft/presidio` (root listing via `gh api`)
  - `https://raw.githubusercontent.com/microsoft/presidio/main/README.MD`
  - `https://raw.githubusercontent.com/microsoft/presidio/main/CHANGELOG.md`
  - `https://raw.githubusercontent.com/microsoft/presidio/main/docker-compose.yml`
  - `https://raw.githubusercontent.com/microsoft/presidio/main/docker-compose-transformers.yml`
- REST app files:
  - `https://raw.githubusercontent.com/microsoft/presidio/main/presidio-analyzer/app.py`
  - `https://raw.githubusercontent.com/microsoft/presidio/main/presidio-anonymizer/app.py`
  - `https://raw.githubusercontent.com/microsoft/presidio/main/presidio-image-redactor/app.py`
  - `https://raw.githubusercontent.com/microsoft/presidio/main/presidio-analyzer/logging.ini`
- Package manifests / Python entry points:
  - `pyproject.toml` for `presidio-analyzer`, `presidio-anonymizer`, `presidio-image-redactor`, `presidio-structured`
  - `__init__.py` for each of the four `presidio_*` packages
  - `https://raw.githubusercontent.com/microsoft/presidio/main/presidio-cli/README.md` and `presidio_cli/` listing
- OpenAPI:
  - `https://raw.githubusercontent.com/microsoft/presidio/main/docs/api-docs/api-docs.yml`
- Docs / samples:
  - `https://microsoft.github.io/presidio/installation/`
  - `https://raw.githubusercontent.com/microsoft/presidio/main/docs/samples/index.md`
  - `https://raw.githubusercontent.com/microsoft/presidio/main/docs/ahds_integration.md`
  - Deployment indexes: `app-service`, `k8s` (+ Helm chart templates listing), `data-factory`, `spark`, `redacting-telemetry`, `openai-anonymaztion-and-deanonymaztion-best-practices`, `fabric`
  - Postman collections under `docs/samples/docker/`
- CI/release workflows:
  - `https://raw.githubusercontent.com/microsoft/presidio/main/.github/workflows/ci.yml`
  - `https://raw.githubusercontent.com/microsoft/presidio/main/.github/workflows/release.yml`

## REST APIs

All three services are Flask apps served by `gunicorn` (Linux/macOS) or `waitress` (Windows). Default container port `3000`; docker-compose maps them to host `5001/5002/5003`. Errors are uniformly returned as JSON `{ "error": "<message>" }`.

### Analyzer API

Host (Microsoft demo): `presidio-analyzer-prod.azurewebsites.net`.

| Method | Path                | Purpose                          | Request                                                                                                                                                          | Response                                                                                                                                  |
| ------ | ------------------- | -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/health`           | Liveness                         | —                                                                                                                                                                | Plain text: `"Presidio Analyzer service is up"`                                                                                            |
| POST   | `/analyze`          | Detect entities (single & batch) | `AnalyzerRequest`: `text` (string or list), `language`, `correlation_id`, `score_threshold`, `entities`, `return_decision_process`, `ad_hoc_recognizers`, `context`, `allow_list`, `allow_list_match`, `regex_flags` | Array of `RecognizerResult` (or array-of-arrays if `text` was a list). Each item: `entity_type`, `start`, `end`, `score`, optional `analysis_explanation`. `400` on parse error, `500` otherwise. |
| GET    | `/recognizers`      | List loaded recognizers          | Query: `language`                                                                                                                                                | JSON array of recognizer class names                                                                                                       |
| GET    | `/supportedentities`| List entity types                | Query: `language`                                                                                                                                                | JSON array of entity-type strings                                                                                                          |

Tunable via env: `PORT`, `BATCH_SIZE` (default 500), `N_PROCESS` (default 1), `LOG_LEVEL`, `ANALYZER_CONF_FILE`, `NLP_CONF_FILE`, `RECOGNIZER_REGISTRY_CONF_FILE`.

### Anonymizer API

Host (Microsoft demo): `presidio-anonymizer-prod.azurewebsites.net`.

| Method | Path             | Purpose                       | Request                                                                                              | Response                                            |
| ------ | ---------------- | ----------------------------- | ---------------------------------------------------------------------------------------------------- | --------------------------------------------------- |
| GET    | `/health`        | Liveness                      | —                                                                                                    | Plain text                                          |
| POST   | `/anonymize`     | Apply operators to detections | `AnonymizeRequest`: `text`, `analyzer_results[]`, `anonymizers` map keyed by entity type (or `DEFAULT`) using operators (`replace`, `redact`, `mask`, `hash`, `encrypt`, `keep`, `custom`) | `AnonymizeResponse`: anonymized `text` + `items[]` of `OperatorResult` |
| POST   | `/deanonymize`   | Reverse reversible ops        | `DeanonymizeRequest`: `text`, `anonymizer_results[]`, `deanonymizers` map (e.g., `decrypt`)          | `DeanonymizeResponse`                               |
| GET    | `/anonymizers`   | List supported operators      | —                                                                                                    | JSON array of operator names                        |
| GET    | `/deanonymizers` | List supported reverse ops    | —                                                                                                    | JSON array                                          |

Error mapping: `InvalidParamError -> 422`, `HTTPException -> e.code`, fallback `500 Internal server error`.

### Image redactor API

| Method | Path      | Purpose       | Request                                                                                                                          | Response                                                       |
| ------ | --------- | ------------- | -------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------- |
| GET    | `/health` | Liveness      | —                                                                                                                                | Plain text                                                     |
| POST   | `/redact` | Redact image  | Mode A — JSON body: `image` (base64), optional `analyzer_entities`, form `data` JSON with color fill. Mode B — multipart upload of `image` file + `data` JSON (fixed `score_threshold=0.4`) | `application/octet-stream` (base64 for Mode A, raw bytes for Mode B). `422` on invalid params, `500` on internal errors. |

### Health/info endpoints

Each of the three services exposes `GET /health` returning the plain string `"<Service> service is up"`. There are **no** metrics endpoints (`/metrics`), version endpoints, or readiness/liveness probes beyond the single `/health` route. The k8s Helm chart points its probes at `/health`.

## Python SDK shape

Four PyPI packages, all MIT-licensed, Python 3.10–3.13. Public API is class-based (every `__init__.py` exports only classes via `__all__`; no shortcut functions).

**`presidio-analyzer`** (`pyproject.toml`: `spacy`, `regex`, `tldextract`, `pyyaml`, `phonenumbers`, `pydantic`):

- Engines: `AnalyzerEngine`, `BatchAnalyzerEngine`, `AnalyzerEngineProvider`, `AnalyzerRequest`
- Recognizer hierarchy: `EntityRecognizer`, `LocalRecognizer`, `PatternRecognizer`, `RemoteRecognizer`, `LMRecognizer`
- Registry & types: `RecognizerRegistry`, `Pattern`, `AnalysisExplanation`, `RecognizerResult`, `DictAnalyzerResult`
- Context enhancement: `ContextAwareEnhancer`, `LemmaContextAwareEnhancer`
- Optional extras: `server`, `transformers`, `stanza`, `azure-ai-language`, `ahds`, `gliner`, `langextract`

**`presidio-anonymizer`** (only hard dep is `cryptography>=46`):

- Engines: `AnonymizerEngine`, `DeanonymizeEngine`, `BatchAnonymizerEngine`
- Entities/results: `RecognizerResult`, `EngineResult`, `DictRecognizerResult`, `OperatorResult`, `PIIEntity`
- Config: `OperatorConfig`, `ConflictResolutionStrategy`
- Errors: `InvalidParamError`
- Extras: `server`, `ahds`

**`presidio-image-redactor`** (`pillow`, `matplotlib`, `pypng`, `pytesseract`, `opencv-python`, `pydicom`, `python-gdcm`, optional `azure-ai-formrecognizer`):

- OCR: `OCR`, `TesseractOCR`, `DocumentIntelligenceOCR`
- Engines: `ImageAnalyzerEngine`, `ImageRedactorEngine`, `ImagePiiVerifyEngine`, `DicomImageRedactorEngine`, `DicomImagePiiVerifyEngine`
- Utilities: `BboxProcessor`, `ImagePreprocessor`, `ContrastSegmentedImageEnhancer`, `BilateralFilter`, `SegmentedAdaptiveThreshold`, `ImageRescaling`

**`presidio-structured`** (`pandas>=1.5`):

- `StructuredEngine`, `JsonAnalysisBuilder`, `PandasAnalysisBuilder`, `StructuredAnalysis`
- Readers/processors: `CsvReader`, `JsonReader`, `PandasDataProcessor`, `JsonDataProcessor`

**`presidio-cli`** (separate package, not in main release wave):

- Executable `presidio` scans files/directories. Source: `cli.py` (8.3 KB), `analyzer.py`, `config.py`, conf bundle.
- Output formats: `standard`, `github` (Actions annotations), `colored`, `parsable` (JSON-style), `auto`.
- Config via `.presidiocli` YAML (`language`, `entities`, `ignore`, `allow`).

## Deployment artifacts

**Dockerfiles** (in each package):

- `presidio-analyzer`: `Dockerfile`, `Dockerfile.dev`, `Dockerfile.stanza`, `Dockerfile.transformers`, `Dockerfile.windows` — five variants distinguishing NLP backend.
- `presidio-anonymizer`: `Dockerfile`, `Dockerfile.dev`, `Dockerfile.windows`.
- `presidio-image-redactor`: `Dockerfile`, `Dockerfile.dev`.
- `presidio-structured` and `presidio-cli`: no Dockerfile (library-only).

Each service has an `entrypoint.sh` and (for analyzer/anonymizer) a `logging.ini`.

**docker-compose** files at repo root:

- `docker-compose.yml` — analyzer + anonymizer + image-redactor + an `ollama/ollama:latest` sidecar (analyzer depends on `service_healthy`).
- `docker-compose-text.yml` — text services only.
- `docker-compose-image.yml` — image redactor only.
- `docker-compose-transformers.yml` — analyzer built from `Dockerfile.transformers` with `NLP_CONF_FILE=presidio_analyzer/conf/transformers.yaml` build arg.

Images: `${REGISTRY_NAME}/${IMAGE_PREFIX}presidio-{service}${TAG}`, defaults pulled from `mcr.microsoft.com` (e.g., `mcr.microsoft.com/presidio-analyzer`).

**Kubernetes manifests / Helm chart** under `docs/samples/deployments/k8s/`:

- Helm chart `charts/presidio/` with `Chart.yaml`, `values.yaml`, and templates:
  - 3 Deployments: `analyzer-deployment.yaml`, `anonymizer-deployment.yaml`, `anonymizer-image-deployment.yaml`
  - 3 Services: matching service objects
  - 1 Ingress (`nginx` class, on by default; `ingress.enabled=false` to disable)
  - `NOTES.txt`, `_helpers.tpl`
  - No ConfigMaps, Secrets, HPAs, ServiceAccounts, NetworkPolicies, or PDBs shipped
- Scripts: `deployment/deploy-presidio.sh`, `deployment/run-with-kind.sh` (local KIND dev)
- AKS-targeted; values support overriding registry/tag

**Azure deployment templates**:

- Per-service `deploytoazure.json` (ARM) at the root of analyzer, anonymizer, and image-redactor packages — one-click "Deploy to Azure" buttons.
- App Service: `docs/samples/deployments/app-service/` ships `presidio-app-service.json`, `presidio-services.json`, `values.json`. Provisions resource group, Linux App Service Plan, Web Apps for analyzer/anonymizer, IP allow rules, and (optionally) Log Analytics wiring for `AppServicePlatformLogs` / `AppServiceConsoleLogs`.
- Data Factory: `arm-templates/` plus separate gallery-template docs for HTTP-service and Databricks variants.
- Spark/Databricks: ARM template, init script for DBFS, configure_databricks.sh, and notebooks (`00_setup`, `01_transform_presidio`).

**Postman collections** (`docs/samples/docker/`): `PresidioAnalyzer.postman_collection.json`, `PresidioAnonymizer.postman_collection.json`.

## Sample integrations (notebook + script samples)

`docs/samples/index.md` is organized as a four-column table (Topic / Data Type / Resource / Sample). Notable entries grouped by theme:

**Core text usage notebooks (`docs/samples/python/`)**:

- `presidio_notebook.ipynb` — basic usage
- `customizing_presidio_analyzer.ipynb`
- `ner_model_configuration.ipynb`, `no_code_config.ipynb` — YAML-driven config
- `encrypt_decrypt.ipynb`, `pseudonymization.ipynb`
- `getting_entity_values.ipynb` (custom Operator)
- `Anonymizing known values.ipynb`, `keep_entities.ipynb`
- `integrating_with_external_services.ipynb`
- `synth_data_with_openai.ipynb` — generate synthetic replacements with OpenAI
- `batch_processing.ipynb`, `process_csv_file.py`, `example_structured.ipynb`

**Image / PDF / DICOM**:

- `example_dicom_image_redactor.ipynb`, `example_dicom_redactor_evaluation.ipynb`
- `image_redaction_allow_list_approach.ipynb`
- `plot_custom_bboxes.ipynb`
- `example_pdf_annotation.ipynb`

**External / remote recognizers (Python files)**:

- `flair_recognizer.py` — Flair NLP
- `transformers_recognizer/` — HuggingFace
- `span_marker_recognizer.py` — SpanMarker NER
- `gliner.md`, `langextract/` — GLiNER and LLM-driven LangExtract
- `text_analytics/`, `ahds/` — Azure AI Language and Azure Health Data Services
- `example_remote_recognizer.py` — generic remote recognizer pattern
- `example_custom_lambda_anonymizer.py` — Faker-based anonymization

**Cross-service / proxy patterns**:

- `docs/samples/docker/litellm.md` — LiteLLM proxy masking LLM prompts/responses

**Deployment patterns (`docs/samples/deployments/`)**:

- `app-service/` — Azure App Service one-click + scripted deploy
- `k8s/` — Helm chart + KIND local-dev script
- `data-factory/` — three ETL routes (full sample, gallery for text, gallery for CSV)
- `spark/` — Azure Databricks + Blob Storage + pandas UDF distributed PII masking
- `redacting-telemetry/` — full OTel stack (described below)
- `openai-anonymaztion-and-deanonymaztion-best-practices/` ("Invisio") — production-shaped reference: AKS API + Redis session store + Bicep IaC + client app + Streamlit spike, with custom `InstanceCounterAnonymizer`/`InstanceCounterDeanonymizer` for consistent per-session mapping.

**Microsoft Fabric notebooks** (`docs/samples/fabric/`): Spark-based PII detection in Fabric notebooks writing to Delta Lake.

**Demo**: `docs/samples/python/streamlit/` — multi-file Streamlit demo (`presidio_streamlit.py`, `presidio_helpers.py`, `presidio_nlp_engine_config.py`, helpers for Flair, Azure AI Language, OpenAI synth data), plus its own Dockerfile.

## Observability & telemetry

**Built into Presidio itself: essentially none.**

- The `logging.ini` files for analyzer and anonymizer are plain Python `logging.config` INI: one `consoleHandler` writing to `sys.stdout`, formatter `"%(asctime)s - %(name)s - %(levelname)s - %(message)s"`, level `INFO`. No JSON / structured logging.
- Each `__init__.py` attaches a `NullHandler` to its named logger (`presidio-analyzer`, `presidio-anonymizer`, `presidio-image-redactor`, `presidio-structured`) — standard library convention.
- The analyzer additionally configures a separate `decision_process` logger (StreamHandler) gated behind the `return_decision_process` request flag, used to emit recognizer match rationale.
- **No OpenTelemetry, Prometheus, statsd, Sentry, or App Insights SDK** appears in any of the four `pyproject.toml` files. There is no `/metrics` endpoint and no emitted metric counters or histograms.
- No request correlation IDs are auto-generated; callers may pass `correlation_id` in `AnalyzerRequest`, but it is opaque to the engine.

**Sample-level only**: `docs/samples/deployments/redacting-telemetry/` is a *demo* (explicitly labeled "proof-of-concept, not production-ready") that shows the *user's app* sending logs through an OTel Collector → Loki/Tempo → Grafana, with the user's app calling Presidio HTTP twice (analyze, then anonymize) to mask PII *before* emission. Stack: OTel Collector (4317/4318), Loki (3100), Tempo (3200), Grafana (3000), plus a FastAPI `pii-demo-app`. Presidio is the redactor, not an emitter.

App Service deployments can opt-in to Azure diagnostic settings → Log Analytics for `AppServicePlatformLogs` and `AppServiceConsoleLogs`, but this is a platform feature, not a Presidio one.

## Configuration system

**YAML files**, loaded via `NlpEngineProvider(conf_file=...)` or env-var overrides on the analyzer service:

- `ANALYZER_CONF_FILE`, `NLP_CONF_FILE`, `RECOGNIZER_REGISTRY_CONF_FILE` — paths picked up by `AnalyzerEngineProvider`
- NLP config keys: `nlp_engine_name` (`spacy` | `transformers` | `stanza`), `models[]` with `lang_code`/`model_name`, and `ner_model_configuration` (`labels_to_ignore`, `model_to_presidio_entity_mapping`, `low_confidence_score_multiplier`, `low_score_entity_names`)
- `presidio_analyzer/conf/transformers.yaml` referenced by `Dockerfile.transformers` shows a transformers-backed default config
- CLI: `.presidiocli` YAML (`language`, `entities`, `ignore`, `allow`)

**Environment variables**:

- HTTP services: `PORT` (default 3000), `LOG_LEVEL`
- Analyzer: `BATCH_SIZE` (default 500), `N_PROCESS` (default 1), plus the three conf-file paths above
- Analyzer (default compose stack): `OLLAMA_HOST` (e.g., `http://ollama:11434`) — used by LangExtract recognizer
- AHDS: `AHDS_ENDPOINT` plus `ENV=development` to flip from restricted credential chain (Environment + Workload Identity + Managed Identity) to `DefaultAzureCredential`

**Per-service configuration** is otherwise minimal — there is no central runtime registry, no hot-reload, no Configmap/Secret integration shipped with the Helm chart, no feature flags.

## Multi-language / non-Python bindings

**Python is the only official binding.** All four packages and the CLI are Python. There are no official Java, JavaScript/TypeScript, Go, or .NET clients in the repo.

**Cross-language access path is HTTP** via the REST APIs and the Postman collections — i.e., any language with an HTTP client. There is no published OpenAPI generator in CI, but `docs/api-docs/api-docs.yml` is the OpenAPI 3 source consumers can run codegen against.

**Community ports**: none referenced in the README, docs, or CI workflows reviewed. The README's positioning is "framework" with Python-first usage and Docker for everything else.

## Versioning & release cadence

- **Current line**: `2.2.x`. Latest stable per CHANGELOG: **2.2.362** (2026-03-15). Unreleased section in `CHANGELOG.md` enumerates new recognizers (Canadian SIN, Swedish Personnummer, German PII suite, Korean RRN, Thai National ID, Turkish TCKN/phone/license plates, Philippine mobile, Spanish Passport) plus Anonymizer fixes.
- **`presidio-image-redactor`** is versioned **independently** of the other packages — the release workflow extracts its version from its own `pyproject.toml` and tags its Docker image separately, while the analyzer's `pyproject.toml` supplies the "main version" applied to everything else.
- **Cadence**: ~1.5–3 months per release in 2025–2026 (Mar 2025, Jul 2025, Sep 2025, Feb 2026, Mar 2026). 2024 was the busiest year (6+ releases). Hotfixes happen days apart (e.g., 2.2.350 → 2.2.351 within days for a config parsing fix).
- **Trigger**: release is `workflow_dispatch` only (no tag/push auto-release). Publishes:
  - Draft GitHub release (tagged with main version, marked `--latest`)
  - 5 PyPI packages (`presidio`, `analyzer`, `anonymizer`, `image-redactor`, `structured`) via OIDC trusted publishing with `skip-existing: true`
  - 3 Docker images to ACR (`<ACR>.azurecr.io/public/<image>`) — multi-arch `linux/amd64`+`linux/arm64`, with SBOM and max-mode provenance attestations
- **Breaking-change policy**: Not formally documented in the repo. The 2.2.x series has been stable for years; the "Presidio V2" doc (`docs/presidio_V2.md`) is the last documented architectural reset.

## Licensing

- **Repository**: MIT (`LICENSE`, plus `NOTICE` file). All four package `pyproject.toml` files declare MIT.
- **CI dependency review** restricts allowed transitive licenses to **MIT, Apache-2.0, BSD-3-Clause, 0BSD**.
- **Caveats** (model / OCR / cloud SDK licensing is on the user):
  - **spaCy models** ship under varying licenses — `en_core_web_lg` is MIT, but other language models can be CC-BY-SA-3.0 or GPL (e.g., some Polish/Spanish models). Users download these at install time; Presidio does not redistribute weights.
  - **Stanza** is Apache-2.0, but its models are CC-BY-SA-4.0.
  - **Transformers models** depend on the hub author (often Apache-2.0, sometimes more restrictive).
  - **Tesseract** is Apache-2.0 (installed at the OS level for the image redactor).
  - **`python-gdcm`** is BSD-style but bundles GDCM, which is BSD with a custom variant.
  - **Azure SDKs** (`azure-ai-textanalytics`, `azure-health-deidentification`, `azure-identity`, `azure-ai-formrecognizer`) are MIT but require an Azure account; AHDS service usage has its own commercial terms.
  - **OpenAI** integration in samples implies OpenAI API terms.

## Anything notable / unusual

- **Five Dockerfile variants for the analyzer** (default + dev + stanza + transformers + windows) — they switch NLP backend at build time rather than at runtime. The corresponding compose files (`docker-compose-transformers.yml`, etc.) make the variant the deployment surface.
- **Native ARM64 in CI**: the workflow uses `ubuntu-24.04-arm` runners (no QEMU emulation) to build `linux/arm64` images, and runs the E2E suite on both arches. SBOM + provenance attestations are emitted with every push.
- **Ollama is now a first-class compose dependency** of the analyzer in the default `docker-compose.yml` — analyzer waits on `ollama service_healthy` so the LangExtract recognizer (and its E2E test using `qwen2.5:1.5b`) can call a local LLM. This is the strongest LLM-as-a-recognizer signal in the repo.
- **LangExtract + LiteLLM**: two distinct LLM integration shapes ship in the same release — LangExtract (extras: `langextract`, `openai`, `azure-identity`, `more-itertools`, `jinja2`) for LLM-based entity extraction *inside* the analyzer, and a LiteLLM proxy sample for redacting prompts/responses *around* third-party LLM calls.
- **GLiNER + ONNX Runtime** are wired up as another optional NER backend (extra: `gliner`) — narrow-purpose generalist NER models that run via `onnxruntime` rather than Torch.
- **Azure Health Data Services** is the only Microsoft cloud service Presidio integrates as both an analyzer (AHDS Recognizer detects `PATIENT`/`DOCTOR`/`DATE`) and an anonymizer operator (AHDS Surrogate generates medically plausible replacements that preserve format and stay consistent within a document).
- **Decision-process logging is special-cased**: it lives outside the normal logger hierarchy and is gated behind `return_decision_process` per-request, suggesting the team treats audit/explanation logs as a distinct concern rather than building general structured logging.
- **`presidio-cli` lives in its own subtree** with its own `Pipfile` and `pyproject.toml` and is *not* on the release.yml publish list — it appears to ship independently and is omitted from the multi-package release wave.
- **The Helm chart is bare-bones** (3 Deployments + 3 Services + 1 Ingress, nothing else). No HPA, no PDB, no NetworkPolicy, no ConfigMap-driven recognizer config, no ServiceAccount. Anyone running this in production layers their own platform concerns on top.
- **No request correlation, tracing, or metrics in the services themselves** — the `correlation_id` field in the analyzer request is accepted but not propagated to logs. Anyone needing distributed tracing has to add it in their wrapper.
- **The "Invisio" OpenAI sample is the closest thing Presidio ships to a reference production deployment**: AKS + Bicep IaC + Redis-backed session storage + custom counter-based pseudonymizer for stable cross-call mapping. It is buried under `docs/samples/deployments/` rather than featured on the landing page.
