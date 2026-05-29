# Presidio — Master Feature Inventory

**Purpose.** A single, exhaustive list of every feature Microsoft Presidio
exposes. This is the **reference** the octarine team uses to identify gaps:
each row is a thing octarine should either (a) implement, (b) consciously
decline to implement (and document why), or (c) already cover.

**Sources.** Compiled from the eleven companion catalogs in this directory:

- [`01-analyzer-recognizers.md`](01-analyzer-recognizers.md) — every built-in
  recognizer class (62 total)
- [`02-anonymizer-operators.md`](02-anonymizer-operators.md) — every
  anonymizer / deanonymizer operator (8 + 2)
- [`03-image-and-structured.md`](03-image-and-structured.md) — image
  redactor, DICOM, structured data (pandas/JSON/CSV)
- [`04-analyzer-engine.md`](04-analyzer-engine.md) — analyzer engine, NLP,
  context enhancement, registry, YAML config
- [`05-deployment-and-integrations.md`](05-deployment-and-integrations.md) —
  REST APIs, Docker/k8s/Azure, observability, sample integrations
- [`06-presidio-research.md`](06-presidio-research.md) — separate
  `microsoft/presidio-research` repo: Faker-based fake-data generator,
  token + span evaluators, model wrappers, datasets
- [`07-types-and-utilities.md`](07-types-and-utilities.md) — request/response
  objects, enums, config types, exceptions, constants, serialization
- [`08-docs-cli-roadmap.md`](08-docs-cli-roadmap.md) — full docs nav,
  `presidio-cli` flag surface, CHANGELOG `Unreleased` + last 2 releases
- [`09-samples-deep.md`](09-samples-deep.md) — every notebook + script +
  deployment read for the pattern it teaches (incl. Invisio reference)
- [`10-tests-issues-prs.md`](10-tests-issues-prs.md) — tests as
  feature-reveal, open issues, merged PRs not yet in CHANGELOG, dormant
  discussions
- [`11-loose-ends.md`](11-loose-ends.md) — OpenAPI, Postman, entrypoints,
  logging, PII Verify engine, all optional-deps, NOTICE, V1→V2 docs

Read each catalog for sources, regex specifics, and per-class detail. This
document is the **index**.

Compiled 2026-05-28 against `microsoft/presidio` `main` (release line
2.2.x, most recent stable 2.2.362) and `microsoft/presidio-research`
`master` (release line `presidio-evaluator` 0.2.5).

---

## A. Detection — entity recognizers (62 classes)

### A.1 Generic (locale-agnostic) — 9 classes

| Entity | Class | Detection | Validation |
|---|---|---|---|
| `CREDIT_CARD` | `CreditCardRecognizer` | Per-brand regex + context | **Luhn** |
| `CRYPTO` | `CryptoRecognizer` | Regex | **Double-SHA-256 base58** for P2PKH/P2SH, **Bech32/Bech32m** for `bc1`. **Bitcoin-only — no ETH/SOL/Monero.** |
| `DATE_TIME` | `DateRecognizer` | 13 regex patterns (ISO 8601, slash, dot, dash, named-month formats) | — |
| `EMAIL_ADDRESS` | `EmailRecognizer` | Regex + context | `validate_result` checks TLD via `tld` library |
| `IBAN_CODE` | `IbanRecognizer` | Country-specific regex (**70 ISO IBAN countries**) | **ISO 7064 mod-97** check digit |
| `IP_ADDRESS` | `IpRecognizer` | 5 regex patterns (IPv4, IPv6, IPv4-mapped IPv6, IPv4-embedded IPv6, unspecified `::`) | `invalidate_result` filters false positives |
| `MAC_ADDRESS` | `MacAddressRecognizer` | Regex (colon-form + dot-form) + context | `invalidate_result` |
| `PHONE_NUMBER` | `PhoneRecognizer` | `python-phonenumbers` `PhoneNumberMatcher` — **no internal regex** | Library-level. Default 8 regions (US/UK/DE/FR/IL/IN/CA/BR); can open to all ~250 |
| `URL` | `UrlRecognizer` | 4 regexes (schemed/schemeless/quoted/IPv4-or-IDN host) | — |

### A.2 Country-specific packs — 47 classes across 16 countries

Most country packs are **disabled by default** in the YAML registry — users
opt in. The 70-country IBAN list inside `IbanRecognizer` is not double-counted
here.

#### Germany (13) — largest single-country pack

| Entity | Class | Validation |
|---|---|---|
| `DE_TAX_ID` | `DeTaxIdRecognizer` | **ISO 7064 mod-11,10** |
| `DE_TAX_NUMBER` | `DeTaxNumberRecognizer` | — (3 regex variants, ELSTER + per-state) |
| `DE_VAT_ID` | `DeVatIdRecognizer` | **mod-11** |
| `DE_PASSPORT` | `DePassportRecognizer` | **ICAO 9303 MRZ check digit** |
| `DE_ID_CARD` | `DeIdCardRecognizer` | **MRZ check digit** |
| `DE_SOCIAL_SECURITY` | `DeSocialSecurityRecognizer` | **DRV checksum** (Rentenversicherungsnummer) |
| `DE_HEALTH_INSURANCE` | `DeHealthInsuranceRecognizer` | **GKV-Spitzenverband checksum** (KVNR) |
| `DE_KFZ` | `DeKfzRecognizer` | — (5 regex, vehicle plates) |
| `DE_HANDELSREGISTER` | `DeHandelsregisterRecognizer` | — (commercial register HRA/HRB) |
| `DE_PLZ` | `DePlzRecognizer` | — (postal codes, explicit **base score 0.05** for FP risk) |
| `DE_LANR` | `DeLanrRecognizer` | **mod-10** (doctor ID) |
| `DE_BSNR` | `DeBsnrRecognizer` | **checksum** (medical practice ID) |
| `DE_FUEHRERSCHEIN` | `DeFuehrerscheinRecognizer` | — (driver license) |

#### United States (9)

| Entity | Class | Validation |
|---|---|---|
| `US_SSN` | `UsSsnRecognizer` | **Denylist** rules (000/666/9xx area, group 00, serial 0000, famous fakes 078-05-1120 / 123-45-6789) |
| `US_ITIN` | `UsItinRecognizer` | — |
| `US_PASSPORT` | `UsPassportRecognizer` | — (legacy 9-digit + next-gen letter+8-digit) |
| `US_DRIVER_LICENSE` | `UsLicenseRecognizer` | — |
| `US_BANK_NUMBER` | `UsBankRecognizer` | — (8–17 digit) |
| `US_NPI` | `UsNpiRecognizer` | **Luhn** (NPI) |
| `US_MBI` | `UsMbiRecognizer` | — (Medicare Beneficiary Identifier) |
| `ABA_ROUTING_NUMBER` | `AbaRoutingRecognizer` | **ABA mod-10 weighted (3,7,1,…)**. **Not in YAML registry — code-only**, missing from supported_entities docs |
| `MEDICAL_LICENSE` | `MedicalLicenseRecognizer` | **DEA number checksum**. Lives under `us/` but documented as global |

#### India (6)

| Entity | Class | Validation |
|---|---|---|
| `IN_AADHAAR` | `InAadhaarRecognizer` | **Verhoeff** |
| `IN_PAN` | `InPanRecognizer` | — (10-char fixed-format weak/medium/strict) |
| `IN_PASSPORT` | `InPassportRecognizer` | — |
| `IN_VOTER` | `InVoterRecognizer` | — (10-char EPIC alphanumeric) |
| `IN_GSTIN` | `InGstinRecognizer` | **GSTIN modulus** |
| `IN_VEHICLE_REGISTRATION` | `InVehicleRegistrationRecognizer` | **State code validation** (9 per-state RTO regex) |

#### United Kingdom (6)

| Entity | Class | Validation |
|---|---|---|
| `UK_NHS` | `NhsRecognizer` | **NHS mod-11** |
| `UK_NINO` | `UkNinoRecognizer` | — |
| `UK_DRIVING_LICENCE` | `UkDrivingLicenceRecognizer` | **DVLA checksum** |
| `UK_PASSPORT` | `UkPassportRecognizer` | — |
| `UK_POSTCODE` | `UkPostcodeRecognizer` | — (**duplicated in YAML**, likely bug) |
| `UK_VEHICLE_REGISTRATION` | `UkVehicleRegistrationRecognizer` | **Format/age-tag validation** |

#### Italy (5)

| Entity | Class | Validation |
|---|---|---|
| `IT_FISCAL_CODE` | `ItFiscalCodeRecognizer` | **Codice Fiscale alphanumeric checksum** |
| `IT_VAT_CODE` | `ItVatCodeRecognizer` | **Luhn on Partita IVA** |
| `IT_PASSPORT` | `ItPassportRecognizer` | — |
| `IT_IDENTITY_CARD` | `ItIdentityCardRecognizer` | — (CIE + legacy) |
| `IT_DRIVER_LICENSE` | `ItDriverLicenseRecognizer` | — |

#### Korea (5)

| Entity | Class | Validation |
|---|---|---|
| `KR_RRN` | `KrRrnRecognizer` | **mod-11** + birth-date sanity check |
| `KR_FRN` | `KrFrnRecognizer` | inherits `KrRrnRecognizer` math |
| `KR_BRN` | `KrBrnRecognizer` | **BRN checksum** (Business Registration) |
| `KR_PASSPORT` | `KrPassportRecognizer` | — (uses `"kr"` language code, all others use `"ko"` — internal inconsistency) |
| `KR_DRIVER_LICENSE` | `KrDriverLicenseRecognizer` | **License-format check** |

#### Australia (4)

| Entity | Class | Validation |
|---|---|---|
| `AU_ABN` | `AuAbnRecognizer` | **ABN mod-89** |
| `AU_ACN` | `AuAcnRecognizer` | **ACN modulus** |
| `AU_MEDICARE` | `AuMedicareRecognizer` | **Medicare checksum** |
| `AU_TFN` | `AuTfnRecognizer` | **TFN mod-11** |

#### Spain (3)

| Entity | Class | Validation |
|---|---|---|
| `ES_NIF` | `EsNifRecognizer` | **NIF mod-23 letter** |
| `ES_NIE` | `EsNieRecognizer` | **NIE mod-23** |
| `ES_PASSPORT` | `EsPassportRecognizer` | — |

#### Turkey (2)

| Entity | Class | Validation |
|---|---|---|
| `TR_NATIONAL_ID` | `TrNationalIdRecognizer` | **TCKN mod-10/mod-11** |
| `TR_LICENSE_PLATE` | `TrLicensePlateRecognizer` | **Province code 01–81 + letter exclusion (no Q/W/X)** |

#### Sweden (2)

| Entity | Class | Validation |
|---|---|---|
| `SE_PERSONNUMMER` | `SePersonnummerRecognizer` | **Luhn** (also accepts Samordningsnummer) |
| `SE_ORGANISATIONSNUMMER` | `SeOrganisationsnummerRecognizer` | **Luhn** |

#### Singapore (2)

| Entity | Class | Validation |
|---|---|---|
| `SG_NRIC_FIN` | `SgFinRecognizer` | — (no checksum in code despite presence in similar NRIC validators) |
| `SG_UEN` | `SgUenRecognizer` | **ACRA UEN checksum**. **Not in YAML — code-only** |

#### Nigeria (2)

| Entity | Class | Validation |
|---|---|---|
| `NG_NIN` | `NgNinRecognizer` | **NIN check** |
| `NG_VEHICLE_REGISTRATION` | `NgVehicleRegistrationRecognizer` | — |

#### Canada (1)

| Entity | Class | Validation |
|---|---|---|
| `CA_SIN` | `CaSinRecognizer` | **Luhn** (registered for both `en` and `fr`; rejects SINs starting with 0 or 8) |

#### Finland (1)

| Entity | Class | Validation |
|---|---|---|
| `FI_PERSONAL_IDENTITY_CODE` | `FiPersonalIdentityCodeRecognizer` | **HETU mod-31 check character**. **Not in default YAML — code-only** |

#### Poland (1)

| Entity | Class | Validation |
|---|---|---|
| `PL_PESEL` | `PlPeselRecognizer` | **PESEL weighted-sum** + birth-date sanity check |

#### Thailand (1)

| Entity | Class | Validation |
|---|---|---|
| `TH_TNIN` | `ThTninRecognizer` | **Thai mod-11 weighted** |

### A.3 NLP/NER-driven recognizers — 6 classes

Pull entities from an NLP pipeline rather than regex.

| Class | Engine | Entities emitted | Notes |
|---|---|---|---|
| `SpacyRecognizer` | spaCy (default `en_core_web_lg`) | `PERSON`, `LOCATION`, `NRP`, `DATE_TIME`, `ORGANIZATION` (latter ignored by default — Microsoft considers spaCy ORG unreliable) | `NRP` = Nationality/Religious/Political. Default `labels_to_ignore` also drops CARDINAL, EVENT, LANGUAGE, LAW, MONEY, ORDINAL, PERCENT, PRODUCT, QUANTITY, WORK_OF_ART |
| `StanzaRecognizer` | Stanford Stanza via `spacy-stanza` | Same set | Subclass of `SpacyRecognizer` |
| `TransformersRecognizer` | HuggingFace via `spacy-huggingface-pipelines` | Adds `AGE`, `ID`, `EMAIL`, `PHONE_NUMBER` | Subclass of `SpacyRecognizer` |
| `HuggingFaceNerRecognizer` | Direct `transformers.pipeline("token-classification")` | Configurable; defaults to PERSON/LOCATION/ORGANIZATION/MISC/DATE_TIME | Standalone — no spaCy. Has Korean label aliases (`PS`/`LC`/`OG`/`DT`/`TI`) |
| `MedicalNERRecognizer` | HuggingFace, default `blaze999/Medical-NER` | 8 medical entities: `MEDICAL_DISEASE_DISORDER`, `MEDICAL_MEDICATION`, `MEDICAL_THERAPEUTIC_PROCEDURE`, `MEDICAL_CLINICAL_EVENT`, `MEDICAL_BIOLOGICAL_ATTRIBUTE`, `MEDICAL_BIOLOGICAL_STRUCTURE`, `MEDICAL_FAMILY_HISTORY`, `MEDICAL_HISTORY` | Subclass of `HuggingFaceNerRecognizer` |
| `GLiNERRecognizer` | GLiNER zero-shot NER (via `onnxruntime`) | Fully user-configurable | Bundled by default in `slim.yaml` — Presidio is moving toward zero-shot by default in slim deployments |

### A.4 Third-party / remote recognizers — 5 classes

| Class | Service | Pattern |
|---|---|---|
| `AzureAILanguageRecognizer` | Azure AI Language PII | `RemoteRecognizer` |
| `AzureHealthDeidRecognizer` | Azure Health Data Services de-identification | `RemoteRecognizer` |
| `LangExtractRecognizer` (abstract) | LLM-based extraction via `langextract` package | Base for the two below |
| `BasicLangExtractRecognizer` | Generic LLM (configurable provider, e.g., Ollama) | Prompt YAML at `conf/langextract_config_basic.yaml` |
| `AzureOpenAILangExtractRecognizer` | Azure OpenAI | Prompt YAML at `conf/langextract_config_azureopenai.yaml` |

### A.5 Detection mechanism summary

- **Regex-only + context**: ~24 recognizers
- **Regex + algorithmic validation**: ~27 recognizers across the following families:
  - **Luhn (mod-10)**: CreditCard, CA_SIN, IT_VAT, SE_PERSONNUMMER, SE_ORGANISATIONSNUMMER, US_NPI, ABA_ROUTING (weighted variant)
  - **ISO 7064 (mod-97 / mod-11,10)**: IBAN, DE_TAX_ID
  - **mod-11 weighted**: DE_VAT_ID, DE_LANR, DE_BSNR, AU_TFN, KR_RRN/FRN, TR_NATIONAL_ID, TH_TNIN, UK_NHS, PL_PESEL, IT_FISCAL_CODE, FI_PERSONAL_IDENTITY_CODE (mod-31)
  - **mod-23 letter table**: ES_NIF, ES_NIE
  - **Verhoeff**: IN_AADHAAR
  - **GSTIN modulus**: IN_GSTIN
  - **ICAO 9303 MRZ check digit**: DE_PASSPORT, DE_ID_CARD
  - **DRV / GKV / DEA / ABN / ACN / Medicare / BRN / UEN / DVLA / NHS / NIN / TCKN** — domain-specific
  - **Double-SHA256 + base58 / Bech32(m)**: CRYPTO (Bitcoin)
  - **Format/range only** (no cryptographic checksum): TR_LICENSE_PLATE (province 01–81), IN_VEHICLE_REGISTRATION (state codes), UK_VEHICLE_REGISTRATION (age tag), US_SSN (area/group/serial rules + denylist)
- **External library**: `phonenumbers` (PhoneRecognizer)
- **NER**: 6 model-driven recognizers (spaCy, Stanza, Transformers, HF direct, Medical NER, GLiNER)
- **Remote / LLM**: 5 service-based recognizers (Azure AI Language, AHDS, LangExtract family)
- **Context**: every `PatternRecognizer` carries a context word list consumed by the `LemmaContextAwareEnhancer`

### A.6 Languages registered in default YAML

`en`, `es`, `it`, `pl`, `de`, `fi`, `sv`, `ko` (+ `kr` alias for KrPassport),
`th`, `tr`, `fr` (CA_SIN). NER-driven recognizers cover any language their
underlying model supports; multilingual configs ship at
`spacy_multilingual.yaml` and `stanza_multilingual.yaml`.

### A.7 Notable absences (gap signals)

- **Bitcoin only** for crypto wallets — no Ethereum (`0x…`), Solana, Monero, etc.
- **No SWIFT/BIC** recognizer despite 70-country IBAN coverage
- **No driver's license** recognizer for FR, AU (US, UK, IT, KR exist)
- **No native ZIP/postal recognizer** outside DE/UK (sample YAML shows a custom one)
- `DATE_TIME` is **produced by both** the regex `DateRecognizer` and every NER recognizer — overlapping entity types
- A handful of recognizers (`ABA_ROUTING_NUMBER`, `SG_UEN`, `FI_PERSONAL_IDENTITY_CODE`) **exist as classes but are absent from the YAML registry and/or the public supported-entities doc**

---

## B. Analyzer engine (orchestration + pipeline)

### B.1 `AnalyzerEngine`

10-step pipeline per `analyze()` call:

1. Resolve language + recognizer set (+ ad-hoc)
2. Run NLP `process_text(text, language)` → `NlpArtifacts` (skipped if caller supplied)
3. Trace artifacts when `log_decision_process=True`
4. Per recognizer: `recognizer.analyze(text, entities, nlp_artifacts)`; aggregate
5. Inject `recognizer_identifier` + `recognizer_name` into each result's metadata
6. Per-recognizer self-enhancement via `enhance_using_context(...)` (default no-op; overridable)
7. Global enhancement via `context_aware_enhancer.enhance_using_context(...)`
8. Allow-list filtering
9. Deduplication via `EntityRecognizer.remove_duplicates(results)`
10. Low-score filter using `score_threshold ?? default_score_threshold`; strip `analysis_explanation` unless `return_decision_process=True`

### B.2 `analyze()` API

Knobs (per request): `text`, `language`, `entities`, `correlation_id`,
`score_threshold`, `return_decision_process`, **`ad_hoc_recognizers`**
(single-call recognizer injection), `context` (extra context words at call
time), `allow_list`, **`allow_list_match`** (`"exact"` or `"regex"`),
`regex_flags`, `nlp_artifacts` (pre-computed).

### B.3 Allow-list / deny-list

- **Allow-list** is engine-level on `analyze`. Modes: `"exact"` (set membership) or `"regex"` (joined with `|`, compiled with request flags, with per-pattern timeout).
- **Deny-list** is recognizer-level on `PatternRecognizer(deny_list=...)`. Wrapped in word-boundary lookarounds and scored at `deny_list_score` (default `1.0`).

### B.4 Score thresholds

- Single engine-level `default_score_threshold`; per-call `score_threshold` override.
- **No per-entity threshold map.** All entities share the same threshold per call.

### B.5 Decision-process tracing

- `AppTracer` (built-in audit hook, **distinct from Python logger**) writes NLP artifacts + result JSON keyed by `correlation_id`.
- Independent of `return_decision_process` — call-side logging vs response payload are decoupled.

### B.6 `BatchAnalyzerEngine`

- `analyze_iterator(texts, language, batch_size, n_process, **kwargs)` — uses `nlp_engine.process_batch(...)` for spaCy/Stanza efficiency; then per-text `analyze`.
- `analyze_dict(input_dict, language, keys_to_skip, batch_size, n_process, **kwargs)` — recurses nested dicts. **Auto-promotes dict keys to context words**, so `{"ssn": "..."}` boosts a weak SSN regex hit automatically.

### B.7 Pattern recognizer features

- `Pattern` = `{name, regex, score ∈ [0,1]}`, JSON-serializable.
- `PatternRecognizer(supported_entity, name, supported_language, patterns, deny_list, context, deny_list_score, global_regex_flags, version, country_code)`. Requires `patterns` *or* `deny_list`.
- Uses **third-party `regex` module** (not stdlib `re`) — supports `\p{...}`, atomic groups.
- **Regex timeout** out of the box: every pattern run wraps in `REGEX_TIMEOUT_SECONDS` (default 60s). On timeout the pattern is logged and skipped.
- `validate_result(text)` returns:
  - `True` → score forced to `MAX_SCORE` (checksum-pass)
  - `False` → score forced to `MIN_SCORE` (checksum-fail)
  - `None` → leave score alone
- `invalidate_result(text)` truthy → score forced to `MIN_SCORE`, result dropped
- `country_code` is reconciled against class-level `COUNTRY_CODE` ClassVar; mismatch raises

### B.8 `EntityRecognizer` base + class tree

- Constants: `MIN_SCORE=0`, `MAX_SCORE=1.0`, `COUNTRY_CODE: ClassVar[Optional[str]]`
- Subclass tree: `EntityRecognizer` → `LocalRecognizer` + `RemoteRecognizer` (first-class abstraction for delegating detection to a network service); `PatternRecognizer` extends `LocalRecognizer`
- No `score_threshold` field on the recognizer — engine-level only

### B.9 `RecognizerRegistry`

- `load_predefined_recognizers(languages, nlp_engine, countries)` with `countries` filter (skip locale-agnostic exempted)
- `add_recognizer`, `remove_recognizer(name, language=None)` — no in-place update; remove + re-add
- `add_pattern_recognizer_from_dict(dict)` and `add_recognizers_from_yaml(path)`
- Each recognizer instance is bound to a **single language**; loader fans out per language for custom recognizers
- `get_country_codes()` enumerates loaded recognizers

### B.10 YAML configuration system (no-code config)

**Three layered config files** with explicit precedence (inline > per-section file > defaults):

1. `default_analyzer_full.yaml` — top-level engine YAML (supported_languages, default_score_threshold, inline `nlp_configuration` + inline `recognizer_registry`)
2. `default.yaml` / NLP YAML — NLP engine + `NerModelConfiguration`
3. `default_recognizers.yaml` — registry entries

Recognizer YAML entry keys: `name`, `class_name`, `type` (`predefined` or `custom`),
**`enabled`** (bool — lets ops disable noisy recognizers without code),
`supported_languages` (list **or** list of `{language, context}` dicts —
per-language context!), `supported_language` (legacy), `supported_entity`,
`patterns`, `deny_list`, `context`, **`country_code`**, `config_path` (external
file, used by LangExtract).

Engine-level YAML supports:

- `nlp_configuration` block with full `NerModelConfiguration` (labels_to_ignore, aggregation_strategy, stride, alignment_mode, model_to_presidio_entity_mapping, low_confidence_score_multiplier, low_score_entity_names)
- For transformers: `model_name` is a dict `{spacy: ..., transformers: ...}`
- `supported_countries: [us, uk]` filters which country packs load

Env-var overrides: `ANALYZER_CONF_FILE`, `NLP_CONF_FILE`, `RECOGNIZER_REGISTRY_CONF_FILE`.

### B.11 Context-aware enhancement

`LemmaContextAwareEnhancer(context_similarity_factor=0.35, min_score_with_context_similarity=0.4, context_prefix_count=5, context_suffix_count=0, context_matching_mode="substring" | "whole_word")`.

- Window: **5 lemmas before, 0 after** (asymmetric — biased to left-context indicators)
- Matching modes: case-insensitive substring or whole-word
- Scoring math when supportive word found: `score = clamp(score + 0.35, min=0.4, max=1.0)`
- Skip conditions: missing `RECOGNIZER_IDENTIFIER_KEY` metadata, empty recognizer context list, or `IS_SCORE_ENHANCED_BY_CONTEXT_KEY` already set
- Records `supportive_context_word` and `score_context_improvement` delta in `AnalysisExplanation`
- External context kwarg from `analyze()` is appended to window lemmas

### B.12 NLP engine abstraction

Required interface (`NlpEngine` ABC): `load()`, `is_loaded()`, `process_text()`, `process_batch()`, `is_stopword()`, `is_punct()`, `get_supported_entities()`, `get_supported_languages()`.

Bundled engines:

- `SpacyNlpEngine` (default `en_core_web_lg`)
- `StanzaNlpEngine` (Stanza via `spacy-stanza`)
- `TransformersNlpEngine` (spaCy for tokens/lemmas/POS + HF for NER via `spacy-huggingface-pipelines`)
- `SlimSpacyNlpEngine` (lightweight, generic tokenizer)

Bundled HF models in default configs: `obi/deid_roberta_i2b2` (default), `StanfordAIMI/stanford-deidentifier-base` (transformers.yaml), `dslim/bert-base-NER-uncased` (label-mapping docs).

`NlpArtifacts` per text: entities (spans), tokens, token character offsets, lemmas, scores, computed keywords, nlp_engine back-ref.

### B.13 `AnalysisExplanation` / decision process

Fields: `recognizer`, `original_score`, `pattern_name`, `pattern`, `validation_result`, `textual_explanation`, `regex_flags`, `score`, `score_context_improvement`, `supportive_context_word`. Methods: `set_improved_score`, `set_supportive_context_word`, `append_textual_explanation_line`, `to_dict`.

### B.14 `RecognizerResult` + conflict resolution

Fields: `entity_type`, `start`, `end`, `score`, `analysis_explanation`, `recognition_metadata`. Metadata keys: `RECOGNIZER_NAME_KEY`, `RECOGNIZER_IDENTIFIER_KEY`, `IS_SCORE_ENHANCED_BY_CONTEXT_KEY`.

Span methods: `intersects`, `contained_in`, `contains`, `equal_indices`, `has_conflict`.

Engine-level dedup (`EntityRecognizer.remove_duplicates`):

- Drops zero-score entries
- Drops equal results
- Drops results contained in another result **of the same entity_type only** (longer hit wins same-type containment)
- **No cross-type overlap removal** — PHONE inside URL both survive

### B.15 Confidence scoring summary

- Range: `[0, 1]`
- `Pattern.score` per-pattern, in `[0, 1]`
- NER `default_score=0.85` fallback
- Deny-list default `1.0`
- Validator `True/False` clamps to `MAX_SCORE`/`MIN_SCORE` (checksum-strong full confidence even with weak regex)
- Context boost: `+0.35`, floor `0.4`, cap `1.0` (defaults)
- Score 0 results are silently dropped

---

## C. Transformation — anonymizer operators

### C.1 Anonymizers (8)

| Operator | Class | Parameters | Reversible | Notes |
|---|---|---|---|---|
| `replace` (engine default) | `Replace` | `new_value: str` (falls back to `<ENTITY_TYPE>` if empty) | No | |
| `redact` | `Redact` | none | No | Returns empty string |
| `mask` | `Mask` | `masking_char` (**single char only**), `chars_to_mask`, `from_end` | No | `from_end=True` for PAN/phone tail-mask |
| `hash` | `Hash` | `hash_type` (`sha256` or `sha512`), optional `salt` (must be ≥16 bytes if supplied) | No | **No HMAC, BLAKE, Argon2, bcrypt, SHA-1/3, MD-family.** Default salt = per-call `os.urandom(32)` not returned to caller, so unsalted hashes are **non-joinable across runs**. Hex digest, no algorithm prefix. |
| `encrypt` | `Encrypt` | `key` (128/192/256-bit raw bytes or UTF-8 str) | **Yes** | AES-CBC + PKCS7 + random 16-byte IV prepended, URL-safe base64. **No KDF, no HMAC/GCM/SIV, no AAD, no algorithm tag, no version byte.** Ciphertext is malleable. |
| `keep` | `Keep` | none | n/a | No-op — surfaces span in `EngineResult.items` for audit without modifying text |
| `custom` | `Custom` | `lambda: Callable[[str], str]` | Caller's choice | Validator only checks `callable(...)` — deliberately does NOT invoke the lambda (so stateful closures e.g. token-vault lookups survive validation) |
| `surrogate_ahds` (optional Azure extra) | `AHDSSurrogate` | `endpoint`, `entities`, `input_locale`, `surrogate_locale` | No | Azure Health Data Services REST → realistic synthetic replacements (real-looking but fake patient names/dates/addresses). Carries ~80-entry Presidio→PhiCategory mapping. |

### C.2 Deanonymizers (2)

| Operator | Class | Reverses | Notes |
|---|---|---|---|
| `decrypt` | `Decrypt` | `encrypt` | AES-CBC decryption with same key |
| `deanonymize_keep` | `DeanonymizeKeep` | `keep` | No-op mirror of `Keep` |

### C.3 Custom operator extension model

Two paths:

1. **Per-call lambda** via `OperatorConfig("custom", {"lambda": fn})` — typical pattern for stateful pseudonymization (closure mapping original→token).
2. **Subclass + register**: `AnonymizerEngine.add_anonymizer(cls)` / `remove_anonymizer(cls)`, mirrored on `DeanonymizeEngine`. Implement `Operator.operate`, `validate`, `operator_name`, `operator_type`.

`OperatorsFactory` is **instance-scoped per engine** (not process-global).

### C.4 `AnonymizerEngine` features

- **Default operator fallback**: if `operators` dict lacks the entity, check `"DEFAULT"` key; if absent, insert `replace` → produces `<ENTITY_TYPE>` tags. So `engine.anonymize(text, results)` works with no operators map.
- **Sort + deep copy**: caller's `analyzer_results` not mutated; sorted `(start, end)` before merge logic
- **Adjacent-span merging** (`merge_entities_with_spaces=True`, default): merges same-type entities separated by whitespace
- **Conflict resolution** (`ConflictResolutionStrategy`):
  - `MERGE_SIMILAR_OR_CONTAINED` (default) — two-phase: same-type union merge → drop conflicted results
  - `REMOVE_INTERSECTIONS` — additionally trim partial overlaps (shrink lower-scoring span)
  - `NONE` — **documented in docstring but not defined in enum body** (source inconsistency)

### C.5 `BatchAnonymizerEngine`

- `anonymize_list(texts, recognizer_results_list, **kwargs)` — sequential loop, no parallelism. Coerces bool/int/float to str.
- `anonymize_dict(analyzer_results: Iterable[DictRecognizerResult])` — recurses nested dicts, dispatches lists to `anonymize_list`.
- **No batch deanonymizer engine.** Deanonymize is single-text only.

### C.6 Notable absences (gap signals)

- **No format-preserving encryption** (FPE) operator
- **No tokenization with built-in vault**
- **No HMAC / keyed-hash** operator
- **No k-anonymity / generalization** (no date-shift, age-bucket, zip-truncate)
- **No differential-privacy noise** operator
- **AES-CBC without authentication** — no GCM/SIV/AEAD option
- **Mask is single-character only** — can't use `"**"` as a unit
- **Batch is sequential**, no async / multiprocessing

---

## D. Image redaction

### D.1 Input formats

- `PIL.Image.Image` (PNG, JPEG, BMP, GIF, TIFF, WebP via Pillow codecs)
- Tesseract path: also accepts `numpy.ndarray` or file-path string
- Azure Document Intelligence path: also accepts raw `bytes`
- DICOM: `pydicom.dataset.FileDataset` via separate engine
- **No PDF, no video, no multi-frame** (except DICOM)

### D.2 OCR backends (pluggable behind `OCR` ABC)

| Backend | Class | Notes |
|---|---|---|
| **Tesseract** (default) | `TesseractOCR` | Wraps `pytesseract.image_to_data`. Requires native Tesseract install. |
| **Azure Document Intelligence** (cloud) | `DocumentIntelligenceOCR` | Env: `DOCUMENT_INTELLIGENCE_ENDPOINT`, `DOCUMENT_INTELLIGENCE_KEY`. **Single-page only.** |

`DocumentIntelligenceOCR` exposes 9 prebuilt model IDs: `prebuilt-document` (default), `prebuilt-read`, `prebuilt-layout`, `prebuilt-contract`, `prebuilt-healthInsuranceCard.us`, `prebuilt-invoice`, `prebuilt-receipt`, `prebuilt-idDocument`, `prebuilt-businessCard`.

Custom backends: subclass `OCR`, pass to `ImageAnalyzerEngine(ocr=...)`.

**OCR contract leaks Tesseract shape** — every backend must reshape its output to Tesseract-style parallel lists `{left, top, width, height, conf, text}`. Document Intelligence layout/lines/paragraphs/tables are discarded.

### D.3 Redaction methods

- **Solid fill rectangle only** via `PIL.ImageDraw.Draw.rectangle(fill=...)`
- `fill` = grayscale int or RGB tuple; default black `(0,0,0)`
- DICOM: `fill = "contrast" | "background"`, derived from image corner crop
- **No blur, pixelation, mosaic, or inpainting**

### D.4 Preprocessing (pluggable, improves OCR — doesn't redact)

`ImagePreprocessor` interface + concrete classes:

- `BilateralFilter` (cv2 grayscale bilateral)
- `SegmentedAdaptiveThreshold` (cv2 adaptive thresholding)
- `ImageRescaling` (cv2 resize for very small/large images)
- `ContrastSegmentedImageEnhancer` (full pipeline: bilateral + contrast + adaptive threshold + Otsu + rescale)

`ImageAnalyzerEngine` tracks `scale_factor` and back-scales OCR bboxes to the original pixel space.

### D.5 DICOM support (`DicomImageRedactorEngine`)

**Scope:**

- Scrubs **pixel data only** — DICOM metadata tags are explicitly OUT OF SCOPE (docs say so)
- Tags scrubbed are detected by **case-insensitive substring on `element.name`**: looks for `"name"` and `"patient"` in the human-readable element name. Catches `PatientName`, `PatientID`, `PatientBirthDate`, `OtherPatientNames`, `ReferringPhysicianName`, `PerformingPhysicianName`, `OperatorsName`. **Misses `InstitutionName`, `AccessionNumber`, `StudyID`.**
- All values from name-tagged + patient-tagged elements become an ad-hoc `PatternRecognizer` over the OCR'd pixel-data text

**Augmentation:** each name token is exploded into 4 casings (original/UPPER/lower/Title), each split on whitespace; `^` and `-` collapsed to space (PN VR component separator). Adds generic PHI list `["[M]", "[F]", "[X]", "[U]", "M", "F", "X", "U"]`.

**Pixel pipeline:** grayscale via `PhotometricInterpretation`, VOI LUT, padding (default 25 px), corner-crop fill color (default `crop_ratio=0.75`), recompress to `YBR_FULL` if source was YBR. Hard dep on `python-gdcm`.

**Bulk DICOM APIs:**

- `redact_from_file(input, output_dir)` — single file (copies first)
- `redact_from_directory(input_dir, output_dir)` — sequential glob for `*.dcm`/`*.dicom`. **No parallelism.**
- Both support `save_bboxes=True` (JSON sidecars)

### D.6 Bounding box API

- `ImageRedactorEngine.redact(image, fill, ocr_kwargs, ad_hoc_recognizers, **text_analyzer_kwargs) -> Image`
- `redact_and_return_bbox(image, ...) -> (Image, List[ImageRecognizerResult])`
- `ImageRecognizerResult` extends `RecognizerResult` with `left, top, width, height`
- `ocr_kwargs={"ocr_threshold": 60.0}` — OCR confidence filter
- `allow_list` exempts strings
- `ad_hoc_recognizers` accepts `PatternRecognizer` list (DICOM engine uses this internally)

`BboxProcessor` (static utility): `get_bboxes_from_ocr_results`, `get_bboxes_from_analyzer_results`, `remove_bbox_padding`, `match_with_source` (eval tooling).

### D.7 PII verify workflow

`get_pii_bboxes(ocr_bboxes, analyzer_bboxes)` + `add_custom_bboxes(image, bboxes, ...)` produce a Matplotlib overlay (red for PII, blue for non-PII OCR words) — debugging / labeling visualization. `ImagePiiVerifyEngine` + `DicomImagePiiVerifyEngine` wrap this.

### D.8 Notable absences (gap signals)

- **No bbox merging / NMS / overlap suppression** — multi-word entities produce N separate rectangles
- **No PDF support**
- **No async APIs** — Azure Document Intelligence client used synchronously
- **No streaming**
- **DICOM metadata scrubbing out of scope** — half-story for de-id
- Package is still **beta** (version `0.0.58`)
- **Heavy native deps for "just redaction"**: OpenCV, pydicom, GDCM, matplotlib, Azure Form Recognizer, pytesseract, pypng

---

## E. Structured data redaction

### E.1 Inputs

| Input | Builder | Processor |
|---|---|---|
| `pandas.DataFrame` | `PandasAnalysisBuilder` | `PandasDataProcessor` |
| `dict` (JSON-shaped, arbitrary nesting) | `JsonAnalysisBuilder` | `JsonDataProcessor` |
| CSV file | `CsvReader.read(path)` (thin `pd.read_csv`) | Pandas path |
| JSON file | `JsonReader.read(path)` (thin `json.load`) | JSON path |

**Explicitly NOT supported**: PySpark, Parquet, Arrow, Avro, ORC, Polars, SQL row iterators, streaming readers.

### E.2 Schema analysis

- **No dtype / column-type inference** — entity-based.
- `PandasAnalysisBuilder.generate_analysis(df, n=None, language, selection_strategy="most_common", mixed_strategy_threshold=0.5)`
  - Samples `n` rows (default = all rows), `random_state=123`
  - Analyzes each column independently via `BatchAnalyzerEngine.analyze_iterator`
  - **Three column-level selection strategies**:
    - `"most_common"` — most frequent entity type wins (score = proportion)
    - `"highest_confidence"` — single highest score across cells
    - `"mixed"` — highest-confidence if above threshold, else most-common
  - Columns with no detection tagged `NON_PII` and excluded
- `JsonAnalysisBuilder.generate_analysis(data, language)`
  - `batch_analyzer.analyze_dict(...)` on whole dict; recurses via dotted keys (`"user.address.city"`)
  - **Always uses the FIRST `RecognizerResult` per key** (no strategy selection — silently first-result-wins)

Both forward `n_process` and `batch_size` to `BatchAnalyzerEngine`. Result is `StructuredAnalysis(entity_mapping: dict[str, str])`.

### E.3 Tabular vs nested handling

- **Pandas**: row-major Python — `df.itertuples()` + `df.at[row.Index, key] = operated_text`. **No vectorization** — will be slow on large frames.
- **JSON**: dotted-path navigation with list-index support. Sets back at same path.

### E.4 Operators on structured data

Delegates to `presidio_anonymizer.operators.OperatorsFactory` — supports all anonymize operators (replace, redact, hash, mask, encrypt, keep, custom). **`OperatorType.Anonymize` is hardcoded** → deanonymization is NOT wired through structured engine, even though the operator exists.

`"DEFAULT"` operator auto-inserted as `replace` if caller doesn't supply one.

---

## F. REST APIs

Three Flask services served by `gunicorn` (Linux/macOS) or `waitress` (Windows). Container port `3000`, compose maps to host `5001/5002/5003`. JSON errors uniform: `{ "error": "..." }`.

### F.1 Analyzer

| Method | Path | Notes |
|---|---|---|
| `GET /health` | "Presidio Analyzer service is up" |
| `POST /analyze` | `AnalyzerRequest`: `text` (string OR list), `language`, `correlation_id`, `score_threshold`, `entities`, `return_decision_process`, `ad_hoc_recognizers`, `context`, `allow_list`, `allow_list_match`, `regex_flags`. Returns array (or array-of-arrays) of `RecognizerResult` |
| `GET /recognizers?language=...` | List loaded recognizer class names |
| `GET /supportedentities?language=...` | Entity type strings |

Env: `PORT`, `BATCH_SIZE` (500), `N_PROCESS` (1), `LOG_LEVEL`, `ANALYZER_CONF_FILE`, `NLP_CONF_FILE`, `RECOGNIZER_REGISTRY_CONF_FILE`.

### F.2 Anonymizer

| Method | Path | Notes |
|---|---|---|
| `GET /health` | — |
| `POST /anonymize` | `text`, `analyzer_results[]`, `anonymizers` map keyed by entity type (or `DEFAULT`) using any operator |
| `POST /deanonymize` | `text`, `anonymizer_results[]`, `deanonymizers` map |
| `GET /anonymizers` | List anonymize operator names |
| `GET /deanonymizers` | List deanonymize operator names |

Errors: `InvalidParamError → 422`, `HTTPException → e.code`, fallback `500`.

### F.3 Image redactor

| Method | Path | Notes |
|---|---|---|
| `GET /health` | — |
| `POST /redact` | Mode A: JSON body with base64 image + optional `analyzer_entities`. Mode B: multipart upload + `data` JSON (fixed `score_threshold=0.4`). Returns `application/octet-stream`. `422` on invalid, `500` on error |

### F.4 Notable absences

- **No `/metrics` endpoint** anywhere
- **No version endpoint**
- **No readiness/liveness distinction** beyond single `/health`
- **`correlation_id` is accepted but NOT propagated** to logs

---

## G. Python SDK (4 PyPI packages + CLI)

All MIT-licensed, Python 3.10–3.13. **Class-based API only — no shortcut functions.** Each `__init__.py` exports classes via `__all__`.

### G.1 `presidio-analyzer`

Hard deps: `spacy`, `regex`, `tldextract`, `pyyaml`, `phonenumbers`, `pydantic`.

Exports: `AnalyzerEngine`, `BatchAnalyzerEngine`, `AnalyzerEngineProvider`, `AnalyzerRequest`, `EntityRecognizer`, `LocalRecognizer`, `PatternRecognizer`, `RemoteRecognizer`, `LMRecognizer`, `RecognizerRegistry`, `Pattern`, `AnalysisExplanation`, `RecognizerResult`, `DictAnalyzerResult`, `ContextAwareEnhancer`, `LemmaContextAwareEnhancer`.

Extras: `server`, `transformers`, `stanza`, `azure-ai-language`, `ahds`, `gliner`, `langextract`.

### G.2 `presidio-anonymizer`

Hard dep: `cryptography>=46`. Exports: `AnonymizerEngine`, `DeanonymizeEngine`, `BatchAnonymizerEngine`, `RecognizerResult`, `EngineResult`, `DictRecognizerResult`, `OperatorResult`, `PIIEntity`, `OperatorConfig`, `ConflictResolutionStrategy`, `InvalidParamError`. Extras: `server`, `ahds`.

### G.3 `presidio-image-redactor`

Hard deps: `pillow`, `matplotlib`, `pypng`, `pytesseract`, `opencv-python`, `pydicom`, `python-gdcm`. Optional: `azure-ai-formrecognizer`.

Exports: `OCR`, `TesseractOCR`, `DocumentIntelligenceOCR`, `ImageAnalyzerEngine`, `ImageRedactorEngine`, `ImagePiiVerifyEngine`, `DicomImageRedactorEngine`, `DicomImagePiiVerifyEngine`, `BboxProcessor`, `ImagePreprocessor`, `ContrastSegmentedImageEnhancer`, `BilateralFilter`, `SegmentedAdaptiveThreshold`, `ImageRescaling`.

### G.4 `presidio-structured`

Hard dep: `pandas>=1.5`. Exports: `StructuredEngine`, `JsonAnalysisBuilder`, `PandasAnalysisBuilder`, `StructuredAnalysis`, `CsvReader`, `JsonReader`, `PandasDataProcessor`, `JsonDataProcessor`.

### G.5 `presidio-cli` (separate, not in main release wave)

Executable `presidio` scans files/directories. Output formats: `standard`, `github` (Actions annotations), `colored`, `parsable` (JSON-style), `auto`. Config via `.presidiocli` YAML (`language`, `entities`, `ignore`, `allow`).

---

## H. Deployment artifacts

### H.1 Dockerfiles

Per-package:

- `presidio-analyzer`: `Dockerfile`, `Dockerfile.dev`, `Dockerfile.stanza`, `Dockerfile.transformers`, `Dockerfile.windows` — **5 variants** switching NLP backend at build time
- `presidio-anonymizer`: `Dockerfile`, `Dockerfile.dev`, `Dockerfile.windows`
- `presidio-image-redactor`: `Dockerfile`, `Dockerfile.dev`
- `presidio-structured`, `presidio-cli`: library-only

Each service ships `entrypoint.sh` and (analyzer/anonymizer) `logging.ini`.

### H.2 docker-compose files

- `docker-compose.yml` — analyzer + anonymizer + image + **`ollama/ollama:latest` sidecar** (analyzer waits on `ollama service_healthy` so LangExtract works locally)
- `docker-compose-text.yml` — text services only
- `docker-compose-image.yml` — image redactor only
- `docker-compose-transformers.yml` — analyzer with `Dockerfile.transformers` + `NLP_CONF_FILE=presidio_analyzer/conf/transformers.yaml`

Images: `${REGISTRY_NAME}/${IMAGE_PREFIX}presidio-{service}${TAG}` defaulting to `mcr.microsoft.com/presidio-{service}`.

### H.3 Kubernetes / Helm

Helm chart at `docs/samples/deployments/k8s/charts/presidio/`:

- 3 Deployments + 3 Services + 1 Ingress (`nginx`, on by default)
- `NOTES.txt`, `_helpers.tpl`
- **NO** ConfigMaps, Secrets, HPAs, ServiceAccounts, NetworkPolicies, PDBs
- AKS-targeted; values override registry/tag
- Scripts: `deploy-presidio.sh`, `run-with-kind.sh` (local KIND)

### H.4 Azure deployment templates

- Per-service `deploytoazure.json` (ARM) — one-click "Deploy to Azure" buttons
- App Service: `presidio-app-service.json`, `presidio-services.json`, `values.json` (Web Apps, IP allow, Log Analytics opt-in for `AppServicePlatformLogs`/`AppServiceConsoleLogs`)
- Data Factory: ARM + gallery templates (HTTP-service + Databricks variants)
- Spark/Databricks: ARM + init script + `configure_databricks.sh` + notebooks

### H.5 Postman collections

`docs/samples/docker/`: `PresidioAnalyzer.postman_collection.json`, `PresidioAnonymizer.postman_collection.json`.

### H.6 OpenAPI

`docs/api-docs/api-docs.yml` — OpenAPI 3.

### H.7 Release & CI

- **Workflow**: `workflow_dispatch` only (no tag/push auto-release)
- Per release: draft GitHub release (`--latest`), 5 PyPI packages via OIDC trusted publishing (`skip-existing: true`), 3 Docker images to ACR
- **Native ARM64**: `ubuntu-24.04-arm` runners, no QEMU. Multi-arch `linux/amd64` + `linux/arm64`. **SBOM + max-mode provenance attestations** every push.
- Image-redactor versioned **independently** of analyzer/anonymizer/structured
- Cadence: ~1.5–3 months per release (Mar/Jul/Sep 2025, Feb/Mar 2026). Hotfixes within days when needed.

---

## I. Observability & telemetry

**In-process observability: essentially absent.**

- `logging.ini` — plain Python `logging.config` INI: console-handler to stdout, `INFO` level. **No JSON / structured logging.**
- Each `__init__.py` attaches a `NullHandler` (stdlib convention).
- Analyzer has a separate `decision_process` logger (StreamHandler) gated behind `return_decision_process` per request.
- **No OpenTelemetry, Prometheus, statsd, Sentry, or App Insights SDK** in any `pyproject.toml`. No `/metrics` endpoint. No emitted counters/histograms.
- **`correlation_id` is accepted but NOT propagated to logs**.

**Sample only**: `docs/samples/deployments/redacting-telemetry/` is a *proof-of-concept demo* where the *user's app* sends logs through OTel Collector → Loki/Tempo → Grafana, calling Presidio HTTP to redact before emission. Stack: OTel Collector (4317/4318), Loki (3100), Tempo (3200), Grafana (3000), FastAPI `pii-demo-app`. **Presidio is the redactor, not an emitter.**

---

## J. Configuration system

### J.1 YAML config (layered)

- `ANALYZER_CONF_FILE`, `NLP_CONF_FILE`, `RECOGNIZER_REGISTRY_CONF_FILE` — env-var overrides on the analyzer service
- NLP keys: `nlp_engine_name` (`spacy|transformers|stanza`), `models[]` with `lang_code`/`model_name`, full `NerModelConfiguration` block
- `presidio_analyzer/conf/transformers.yaml` for transformers-backed default
- CLI: `.presidiocli` YAML (`language`, `entities`, `ignore`, `allow`)

### J.2 Environment variables

| Variable | Default | Service |
|---|---|---|
| `PORT` | 3000 | All HTTP services |
| `LOG_LEVEL` | — | All HTTP services |
| `BATCH_SIZE` | 500 | Analyzer |
| `N_PROCESS` | 1 | Analyzer |
| `ANALYZER_CONF_FILE`, `NLP_CONF_FILE`, `RECOGNIZER_REGISTRY_CONF_FILE` | — | Analyzer |
| `OLLAMA_HOST` | e.g., `http://ollama:11434` | Analyzer (LangExtract) |
| `AHDS_ENDPOINT` | — | AHDS surrogate |
| `ENV` | `production` | Flips credential chain (`development` → `DefaultAzureCredential`) |
| `DOCUMENT_INTELLIGENCE_ENDPOINT`, `DOCUMENT_INTELLIGENCE_KEY` | — | Image redactor (Azure backend) |
| `REGEX_TIMEOUT_SECONDS` | 60 | Analyzer (regex safety net) |

### J.3 Not provided

- No central runtime registry, no hot-reload, no ConfigMap/Secret integration in the Helm chart, no feature flags

---

## K. Sample integrations (the breadth)

### K.1 Core text usage notebooks (`docs/samples/python/`)

- `presidio_notebook.ipynb`, `customizing_presidio_analyzer.ipynb`
- `ner_model_configuration.ipynb`, `no_code_config.ipynb` (YAML-driven)
- `encrypt_decrypt.ipynb`, `pseudonymization.ipynb`
- `getting_entity_values.ipynb` (custom Operator)
- `Anonymizing known values.ipynb`, `keep_entities.ipynb`
- `integrating_with_external_services.ipynb`
- `synth_data_with_openai.ipynb` (OpenAI synthetic replacement)
- `batch_processing.ipynb`, `process_csv_file.py`, `example_structured.ipynb`

### K.2 Image / PDF / DICOM

- `example_dicom_image_redactor.ipynb`, `example_dicom_redactor_evaluation.ipynb`
- `image_redaction_allow_list_approach.ipynb`
- `plot_custom_bboxes.ipynb`
- `example_pdf_annotation.ipynb`

### K.3 External / remote recognizers (Python files)

- `flair_recognizer.py` (Flair NLP)
- `transformers_recognizer/` (HF)
- `span_marker_recognizer.py` (SpanMarker NER)
- `gliner.md`, `langextract/`
- `text_analytics/`, `ahds/` (Azure AI Language + AHDS)
- `example_remote_recognizer.py` (generic remote pattern)
- `example_custom_lambda_anonymizer.py` (Faker)

### K.4 Cross-service / proxy patterns

- `docs/samples/docker/litellm.md` — LiteLLM proxy redacting LLM prompts/responses

### K.5 Deployment patterns (`docs/samples/deployments/`)

- `app-service/` — Azure App Service (one-click + scripted)
- `k8s/` — Helm + KIND
- `data-factory/` — three ETL routes
- `spark/` — Azure Databricks + Blob Storage + pandas UDF distributed PII masking
- `redacting-telemetry/` — full OTel stack demo (described above)
- `openai-anonymaztion-and-deanonymaztion-best-practices/` ("Invisio") — AKS API + Redis session store + Bicep IaC + Streamlit spike + custom `InstanceCounterAnonymizer`/`InstanceCounterDeanonymizer` for stable cross-call mapping

### K.6 Microsoft Fabric + Streamlit

- `docs/samples/fabric/` — Spark PII detection in Fabric notebooks → Delta Lake
- `docs/samples/python/streamlit/` — multi-file Streamlit demo with its own Dockerfile

---

## L. LLM integrations (consolidated)

Two distinct shapes:

1. **LLM as a recognizer (inside the analyzer)**
   - `LangExtractRecognizer` family — `BasicLangExtractRecognizer` (generic provider, default points to Ollama) + `AzureOpenAILangExtractRecognizer`
   - Prompt YAML at `conf/langextract_config_*.yaml`
   - Ollama is a **first-class compose dep** of the default stack (`docker-compose.yml` waits on `service_healthy`)
   - Extras: `langextract`, `openai`, `azure-identity`, `more-itertools`, `jinja2`
   - GLiNER (zero-shot NER) via `onnxruntime`, bundled in `slim.yaml`
   - Transformers NER (StanfordAIMI, obi/deid_roberta_i2b2, blaze999/Medical-NER)

2. **LLM as a downstream consumer (Presidio as protection layer)**
   - LiteLLM proxy sample — redacts prompts/responses around third-party LLM calls
   - "Invisio" OpenAI AKS reference (Redis-backed session-stable pseudonymization)
   - `synth_data_with_openai.ipynb` for realistic fake replacements

---

## M. Licensing

- Repository + all four packages: **MIT**. CI dependency review allows transitive MIT / Apache-2.0 / BSD-3-Clause / 0BSD.
- **User-bears-risk caveats**: spaCy models vary (en_core_web_lg MIT, some non-EN models CC-BY-SA-3.0 or GPL); Stanza Apache-2.0 but models CC-BY-SA-4.0; Transformers model licenses depend on hub author; Tesseract Apache-2.0; `python-gdcm` BSD-style; Azure SDKs MIT but require Azure account; OpenAI integration implies OpenAI terms.

---

## N. Versioning summary

- **Current line**: `2.2.x` — most recent stable **2.2.362** (2026-03-15)
- Image redactor versioned independently
- Cadence: ~1.5–3 months per release; hotfixes within days when needed
- Trigger: `workflow_dispatch` only, no auto-release
- No formal breaking-change policy in repo. Last documented architectural reset: `docs/presidio_V2.md`

---

## O. The thing-by-thing index for octarine comparison

For each section below, the gap-mapping is **"does octarine have an equivalent? if not, conscious decline or known gap?"** — that's the next step (a separate audit using this list as input).

Surface areas to map against octarine:

1. **Identifier coverage** (A.1–A.5) — entity-by-entity. Special attention to:
   - Country packs (DE, US, IN, UK, IT, KR, AU, ES, TR, SE, SG, NG, CA, FI, PL, TH)
   - Algorithmic validators per identifier (Luhn / Verhoeff / ISO 7064 / mod-11 / DEA / MRZ / ABA / GSTIN / Bech32m / etc.)
   - Phone via `phonenumbers` (likely already covered)
   - IBAN 70-country list (likely already covered)
2. **NLP / NER integration** (B.12, A.3) — spaCy / Stanza / Transformers / GLiNER plug-ins, NerModelConfiguration mapping, medical NER
3. **Context-aware enhancement** (B.11) — `LemmaContextAwareEnhancer` math (`+0.35`, floor `0.4`, cap `1.0`), per-recognizer context lists, dict-key auto-promotion
4. **YAML no-code config** (B.10, J.1) — three-file layered config, `enabled` flag, per-language context, country filtering, ad-hoc recognizers per request
5. **Pipeline features** (B.1–B.7) — regex timeout, `validate_result`/`invalidate_result` hooks, `RemoteRecognizer` abstraction, ad-hoc recognizers per call, `BatchAnalyzerEngine.analyze_dict` with key→context promotion, allow-list (`exact`/`regex` modes), `AnalysisExplanation` decision-process trace, `AppTracer` audit hook
6. **Conflict resolution** (B.14, C.4) — same-type containment dedup, three-strategy enum
7. **Anonymizer operators** (C.1–C.5) — 8 anonymize + 2 deanonymize, AES-CBC encrypt/decrypt, hash (SHA-256/512 only), custom lambda, AHDS surrogate, batch anonymize
8. **Image redaction** (D) — PIL/Tesseract/Azure Document Intelligence pipeline, single-fill redaction, bbox API, PII verify workflow
9. **DICOM** (D.5) — pixel-only scrubbing, substring-on-element-name detection, name augmentation, bulk file/dir APIs
10. **Structured data** (E) — pandas / JSON / CSV / nested dict; three column-selection strategies; row-major operator application
11. **REST APIs** (F) — three Flask services, OpenAPI spec, Postman collections, health endpoints
12. **CLI** (G.5) — file/directory scanning, GitHub Actions output format, `.presidiocli` config
13. **Deployment artifacts** (H) — Dockerfiles (5 analyzer variants), docker-compose (4 files including Ollama sidecar), Helm chart, ARM templates, ACR + SBOM + provenance, ARM64 native
14. **Observability** (I) — minimal in-process; sample OTel stack; correlation-id propagation gap
15. **Configuration** (J) — env vars, YAML, regex timeout, AHDS credential chain
16. **Sample integrations breadth** (K) — Spark/Databricks, Data Factory, Fabric, Streamlit, LiteLLM, OpenAI, AHDS, Flair, SpanMarker, Faker
17. **LLM integration shapes** (L) — both as recognizer and as protected downstream
18. **License posture** (M) — MIT + dep allowlist

This document is the master reference. Use it as the input to the next pass:
"compare octarine, surface area by surface area, against each numbered group."

---

## P. Evaluation & benchmarking (`microsoft/presidio-research`)

Separate MIT-licensed Python package `presidio-evaluator` (PyPI; current 0.2.5; Python ≥3.10). NOT a production detector — it's a data-science / evaluation companion. Three pillars: fake-data generation, dual evaluation, model wrappers.

### P.1 Fake PII data generation (`presidio_evaluator.data_generator`)

Built on `joke2k/faker`, extended in three layers:

| Class | Role |
|---|---|
| `SpanGenerator` (extends `faker.Generator`) | Overrides `parse()` to also return character spans for every replaced placeholder. Output: `InputSample(full_text, spans, masked_template)`. |
| `RecordGenerator` (extends `SpanGenerator`) | Adds a `DynamicProvider` over a DataFrame of personas. When a template uses `{{name}}` and `{{email}}` of the same persona, both come from the **same record** — semantic coherence. |
| `SentenceFaker` (extends `faker.Faker`) | Top-level entrypoint. `lower_case_ratio=0.05` knob; `add_provider_alias()`. |

Higher-level: `PresidioSentenceFaker(locale=...)` is the public API; `PresidioPseudonymization` is the detect → anonymize → re-fake glue.

**Custom Faker providers** (all in `faker_extensions/providers.py`):

| Provider | Data source |
|---|---|
| `NationalityProvider` | `nationalities.csv` (~140 countries) — country, nationality, nation_man/woman/plural |
| `OrganizationProvider` | `companies_and_organizations.csv` (10 exchanges: AEX/BSE/CNQ/GER/LSE/NASDAQ/NSE/NYSE/PAR/TYO) |
| `UsDriverLicenseProvider` | `us_driver_license_format.yaml` (per-state regex masks, ported from faker-ruby) |
| `ReligionProvider` | `religions.csv` (12 religions) |
| `IpAddressProvider` | Wraps Faker ipv4/ipv6 (80/20) |
| `AgeProvider` | Weighted age format generator (`%#`, `%`, `1.%`, `2.%`, `100`, `101`, `104`, `0.%`) |
| `AddressProviderNew` | Extends Faker en_US with multi-line / military APO/FPO/DPO / "corner of X and Y" templates |
| `PhoneNumberProviderNew` | Extends Faker en_US with US/UK/IN/CH/SE formats + extensions |
| `HospitalProvider` | **Live WikiData SPARQL query at import** (Q16917 hospitals in Q30=US); falls back to 4-item default on network failure |

Templates: `templates.txt` ships **~280 Jinja-ish `{{token}}` templates**. `ENTITY_TYPE_MAPPING` is the canonical Faker → Presidio glossary (`ssn → US_SSN`, `iban → IBAN_CODE`, `prefix_male → TITLE`, etc.).

**Format-conforming generation**:

- Credit cards — **valid Luhn** (Faker built-in)
- IBAN — valid format (Faker built-in)
- US SSN — format-only (no SSA rules)
- US driving license — per-state mask
- Phones — format-only with US/UK/IN/CH/SE
- IP — real valid IPv4/IPv6
- Email/URL/Domain — Faker built-ins

### P.2 Evaluation framework (`presidio_evaluator.evaluation`)

Two evaluators with different philosophy:

```
BaseEvaluator (abc)
 ├── TokenEvaluator   (alias Evaluator, deprecated)
 └── SpanEvaluator
```

**`TokenEvaluator`** — classic per-token NER eval. Confusion matrix as `Counter[(annotation_tag, predicted_tag)]`. BIO/BILUO collapsed to IO by default (`compare_by_io=True`). Per-entity + global "PII" precision/recall/F-beta.

**`SpanEvaluator`** — span-level fuzzy match via character or token IoU. `iou_threshold=0.9`, `char_based=True`. Merges adjacent same-type spans across skip-words / punctuation. Matching rules (codified in `docs/span_matching_strategies.md`):

- High IoU + same type → TP
- High IoU + wrong type → FN(annotated) + FP(predicted)
- Low IoU → both FN and FP
- No overlap → FN(annotation), FP(unmatched prediction)

Metrics: `precision = tp / (tp + fp)`, `recall = tp / (tp + fn)`, `f_beta = ((1+β²) * p * r) / ((β² * p) + r)`. **Default `beta=2.0`** (recall-weighted — PII bias).

`EvaluationResult.per_type: Dict[str, PIIEvaluationMetrics]` (precision, recall, f_beta, num_predicted, num_annotated, tp, fp, fn). Outputs: `to_log()`, `to_confusion_matrix()`, `to_confusion_df()` (DataFrame with O row/col last, precision row + recall col appended). `Plotter` (Plotly) draws per-entity bar charts + confusion matrix heatmap.

**Skip words** (`get_skip_words()`): ~100 tokens ignored when matching — punctuation, whitespace, `'s`, `street`, `st.`, `de`, `rue`, `via`, `and`, `the`, `or`, `of`, `address`, `city`, `state`, `zip`, `apt`, `unit`, `mr.`, `mrs.`, `miss`, `y/o`, `morning`, `inc`, `ltd`, etc., plus spaCy's `STOP_WORDS`. Overridable via `SpanEvaluator(skip_words=...)`.

**Error analysis** (`model_error.py`):

```python
class ErrorType(Enum): FP, FN, WrongEntity
class ModelError:
    error_type, annotation, prediction, token, full_text,
    sample_id, metadata, explanation
```

Static helpers: `most_common_fp_tokens(n)`, `most_common_fn_tokens(n)`, `get_fps_dataframe()`, `get_fns_dataframe()`, `get_wrong_entity_dataframe()`. Each prints top-N FPs/FNs with one example sentence each.

**Generic entity tolerance**: `GENERIC_ENTITIES = ("PII", "ID", "PHI", "ID_NUM", "NUMBER", "NUM", "GENERIC_PII")`. Predicting a generic tag where ground truth has a specific tag (or vice-versa) is treated as a correct prediction. This is a deliberate accommodation for LLM-as-detector setups that don't disambiguate PII subtypes.

### P.3 Model wrappers (`presidio_evaluator.models`)

`BaseModel(labeling_scheme, entities_to_keep, entity_mapping, verbose)` with `predict(sample) -> List[str]` and `batch_predict(dataset) -> List[List[str]]`.

| Wrapper | Wraps |
|---|---|
| `PresidioAnalyzerWrapper` | `AnalyzerEngine` + `BatchAnalyzerEngine`. Ships 60-entry `presidio_entities_map` (PER/FIRST_NAME/STREET_ADDRESS/ZIP/DOB/HCW/PATIENT/HOSP/NORP/VENDOR/...) → canonical Presidio types |
| `PresidioRecognizerWrapper` | A single `EntityRecognizer` + `NlpEngine` — score one custom recognizer in isolation |
| `SpacyModel` | A `spacy.Language` pipeline. Uses `PRESIDIO_SPACY_ENTITIES` translator |
| `StanzaModel(SpacyModel)` | Stanza via `spacy_stanza.load_pipeline` |
| `FlairModel` | `flair.models.SequenceTagger`. Lazy-imports flair; SpacyTokenizer for consistency; PER → PERSON auto-map |
| `TextAnalyticsWrapper` | Azure AI Language. **Marked deprecated** in favor of in-Presidio `TextAnalyticsRecognizer` |

No HuggingFace wrapper class — HF models plug in via `spacy-huggingface-pipelines` and `SpacyModel`.

### P.4 Datasets shipped

| Path | Content |
|---|---|
| `data/synth_dataset_v2.json` | **1500 synthetic samples** with annotated spans. Entity coverage: PERSON (857), STREET_ADDRESS (598), GPE (411), ORGANIZATION (250), CREDIT_CARD (136), DATE_TIME (119), TITLE (92), PHONE_NUMBER (92), AGE (74), NRP (55), EMAIL_ADDRESS (49), ZIP_CODE (37), DOMAIN_NAME (37), IBAN_CODE (21), US_SSN (16), IP_ADDRESS (14), US_DRIVER_LICENSE (5). License: MIT |
| `FakeNameGenerator.com_3000.csv` | 3000 personas (CC-BY-SA-3.0; attribution to Corban Works, LLC required) |

CoNLL-2003 (via `CONLL2003Formatter.download()`) and i2b2-2014 PHI (XML, user-procured) are formatters only — not bundled.

### P.5 Dataset formatters

`DatasetFormatter` (ABC) → `CONLL2003Formatter`, `I2B22014Formatter`. Each parses an external corpus into `InputSample` lists.

### P.6 Train/test split — `validation.py`

`split_by_template(samples, train_ratio, test_ratio, ...)` — **template-aware split** that guarantees the same template never appears in two folds. Prevents the model from memorising templates rather than learning entities.

Also: `split_dataset`, `get_samples_by_pattern`, `group_by_template`, `save_to_json`.

### P.7 Experiment tracking

`ExperimentTracker` (abstract) + `LocalExperimentTracker` — local JSON log of runs/metrics.

### P.8 Notebooks

5 root notebooks (`1_Generate_data` → `5_Evaluate_Custom_Presidio_Analyzer`) + 5 per-model evaluation notebooks (Azure, Flair, spaCy, Stanza, "Create datasets for Spacy training"). **Notebook 5 demonstrates ~30% F-score lift** from custom recognizer / context / score-threshold tuning vs vanilla Presidio.

### P.9 CLI / runnable scripts

**No installed CLI entry point.** Module-as-script support:

- `python -m presidio_evaluator.data_generator.presidio_sentence_faker` — generates 10000 samples
- `python -m presidio_evaluator.dataset_formatters.conll_formatter` — CoNLL-2003 → InputSamples
- `python -m presidio_evaluator.dataset_formatters.i2b2_formatter` — i2b2 XML → JSON
- `python -m presidio_evaluator.experiment_tracking.local_tracker` — toy example

### P.10 Notable gaps

- No transformers wrapper class (must plug HF via spaCy)
- **CRF and FlairTrainer were deleted in 0.2.0** — repo is now strictly evaluation, not training
- No identifier-format generators unique to presidio-research (no Aadhaar Verhoeff, no UK NHS mod-11 generator, etc.) — sits downstream of presidio's recognizer set
- Only one bundled real-world-shaped dataset; everything else is fully synthetic or external

---

## Q. Type system & constants

### Q.1 Class kind — predominantly plain Python

Presidio types are **plain Python classes** unless noted; only 3 dataclasses (`DictAnalyzerResult`, `DictRecognizerResult`, `StructuredAnalysis`); pydantic is confined to NER config + YAML schema validation.

### Q.2 Request / response objects

| Class | Package | Fields summary |
|---|---|---|
| `AnalyzerRequest` | analyzer | `text`, `language`, `entities`, `correlation_id`, `score_threshold`, `return_decision_process`, `ad_hoc_recognizers`, `context`, `allow_list`, `allow_list_match`, `regex_flags` |
| `RecognizerResult` (analyzer) | analyzer | `entity_type`, `start`, `end`, `score`, `analysis_explanation`, `recognition_metadata`. Implements `__eq__`/`__hash__`/`__gt__`/`intersects`/`contains`/`contained_in`/`equal_indices`/`has_conflict` |
| `RecognizerResult` (anonymizer) | anonymizer | **Parallel "exact copy"** subclass of `PIIEntity` — but no `analysis_explanation`, no `recognition_metadata`. Different `__gt__` from the analyzer's version |
| `AnalysisExplanation` | analyzer | `recognizer`, `original_score`, `score` (mutable), `pattern_name`, `pattern`, `validation_result`, `textual_explanation`, `regex_flags`, `score_context_improvement`, `supportive_context_word`. One-way serialization (no `from_dict`) |
| `DictAnalyzerResult` | analyzer | `@dataclass` — `key`, `value`, `recognizer_results` (recursive for nested dicts) |
| `DictRecognizerResult` | anonymizer | `@dataclass` — same shape, anonymizer's `RecognizerResult` |
| `PIIEntity` | anonymizer | `abc.ABC` — `start`, `end`, `entity_type`. `__gt__` by `start` only. `__validate_fields` enforces `start >= 0`, `end >= 0`, `start <= end` |
| `OperatorConfig` | anonymizer | `operator_name`, `params: Dict`. **`params` mutated by the engine** — `entity_type` is injected before `operator.validate()` |
| `OperatorResult` | anonymizer | Subclass of `PIIEntity` — adds `text`, `operator` |
| `EngineResult` | anonymizer | `text`, `items: List[OperatorResult]`. Mutators: `set_text`, `add_item`, `normalize_item_indexes`. `to_json()` = `json.dumps(self, default=lambda x: x.__dict__)` — only built-in JSON encoder |
| `ImageRecognizerResult` | image | Extends analyzer's `RecognizerResult` with `left`, `top`, `width`, `height` |
| `StructuredAnalysis` | structured | `@dataclass` — `entity_mapping: Dict[str, str]` (column/key → entity type) |
| `NlpArtifacts` | analyzer | `entities`, `tokens`, `tokens_indices`, `lemmas`, `nlp_engine`, `language`, `scores`, `keywords`. `to_json()` **strips `nlp_engine`** (back-reference) |
| `OCR.perform_ocr` return | image | Tesseract-style parallel-list dict `{text, left, top, width, height, conf}` |

### Q.3 Enums (only two)

| Enum | Members |
|---|---|
| `OperatorType` | `Anonymize = 1`, `Deanonymize = 2`. Module also exposes `types = [Anonymize, Deanonymize]` |
| `ConflictResolutionStrategy` | `MERGE_SIMILAR_OR_CONTAINED = "merge_similar_or_contained"`, `REMOVE_INTERSECTIONS = "remove_intersections"`. **Docstring also mentions `NONE` but it's NOT defined** — known doc/code mismatch |

Everything else (recognizer `type`, allow-list match mode, operator names, hash algorithms) is plain `str` constants.

### Q.4 Pydantic-backed configuration types

| Class | Purpose |
|---|---|
| `NerModelConfiguration` | NER inference knobs: `labels_to_ignore`, `aggregation_strategy` (`simple`/`first`/`average`/`max`), `stride` (14), `alignment_mode` (`strict`/`contract`/`expand`), `default_score` (0.85), `model_to_presidio_entity_mapping` (defaults to module-level 19-entry constant), `low_score_entity_names`, `low_confidence_score_multiplier` (0.4). `ConfigDict(arbitrary_types_allowed=True)` |
| `LanguageContextConfig` | `language`, `context: Optional[List[str]]` |
| `BaseRecognizerConfig` | Common YAML fields: `name`, `class_name`, `enabled`, `type`, `supported_language(s)`, `supported_entit{y,ies}`, `context`. Cross-field validators reject conflicting singular/plural pairs |
| `PredefinedRecognizerConfig` | Extends `Base` with `validate_predefined_recognizer_exists` validator |
| `HuggingFaceRecognizerConfig` | `model_name`, `tokenizer_name`, `label_mapping`, `threshold`, `aggregation_strategy`, `chunk_overlap`, `chunk_size`, `device`, `label_prefixes`. `ConfigDict(extra="allow")` |
| `GLiNERRecognizerConfig` | `model_name`, `flat_ner`, `multi_label`, `threshold`, `map_location`, `load_onnx_model`, `onnx_model_file`, `entity_mapping` |
| `CustomRecognizerConfig` | Extends `Base` with `country_code` (lower/strip-normalized), `patterns`, `deny_list`, `deny_list_score`. `check_predefined_name_conflict` rejects custom names that collide with predefined classes |
| `RecognizerRegistryConfig` | Top-level: `supported_languages`, `global_regex_flags: int = 26`, `recognizers: List[Union[...]]`. `parse_recognizers` validator selects appropriate subclass via `CONFIG_MODEL_MAP` |
| `ConfigurationValidator` (static methods) | `validate_language_codes`, `validate_file_path`, `validate_score_threshold`, `validate_nlp_configuration`, `validate_recognizer_registry_configuration`, `validate_analyzer_configuration` |

### Q.5 Exception hierarchy

**No shared Presidio base exception.** Two independent `InvalidParamError` classes (anonymizer + image-redactor); everything else is `ValueError`/`TypeError`.

| Exception | Package | Raised when |
|---|---|---|
| `InvalidParamError` (anonymizer) | anonymizer | Param validation failures, operator `validate()`, factory lookups, `TextReplaceBuilder` index OOB, `Custom.operate` (lambda returned non-string), `AppEntitiesConvertor`, `AHDSSurrogate` config, `PIIEntity.__validate_fields` |
| `InvalidParamError` (image-redactor) | image | REST JSON parse failures, malformed RGB triple. **Independent class — NOT same as anonymizer's** |
| `PredefinedRecognizerNotFoundError` | analyzer | `RecognizerListLoader.get_existing_recognizer_cls` — used as a control-flow signal inside pydantic validators |
| `ValueError` | analyzer + structured | Generic "bad input" — patterns, country code, registry checks, structured data type validation |
| `TypeError` | analyzer | Country-code kwarg not a str |
| `BadRequest` (werkzeug) | anonymizer | Empty body, custom operator over REST (REST explicitly rejects `custom`) |
| `OSError`, `yaml.YAMLError` | analyzer | YAML loader. Re-raised after a `print()` — yes, `print`, not logger |

### Q.6 HTTP error contract (asymmetric across services)

**Anonymizer**: `InvalidParamError → 422 {"error": err.err_msg}`. Other exceptions → `500 {"error": "Internal server error"}` (message NOT exposed). `HTTPException → e.code`.

**Analyzer**: `TypeError → 400` with parse-error message. Other exceptions → `500 {"error": e.args[0]}` — **raw message IS exposed**. `HTTPException → e.code`.

### Q.7 Utility primitives

- **Anonymizer `services/validators.py`** — `validate_parameter`, `validate_type` (**silently passes on falsy values**), `validate_parameter_exists`, `validate_parameter_not_empty`, `validate_parameter_in_range`. JSON-friendly type names: `str→"string"`, `bool→"boolean"`, `int→"number"`, `list→"array"`, `object→"object"`. All raise `InvalidParamError`.
- **Analyzer `input_validation/`** — `validate_language_codes` (`^[a-z]{2}(-[A-Z]{2})?$`), `ConfigurationValidator` static methods.
- **Image — `BboxProcessor`** — `get_bboxes_from_ocr_results`, `get_bboxes_from_analyzer_results`, `remove_bbox_padding` (mode-switches on dict keys), `match_with_source(..., tolerance=50)`.
- **Image — `api_request_convertor`** — `get_json_data(data)` (**`data.replace("'", '"')` before `json.loads`** — corrupts legitimate apostrophes), `color_fill_string_to_value`, `image_to_byte_array`.
- **Anonymizer — `AESCipher`** — static `encrypt(key, text)`, `decrypt(key, text)`, `is_valid_key_size(key)`. Hardcoded `padding.PKCS7(128)` on decrypt (asymmetric with encrypt).
- **Anonymizer — `TextReplaceBuilder`** — operates **end-to-start** so earlier indices stay valid; then `EngineResult.normalize_item_indexes` flips at the end.
- **`AppEntitiesConvertor`** — `analyzer_results_from_json`, `operators_config_from_json`, `deanonymize_entities_from_json`, `check_custom_operator` (REST handler uses this to reject custom over HTTP).
- **`EntityRecognizer.sanitize_value`** — naive chained `str.replace` loop. Not used anywhere else.
- **`EntityRecognizer._resolve_country_code`** — classmethod reconciling class-level `COUNTRY_CODE` ClassVar with constructor kwarg. Lowercases, strips, raises on conflict.

### Q.8 Constants

**Analyzer**:

- `EntityRecognizer.MIN_SCORE = 0`, `MAX_SCORE = 1.0` (duplicated on `ContextAwareEnhancer`)
- Metadata keys: `RECOGNIZER_NAME_KEY = "recognizer_name"`, `RECOGNIZER_IDENTIFIER_KEY = "recognizer_identifier"`, `IS_SCORE_ENHANCED_BY_CONTEXT_KEY = "is_score_enhanced_by_context"`
- `REGEX_TIMEOUT_SECONDS = int(os.environ.get("REGEX_TIMEOUT_SECONDS", 60))`
- `_COUNTRY_SPECIFIC_MODULE_SEGMENT = "country_specific"` (private)
- `MODEL_TO_PRESIDIO_ENTITY_MAPPING` — 19-key module-level mutable (PER→PERSON, LOC→LOCATION, GPE→LOCATION, NORP→NRP, HCW→PERSON, …)
- `RecognizerRegistryConfig.global_regex_flags: int = 26` (= `re.DOTALL | re.MULTILINE | re.IGNORECASE`) — also hardcoded as the default in `AnalyzerRequest.regex_flags`. **Two sources of truth.**
- `app.py`: `DEFAULT_PORT = "3000"`, `DEFAULT_BATCH_SIZE = "500"`, `DEFAULT_N_PROCESS = "1"`

**Anonymizer**:

- `anonymizer_engine.DEFAULT = "replace"`
- Operator-parameter key class-attr strings: `Encrypt.KEY`, `Decrypt.KEY`, `Mask.CHARS_TO_MASK`/`FROM_END`/`MASKING_CHAR`, `Hash.HASH_TYPE`/`SALT`/`SHA256`/`SHA512`, `Custom.LAMBDA`, `Replace.NEW_VALUE`
- Hash salt minimum: 16 bytes (128 bits) if user-supplied
- `AHDS_AVAILABLE` module-level boolean — `True` iff `azure-health-deidentification` extra installs. `OperatorsFactory` conditionally adds `AHDSSurrogate` to `ANONYMIZERS`

### Q.9 Serialization — ad-hoc and inconsistent

| Class | Mechanism | What's stripped / included |
|---|---|---|
| `RecognizerResult` (analyzer) | `to_dict() → __dict__`, `from_json(data)` | `from_json` only reads `entity_type/start/end/score` (drops explanation + metadata) |
| `AnalysisExplanation` | `to_dict() → __dict__` | **One-way** — no `from_*` |
| `Pattern` | Explicit `to_dict()` → `{name, score, regex}`, `from_dict(d)` | Excludes `compiled_regex` and `compiled_with_flags` |
| `EntityRecognizer` | `to_dict()` → allowlist (`supported_entities`, `supported_language`, `name`, `version`, optional `country_code`), `from_dict(d) → cls(**d)` | Loses `is_loaded`, `_id`, `context` |
| `OperatorConfig` | `from_json` only | **One-way deserialization** |
| `EngineResult` | `to_json() → json.dumps(self, default=lambda x: x.__dict__)` | **Only built-in JSON encoder**; walks `__dict__` blindly |
| `NlpArtifacts` | `to_json()` — strips `nlp_engine` back-ref | Only place back-ref handling is acknowledged |
| `NerModelConfiguration` | pydantic `model_dump(exclude_none=True)`, `from_dict` | Pydantic v2 patterns |
| `HuggingFaceRecognizerConfig` / `GLiNERRecognizerConfig` | Override `model_dump` to default `exclude_none=True` | Subtle footgun: forgetting this would silently break HF/GLiNER kwargs |
| Analyzer `/analyze` response | `json.dumps(results, default=lambda o: o.to_dict(), sort_keys=True)` + strips `recognition_metadata` via `_exclude_attributes_from_dto` (**in-place mutation**) | Wire format intentionally drops metadata |
| Anonymizer `/anonymize` response | `EngineResult.to_json()` | Whole `__dict__` walk |

### Q.10 Type-system quirks worth carrying forward

1. **`Custom.validate()` deliberately does NOT invoke the lambda** (cites issue #2024). Stateful lambdas would be corrupted by a probe call. Return-type contract enforced only at `operate()` time.
2. **`validate_type` silently passes on falsy values** — empty string or `0` bypasses type check entirely. Callers must precede it with `validate_parameter_not_empty` if they care.
3. **Two `InvalidParamError` classes** — anonymizer + image-redactor independent; `isinstance` checks won't cross packages.
4. **Two `RecognizerResult` classes** — different fields, different `__gt__`. Round-tripping through JSON loses fields.
5. **`OperatorConfig.params` mutated by engine** — `entity_type` injected before `validate()`. Direct callers get a surprise key.
6. **`ConflictResolutionStrategy.NONE` documented but missing** — known mismatch.
7. **Asymmetric REST error exposure** — analyzer leaks `e.args[0]`, anonymizer doesn't.
8. **`get_json_data` corrupts apostrophes** via `data.replace("'", '"')` before parse.
9. **REST handler rejects `Custom` operators** — `AppEntitiesConvertor.check_custom_operator → BadRequest`. Custom is library-only.
10. **`_exclude_attributes_from_dto` mutates engine output in-place** for REST serialization.
11. **`Pattern` uses third-party `regex` lib**, not stdlib `re` — required for `\p{...}` and timeout support (stdlib `re` doesn't support timeout).
12. **`AESCipher.decrypt` uses hardcoded `padding.PKCS7(128)`** instead of `algorithms.AES.block_size`. Functionally identical (AES is 128 bits) but asymmetric with `encrypt`.
13. **`PIIEntity.__gt__` (by `start` only) differs from anonymizer's `RecognizerResult.__gt__` (by `(start, end)`)** — sorting mixed lists is order-sensitive.
14. **`PredefinedRecognizerNotFoundError` used as control-flow** inside YAML validators.
15. **No common engine-result base type** — `EngineResult` (anonymizer) vs `List[RecognizerResult]` (analyzer) vs `List[DictAnalyzerResult]` (batch). Wrappers handle three shapes.

---

## R. CLI surface — `presidio-cli`

**Separate PyPI package** (`presidio-cli`), not in the main release wave. Executable `presidio`. Entry point `presidio_cli.cli:run`. Python 3.10–3.13. Single-shot scanner — **no subcommands**.

### R.1 Flags

| Flag | Type | Default | Notes |
|---|---|---|---|
| `-v` / `--version` | action=version | — | Prints `v{APP_VERSION}` and exits |
| (positional) `FILE_OR_DIR` | `nargs="*"` | `()` | Files / dirs. **Mutually exclusive with `-`**. Required unless `-` is given |
| `-` | flag (`stdin=True`) | False | Read from stdin. Mutually exclusive with positional |
| `-c` / `--config-file` | str | None | Path to YAML config. Mutually exclusive with `-d` |
| `-d` / `--config-data` | str | None | Inline YAML string. If no `:`, auto-prefixed `extends:` (so `-d default` works) |
| `-f` / `--format` | choice | `"auto"` | One of: `standard`, `github`, `auto`, `colored`, `parsable` |
| `--no-warnings` | flag | False | "Output only error-level problems" — **effectively a no-op** because `PIIProblem` never sets `level` |
| `-h` / `--help` | flag | — | argparse default |

### R.2 Config-file precedence

1. `-d <yaml>` if given
2. `-c <path>` if given
3. `./.presidiocli` in cwd, if present
4. Fallback: `extends: default` → loads `presidio_cli/conf/default.yaml`

### R.3 Output formats

| Format | Description |
|---|---|
| `standard` | `LINE:COL  SCORE  ENTITY_TYPE  (explanation?)` plain text. Filename printed once at top of block |
| `colored` | Same as standard with ANSI colors (score ≥1 red, <1 yellow, line/col dim, filename underlined) |
| `github` | GitHub Actions workflow command format: `::group::FILE` … `::SCORE file=...,line=...,col=...::LINE:COL [TYPE]` … `::endgroup::` |
| `parsable` | One JSON object per line from `RecognizerResult.to_dict()` |
| `auto` (default) | `github` if `GITHUB_ACTIONS` AND `GITHUB_WORKFLOW` env set; else `colored` if TTY + ANSI; else `standard` |

### R.4 Config keys (`.presidiocli` / any YAML)

| Key | Type | Default | Notes |
|---|---|---|---|
| `language` | string | `"en"` | Passed to `analyze(language=...)` |
| `entities` | list[str] | All supported | Validated against `AnalyzerEngine.get_supported_entities()`; unknown raises `PresidioCLIConfigError` |
| `ignore` | gitwildmatch string (multi-line) | None | Parsed by `pathspec.PathSpec.from_lines("gitwildmatch", ...)`. Same syntax as `.gitignore` |
| `allow` | list[str] | `[]` | Passed to `analyze(allow_list=...)` |
| `threshold` | float in [0, 1] | `0` | Filters results below threshold |
| `locale` | string | None | Passed to `locale.setlocale(LC_ALL, ...)` |
| `extends` | string | None | Path to base config OR bundled name (`default`, `limited`) resolved from `presidio_cli/conf/{name}.yaml`. **Recursive**. Extension semantics: union entities, base wins on language/ignore |

Bundled `default.yaml`:

```yaml
language: en
ignore: |
  .git
```

Repo `.presidiocli` covers: CREDIT_CARD, CRYPTO, DATE_TIME, EMAIL_ADDRESS, IBAN_CODE, IP_ADDRESS, NRP, LOCATION, PERSON, PHONE_NUMBER, MEDICAL_LICENSE.

### R.5 Exit codes

- `0` — no PII problems found
- `1` — `PresidioCLIConfigError` OR at least one PII problem reported
- Other — propagated from `EnvironmentError` on stdin read

**Latent bug**: the CLI returns 1 if `prob_num > 0`, but `prob_num` is set from `show_problems()`'s `max_level` which is initialized to 0 and never modified — so in practice exit 1 only fires from config errors, not from finding PII. (Octarine's CLI should design exit-on-finding from the start.)

### R.6 Env vars consumed

- `GITHUB_ACTIONS`, `GITHUB_WORKFLOW` — switch `auto` format to `github`
- `ANSICON`, `TERM` — ANSI-support detection on Windows
- Indirect via `presidio-analyzer`: `PRESIDIO_DEVICE`, `AHDS_ENDPOINT`, `REGEX_TIMEOUT_SECONDS`

### R.7 Shell behavior

- Walks dirs recursively via `os.walk`
- Rejects binary files via UTF-8 decode + null-byte check on first 1024 bytes (Stack Overflow heuristic — brittle)
- Strips leading `./` or `.\` from filenames in output
- Stdin: single buffer, no streaming; filename rendered as `"stdin"`
- Globs: relies on shell expansion; `ignore` supports gitwildmatch
- Encoding: `utf-8`, `newline=""`
- **Line chunking**: splits on `\n`, strips trailing `\r`. **Each line analyzed independently — multi-line entities won't be detected**

### R.8 CLI scope gap

`presidio-cli` only wraps the analyzer. **No CLI for anonymizer, image redactor, or structured.** No batch CLI flag despite `BatchAnalyzerEngine` existing.

---

## S. Concepts taught by docs (feature inventory from `mkdocs.yml`)

The docs nav has six top-level sections. Each first-class CONCEPT below is something octarine likely needs a parallel for.

### S.1 Core vocabulary (from `learn_presidio/concepts.md`)

- **Entity / Entity type** — strongly-typed PII category
- **Recognizer** — pluggable detector. Hierarchy: `EntityRecognizer` → `LocalRecognizer` / `RemoteRecognizer` → `PatternRecognizer`
- **Predefined vs custom recognizer** — `type: predefined|custom` in YAML
- **Ad-hoc recognizer** — per-request JSON in `/analyze` body
- **Persistent recognizer** — in code or YAML; survives across calls
- **Deny list** vs **Allow list** — literal tokens always vs never flagged
- **Score / confidence** — `[0, 1]`
- **Score threshold** — engine-wide `default_score_threshold`, per-call override
- **Context / context word** — boosts score
- **Context-aware enhancement** — `LemmaContextAwareEnhancer(context_similarity_factor=0.35, min_score_with_context_similarity=0.4)` + custom enhancer pluggable. New in 2.2.361: `context_matching_mode="whole_word"` to avoid `lic` matching `duplicate`
- **Decision process / decision trace** — `return_decision_process=True` and `log_decision_process=True`. Explains why PII WAS detected, **never why it WASN'T**
- **Correlation ID** — optional kwarg; returned via `x-correlation-id` HTTP header
- **No-code configuration** — entire pipeline driven by YAML
- **`global_regex_flags`** — single int applied to all patterns
- **Country filtering** (new unreleased) — `countries=` kwarg, YAML `supported_countries`, per-recognizer `country_code`, `EntityRecognizer.COUNTRY_CODE` ClassVar, `is_country_specific()`
- **`enabled: false` toggle** — selectively disable predefined recognizers
- **`labels_to_ignore`** — NER label filter
- **`model_to_presidio_entity_mapping`** — model labels → Presidio entity types
- **`low_confidence_score_multiplier` / `low_score_entity_names`** — per-entity score adjustment

### S.2 NLP / detection concepts

- **NLP engine** — `SpacyNlpEngine`, `StanzaNlpEngine`, `TransformersNlpEngine`, slim
- **`NlpEngineProvider`** — builds engine from dict or YAML
- **`HuggingFaceNerRecognizer`** — direct HF without spaCy wrapper (new in 2.2.362)
- **`MedicalNERRecognizer`** — clinical entity detection (new in 2.2.362)
- **GLiNER recognizer** — open-vocab NER, ONNX backend supported (CPU without AVX2)
- **LangExtract recognizer** — LLM-based, any provider via YAML; Azure OpenAI managed-identity
- **Remote recognizer** — subclass `RemoteRecognizer`, wrap HTTP service
- **GPU device control** — `PRESIDIO_DEVICE` env var (`cpu`/`cuda`/`cuda:0`/`mps`); `en_core_web_lg` NOT recommended for GPU
- **Custom NLP engine** — subclass `SpacyNlpEngine` to reuse pre-loaded models
- **`NerModelConfiguration`** — aggregation strategy, stride, alignment mode, label mapping
- **Multi-language support** — engine-wide `supported_languages=[...]` + per-recognizer `supported_language`
- **`BatchAnalyzerEngine` / `BatchAnonymizerEngine`** — batch APIs; REST batch endpoints landed in 2.2.361. Tunable `n_process`, `batch_size`
- **`DeviceDetector` singleton** — 4-10× perf boost for GLiNER/Transformers/Stanza (new in 2.2.361)

### S.3 Operator concepts

- **Operator** — anonymizer plugin. Two types: `Anonymize`, `Deanonymize`
- **Operator: `replace`** — defaults to `<ENTITY_TYPE>`
- **Operator: `redact`** — removes entity
- **Operator: `mask`** — `masking_char`, `chars_to_mask`, `from_end`
- **Operator: `hash`** — SHA-256 (default), SHA-512. **Salted by default since 2.2.361 (BREAKING)**, min 16 bytes
- **Operator: `encrypt`/`decrypt`** — AES-CBC, 16-char symmetric key
- **Operator: `custom`** — user lambda
- **Operator: `surrogate_ahds`** — AHDS surrogate; cross-reference consistency within a document
- **Operator: `keep`** — pass-through
- **`DEFAULT` operator key** — catch-all
- **Pseudonymization** — reversible replacement pattern via `custom` + state-bearing lambda (FAQ defines it as "reversible fake-data substitution")
- **`InstanceCounterAnonymizer`** — sample pattern: monotonic per-entity counter
- **`OperatorResult`** — per-entity item; allows partial decryption
- **Conflict resolution / overlap handling** — higher score wins on full overlap; larger span wins on containment; partial intersections concatenated

### S.4 Image / structured / DICOM

- **DICOM redaction** — pixel-data only; `_make_phi_list` uses both `is_patient` and `is_name` (since 2.2.361)
- **OCR engines** — Tesseract (default), Azure Document Intelligence
- **`ImageAnalyzerEngine`** — wraps OCR
- **`redact_and_return_bbox`** — variant returning bboxes (new in 2.2.361)
- **`DicomImagePiiVerifyEngine`** — eval engine for DICOM redaction
- **`StructuredEngine` selection strategy** — `most_common` / `highest_confidence` / `mixed`
- **`PandasAnalysisBuilder` / `JsonAnalysisBuilder`** — column → entity inference
- **`StructuredAnalysis`** — manual entity-mapping dict for nested JSON

### S.5 Evaluation

- **PII detection evaluation framework** — Precision, Recall, Fβ (β=2 for PII recall bias)
- **LLM-as-a-judge evaluation** — new in 2.2.362
- **Sampling support in eval framework** — new in 2.2.362
- **Dataset interface for eval framework** — new in 2.2.362

### S.6 Operational concepts

- **REST batch API** — array-in/array-out with backward compatibility (new in 2.2.361)
- **Regex execution timeout** — `REGEX_TIMEOUT_SECONDS` env var (default 60s) to prevent catastrophic backtracking
- **No-auth-by-design stance** — explicit FAQ: "Presidio API endpoints do not include built-in authentication by design." Expected at gateway layer
- **`presidio` meta-package** — `pip install presidio` installs analyzer + anonymizer (new in 2.2.362). Distinct from `presidio-cli`
- **Pydantic-based YAML validation** — `ConfigurationValidator` (new in 2.2.361)
- **Multiple recognizer instances from same class** — `class_name` parameter (new in 2.2.361)
- **Disable NLP recognizer entirely** — via config flag (new in 2.2.359). Useful for pure-pattern pipelines
- **Performance budget** — Best-practices doc quotes: "Anything above 100ms per request with 100 tokens is probably not good enough."

### S.7 Recipes section is essentially empty

The mkdocs nav has a "Recipes" section with only Home/Contributing/Template — community scaffolding only. Suggests an intended-but-unrealized cookbook surface.

---

## T. Roadmap signals (CHANGELOG `Unreleased` + recent releases)

### T.1 Unreleased (verbatim themes)

**Major new subsystem**: Country-filter machinery — `countries=` kwarg on `RecognizerRegistry.load_predefined_recognizers()`, `supported_countries` YAML field, per-recognizer `country_code:`, `EntityRecognizer.COUNTRY_CODE` ClassVar + constructor kwarg, `country_code()` / `is_country_specific()` methods, `to_dict()`/`from_dict()` round-trip, `RecognizerRegistry.get_country_codes()`, WARNING log for empty matches. Fixes #1328.

**New recognizers** (Unreleased): CA_SIN, SE_PERSONNUMMER + samordningsnummer, SE_ORGANISATIONSNUMMER, the **full German pack** (DE_TAX_ID, DE_TAX_NUMBER, DE_PASSPORT, DE_ID_CARD, DE_SOCIAL_SECURITY, DE_HEALTH_INSURANCE, DE_KFZ, DE_HANDELSREGISTER, DE_PLZ), ES_PASSPORT, KR_RRN, TH_TNIN, TR_NATIONAL_ID, Turkish phones via `PhoneRecognizer(supported_regions=["TR"])`, TR_LICENSE_PLATE, PH_MOBILE_NUMBER, `PhoneRecognizer` now accepts `supported_entity` (previously hardcoded `"PHONE_NUMBER"`).

**Bug fixes** (Unreleased): CreditCard regex matching 13-digit Unix timestamps; KVNR checksum; RVNR check-digit weights; LANR check-digit algorithm; post-2016 BZSt repetition rule in DeTaxId; registered LANR/BSNR/VAT/Fuehrerschein in default YAML (previously imported but unreachable); ISO 7064 Mod 11,10 checksum in DeVatId; ICAO MRZ check in DePassport/DeIdCard; BSNR structural validation per KBV Anlage 1.

### T.2 Release 2.2.362 (2026-03-15)

**Headlines**: `presidio` PyPI meta-package, `HuggingFaceNerRecognizer` (direct HF without spaCy), `MedicalNERRecognizer`, UK_DRIVING_LICENCE, US_NPI (Luhn), UK_POSTCODE, UK_PASSPORT, UK_VEHICLE_REGISTRATION, NG_NIN (Verhoeff), NG_VEHICLE_REGISTRATION. **ONNX Runtime backend for GLiNER** (`load_onnx_model=True` — fixes crashes on CPUs without AVX2). **`REGEX_TIMEOUT_SECONDS` env var** (default 60s, prevents catastrophic backtracking). **GPU device control via env**. **LLM-as-a-judge evaluation**. **Sampling support + Dataset interface** for eval framework. Italian driver license anchor fix.

**Security**: SHA-pinned GitHub Actions + Docker base images; ruff/build pinned with SHA256 hashes; CVE-2024-47874, CVE-2025-54121, CVE-2025-2953, CVE-2025-3730 fixed.

### T.3 Release 2.2.361 (2026-02-12)

**Headlines**: **BREAKING** — Hash operator now uses random salt by default; same PII produces different hashes unless `salt` param explicitly provided; min 16 bytes. Cryptography ≥46.0.4 for CVE-2025-15467. **Configurable `context_matching_mode`** on LemmaContextAwareEnhancer (`substring` default; `whole_word` prevents `lic` matching `duplicate`).

**New recognizers**: US_MBI, MAC address, KR_BRN, KR_FRN, KR_DRIVER_LICENSE, KR_PASSPORT, TH_TNIN. **Configurable LangExtract recognizer** with any LLM provider via YAML + Azure OpenAI managed-identity. **REST batch API** (arrays in/out, backward-compatible). **`PRESIDIO_DEVICE` env var**. **Support for multiple recognizer instances from same class via `class_name`**. **Pydantic-based YAML validation with `ConfigurationValidator`**. JA/CN mobile test cases for PhoneRecognizer.

**Perf**: DeviceDetector singleton (4-10× speedup for GLiNER/Transformers/Stanza). Lazy device-detector init. IBAN regex simplified from 8 capture groups to 3. KR_RRN regex tightened (negative lookahead/lookbehind + gender digit validation).

**Image**: DICOM `use_metadata` now uses both `is_patient` and `is_name`. `redact_and_return_bbox` added.

### T.4 Inferred direction (what the team is prioritising)

1. **Coverage expansion to non-English locales** is the dominant theme. Country-filter machinery is now first-class.
2. **Checksum-based validation everywhere** — Luhn, Verhoeff, ISO 7064, ICAO 9303 MRZ, TCKN, KVNR, RVNR, LANR, BSNR, DEA. Direction: reduce FPs via structural validation.
3. **LLM-as-a-judge + dataset/sampling for evaluation** — investing in eval tooling for the LLM era.
4. **LLM-based detection itself** — LangExtract (any LLM provider, including Azure OpenAI + managed identity), GLiNER zero-shot NER with ONNX backend.
5. **GPU + performance** — `PRESIDIO_DEVICE`, DeviceDetector singleton, regex timeout for ReDoS prevention.
6. **Security hardening** — SHA-pinned CI deps, random salt for hash (breaking), MD5 deprecated, cryptography bumped for CVE.
7. **No-code / YAML-driven config** — pydantic validation on YAML, `class_name` for multiple instances, default-disabled country recognizers.
8. **PyPI meta-package `presidio`** — UX win for "why two packages?"
9. **Anonymizer is quieter than analyzer** — only meaningful Anonymizer changes recently: salted hash (BREAKING), MD5 deprecation, crypto-backend swap (pycryptodome → cryptography), AHDS surrogate, unreleased custom-validate fix.
10. **Roadmap promised but not delivered** (per Structured docs): **PySpark backend, K-Anonymity, Differential Privacy, sensitive column-name detection**. None present in any recent CHANGELOG.

---

## U. Extended thing-by-thing index (additions for octarine comparison)

Items 1–18 are in section O above. The following extend the index with the second-pass findings.

19. **Evaluation framework** (section P) — token-level + span-level evaluators with character-IoU, generic-entity tolerance for LLM detectors, template-aware train/test split, plotter, per-entity confusion matrix, error analysis with top-N FP/FN tokens
20. **Fake-PII data generation** (P.1) — Faker-based, semantic-coherence via `RecordGenerator`, custom providers (hospital, organization, US DL, nationalities), ~280 templates, format-conforming Luhn / IBAN
21. **Dataset formatters** (P.5) — CoNLL-2003 + i2b2-2014 PHI; bundled `synth_dataset_v2.json` (1500 samples, 17 entity types)
22. **Type system parallels** (section Q) — recognizer-result shape, operator-config shape, enums (only 2!), pydantic config families, error hierarchy. Decisions octarine needs: (a) shared base exception or not, (b) consistent `to_dict`/`from_dict`, (c) explicit back-ref handling in serialization, (d) `Custom` operator validation that doesn't probe-call user code
23. **CLI surface** (section R) — single-shot scanner UX, gitwildmatch ignore, GitHub Actions output format, exit-on-finding semantics, multi-line entity handling (Presidio's CLI gets this wrong!)
24. **Docs-implied concepts** (section S) — full feature vocabulary; the FAQ stances ("no auth by design", pseudonymization = reversible substitution); performance budget (100ms / 100 tokens); "Recipes" section as the unfilled cookbook
25. **Country-filter subsystem** (T.1) — three-way reconciliation (kwarg + YAML + ClassVar), `is_country_specific()` introspection, deployment-time country filter
26. **Regex safety net** (T.2, B.7) — `REGEX_TIMEOUT_SECONDS` envvar; uses third-party `regex` module (not stdlib) for Unicode property classes
27. **GPU acceleration concept** (S.2, T.3) — env-var device control, singleton detector with measurable speedup, explicit non-recommendations (`en_core_web_lg`)
28. **LLM-as-detector vs LLM-as-judge** (T.4) — Presidio invests in both shapes
29. **Roadmap unfilled gaps** (T.4 item 10) — PySpark, K-Anonymity, Differential Privacy, column-name detection are promised by docs but undelivered. Potential octarine opportunity area
30. **Latent bugs Presidio carries** — `ConflictResolutionStrategy.NONE` declared/undefined, CLI exit code never reaches 1 from PII, `--no-warnings` is a no-op, `get_json_data` corrupts apostrophes, AESCipher decrypt/encrypt asymmetry, two `RecognizerResult` types with different `__gt__`. Octarine should design around these from day one

---

## V. Sample-only patterns (production-shaped but not in core libraries)

Surface revealed by reading `docs/samples/` notebooks and deployments
([`09-samples-deep.md`](09-samples-deep.md)). These are **patterns Presidio
documents and ships in samples but does NOT ship as first-class library
APIs** — sample code is the only place they exist.

### V.1 The "Invisio" reference architecture (`deployments/openai-anonymaztion-and-deanonymaztion-best-practices/`)

The most production-shaped sample in the repo. Architecture: Textual TUI →
FastAPI API → Redis (session state) → swappable Presidio backend; client
calls AzureOpenAI directly. Deployed to AKS + ACR + Azure Cache for Redis
via Bicep.

- **Three swappable `PresidioService` implementations** — `python` (in-process
  spaCy + custom operators), `http` (REST analyzer + REST anonymizer; **does
  pure-local string-replace for deanonymization**), `hybrid` (HTTP analyzer
  + in-process anonymizer/deanonymizer so custom operators stay local).
  Clean perf/architecture trade-off matrix.
- **State backends** — `InMemoryStateService` + `RedisStateService` behind
  abstract `StateService`. Session ID via `uuid.uuid4()`.
- **Bicep IaC** — `main.bicep` orchestrating `modules/{redis,aks,acr,roles}.bicep`.
  AKS uses SystemAssigned identity; ACR role-bound for pull; Redis Standard C SKU
  (`enableNonSslPort: false`). Default project name `preshack` (likely
  "Presidio hackathon" — signal that this is community-authored).
- **K8s manifests** define their own in-cluster Redis (for testing) **separate
  from** the Bicep-provisioned Azure Cache (production). Two deployment paths.
- Textual TUI client (`InputApp`) with `--mode {llm|manual}`, `--language en`.

### V.2 `InstanceCounterAnonymizer` / `InstanceCounterDeanonymizer` (session-stable pseudonymization)

**The most important sample-only operator pair.** Defined verbatim in
`docs/samples/python/pseudonymization.ipynb` and reused in Invisio.

```python
class InstanceCounterAnonymizer(Operator):
    REPLACING_FORMAT = "<{entity_type}_{index}>"
    def operate(self, text, params) -> str:
        entity_mapping = params["entity_mapping"]  # caller threads this dict
        if text in entity_mapping[entity_type]:
            return entity_mapping[entity_type][text]   # ← stability point
        previous_index = self._get_last_index(entity_mapping[entity_type])
        new_text = self.REPLACING_FORMAT.format(entity_type=entity_type, index=previous_index + 1)
        entity_mapping[entity_type][text] = new_text
        return new_text
```

- **Stateless operator** — the caller threads the same `entity_mapping` dict
  through every call. That dict (persisted to Redis under `session_id`) IS the
  session memory.
- **Format**: `<PERSON_0>`, `<PERSON_1>`, `<PHONE_NUMBER_0>` …
- **Deanonymizer** is a pure reverse lookup over the same dict (O(n) per token).
- The notebook explicitly notes: **"The following logic is NOT thread-safe"**.

This is the canonical pattern for reversible LLM-protection pseudonymization.

### V.3 LLM downstream protection patterns

- **LiteLLM proxy callback model** (`docs/samples/docker/litellm.md`) —
  Presidio as a callback in front of any LLM provider (Anthropic, Gemini,
  Bedrock, OpenAI). Capabilities:
  - **Input masking** to `[PERSON]`, `[PHONE_NUMBER]` tokens before LLM call
  - **Output parsing** (`output_parse_pii: true`) reverses tokens in LLM response
  - **Ad-hoc recognizers per LiteLLM virtual key** via
    `presidio_ad_hoc_recognizers` JSON file ref
  - **Per-key permission control** — `permissions: {"pii": false}` on a
    virtual key
  - **Per-request override** — clients send
    `extra_body={"content_safety": {"output_parse_pii": False}}`
  - **Logging-only mode** — `presidio_logging_only: true` redacts only in
    logs (Langfuse-style observers), passes raw to LLM
- **Invisio FastAPI model** (V.1 above) — long-lived session with
  Redis-backed mapping; client orchestrates the round trip itself

### V.4 Spark / Databricks / Fabric distributed pattern

Identical broadcast + pandas UDF pattern in `deployments/spark/01_transform_presidio.py`
and `fabric/artifacts/presidio_and_spark.ipynb`:

```python
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()
broadcasted_analyzer = sc.broadcast(analyzer)
broadcasted_anonymizer = sc.broadcast(anonymizer)

def anonymize_text(text: str) -> str:
    analyzer_results = broadcasted_analyzer.value.analyze(text=text, language="en")
    return broadcasted_anonymizer.value.anonymize(
        text=text, analyzer_results=analyzer_results,
        operators={"DEFAULT": OperatorConfig("replace", {"new_value": "<ANONYMIZED>"})},
    ).text

anonymize = pandas_udf(lambda s: s.apply(anonymize_text), returnType=StringType())
df = df.withColumn(col_name, anonymize(col(col_name)))
```

**Critical pattern**: broadcast engines once on driver (avoids reloading
heavy spaCy models per executor task); pandas UDF gives Arrow-vectorized
execution. Fabric variant adds **Delta Lake write** (`df.write.format("delta")
.mode("overwrite").saveAsTable(...)`) and Lakehouse `.whl` install for
`en_core_web_lg` (size limit workaround).

Spark sample is pinned to Databricks runtime 8.1 / spark 3.1.1 (relatively
old); Fabric sample is the actively maintained Spark reference.

### V.5 OpenTelemetry pre-emission redaction pattern

`deployments/redacting-telemetry/` — 7-service stack (presidio-analyzer +
presidio-anonymizer + pii-demo-app + otel-collector + loki + tempo + grafana).
PII is masked **at `set_attribute()` time** before `BatchSpanProcessor`
flushes:

```python
def mask_pii(pii: str) -> str:
    try:
        return presidio_mask_pii(pii)
    except Exception as e:
        logger.error(f"Error masking PII: {e}")
        return "[REDACTED]"  # fail-safe fallback

span.set_attribute("user.name", mask_pii(name))
```

Notable **inconsistency in the sample itself**: `user-registration` span
sets `user.name` and `user.email` raw — gap in coverage. The pattern is
right but the discipline is not enforced even in Presidio's own demo.

### V.6 PDF highlight annotation (not redaction)

`example_pdf_annotation.ipynb` uses **`pdfminer.six`** for text + char-level
bboxes and **`pikepdf`** for PDF annotation objects (NOT PyMuPDF, NOT
pdfplumber). Builds translucent red **highlight annotations** (`C=[1,0,0]`,
`CA=0.5`, `Subtype=Name.Highlight`, `QuadPoints` set to four-point bbox)
with the entity type stored in the `T` (title) field for hover-display.
Custom `combine_rect(rectA, rectB)` merges char boxes into phrase boxes.
Limitations called out: no OCR for image text, no extraction from PDF
annotations themselves, hidden text from incremental edits, ordering issues.

This is **the only PDF support Presidio has** — sample-only, highlight
not redaction.

### V.7 The "anonymize known values" pattern (per-record ad-hoc recognizers)

`Anonymizing known values.ipynb`:

```python
for row in df.iterrows():
    name_recognizer = PatternRecognizer(
        supported_entity="name", deny_list=[row.name])
    value_recognizer = PatternRecognizer(
        supported_entity="special_value", deny_list=[row.special_value])
    results = analyzer.analyze(
        text=row.text, language="en",
        ad_hoc_recognizers=[name_recognizer, value_recognizer])
```

**Per-record** recognizers — built per row from row data, passed via
`ad_hoc_recognizers` kwarg. This is a unique capability of the
`ad_hoc_recognizers` per-call mechanism that most PII libraries can't match.

### V.8 OpenAI as a surrogate generator (`synth_data_with_openai.ipynb`)

Pipeline: real text → Presidio analyze+anonymize to `<PERSON>` placeholders
→ OpenAI `client.chat.completions.create(model="gpt-3.5-turbo")` with
few-shot prompt using `[[TEXT STARTS]] / [[TEXT ENDS]]` delimiters and
double-brace Faker tokens (`{{credit_card_number}}`, `{{first_name_male}}`,
`{{nation_woman}}`, …). Author flags four limitations: extra unwanted output,
hallucinated PII, cross-field contamination, missed coreferences.

### V.9 Multi-NER ensemble registration pattern

```python
analyzer.registry.remove_recognizer("SpacyRecognizer")  # avoid duplicate NER
analyzer.registry.add_recognizer(flair_recognizer)
# or
analyzer.registry.add_recognizer(gliner_recognizer)
```

Streamlit demo, GLiNER sample, transformers sample all show this — register
new NER, **remove default SpacyRecognizer** to avoid duplicate NER. This
"remove + add" idiom is undocumented in core docs.

### V.10 Hardcoded AES key smell across samples

`presidio_streamlit.py` defaults `crypto_key = "WmZq4t7w!z%C&F)J"` — same
string is copied in `encrypt_decrypt.ipynb`. Trivial decrypt for anyone
reading the repo unless overridden. **Cited here as a documentation /
demo-quality smell**, not a recommendation.

### V.11 Typos accepted as production behavior

The Invisio sample uses `build_entity_mappgings` (sic) and `table_namne`
(sic) consistently — renaming would be a behavior-breaking refactor.
Smell, not a feature.

### V.12 The Streamlit demo phones home

`components.html(...)` injects Microsoft Clarity tracking
(`clarity.ms/tag/h7f8bp42n8`) — the public Presidio Streamlit demo is
NOT a privacy-preserving recommendation despite Presidio being a privacy
tool.

---

## W. In-flight surface (not yet in CHANGELOG)

From [`10-tests-issues-prs.md`](10-tests-issues-prs.md). The CHANGELOG covers
released work; this section captures what's merged-but-unreleased, in flight,
and on the maintainers' roadmap.

### W.1 Major behavioral shifts merged post-2.2.362 (imminent next release)

| PR | Change | Impact |
|---|---|---|
| **#1970** | **Unified `analyzer.yaml` config** | Consolidates `default_analyzer.yaml` + `default.yaml` + `default_recognizers.yaml` into one file. Breaking-ish for power users with custom configs. Old files retained with deprecation banners |
| **#1916** | **Slim NLP Engine becomes the new default** | New `SlimSpacyNlpEngine` — tokenization + lemmatization only, no NER, no parser. Pairs with `GLiNERRecognizer`. Adds `slim.yaml` / `slim_nlp.yaml`. **Default behavior shifts**: users relying on out-of-box spaCy NER lose `PERSON`/`LOCATION`/`ORGANIZATION` unless they add NER explicitly |
| **#2000** | **`countries=[...]` filter** on `RecognizerRegistry.load_predefined_recognizers()` | Infers country from module path. `countries=[]` keeps only locale-agnostic; `countries=None` is backwards-compat |
| **#1932** | **`merge_entities_with_whitespace=True` default** | Adjacent same-type entities now merged by default (single space; tabs/newlines NOT merged) |
| **#2014** | `supported_entity` configurable on `PhoneRecognizer` | Can override hardcoded `"PHONE_NUMBER"` to e.g. `TELEPHONE_OR_FAX` |
| **#1990** | German recognizer Prüfziffer fixes | KVNR, RVNR, LANR check-digit algorithms corrected; missing DE_VAT_ID checksum added |
| **#2025** | Custom operator `validate()` MUST NOT invoke lambda | Stateful-lambda corruption fix |

### W.2 Merged new recognizers post-2.2.362

CA_SIN, SE_ORGANISATIONSNUMMER, ES_PASSPORT, TR_NATIONAL_ID, TR_LICENSE_PLATE,
TR_PHONE_NUMBER, PH_MOBILE_NUMBER, configurable LangExtract (PR #1815).
DE family completion (#1990) including Prüfziffer corrections. PESEL
checksum fix (#1998). GLiNER YAML config preservation (#2007).

### W.3 Open PRs (in flight, expected in 2.2.363+)

| PR | Theme |
|---|---|
| #2041 | Tokenizer-based text chunking for NER (companion to #1916 slim engine) |
| **#2039** | **FastAPI anonymizer server** (addresses #1769; analyzer likely to follow) |
| #2040 | Image-redactor verify bug fix |
| **#2036** | **Indian UPI ID recognizer** — new payment-system PII category |
| #2035 | GSTIN checksum validation |
| #2031 | Country filtering follow-up |
| #2030 | PH passport recognizer |
| **#2029** | **US CLIA recognizer** — Clinical Laboratory Improvement Amendments identifier |
| #2028 | PH license plate |
| #2018 | Multiple GLiNER YAML configs |
| #2016 | PH TIN |
| **#1969** | **`negative_context` enhancer** — reduces FPs by penalizing if specific words appear nearby. New axis on context enhancer |
| #1943 | Fix `BasicLangExtractRecognizer.language_model_params` propagation |

### W.4 Long-term wishes (issues with no PRs)

1. **ML-based context awareness** (#1686, 15 comments) — beyond regex+lemma
2. **Recognizer-level thresholds** (#1572) — per-recognizer score gating
3. **Per-entity-type context words** (#1711) within a single recognizer
4. **Match-group support in PatternRecognizer** (#1120) — capture-group scoping
5. **Stable encrypt output / deterministic IV** (#1033) — long-standing
6. **Recipes gallery** (#1687), **3 starter modes** (#1809, "fast/balanced/accurate"),
   **benchmark dataset** (#1810) — maintainer's own UX issues
7. **AI-generated content labeling** (#1923) — EU AI Act Article 50 (Aug 2, 2026) angle
8. **Medical recognizer suite** (#1491) — MRN, accession numbers, NPI
9. **Precision/recall/latency CI gates** (#1639)
10. **Multi-frame DICOM + XA modality** (#1512, #1737, #1731)

### W.5 Open bugs of note

- **#1262** (20 comments) — spacy-huggingface-pipelines drops overlapping/unaligned spans
- **#1309** (14 comments) — DICOM redaction fails to detect Patient Name on official tutorial data
- **#1603** (11 comments) — Ad-hoc recognizer regexes are **always case-insensitive** even when caller doesn't want it (significant footgun)
- **#1063** — US Driver License recognizer FPs ("INTRODUCTORY", "INTERVENTION" matched as WA driver license)
- **#1444** — Context words used outside the suffix/prefix window (Lemma enhancer bug; substring-mode default)
- **#1498** — UrlRecognizer false-positives on code (`os.system`, `rpc.py`)
- **#1476** — IPv6 `::` handling broken (partial fix in #1941/#1940, issue still open)
- **#1316** — `presidio-structured` misidentifies email column as URL (`most_common` strategy bug)
- **#1156** — Anonymizing intersecting entities where bigger-span has lower score replaces the bigger one (counterintuitive)
- **#1731** — Image Redactor crashes on XA modality DICOM
- **#1942** — `BasicLangExtractRecognizer` silently drops `language_model_params` (timeout, num_ctx)

### W.6 Edge-case behaviors revealed by tests (not in docs)

- **11 predefined recognizers silently disabled by default in English registry**
  — undocumented convention surfaced only by `test_recognizer_registry.py`
- **Allow-list regex timeout retains entity** (fail-closed default) —
  surprising but security-favoring
- **Allow-list literal entries are case-sensitive by default** — must pass
  `regex_flags=re.IGNORECASE` explicitly
- **Empty deny lists raise `ValueError`**; allow lists do not
- **`::ffff:` IPv4-mapped IPv6 captured as single span** — explicit comment
  "to avoid leaking the `::ffff:` prefix" (security-by-design)
- **`REMOVE_INTERSECTIONS` tie-break adjusts the SECOND entity boundary** on
  score ties (deterministic but undocumented)
- **Substring-mode context matching is the historical default** — `"lic"`
  matches inside `"duplicate"`; root cause of issue #1444
- **`Mask` operator silently accepts negative `chars_to_mask` as no-op**
  (sloppy validation)
- **Custom operator `validate()` regression #2025**: probe-calling user
  lambdas corrupted stateful closures (token-counter maps were spoiled by
  the test invocation)
- **Email recognizer test coverage is notably shallow** — no IDN, no
  quoted local, no length attack. Likely a real FN source
- **`countries=None` ≠ `countries=[]`**: `None` is "no filter"; `[]` strips
  all country-specific but keeps generic
- **Class-level `COUNTRY_CODE` wins over constructor `country_code=`** but
  loudly (`ValueError` with "conflicts with class-level")
- **Anonymizer merges adjacent same-type entities separated by single space**
  (post-#1932) but NOT tabs/newlines

### W.7 Discussions are largely dormant

Most active GH Discussions threads are 2022-2024. No substantive 2026
threads. Notable historical:

- **#714** (30 comments) — RFC that led to `presidio-structured`
- **#669** — Spark friction (drove the broadcast pattern docs)
- **#758** — .NET Nuget package desired but unsupported
- **#609** — Decision-process should output detected text (same ask as #1361)

### W.8 `presidio-research` parallel work

Sustained span-evaluation work (PRs #157, #155, #156, #153, #152, #141)
replacing token-level metrics with IoU-based span metrics. Aligns with
#1639 (CI precision/recall gating). Open issue #98: integrate evaluation
for PII column identification in tables/JSONs with `presidio-structured`
(currently a gap).

---

## X. Loose-ends surface

From [`11-loose-ends.md`](11-loose-ends.md). Small surfaces that mattered.

### X.1 OpenAPI spec specifics not in §F

- `text` field in `AnalyzeRequest` is `string | string[]` — response is
  `RecognizerResult[]` for string input, `RecognizerResult[][]` for array
  input (documented as `oneOf` with two example payloads)
- **`context: []`** at the REQUEST level (separate from per-recognizer context)
  — globally boost any detection's score based on surrounding words
- **`trace: bool`** appears in V2 doc example but not in the schema (doc lag)
- **No `securitySchemes`, no `security:`** — explicit absence. Public demo
  endpoints are unauthenticated by design
- OpenAPI spec documents public Azure demo URLs as the `servers` value — no
  production-server template variable
- Score guidance documented inline in `Pattern` schema: "0.01 if very noisy,
  0.6–1.0 if very specific"
- Error codes: `400 BadRequest "Invalid request json"`, `422 UnprocessableEntity
  "Invalid input, text can not be empty"`

### X.2 Docker entrypoints (all identical)

```sh
#!/bin/sh
exec poetry run gunicorn -w "$WORKERS" -b "0.0.0.0:$PORT" "app:create_app()"
```

- `PORT=3000`, `WORKERS=1` from Dockerfile ENV
- **Build-time NLP model bake-in**: `poetry run python install_nlp_models.py`
  runs BEFORE source COPY → models baked in, not downloaded at first request
- Image redactor adds: spaCy `en_core_web_lg` as root (so non-root runtime
  can read), `tesseract-ocr` + `ffmpeg` + `libsm6` + `libxext6` apt packages,
  `tesseract -v` build smoke test
- **All three create non-root user `presidio` (uid 1001)** — security
  hardening worth matching
- **Python base versions drift intentionally**: analyzer `3.12-slim`,
  anonymizer `3.14-slim`, image-redactor `3.13.13-slim` (spaCy version
  constraints drive the analyzer pin)
- Healthcheck in Dockerfile (not entrypoint): `curl -f http://localhost:$PORT/health`
  every 30s, 3s timeout, 30s start-period, 3 retries

### X.3 The `decision_process` logger (analyzer-only) — actual implementation

```python
class AppTracer:
    def __init__(self, enabled: bool = True):
        self.logger = logging.getLogger("decision_process")
        self.enabled = enabled
    def trace(self, request_id: str, trace_data: str) -> None:
        if self.enabled:
            self.logger.info("[%s][%s]", request_id, trace_data)
```

Logger name is the literal string `"decision_process"` — **created via
`getLogger()` not declared in `logging.ini`**, so it inherits the root
logger's stdout handler. Anyone wanting separate decision-trace handling
must configure it externally.

### X.4 Image PII Verify engine specifics

Class hierarchy: `ImageRedactorEngine` → `ImagePiiVerifyEngine` →
`DicomImagePiiVerifyEngine` (diamond inherits from
`ImagePiiVerifyEngine` + `DicomImageRedactorEngine`).

`ImagePiiVerifyEngine.verify(image, is_greyscale, display_image, show_text_annotation,
ocr_kwargs, ad_hoc_recognizers, **text_analyzer_kwargs)` → PIL.Image.

`verify_dicom_instance(instance, padding_width=25, ..., use_metadata=True, ...)`
→ `(verify_image, ocr_bboxes, analyzer_bboxes)`.

`eval_dicom_instance(instance, ground_truth: dict, tolerance=50, ...)`
returns:

```python
{ "all_positives": [...], "ground_truth": {...},
  "precision": float, "recall": float }
```

**DICOM eval is dict-equality based**: `tp = [i for i in all_pos if i in gt]`
— any field shape drift silently zeroes precision/recall. Brittle but fine
for academic evaluation use.

**Verify engine emits no overlay colors itself** — it computes bboxes and
passes them to `add_custom_bboxes()` on the analyzer engine, where the
red/blue matplotlib choice lives.

### X.5 The presidio-cli `limited.yaml` misnomer

Not a "feature subset preset" — it's a **fully-documented example config**
showing every available key with comments:

```yaml
language: en              # optional, default en
ignore: |                 # optional list of ignored files/folders
  .git
  *.cfg
entities: [PERSON, CREDIT_CARD, EMAIL_ADDRESS]   # optional limit
threshold: 0.8            # optional score floor
locale: en_US.UTF-8       # optional locale
# extends: custom.yaml    # commented — config file inheritance
```

`default.yaml` is the empty-fallback ("just enough to run");
`limited.yaml` is the "here's what you can set" documentation file;
`.presidiocli` at the repo root is the actual example used to lint
Presidio itself.

### X.6 Streamlit demo NLP engine config detail

`presidio_nlp_engine_config.py` defines five factories: `create_nlp_engine_with_spacy`,
`create_nlp_engine_with_stanza`, `create_nlp_engine_with_transformers`,
`create_nlp_engine_with_flair`, `create_nlp_engine_with_azure_ai_language`.

Transformers config has **19-entity medical mapping** (PATIENT, STAFF, HOSP,
HCW, HOSPITAL, FACILITY, PATORG). spaCy config sets
`low_confidence_score_multiplier=0.4` for `ORG`/`ORGANIZATION`. Flair maps
`PER→PERSON, LOC→LOCATION, ORG→ORGANIZATION`, with `MISC` deliberately
commented out as "probably not PII".

Azure AI Language wrapper pulls
`TA_SUPPORTED_ENTITIES = [r.value for r in PiiEntityCategory]` from the
Azure SDK enum at import time — so adding new Azure entity types requires
no code change in Presidio.

OpenAI synthesis uses **legacy Completions API** (`text-davinci-003`), not
Chat Completions — the demo is outdated.

### X.7 Optional-deps complete enumeration

**`presidio-analyzer` (v2.2.362)**. Base: spacy, regex, tldextract, pyyaml,
phonenumbers, pydantic. Extras:

| Extra | Members |
|---|---|
| `server` | flask, gunicorn (non-Windows), waitress (Windows) |
| `transformers` | transformers, accelerate, huggingface_hub, spacy_huggingface_pipelines |
| `stanza` | stanza |
| `azure-ai-language` | azure-ai-textanalytics, azure-core |
| `ahds` | azure-identity, **`azure-health-deidentification (1.1.0b1)` — beta dep** |
| `gliner` | transformers, huggingface_hub, gliner, onnxruntime (`<1.24.1` on Python 3.10, unbounded on 3.11+) |
| `langextract` | langextract, openai, azure-identity, more-itertools, jinja2 |

**`presidio-anonymizer` (v2.2.362)**. Base: `cryptography>=46.0.4` (only!).
Extras: `server`, `ahds`.

**`presidio-image-redactor` (v0.0.58)**. Base: pillow, pytesseract,
presidio-analyzer, matplotlib, pydicom, pypng, **`azure-ai-formrecognizer`
(required, not optional!)**, opencv-python, python-gdcm, spaCy
(Py3.13-conditional). Extras: `server`. **Not supported on Windows.**

**`presidio-structured` (v0.0.6)**. Base: presidio-analyzer, presidio-anonymizer,
`pandas>=1.5.2`. **No optional extras.**

**`presidio-cli` (v0.0.9)**. Base: presidio-analyzer, pyyaml,
`pathspec>=0.9.0`. **No optional extras.** Entry point:
`presidio = presidio_cli.cli:run`. Python upper bound `<3.14`.

**Python upper bound drift across pyproject files**: analyzer `<3.14`,
anonymizer `<4.0`, image-redactor `<3.14`, structured `<4.0`, cli `<3.14`.
The `<4.0` ones will silently break when 3.14 cuts new APIs that pin spaCy
or cryptography upper bounds.

### X.8 Build/release process detail

- **Azure DevOps YAML pipelines** + **GitHub Actions** for releases. Azure
  DevOps: PR Validation + CI (deploys to internal dev) + Release (manual,
  releases to PyPI + MCR + Docker Hub + GitHub + updates public demo).
- **PyPI publishing via OIDC trusted publishing**
  (`pypa/gh-action-pypi-publish@release/v1`, `id-token: write`) — no PyPI
  tokens stored. Azure DevOps pipeline still uses traditional token auth.
- Two-maintainer approval requirement on PRs (governance signal).
- Test naming convention: `test_when_[condition]_then_[expected_behavior]`.
- Ruff + ruff-format via pre-commit; `pep8-naming` and `flake8-docstrings`.

### X.9 V1 → V2 history (March 2021 reset)

Key V1 → V2 changes per `docs/presidio_V2.md`:

- gRPC → HTTP
- pip-installable Python anonymizer (was Go-based in V1)
- Image Redactor renamed from `presidio-image-anonymizer` + rewritten in Python
- **FPE replaced with AES** — V2 encryption is non-format-preserving; FPE is
  no longer a Presidio feature
- Other V1 services (scheduler, datasink, etc.) "deprecated, may be migrated
  with community help"
- V1 branch still exists: `microsoft/presidio/tree/V1`

### X.10 Community ecosystem (18 integrations)

Per `docs/community.md`: HashiCorp Vault Operator (`sahajsoft/presidio-vault`),
Rasa, LangChain, LlamaIndex, LiteLLM, Guardrails-ai, LLMGuard, Privy,
Huggingface, KNIME, OpenMetadata, dataiku, Obsei, data-describe, Azure
Search Power Skills, DataOps for Modern Data Warehouse, Power BI Python/R
extension, **HebSafeHarbor** (Hebrew clinical notes), Presidio GitHub
Action.

### X.11 NOTICE file quirks

- Double-attribution typos: `azuure-ai-formrecognizer` (sic) and
  `opencv-python` each appear twice (once with typo) — file is partially
  auto-generated, partially hand-maintained
- `regex` library derives from CPython 2.6/3.1's `re` module — falls under
  CNRI's Python 1.6 license + the regex author's terms (unusual but
  well-tested)
- `python-gdcm` (Grassroots DICOM) is BSD with a Mathieu Malaterre copyright
- **No GPL/LGPL/AGPL deps** — Presidio is fully permissive-compatible

### X.12 Public Streamlit demo Microsoft Clarity tracking

`components.html(...)` injects `clarity.ms/tag/h7f8bp42n8` analytics into
the demo. "Use the public demo" is **not** a privacy-preserving recommendation
despite Presidio being a privacy tool.

### X.13 `presidio_evaluator.experiment_tracking` Comet integration

Soft `comet_ml` dependency (try/except). Selected by lowercase env
`tracking_framework`; currently only `"comet"` is recognized.
`LocalExperimentTracker` writes single `experiment_{YYYYMMDD-HHMMSS}.json`
to `os.getcwd()` on `.end()`. Comet env vars: `API_KEY`, `PROJECT_NAME`,
`WORKSPACE` (all uppercase, no `COMET_` prefix).

---

## Y. The complete revised thing-by-thing index for octarine comparison

Items 1–30 are in sections O and U above. The third-pass findings add:

31. **Session-stable token vault** (V.2) — `InstanceCounterAnonymizer` /
    `InstanceCounterDeanonymizer` pattern with persistent storage (Redis /
    in-memory / Postgres). Sample-only in Presidio; could be first-class
    in octarine
32. **Three-implementation swappable backend pattern** (V.1) — `python` /
    `http` / `hybrid` shapes for any service (analyzer, anonymizer,
    image redactor). Architectural pattern worth borrowing
33. **LLM downstream protection** (V.3) — LiteLLM-style proxy callback with
    per-key + per-request controls + logging-only mode; or FastAPI session
    long-lived pattern
34. **Distributed PII masking on Spark / Polars** (V.4) — broadcast engines
    + pandas UDF + Delta Lake write. Pattern is Rust-portable via Polars
    LazyFrame `.map_batches` or Spark via PyO3
35. **OTel pre-emission redaction** (V.5) — packaged Log/Span processor
    (octarine could ship as crate; Presidio's is sample-only)
36. **PDF support is sample-only and highlight-not-redaction** (V.6) —
    octarine could ship first-class PDF redaction
37. **Per-record ad-hoc recognizers** (V.7) — `ad_hoc_recognizers` per call
    + per row from row data. Already in §B.7 but worth elevating
38. **Per-format adapter discipline** (V.9, X.6) — three-NER-backend
    factories with identical surface, swap-friendly. Presidio gets this
    right; octarine should match
39. **Unified config file** (W.1, PR #1970) — single config replacing three.
    Octarine should design for this from day one (TOML, not three TOML files)
40. **Slim/Lean default + GLiNER pairing** (W.1, PR #1916) — opinionated default
    that drops NER to keep install footprint small; pairs with ONNX-backed
    zero-shot NER. octarine should consider similar "lean by default" posture
41. **Three starter modes** (W.4 #1809) — "fast / balanced / accurate" presets.
    Maintainer's own roadmap. Adopt as octarine builder presets
42. **Recipes gallery** (W.4 #1687) — explicit cookbook surface separate from
    docs. Presidio acknowledges this is missing
43. **EU AI Act Article 50 angle** (W.4 #1923) — content-labeling for AI
    output. Speculative but timely (Aug 2026 deadline)
44. **`negative_context` enhancer** (W.3 PR #1969) — penalize matches when
    specific words appear nearby (anti-context). New axis on context enhancer
45. **Country-filter machinery** (W.1 PR #2000) — already in §A but the
    module-path-inference pattern is worth noting; octarine's identifier
    module structure mirrors it naturally
46. **Build-time NLP model bake-in** (X.2) — models in image, not at first
    request. Default for any octarine container shipping models
47. **Non-root user (uid 1001)** in all Docker images (X.2) — standard
    hardening to match
48. **OpenAPI request schema details** (X.1) — `text` polymorphic
    (string | string[]), `context` at request level, `oneOf` response shape
49. **DICOM eval is dict-equality based** (X.4) — brittle but fine for
    academic use. Octarine's eval should use fuzzy IoU matching from day one
    (presidio-research's `SpanEvaluator` is the model)
50. **`limited.yaml` documentation pattern** (X.5) — ship a fully-commented
    example config alongside the empty default. Useful UX pattern
51. **Bundled medical NER label mapping** (X.6) — 19-entity medical map
    (PATIENT/STAFF/HOSP/HCW/HOSPITAL/FACILITY/PATORG) for transformers.
    Octarine should ship the same out of the box
52. **`Mask` silently accepts negative `chars_to_mask`** (W.6) — octarine
    should reject explicitly
53. **`::ffff:` IPv4-mapped IPv6 captured as single span** (W.6) —
    "to avoid leaking the `::ffff:` prefix" security-by-design choice to
    mirror in octarine IP detection
54. **Allow-list regex timeout retains entity** (W.6) — fail-closed default
    octarine should confirm or explicitly invert
55. **Class-level `COUNTRY_CODE` wins over kwarg with loud `ValueError`**
    (W.6) — three-way reconciliation with hard error on conflict
56. **AHDS surrogate as a distinct operator archetype** (audit 11) —
    realistic locale-aware replacements with cross-document consistency.
    Not just "replace" — preserves downstream analytics utility. The
    canonical example of "surrogation" as a separate operator category
    (replace vs surrogate vs mask vs hash vs encrypt vs keep)
57. **Pinned beta dep on AHDS** (`azure-health-deidentification 1.1.0b1`)
    — Presidio ships against Microsoft-published preview SDK and guards
    via try/except. Octarine should be more conservative about beta deps
58. **GLiNER + LangExtract as recent additions** (audit 11) — newer NER
    approaches added as optional extras. Octarine should consider similar
    pluggable-backend pattern
59. **Hardcoded AES key smell across samples** (V.10) — don't ship demos
    with default keys; force key configuration
60. **The "Recipes" section is the unfilled cookbook surface** — octarine
    could differentiate by actually filling it
