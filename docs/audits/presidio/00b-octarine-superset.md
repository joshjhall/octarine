# Octarine ⊇ Presidio — Superset Posture

**Goal.** Octarine is a **strict superset** of Presidio's value proposition.
Presidio is one input; octarine's design intentionally goes wider in scope
(security primitives + observability + identifiers, not just PII) and deeper
in implementation (Rust, zero-cost abstractions, layered architecture).

This document captures:

1. **§A — Gaps from Presidio** — features in Presidio's master inventory
   ([`00-feature-master.md`](00-feature-master.md)) that octarine should
   adopt, decline (with reasoning), or already has. These flow downstream
   into the next octarine audit pass.
2. **§B — Octarine-only surfaces** — features octarine offers that Presidio
   doesn't, and shouldn't need to. These are the asymmetric wins.
3. **§C — Design decisions octarine should NOT inherit** — Presidio
   patterns that octarine explicitly improves on (latent bugs, asymmetric
   error handling, etc.).
4. **§D — The "what's a PII tool for" reframing** — why octarine is
   structurally different and how that drives feature choices.

This is a **planning document**, not an implementation tracker. Issues +
roadmap entries go into GitHub once decided.

---

## §A. Gaps from Presidio — features to triage

Each row is something Presidio has that octarine should consider. Classification:

- **🟢 Adopt** — clearly worth implementing
- **🟡 Adopt later** — defer until needed; not blocking
- **🔵 Adapt** — implement the IDEA but with octarine's design (different shape)
- **🔴 Decline** — explicitly out of scope; document the reasoning
- **✅ Already covered** — octarine already has this

The next audit (octarine-side) will fill in the right column. For now we
just enumerate.

### A.1 Identifier coverage gaps

Presidio ships **62 recognizer classes** spanning **16 countries**. Octarine
should compare entity-by-entity. Specific items to triage:

#### Country packs to compare against octarine's coverage

| Country | Presidio entities | Octarine status |
|---|---|---|
| Germany | 13 — DE_TAX_ID, DE_TAX_NUMBER, DE_VAT_ID, DE_PASSPORT, DE_ID_CARD, DE_SOCIAL_SECURITY (RVNR), DE_HEALTH_INSURANCE (KVNR), DE_KFZ, DE_HANDELSREGISTER, DE_PLZ, DE_LANR, DE_BSNR, DE_FUEHRERSCHEIN | TODO |
| United States | 9 — US_SSN, US_ITIN, US_PASSPORT, US_DRIVER_LICENSE, US_BANK_NUMBER, US_NPI, US_MBI, ABA_ROUTING_NUMBER, MEDICAL_LICENSE (DEA) | TODO |
| India | 6 — IN_AADHAAR (Verhoeff), IN_PAN, IN_PASSPORT, IN_VOTER, IN_GSTIN, IN_VEHICLE_REGISTRATION | TODO |
| United Kingdom | 6 — UK_NHS, UK_NINO, UK_DRIVING_LICENCE, UK_PASSPORT, UK_POSTCODE, UK_VEHICLE_REGISTRATION | TODO |
| Italy | 5 — IT_FISCAL_CODE, IT_VAT_CODE, IT_PASSPORT, IT_IDENTITY_CARD, IT_DRIVER_LICENSE | ✅ Italian pack landed (PR #459) |
| Korea | 5 — KR_RRN, KR_FRN, KR_BRN, KR_PASSPORT, KR_DRIVER_LICENSE | TODO |
| Australia | 4 — AU_ABN, AU_ACN, AU_MEDICARE, AU_TFN | TODO |
| Spain | 3 — ES_NIF, ES_NIE, ES_PASSPORT | TODO |
| Turkey | 2 — TR_NATIONAL_ID, TR_LICENSE_PLATE | 🟡 In progress (current branch) |
| Sweden | 2 — SE_PERSONNUMMER, SE_ORGANISATIONSNUMMER | TODO |
| Singapore | 2 — SG_NRIC_FIN, SG_UEN | TODO |
| Nigeria | 2 — NG_NIN, NG_VEHICLE_REGISTRATION | TODO |
| Canada | 1 — CA_SIN (Luhn, en + fr) | TODO |
| Finland | 1 — FI_PERSONAL_IDENTITY_CODE (HETU) | TODO |
| Poland | 1 — PL_PESEL | TODO |
| Thailand | 1 — TH_TNIN (Thai mod-11) | TODO |
| Philippines (Unreleased) | 1 — PH_MOBILE_NUMBER | TODO |

#### Algorithmic validators to mirror

| Algorithm | Used by | Octarine status |
|---|---|---|
| Luhn (mod-10) | Credit cards, CA_SIN, US_NPI, IT_VAT, SE_PERSONNUMMER, SE_ORGANISATIONSNUMMER, ABA_ROUTING (weighted) | TODO |
| ISO 7064 mod-97 | IBAN (70 countries) | TODO |
| ISO 7064 mod-11,10 | DE_TAX_ID | TODO |
| mod-11 weighted | DE_VAT_ID, DE_LANR, DE_BSNR, AU_TFN, KR_RRN/FRN, TR_NATIONAL_ID, TH_TNIN, UK_NHS, PL_PESEL, IT_FISCAL_CODE, FI_HETU (mod-31) | TODO |
| mod-23 letter table | ES_NIF, ES_NIE | TODO |
| Verhoeff | IN_AADHAAR, NG_NIN | TODO |
| GSTIN modulus | IN_GSTIN | TODO |
| ICAO 9303 MRZ check digit | DE_PASSPORT, DE_ID_CARD (also any other passport using MRZ) | TODO |
| Double-SHA-256 + base58 / Bech32(m) | Bitcoin CRYPTO | TODO |
| DEA number checksum | MEDICAL_LICENSE | TODO |
| DVLA driver licence checksum | UK_DRIVING_LICENCE | TODO |
| Mod-89 / mod-10 custom | AU_ABN, AU_ACN, AU_MEDICARE | TODO |
| ACRA UEN checksum | SG_UEN | TODO |
| BRN checksum | KR_BRN | TODO |
| TCKN mod-10/mod-11 | TR_NATIONAL_ID | TODO |
| KVNR checksum | DE_HEALTH_INSURANCE | TODO |
| RVNR (DRV) checksum | DE_SOCIAL_SECURITY | TODO |

#### Generic recognizers worth comparing

| Entity | Presidio mechanism | Octarine status |
|---|---|---|
| Credit card | Per-brand regex + Luhn (en + es + it + pl) | TODO |
| IBAN | 70-country regex + mod-97 | TODO |
| Phone | `python-phonenumbers` library — 8 default regions, openable to ~250 | TODO |
| Crypto wallet | **Bitcoin only** in Presidio. Octarine gap: add ETH (0x + EIP-55), Solana, Monero, etc. | 🟢 Adopt + extend (multi-chain) |
| SWIFT/BIC | **Presidio doesn't have one** | 🟢 Adopt (Presidio gap) |
| URL | Custom 4-regex | TODO |
| Email | Regex + TLD validation | TODO |
| IP | IPv4/IPv6 with edge cases | TODO |
| MAC | Colon + dot formats + invalidate | TODO |
| Date/time | 13 regex patterns | TODO |

### A.2 Detection orchestration (engine) gaps

| Feature | Presidio | Adopt for octarine? |
|---|---|---|
| Per-call `ad_hoc_recognizers` injection | Yes, JSON-shaped via REST | 🟢 Adopt — API-level per-call recognizer plug-in |
| Allow-list at call time (`exact` / `regex` modes) | Yes | 🟢 Adopt |
| Deny-list at recognizer-level | Yes, `PatternRecognizer(deny_list=...)` | 🟢 Adopt |
| Single engine-wide `score_threshold` | Yes | ✅ Concept covered (we have confidence) |
| **Per-entity score thresholds** | **No — Presidio gap** | 🟢 Adopt + extend (octarine should beat Presidio here) |
| Per-recognizer context word lists | Yes, lemma-based | 🟢 Adopt — drives FP reduction |
| `LemmaContextAwareEnhancer` scoring math (`+0.35`, floor `0.4`, cap `1.0`) | Yes; window 5 lemmas before / 0 after; `substring`/`whole_word` modes | 🟢 Adopt the IDEA. Make it octarine-shape (probably builder-configurable per identifier domain) |
| Dict key → context word auto-promotion (`analyze_dict({"ssn": "..."})`) | Yes — killer feature for structured-data scanning | 🟢 Adopt — high-leverage |
| Regex execution timeout (`REGEX_TIMEOUT_SECONDS`) | Yes, 60s default | 🔵 Adapt — Rust's `regex` crate doesn't have catastrophic backtracking (linear-time guarantees), so we may not need this BUT we should still surface a per-pattern budget for slow patterns |
| Third-party `regex` module for `\p{...}` Unicode | Yes (Python `regex`) | ✅ Rust's `regex` crate supports Unicode property classes natively |
| `validate_result(text) -> bool` checksum hook | Yes — returns True → MAX_SCORE, False → MIN_SCORE | 🟢 Adopt — we likely already do this implicitly with strong-typed validators, but make it a first-class hook |
| `invalidate_result(text)` to drop FPs | Yes | 🟢 Adopt |
| `country_code` three-way reconciliation (class ClassVar + constructor + YAML) | Yes (Unreleased) | 🟢 Adopt — fits octarine's strong-typed identifier model |
| `enabled: false` per-recognizer toggle | Yes | 🟢 Adopt — runtime opt-in/out of recognizers |
| `supported_countries: [us, uk]` registry filter | Yes (Unreleased) | 🟢 Adopt — deployment-region tuning |
| Per-call `correlation_id` | Yes — accepted but **not propagated to logs** (Presidio bug) | 🟢 Adopt + DO propagate (we have `observe`) |
| `AnalysisExplanation` / decision-process trace | Yes — first-class, exposes pattern, validator outcome, context word, score delta | 🟢 Adopt + integrate with `observe` audit trail (it's our native medium) |
| `AppTracer` audit hook (separate from logger) | Yes | ✅ Already covered (`observe` is this concept) |
| `RemoteRecognizer` abstraction | Yes — first-class for delegating detection to network service | 🟡 Adopt later — octarine could ship this as a Layer 3 wrapper. Useful for LLM/cloud integrations |
| Conflict resolution `ConflictResolutionStrategy` enum (`MERGE_SIMILAR_OR_CONTAINED`, `REMOVE_INTERSECTIONS`, NONE) | Yes (mostly; NONE missing from enum body — Presidio bug) | 🟢 Adopt — first-class enum, no missing variants |
| Cross-type overlap removal | **No — Presidio only dedups same-type** | 🟢 Adopt + extend — let callers choose cross-type policy |
| Adjacent same-type span merging across whitespace | Yes (`merge_entities_with_spaces=True`) | 🟢 Adopt |

### A.3 Anonymizer / transformation gaps

| Feature | Presidio | Adopt for octarine? |
|---|---|---|
| `replace` operator | Yes, `<ENTITY_TYPE>` fallback | 🟢 Adopt |
| `redact` | Yes (empty string) | 🟢 Adopt |
| `mask` with `from_end` | **Single char only** in Presidio | 🟢 Adopt + extend (multi-char unit support; configurable preservation of separators) |
| `hash` (SHA-256/512 only, salted by default since 2.2.361) | Yes. **No HMAC, BLAKE, Argon2, bcrypt** | 🟢 Adopt + extend — leverage octarine's `crypto` Layer 3 (BLAKE3, HMAC, etc.) |
| `encrypt`/`decrypt` (AES-CBC, no auth, no KDF, raw key bytes) | Yes — **insecure by modern standards** | 🔵 Adapt — octarine should use AES-GCM-SIV or ChaCha20-Poly1305 (AEAD), with KDF for password-derived keys, version byte, AAD support |
| `keep` (no-op for audit visibility) | Yes | 🟢 Adopt |
| `custom` operator with stateful lambda | Yes; **validate doesn't probe-call** the lambda (deliberate) | 🟢 Adopt — same probe-avoidance discipline |
| `surrogate_ahds` (Azure Health Data Services) | Yes (optional extra) | 🔴 Decline — Azure-specific. Octarine should provide a generic surrogate-generator interface that anyone can plug an Azure backend into |
| `decrypt` / `deanonymize_keep` | Yes (only 2 deanonymizers) | 🟢 Adopt + add **AEAD verify-then-decrypt** as the canonical path |
| **Format-preserving encryption (FPE)** | **No — Presidio gap** | 🟢 Adopt — octarine should offer FPE for PANs, SSNs, etc. |
| **Tokenization with vault** | **No — sample-only via `InstanceCounterAnonymizer`** | 🟢 Adopt — first-class persistent token vault as a Layer 3 service |
| **HMAC / keyed-hash operator** | **No — Presidio gap** | 🟢 Adopt — for joinable cross-system tokenization |
| **k-anonymity / generalization** (date-shift, age-bucket, ZIP truncate) | **No — Presidio gap (roadmap-promised since structured docs)** | 🟢 Adopt — major value-add over Presidio. octarine should ship `generalize_date_to_year()`, `age_bucket(5)`, `truncate_zip(3)`, etc. |
| **Differential-privacy noise** | **No — Presidio gap (roadmap-promised)** | 🟡 Adopt later — Laplace/Gaussian noise on numeric fields. Useful but lower priority |
| `MERGE_SIMILAR_OR_CONTAINED` / `REMOVE_INTERSECTIONS` conflict strategy | Yes | 🟢 Adopt (already enumerated in A.2) |
| Batch anonymize (sequential, no async) | Yes | 🟢 Adopt + add async / parallel via `runtime` |
| Batch deanonymize | **Missing in Presidio** | 🟢 Adopt — symmetric API |
| Custom-operator extension (`add_anonymizer(cls)`) | Yes, instance-scoped | 🟢 Adopt — register custom operators per-engine |

### A.4 Image / DICOM redaction gaps

Octarine is currently text-only. Choosing scope here:

| Feature | Presidio | Adopt for octarine? |
|---|---|---|
| OCR-based image redaction | Yes, Tesseract + Azure DI | 🟡 Adopt later — phase 2 feature. Rust has `tesseract` bindings. Consider as separate `octarine-image` crate |
| DICOM pixel-data scrubbing | Yes (pixel only — metadata out of scope) | 🟡 Adopt later — only if a customer asks |
| DICOM metadata scrubbing | **Presidio gap** | 🟢 Adopt + do better than Presidio: complete DICOM PS3.15 Annex E support, not just pixel data |
| Bbox merge / NMS / overlap suppression | **Presidio gap** | 🟢 Adopt (when image support lands) |
| PDF redaction | **Presidio gap (sample-only)** | 🟡 Adopt later |
| Multiple redaction methods (blur, pixelate, inpaint, fill) | Presidio only does fill | 🟢 Adopt + extend |
| Image PII verify workflow (red/blue overlay) | Yes | 🟡 Adopt later — useful for tooling, not core |

### A.5 Structured data gaps

| Feature | Presidio | Adopt for octarine? |
|---|---|---|
| pandas DataFrame redaction | Yes, row-major Python (slow on large frames) | 🟢 Adopt + DO column-vectorized properly. Use polars or arrow. |
| JSON / nested dict redaction | Yes | 🟢 Adopt |
| CSV file reader | Yes (thin `pd.read_csv`) | 🟢 Adopt |
| Three column-selection strategies (`most_common`, `highest_confidence`, `mixed`) | Yes for pandas, none for JSON | 🟢 Adopt — for both pandas-equivalent and nested JSON |
| **Parquet / Arrow / ORC / Avro** | **Presidio gap (roadmap-promised)** | 🟢 Adopt — natural for Rust ecosystem |
| **PySpark / Polars** | **Presidio gap** | 🟡 Adopt later — Polars first (Rust-native), Spark eventually |
| **SQL row iterators** | **Presidio gap** | 🟢 Adopt — Layer 3 `data/` already has SQL story |
| **Streaming readers** | **Presidio gap** | 🟢 Adopt — Rust async iterators are perfect for this |
| **Sensitive column-name detection** | **Presidio gap (roadmap-promised)** | 🟢 Adopt — ColumnNamePiiHinter that boosts cell scores based on column name heuristics |

### A.6 NLP / NER integration gaps

This is where octarine's design diverges most. Presidio is heavily NER-driven (spaCy + Stanza + Transformers + GLiNER); octarine is regex-and-checksum first.

| Feature | Presidio | Adopt for octarine? |
|---|---|---|
| spaCy NER integration | Yes | 🔵 Adapt — octarine should support optional ONNX-based NER via a feature flag, not require it |
| Stanza NER | Yes | 🔴 Decline — Stanford research framework, niche |
| HuggingFace Transformers NER | Yes | 🔵 Adapt — ONNX runtime path (no PyTorch dep) |
| GLiNER zero-shot NER | Yes (ONNX backend) | 🟢 Adopt — fits Rust + ONNX nicely |
| Medical NER (8 sub-entities) | Yes | 🟢 Adopt — important for HIPAA workflows |
| `NerModelConfiguration` (aggregation_strategy, stride, alignment_mode, label mapping) | Yes | 🟢 Adopt the IDEA for whichever NER paths we support |
| `model_to_presidio_entity_mapping` (config-driven label translation) | Yes | 🟢 Adopt as `model_to_octarine_identifier_mapping` |
| `low_confidence_score_multiplier` / `low_score_entity_names` | Yes | 🟢 Adopt |
| LangExtract LLM-based recognizer | Yes (any LLM provider via YAML, Azure OpenAI w/ managed identity) | 🟢 Adopt as a Layer 3 wrapper. **High-value asymmetric win** if we do it well |
| Custom NLP engine plug-in path | Yes | 🟢 Adopt — `NlpEngine`-equivalent trait |
| Multi-language registration (per recognizer or YAML-driven) | Yes | 🟢 Adopt — locale-aware identifier registry |
| **Dropping ORG/ORGANIZATION via `labels_to_ignore` by default** | Yes — "has many false positives" | ⚠️ Note this as a guidance — opinionated default for NER paths |
| Two NER paths: as `NlpEngine` OR as standalone `Recognizer` | Yes | 🟢 Adopt — gives users flexibility |

### A.7 Operational / deployment gaps

| Feature | Presidio | Adopt for octarine? |
|---|---|---|
| REST API (analyzer/anonymizer/image) | Yes — Flask + gunicorn | 🟢 Adopt — Rust `axum` natural fit. Layer 3 `http` already exists |
| OpenAPI spec | Yes | 🟢 Adopt — `utoipa` or similar |
| Postman collections | Yes | 🟡 Adopt later — generate from OpenAPI |
| Health endpoints | Yes (single `/health`) | 🟢 Adopt + add `/ready` (liveness vs readiness) |
| `/metrics` endpoint | **Presidio gap** | 🟢 Adopt — `observe` produces metrics natively |
| Version endpoint | **Presidio gap** | 🟢 Adopt — `/version` returning build SHA, version, features |
| YAML config (layered: analyzer + NLP + registry) | Yes | 🟢 Adopt the IDEA. octarine should use TOML (Rust ecosystem standard) with the same layering semantics |
| Env var overrides | Yes | 🟢 Adopt |
| Dockerfiles (5 analyzer variants) | Yes | 🟢 Adopt — one Dockerfile per feature combination (no NLP / NLP / LLM) |
| docker-compose with sidecars (Ollama!) | Yes | 🟢 Adopt + add example with Ollama for the LLM recognizer |
| Helm chart | Yes (bare-bones — 3 Deployments, 3 Services, 1 Ingress) | 🟢 Adopt + add proper HPA / PDB / NetworkPolicy / ServiceAccount that Presidio's chart lacks |
| Azure ARM templates | Yes | 🔴 Decline — write generic IaC (Terraform module), not Azure-specific |
| Native ARM64 CI builds | Yes (`ubuntu-24.04-arm`) | 🟢 Adopt — Rust cross-compiles trivially |
| SBOM + provenance attestations | Yes (per Docker image push) | 🟢 Adopt — fits modern security expectations |
| `REGISTRY_NAME` / `IMAGE_PREFIX` env overrides | Yes (mcr.microsoft.com default) | 🟢 Adopt — `ghcr.io/...` default |
| Workflow_dispatch-only release | Yes | 🟢 Adopt + extend — tag-triggered + manual override (we already do this) |
| Independent versioning of subcomponents | Yes (image-redactor on its own version line) | 🟡 Adopt later if we split into multiple crates |
| **No-auth-by-design** stance | Yes (explicit FAQ) | ✅ Same posture for primitives. **DO NOT** add auth in core — push to ingress/gateway |
| `BATCH_SIZE`, `N_PROCESS` env tunables | Yes | 🟢 Adopt similar tunables (`OCTARINE_BATCH_SIZE`, etc.) |
| `PRESIDIO_DEVICE` GPU control | Yes | 🟢 Adopt as `OCTARINE_DEVICE` for any NER path that lands |

### A.8 Observability gaps

This is the **single biggest asymmetry**. Presidio has effectively no in-process observability. Octarine has `observe` as Layer 2 of the architecture. Section §B catalogs what octarine offers that Presidio doesn't.

For completeness, what Presidio does have:

| Feature | Presidio | Adopt for octarine? |
|---|---|---|
| Plain Python `logging` to stdout (INFO level) | Yes | ✅ Replaced by `observe` |
| `decision_process` logger (analyzer-only) | Yes — separate logger gated by `return_decision_process` | ✅ `AnalysisExplanation`-equivalent → `observe` event |
| `AppTracer` audit hook | Yes — distinct from logger | ✅ Already covered (`observe` IS this) |
| `NullHandler` per package | Yes (library convention) | ✅ Standard idiom |

### A.9 CLI gaps

Presidio has `presidio-cli` (analyzer-only, separate package).

| Feature | Presidio | Adopt for octarine? |
|---|---|---|
| File/directory scanning | Yes | 🟢 Adopt — `octarine scan` |
| Stdin input via `-` | Yes | 🟢 Adopt |
| Output formats: `standard`, `github`, `colored`, `parsable`, `auto` | Yes | 🟢 Adopt + add `sarif` (industry standard for security tooling) and `json` |
| YAML config (`.presidiocli`) | Yes — `language`, `entities`, `ignore`, `allow`, `threshold`, `locale`, `extends` | 🟢 Adopt as `.octarinerc` or `octarine.toml` |
| `extends` (recursive YAML inheritance + bundled presets) | Yes | 🟢 Adopt |
| gitwildmatch `ignore` patterns | Yes | 🟢 Adopt |
| Exit codes on PII found | **Broken in Presidio** | 🟢 Adopt + DO RIGHT — exit 1 when PII found |
| `--no-warnings` flag | **No-op in Presidio** | 🟢 Adopt + DO RIGHT |
| GitHub Actions annotation format | Yes | 🟢 Adopt — fits CI use case |
| Anonymize CLI | **Missing in Presidio** | 🟢 Adopt — `octarine anonymize` |
| Image redactor CLI | **Missing in Presidio** | 🟡 Adopt later when image lands |
| Multi-line entity detection in CLI | **Broken in Presidio (line-by-line)** | 🟢 Adopt + DO RIGHT |
| Batch / parallel CLI processing | **Missing in Presidio** | 🟢 Adopt — Rust makes this free |

### A.10 Evaluation & benchmarking gaps (from `presidio-research`)

| Feature | Presidio | Adopt for octarine? |
|---|---|---|
| Faker-based PII data generator | Yes (separate `presidio-evaluator` package) | 🟢 Adopt — `octarine-testing` already has generator infrastructure. Extend with PII templates |
| Token + Span evaluators | Yes (TokenEvaluator + SpanEvaluator with char-IoU) | 🟢 Adopt — testing crate |
| F-beta scoring (default β=2) | Yes | 🟢 Adopt — same default |
| Generic-entity tolerance for LLM detectors | Yes (`GENERIC_ENTITIES` tuple) | 🟢 Adopt |
| Template-aware train/test split | Yes (`split_by_template`) | 🟢 Adopt — borrow the idea |
| Error analysis (top-N FP/FN tokens with example) | Yes | 🟢 Adopt |
| Confusion matrix as `Counter[(annotation, predicted)]` | Yes | 🟢 Adopt |
| Model wrappers (Presidio analyzer/recognizer, spaCy, Stanza, Flair, Azure) | Yes | 🔵 Adapt — wrappers for whichever detectors octarine ships |
| `RecordGenerator` semantic coherence (`{{name}}` + `{{email}}` from same persona) | Yes | 🟢 Adopt |
| `FakeNameGenerator.com_3000.csv` personas | Yes (CC-BY-SA-3.0) | 🟡 Adopt later — licensing constraints |
| Bundled `synth_dataset_v2.json` (1500 samples, 17 entities) | Yes (MIT) | 🟢 Adopt or generate our own |
| CoNLL-2003 + i2b2-2014 PHI formatters | Yes | 🟡 Adopt later — academic datasets, niche |
| `LocalExperimentTracker` | Yes | 🟡 Adopt later |
| Plotter (Plotly bar charts + confusion matrix heatmaps) | Yes | 🟡 Adopt later — separate tooling |

### A.11 Type-system gaps (from §Q)

Presidio's type system is ad-hoc Python. Octarine should be **opinionated and consistent**.

| Concept | Presidio | Adopt for octarine? |
|---|---|---|
| `RecognizerResult` / `OperatorResult` / `EngineResult` | Yes — but two `RecognizerResult` classes with different `__gt__` | 🟢 Adopt the IDEA, fix the consistency problem |
| `OperatorType` enum (`Anonymize`, `Deanonymize`) | Yes | 🟢 Adopt as Rust enum |
| `ConflictResolutionStrategy` enum (with missing NONE!) | Yes | 🟢 Adopt + complete the enum |
| Shared base exception | **No — Presidio gap** | 🟢 Adopt — single `OctarineError` taxonomy (we already have `Problem`) |
| `AnalysisExplanation` decision-process record | Yes | 🟢 Adopt as a first-class observe event |
| `Pattern { name, regex, score }` | Yes, JSON-serializable | 🟢 Adopt + add `compile_flags`, `country_code`, `validator_fn` |
| `Custom` operator validate-without-invoke | Yes (deliberate, ref issue #2024) | 🟢 Adopt — same discipline (avoid probe-calling user callbacks) |
| pydantic-based YAML schema validation | Yes (since 2.2.361) | 🟢 Adopt — use `serde` + `figment` or `config` crate |
| Per-package `to_dict` / `from_dict` inconsistency | Yes — ad-hoc, ugly | 🟢 Adopt + DO RIGHT — `serde` Serialize/Deserialize uniformly |

### A.12 Concept-level gaps

Concepts the docs teach as first-class. Each is something octarine needs a parallel for.

| Concept | Presidio | Adopt for octarine? |
|---|---|---|
| Predefined vs custom recognizer | Yes | 🟢 Adopt |
| Ad-hoc recognizer (per-request) | Yes | 🟢 Adopt — REST + library API |
| Persistent recognizer (in code or YAML) | Yes | 🟢 Adopt |
| Deny list vs allow list | Yes | 🟢 Adopt |
| Score threshold (engine-wide + per-call) | Yes | ✅ + extend (per-entity thresholds) |
| Context word / context-aware enhancement | Yes | 🟢 Adopt |
| Decision process / explainability | Yes | 🟢 Adopt + ENRICH (Presidio explains positives, not negatives — octarine should explain both) |
| No-code YAML configuration | Yes | 🟢 Adopt — TOML for Rust |
| Country filtering | Yes (Unreleased) | 🟢 Adopt — fits strong-typed identifier registry |
| Multi-language support | Yes | 🟢 Adopt — locale-aware registry |
| Pseudonymization (reversible substitution) | Yes (concept, sample-only) | 🟢 Adopt as a first-class operator |
| InstanceCounter pattern (session-stable token mapping) | Yes (sample-only) | 🟢 Adopt as first-class with persistent vault backend |
| LLM-as-a-judge evaluation | Yes (new in 2.2.362) | 🟡 Adopt later |
| LLM-as-detector (LangExtract) | Yes | 🟢 Adopt |
| LLM-protection (LiteLLM proxy pattern) | Yes (sample) | 🟢 Adopt — guidance + example |
| GPU device control | Yes | 🟢 Adopt for any NER path |
| Performance budget (100ms / 100 tokens) | Yes (best-practices doc) | 🟢 Adopt — make octarine's budget explicit and benchmark against it |

---

## §B. Octarine-only surfaces (the asymmetric wins)

These are the features octarine offers that Presidio doesn't — and shouldn't
need to. They're why the comparison isn't symmetric and why we're not just
"Presidio in Rust."

### B.1 The three-layer architecture itself

Presidio is a flat library. Octarine has a deliberate three-layer architecture:

```
Layer 1: primitives/  (pub(crate))  - Pure functions, no dependencies
Layer 2: observe/     (pub)         - Observability, uses primitives
Layer 3: data/, security/, identifiers/, runtime/, crypto/, io/, auth/, http/
                                    - Uses primitives + observe
```

**Why this matters**: Presidio's PII detection sits in a vacuum. Octarine's
identifier detection sits inside a security-and-observability framework
where every detection is automatically observed, audited, and
PII-redactable through the same primitives that detect.

### B.2 The Three Orthogonal Concerns model

| Concern | Question | Presidio analog |
|---|---|---|
| `data/` — FORMAT | "How should this be structured?" | None — Presidio has no format normalization layer |
| `security/` — THREATS | "Is this dangerous?" | None — Presidio has no threat detection |
| `identifiers/` — CLASSIFICATION | "What is it? Is it PII?" | This is all of Presidio |

Presidio answers ONE question. Octarine answers three orthogonal ones. The
asymmetry is structural: Presidio is a subset of octarine's `identifiers/`
domain.

### B.3 Compliance-grade observability (Layer 2 = `observe`)

The single largest asymmetric win. Presidio's logging is `print`-tier:
stdout, INFO level, no structure, no correlation, no audit trail, no
compliance mapping.

Octarine's `observe`:

- **Automatic context capture** — WHO/WHAT/WHEN/WHERE in every event
- **PII auto-redaction in logs** — observe knows the identifiers it observes
- **Compliance control mapping** — SOC2, HIPAA, GDPR, PCI-DSS
- **Multi-tenant isolation** — thread-local tenant
- **Writers**: console, file (JSONL), SQLite, PostgreSQL
- **Tracing, metrics, events, audit, problem** all unified

Presidio gap analog: **none**. This is octarine-only.

### B.4 Security primitives (Layer 3 = `security/`)

Octarine ships `security/{commands,crypto,formats,network,paths,queries}`
covering command injection, traversal, query injection, SSRF detection,
shell metacharacters, etc. Presidio has **none of this**. PII detection
without input-validation primitives is half a story.

### B.5 Auth primitives (Layer 3 = `auth/`)

Octarine ships `auth/{csrf,lockout,mfa,password,remember,reset,session}`.
Presidio explicitly declines authentication. This is fine for Presidio's
scope but means octarine is a strict superset.

### B.6 Crypto primitives (Layer 3 = `crypto/`)

Octarine has crypto Layer 3. Presidio uses a single AES-CBC implementation
with no AEAD, no KDF, no MAC. Octarine offers the full modern crypto
toolkit through Layer 3 wrappers.

### B.7 I/O primitives (Layer 3 = `io/`)

Octarine ships file-operation primitives with observability. Presidio has
no equivalent — file I/O is the user's problem.

### B.8 Runtime primitives (Layer 3 = `runtime/`)

Octarine ships async / runtime utilities. Presidio is synchronous Python;
no async APIs anywhere even where it would matter (Azure DI client used
synchronously despite async SDK available).

### B.9 Rust performance

Linear-time regex (no catastrophic backtracking, so no `REGEX_TIMEOUT_SECONDS`
needed), zero-cost abstractions, true parallelism without GIL. Presidio's
batch APIs are sequential loops; octarine's can use `rayon` natively.

### B.10 Strong typing

Octarine's `IdentifierType`, `PiiType`, identifier-builder pattern give
compile-time guarantees that Presidio's string-keyed entity types can't.
A typo in `"EMAIL_ADDRESS"` is a runtime error in Presidio; in octarine
it's a compilation error.

### B.11 The PII-Identifier bridge

Octarine maintains three parallel registries (IdentifierType ↔ PiiType ↔
scanner domains) with explicit synchronization invariants. Presidio has
a single flat entity-type string registry; there's no concept of "PII
classification distinct from identifier classification."

### B.12 Cross-platform discipline (Layer 3 + `octarine-platform-compat`)

Octarine has skills/agents enforcing cross-platform compatibility (Windows,
macOS, Linux, ARM64). Presidio ships `Dockerfile.windows` but its Python
code makes Unix-isms (gunicorn vs waitress). Octarine targets all four
platforms first-class.

### B.13 Test resilience discipline

Octarine has `octarine-test-resilience` skill + nextest with retries +
ignored perf tests. Presidio's tests have flaky-timing patterns common
in Python.

### B.14 Build / release discipline

Octarine has `just` recipes for everything, `cargo nextest`, architecture
enforcement (`arch-check`), `octarine-release` skill encoding SemVer
policy. Presidio's release is `workflow_dispatch`-only with no SemVer
policy in docs.

### B.15 Skill-based knowledge architecture

Octarine has 7 project-specific skills + 7 project-specific audit agents
encoding implementation discipline. Presidio has no equivalent — Microsoft
ships docs and code but no per-domain implementation guidance.

### B.16 Comprehensive `Problem` type with audit trails

Octarine's `Problem` integrates with observe. Presidio has two
disconnected `InvalidParamError` classes and ad-hoc `ValueError`.

### B.17 The bigger identifier vision

Looking at `crates/octarine/src/primitives/identifiers/`:

```
biometric, common, confidence, correlation, credentials, crypto, database,
entropy, environment, financial, generic, government, location, medical,
metrics, network, organizational, personal, streaming.rs, token, types
```

Presidio has classes spanning roughly: `personal`, `financial`, `network`,
`government`, `medical`. Octarine adds: `biometric` (fingerprints, retinal),
`confidence`, `correlation` (cross-identifier correlation), `credentials`
(API keys, tokens, passwords), `crypto` (wallet addresses across chains),
`database` (connection strings, DSNs), `entropy` (high-entropy strings),
`environment` (env-var-style secrets), `streaming` (streaming-detector
API), `organizational`, `metrics` (telemetry IDs).

Each of those is a category Presidio doesn't even have a name for.

---

## §C. Presidio patterns octarine should NOT inherit

The audit surfaced concrete bugs and bad patterns in Presidio. Octarine
should explicitly avoid each:

| Anti-pattern | Where in Presidio | Octarine's posture |
|---|---|---|
| Two independent `InvalidParamError` classes that don't share a base | anonymizer + image-redactor | Single `Problem` taxonomy via `octarine-problem` crate |
| `ConflictResolutionStrategy.NONE` documented but missing from enum | anonymizer | Strong-typed enums; no doc/code drift |
| CLI exit code never reflects "PII found" (broken `max_level` logic) | presidio-cli | Exit-on-finding designed in from day one |
| `--no-warnings` flag is a no-op | presidio-cli | All flags must do what they say or be removed |
| Line-by-line CLI analysis misses multi-line entities | presidio-cli | Octarine CLI processes the full file |
| `get_json_data` corrupts apostrophes via `data.replace("'", '"')` | image-redactor | Don't do tricky pre-parse rewrites — accept proper JSON |
| `_exclude_attributes_from_dto` mutates engine output in-place for REST | analyzer | Serialize a view, don't mutate the model |
| Asymmetric REST error exposure (analyzer leaks `e.args[0]`, anonymizer doesn't) | analyzer vs anonymizer | Uniform error contract across all HTTP services |
| `correlation_id` accepted but not propagated to logs | analyzer | Propagate via `observe` automatically |
| `validate_type` silently passes on falsy values | anonymizer validators | Validators must validate; explicit None check separately |
| `OperatorConfig.params` mutated by engine (injects `entity_type`) | anonymizer | Immutable config; pass context as separate parameter |
| `Custom.validate()` previously probe-called user lambda → corrupted stateful closures | anonymizer (now fixed) | Never probe-call user callbacks (Presidio learned this, octarine should know it from day one) |
| `os.urandom(32)` salt that's never returned → non-joinable hashes by default | anonymizer hash | Make hash determinism explicit; document the salt contract |
| AES-CBC without authentication or KDF | anonymizer encrypt | AES-GCM-SIV or ChaCha20-Poly1305 with explicit KDF; never roll your own crypto without AEAD |
| `print(...)` in error paths (analyzer YAML loader) | analyzer | All output through `observe` |
| Heavy native deps for "just redaction" (OpenCV, GDCM, matplotlib all required to redact a PNG) | image-redactor | Feature-gated dependencies; opt-in heavy backends |
| `UK_POSTCODE` duplicated in default YAML registry | analyzer | Schema validation catches dup keys at load time |
| `KrPassportRecognizer` uses `"kr"` while other Korean recognizers use `"ko"` | analyzer | Consistent locale codes enforced by enum (ISO 639-1) |
| `MEDICAL_LICENSE` lives under `country_specific/us/` but documented as global | analyzer | Module path = scope; no cross-classification |
| `DATE_TIME` produced by both regex `DateRecognizer` AND every NER recognizer | analyzer | Single source of truth per identifier type |
| `AbaRoutingRecognizer`, `SgUenRecognizer`, `FiPersonalIdentityCodeRecognizer` exist but aren't in YAML registry → unreachable | analyzer | All identifiers reachable through registry by default |
| `BatchAnonymizerEngine` is a `for` loop with no parallelism | anonymizer | Rayon-based parallelism out of the box |
| Hardcoded `padding.PKCS7(128)` in AESCipher.decrypt while `algorithms.AES.block_size` would be cleaner | anonymizer | Use named constants, not magic numbers |
| OCR contract leaks Tesseract's parallel-list shape into all backends | image-redactor | Abstract over a typed `OcrResult` with bbox + confidence per word |
| DICOM tag detection by substring match on `element.name` (misses `InstitutionName`, `AccessionNumber`) | image-redactor DICOM | Match by tag number / VR, not human-readable name |
| Generic Python `logging.config` INI → unstructured stdout | all services | `observe` JSONL with full context |

---

## §D. The "what's a PII tool for" reframing

Presidio is a **PII detection + redaction library**. Octarine is a
**security primitives + observability + identifier classification
framework** of which PII detection is one application of one module.

The implications:

1. **Octarine's identifier registry is for more than PII.** Credentials,
   wallet addresses, telemetry IDs, database DSNs, biometric markers —
   these aren't "PII" in the Presidio sense but they're identifiers
   octarine classifies and redacts.

2. **PII detection in octarine is observation-grade.** Every detection
   produces a structured `observe` event with compliance mapping. Presidio
   produces a Python `RecognizerResult` and that's it.

3. **Octarine has security context.** Detecting "this string is an SSN"
   composes with "this path traverses out of the sandbox" and "this
   command has shell metacharacters." Presidio detects PII in isolation;
   octarine detects PII as part of full input-validation.

4. **Octarine has cryptographic context.** Encrypting a detected SSN
   doesn't go through a hand-rolled AES-CBC. It goes through Layer 3
   `crypto/` which is AEAD by default, has KDF, has key rotation hooks.

5. **Octarine has auth context.** Detected PII in an authenticated
   session belongs to a tenant; observe knows the tenant; the audit
   trail attributes the access. Presidio has no tenant model.

6. **Octarine has runtime context.** Detection can be streamed, batched,
   parallelized, async — natively. Presidio is sequential Python with
   `multiprocessing` as the only escape.

7. **Octarine is multi-language ready.** Locale-aware identifier registry,
   per-locale context lists, per-locale validators. Presidio is mostly
   English with country packs as opt-in afterthoughts.

8. **Octarine has tooling discipline.** Skills, agents, audit hooks, the
   `just` recipe surface, architecture enforcement. Presidio ships code
   and docs; octarine ships a development model.

---

---

## §D′. Expansion opportunities — places Presidio is weak and octarine can lead

These are areas where Presidio has either a known gap or a half-implemented
story. Each is a **strategic opportunity** for octarine to ship a complete
solution where Presidio ships a partial one. Listed by how clean the win is.

### D′.1 LLM integration (HIGH PRIORITY)

**Presidio's current state**:

- **As detector**: `LangExtractRecognizer` family (`BasicLangExtractRecognizer`
  + `AzureOpenAILangExtractRecognizer`) — works but requires the
  `langextract` Python package, Ollama compose dependency, and prompt
  YAML at `conf/langextract_config_*.yaml`. Configuration is YAML-only;
  there's no native streaming or async client.
- **As downstream protection**: Sample-only — `docs/samples/docker/litellm.md`
  shows a LiteLLM proxy pattern; the "Invisio" deployment sample wires
  AKS + Redis-backed session pseudonymization for OpenAI calls. Neither
  is a first-class library API.
- **Provider integrations**: Anthropic, OpenAI, Azure OpenAI, Ollama all
  via the same `langextract` abstraction; no provider-native SDKs.
- **No `langextract` deanonymizer** — LLM detection is one-way; results
  flow through the standard `presidio-anonymizer` pipeline.

**Where octarine can lead**:

1. **First-class `LLMRecognizer` in Layer 3** — Rust-native HTTP clients
   for OpenAI, Anthropic, Azure OpenAI, Ollama, plus a generic
   OpenAI-compatible endpoint. Streaming responses, retry policies,
   timeout budgets, prompt caching all integrated via Layer 3 `http/`.
2. **LLM-as-judge for evaluation** — Presidio added this in 2.2.362 but
   only as a sample; octarine could ship it as a `LLMJudge` evaluator
   in the testing crate.
3. **Prompt-and-response redaction proxy** — A Layer 3 service that
   sits between user code and an LLM provider, redacting on the way
   out and re-hydrating tokens on the way back. This is what the
   "Invisio" sample demonstrates manually; octarine could be the
   library that makes it a one-liner.
4. **Session-stable token vault** — The `InstanceCounterAnonymizer` /
   `InstanceCounterDeanonymizer` pattern is sample-only in Presidio.
   octarine should ship this as a first-class operator with pluggable
   backends (in-memory, Redis, Postgres).
5. **LLM-driven custom recognizer creation** — Use an LLM to draft
   `PatternRecognizer` definitions from natural-language descriptions
   ("detect employee IDs that look like E-followed-by-6-digits").
6. **Tool-use guardrails** — When the LLM calls a tool, redact PII
   from arguments before execution and re-hydrate in the response.
   This is the agentic-AI use case Presidio doesn't address.

**Why this is high priority**: every AI-native company built since 2024
needs this. Presidio's story is "wrap us in a proxy"; octarine could be
"link our crate." That's a categorical UX win.

### D′.2 OpenTelemetry / observability (MEDIUM-HIGH PRIORITY)

**Presidio's current state**:

- **No `/metrics` endpoint** on any of the three REST services
- **No OpenTelemetry, Prometheus, statsd, Sentry, or App Insights SDK**
  in any of the four `pyproject.toml` files
- Plain Python `logging.config` INI → stdout `INFO` level, no JSON
- `correlation_id` accepted in `AnalyzerRequest` but **not propagated** to logs
- Sample only: `docs/samples/deployments/redacting-telemetry/` is a
  proof-of-concept OTel stack where the *user's app* sends logs through
  OTel Collector → Loki/Tempo → Grafana, calling Presidio HTTP to redact
  *before* emission. Presidio is the redactor, not an emitter.

**Where octarine already leads** (this is mostly an asymmetric win):

- `observe` (Layer 2) is the entire framework. Automatic context capture,
  multi-tenant isolation, multiple writers, compliance control mapping.
- Every identifier detection in octarine produces a structured `observe`
  event with `who`/`what`/`when`/`where`.

**Where octarine should still ship to close the deployment story**:

1. **OTLP export adapter** — `observe` already emits events; ship a
   writer for OTLP/gRPC + OTLP/HTTP so users can plug into existing OTel
   Collector deployments. (May already exist — TODO confirm.)
2. **Prometheus exporter** — for the REST service, expose `/metrics`
   with counters for detections by entity type, latency histograms,
   error counters. Trivial given that `observe` already produces these
   metrics internally.
3. **Correlation ID propagation** — REST API accepts `x-correlation-id`
   or W3C `traceparent`, propagates through all `observe` events for
   that request. Solves Presidio's explicit gap.
4. **Distributed tracing spans** — emit OTel spans for each major
   pipeline stage (NLP → recognize → context-enhance → conflict-resolve
   → anonymize) so users can see latency breakdowns.
5. **OTel SDK redactor adapter** — provide a packaged OTel SDK
   `LogProcessor` / `SpanProcessor` that applies octarine PII detection
   to attributes and span data before export. This is the
   `redacting-telemetry` sample turned into a first-class adapter.

**Why this matters**: enterprise customers expect Prometheus + OTel
out of the box. Presidio makes you build that yourself. Octarine can
deliver it as a default.

### D′.3 DICOM redaction (MEDIUM PRIORITY — strong asymmetric opportunity)

**Presidio's current state — half a story**:

The `presidio-image-redactor` package ships `DicomImageRedactorEngine`
(version `0.0.58`, still labeled **beta**) that:

- **Only scrubs DICOM pixel data**. Metadata is explicitly out of scope.
  The docs say so: *"Presidio only redacts pixel data and does not scrub
  text PII which may exist in the DICOM metadata."*
- **Detects PHI tags by substring match on `element.name`**: looks for
  `"name"` and `"patient"` in the human-readable element name. Catches
  `PatientName`, `PatientID`, `PatientBirthDate`, `OtherPatientNames`,
  `ReferringPhysicianName`. **Misses** `InstitutionName`,
  `AccessionNumber`, `StudyID`, plus dozens of other PS3.15 Annex E
  Basic Confidentiality Profile tags.
- **No DICOM PS3.15 Annex E conformance** — the de-facto standard for
  DICOM de-identification. Presidio doesn't claim conformance and
  isn't.
- **Hard dependency on `python-gdcm`** for compressed pixel data —
  GDCM is BSD with custom variant, distribution-restricted in some
  environments.
- **Sequential bulk processing** — `redact_from_directory` is a `for`
  loop, no parallelism.
- **No multi-frame support** beyond what pydicom handles per-instance.

**Where octarine can lead — a complete DICOM de-id pipeline**:

1. **DICOM PS3.15 Annex E Basic Confidentiality Profile conformance** —
   This is the standard healthcare orgs require. It defines actions for
   ~150 tags: D (replace with dummy), Z (replace with zero-length value),
   X (remove), K (keep), C (cleaned — recursive de-id of contained items),
   U (replace UID with internally consistent UID). Octarine could be the
   first library to ship a Rust-native, fully-conformant implementation.
2. **Configurable profile selection** — Annex E defines additional
   options beyond Basic: Retain Patient Characteristics Option, Retain
   Longitudinal Temporal Information Option, Retain Device Identity
   Option, etc. Octarine should let users compose profiles.
3. **Both metadata AND pixel scrubbing** as a single API surface — the
   user shouldn't have to call two libraries. `octarine_dicom::deidentify(
   dataset, profile=BasicConfidentialityProfile)`.
4. **Tag-number-based detection** (not substring-on-name) so renames
   in upstream tag dictionaries don't silently break us.
5. **UID consistency** — when replacing UIDs (StudyInstanceUID,
   SeriesInstanceUID, SOPInstanceUID), maintain internal consistency
   across the dataset and across multiple instances of the same study.
   This requires a session-scoped UID-mapping vault. Presidio doesn't
   do this.
6. **Burnt-in PHI detection in pixel data** — same OCR pipeline as
   regular images, but Presidio's name-augmentation logic
   (UPPER/lower/Title casings, `^`/`-` collapsed) is genuinely useful;
   we should adopt it.
7. **Multi-frame, multi-modality support** — CT, MR, US, CR, DX, MG, PT.
   Each modality has its own PHI conventions. Multi-frame instances
   (e.g., cine loops) need per-frame redaction with consistent fills.
8. **Structured report (SR) handling** — DICOM SR documents contain
   PHI in TextValue tags throughout a recursive tree. Presidio doesn't
   touch SR; octarine should.
9. **Performance** — Rust + `dicom-rs` crate gives us native speed and
   memory safety where Presidio is single-threaded Python on top of
   GDCM.
10. **Audit trail per dataset** — every tag changed, with original
    value hash and replacement value, recorded in `observe`. HIPAA
    auditors love this. Presidio has nothing analogous.
11. **HL7 FHIR integration** — DICOM lives next to FHIR in real
    deployments. octarine could provide FHIR R4 / R5 PHI scrubbing
    using the same identifier registry (Patient, Practitioner,
    Organization resources). This is a natural extension beyond what
    Presidio offers.

**Why DICOM is a strong opportunity**:

- The healthcare/medical imaging market is large and underserved.
- Presidio's beta-tier, pixel-only implementation is genuinely
  inadequate for production healthcare use.
- DICOM PS3.15 is a well-defined standard — there's no ambiguity
  about what "complete" means.
- Rust's `dicom-rs` ecosystem is mature enough to build on.
- It composes well with octarine's identifier registry: PHI in DICOM
  metadata is exactly what `identifiers/medical/` should detect.
- It composes with `observe` for the audit trail that HIPAA
  Section 164.312(b) requires.
- It's a **lower-priority but lower-competition** space than the LLM
  space — fewer competitors to chase a niche specialty.

**Suggested phasing** (since this is lower priority overall):

- **Phase 1 (text-first)**: Metadata-only DICOM PHI scrubbing via the
  identifier registry. No OCR. No pixel data. Lets octarine handle
  90% of real DICOM PHI use cases (most PHI in real-world studies is
  in metadata, not pixels) at low engineering cost.
- **Phase 2 (PS3.15 Annex E conformance)**: Profile selection,
  UID-mapping vault, proper recursive de-id of sequences and
  structured reports. The "we are PS3.15-conformant" claim becomes
  marketable.
- **Phase 3 (pixel data)**: Add the OCR pipeline. By this point
  we'll have learned from the image-redaction landscape.
- **Phase 4 (FHIR / HL7)**: Use the same identifier registry on
  FHIR resources. Cross-format consistency.

### D′.4 Cross-cutting: the asymmetry compounds

These three opportunities (LLM, OTel, DICOM) compose with octarine's
existing architecture in ways Presidio can't match:

- **LLM + observe**: every LLM call is auto-traced with PII redaction
  on the prompt and response. The audit trail records which session,
  which tenant, which entities were redacted. Presidio would need a
  full observability rewrite to match this.
- **DICOM + observe**: HIPAA-grade audit log per dataset, with
  compliance-control mapping built in. Presidio's stdout `INFO` logging
  doesn't even attempt this.
- **DICOM + identifiers**: the same identifier registry detects PHI in
  DICOM metadata, in FHIR resources, in HL7 messages, in EHR exports.
  One registry, all formats. Presidio has separate pipelines per format.
- **LLM + identifiers + observe**: prompt redaction uses the same
  classifier as everything else; LLM-driven custom recognizer creation
  produces validated `PatternRecognizer` configs; tool-use guardrails
  share the audit trail with the regular pipeline.

These three areas are where octarine's three-layer architecture pays
off most. They're not just "Presidio has a gap" — they're "octarine's
shape makes these naturally cheap."

---

## §E. Next steps

This document is the input to the **octarine-side audit**, which will
walk each row in §A and classify it (Adopt / Adopt later / Adapt /
Decline / Already covered). Outputs:

1. A series of GitHub issues, labeled by priority and audit row.
2. A roadmap entry per major missing feature group (anonymizer parity,
   YAML config, REST API, evaluation framework, NER integration paths).
3. An updated CLAUDE.md or architecture doc capturing the §C anti-patterns
   as explicit guardrails.
4. A "Compared to Presidio" docs page that publicly states octarine's
   superset posture, citing this audit.

---

## §F. Third-pass findings — additional gaps & opportunities

The third audit pass (samples deep, tests/issues/PRs, loose ends) surfaced
a number of items that didn't fit into the original §A categorization.
These are added here rather than retrofitted to preserve auditability.

### §F.1 New gaps from sample patterns

These are patterns Presidio ships in samples but **not in core libraries** —
octarine could promote them to first-class.

| Sample pattern | Adopt for octarine? | Source |
|---|---|---|
| **Session-stable counter pseudonymization** (`InstanceCounterAnonymizer` + `InstanceCounterDeanonymizer`) | 🟢 Adopt — first-class with Redis / Postgres / in-memory backends behind a `StateStore` trait. This is the canonical LLM-protection pattern; making it core is a categorical win | V.2 |
| **Three swappable backends** (`python` / `http` / `hybrid`) for service architecture | 🟢 Adopt the discipline — Layer 3 services should support in-process + remote + hybrid wiring with identical surface | V.1 |
| **OTel pre-emission redaction processor** (packaged adapter) | 🟢 Adopt — ship as `octarine-otel` crate with `LogProcessor`/`SpanProcessor` impls that redact attributes before export. Presidio's `redacting-telemetry/` is a demo; octarine's should be a library | V.5 (extends §D′.2) |
| **Spark / Polars distributed pattern** (broadcast engines + per-batch UDF) | 🟢 Adopt — ship as Polars `.map_batches` adapter (Rust-native first), with PyO3 binding for Spark UDF later | V.4 |
| **Delta Lake write integration** | 🟡 Adopt later — `delta-rs` crate makes this trivial; not blocking. Pair with Spark/Polars adapter | V.4 |
| **LLM downstream protection (LiteLLM-style proxy)** | 🟢 Adopt — ship as `octarine-llm-proxy` Layer 3 service with per-key + per-request + logging-only controls. This is the LangChain/LlamaIndex/LiteLLM integration play | V.3 (extends §D′.1) |
| **OpenAI synthetic surrogate generator** (LLM as surrogate-producer) | 🟢 Adopt — alternative to AHDS for "realistic fake" generation. Pair with the LLM recognizer layer | V.8 |
| **PDF highlight annotation** (overlay vs redaction) | 🟡 Adopt later — second-class output mode for PDF integration | V.6 |
| **Per-record ad-hoc recognizers from row data** (`ad_hoc_recognizers` per call built from row content) | 🟢 Adopt — already in §A.2 but worth elevating as a flagship use case | V.7 |
| **Multi-NER ensemble idiom** (register one NER, remove default Spacy) | 🟢 Adopt — ship as a `NerEnsemble` builder that handles the deregistration automatically | V.9 |
| **Hardcoded AES key smell** | 🔴 Decline — actively avoid. Force key configuration; no defaults in samples | V.10 |

### §F.2 In-flight Presidio features octarine should also implement

From [`10-tests-issues-prs.md`](10-tests-issues-prs.md) — what's merged but
unreleased, or in flight as open PRs.

| Feature | PR / Issue | Adopt for octarine? |
|---|---|---|
| **Unified single-file config** (replaces three YAMLs) | PR #1970 | 🟢 Adopt — design for one TOML file from day one, not three |
| **Slim/lean default + GLiNER pairing** | PR #1916 | 🟢 Adopt the posture — octarine should default to a lean install footprint with optional NER backends |
| **`negative_context` enhancer** (anti-context words penalize matches) | PR #1969 | 🟢 Adopt — new axis on context enhancer that reduces FPs without sacrificing recall |
| **FastAPI anonymizer server** (async, vs Flask) | PR #2039 | ✅ Adopt — Rust `axum` is async-native; this is free for us |
| **Tokenizer-based text chunking for NER** | PR #2041 | 🟢 Adopt — proper chunking with overlap for long-input NER |
| **Indian UPI ID recognizer** (payment compliance) | PR #2036 | 🟢 Adopt — adds to A.1 country pack |
| **US CLIA recognizer** (Clinical Laboratory Improvement Amendments) | PR #2029 | 🟢 Adopt — adds to A.1 medical pack |
| **Multiple GLiNER configs in YAML** (multiple instances of same class) | PR #2018, #1819 | 🟢 Adopt the IDEA — Rust's trait-objects make this clean |
| **AI-generated content labeling** (EU AI Act Article 50 compliance) | #1923 | 🟡 Adopt later — speculative but timely (Aug 2026 deadline). Worth scoping |
| **Per-recognizer score thresholds** | #1572 | 🟢 Adopt — already in §A.2 and §A.6 |
| **Per-entity-type context words within single recognizer** | #1711 | 🟢 Adopt — context map keyed by entity type, not just flat list |
| **Match-group support in PatternRecognizer** | #1120 (long-standing) | 🟢 Adopt — let patterns expose capture groups so only group N is anonymized, not full span |
| **Stable encrypt output / deterministic IV opt-in** | #1033 (long-standing) | 🟢 Adopt — `Encrypt::deterministic(key, nonce_fn)` variant for joinable ciphertexts |
| **Precision/recall/latency CI gates** | #1639 | 🟢 Adopt — wire eval framework into `just preflight` for regression prevention |
| **Three starter modes** ("fast / balanced / accurate" presets) | #1809 | 🟢 Adopt as octarine builder presets — explicit tradeoff signaling |
| **Recipes gallery** (cookbook surface) | #1687 | 🟢 Adopt — actually fill the cookbook that Presidio acknowledges is empty |
| **Benchmark dataset** | #1810 | 🟢 Adopt — ship a benchmark dataset with octarine, scored every release |

### §F.3 Edge-case behaviors octarine should design for

Test-reveal items from `10-tests-issues-prs.md` §W.6.

| Behavior | Octarine posture |
|---|---|
| **Allow-list regex timeout retains entity** (fail-closed) | 🟢 Match — fail-closed for security. Document explicitly |
| **Allow-list literal entries case-sensitive by default** | 🔵 Adapt — octarine should default to case-insensitive for human-facing tokens; offer case-sensitive opt-in |
| **`::ffff:` IPv4-mapped IPv6 captured as single span** (anti-leak) | 🟢 Match — same security choice |
| **`REMOVE_INTERSECTIONS` tie-break adjusts SECOND entity** | 🟢 Document explicitly — make octarine's tie-break policy a docs first-class topic |
| **Substring-mode context matching default → `"lic"` matches `"duplicate"`** | 🟢 Default to `whole_word` from day one — Presidio kept this for backwards-compat; octarine has no compat burden |
| **`Mask` accepts negative `chars_to_mask` as no-op** | 🟢 Reject explicitly — `InvalidParam("chars_to_mask must be >= 0")` |
| **Custom operator `validate()` probe-calls user lambda → corrupts stateful closures** | 🟢 Never probe-call user callbacks — already in §C |
| **Email recognizer test coverage is shallow** (no IDN, no quoted local) | 🟢 Test these explicitly in octarine — IDN/quoted-local/length-attack |
| **`countries=None` ≠ `countries=[]`** in registry filter | 🟢 Match — `None`/`Some(vec![])` semantics with explicit docs |
| **No language-fallback logic** — unsupported language → `ValueError` | 🔵 Adapt — implement locale/script fallback chains (`zh-TW` → `zh` → fallback) |
| **11 predefined recognizers silently disabled by default in English** (undocumented convention) | 🟢 Be explicit — every disabled-by-default recognizer should have a one-line rationale visible in the registry |
| **`Mask` silently masks multi-char `masking_char`** — Presidio validates length 1 | 🔵 Adapt — octarine should ALLOW multi-char masking units (`"**"`, `"XX"`) since there's no reason to artificially limit |
| **Anonymizer merges adjacent same-type entities only on SINGLE SPACE (not tabs/newlines)** | 🔵 Adapt — make whitespace policy configurable (regex pattern), with sensible default |

### §F.4 Loose-end gaps

From [`11-loose-ends.md`](11-loose-ends.md).

| Item | Octarine posture |
|---|---|
| **Surrogation as a distinct operator archetype** (AHDS pattern: realistic locale-aware replacements with cross-document consistency) | 🟢 Adopt — ship a `Surrogate` operator category distinct from `Replace`. Pluggable backends: AHDS (Azure), LLM (OpenAI/Anthropic/Ollama), Faker (local). Cross-document consistency via state vault from F.1. This is the **single biggest operator-category gap** the audit surfaced |
| **OpenAPI `text` polymorphic (string \| string[])** | 🟢 Adopt — `axum` with `serde` enum `oneOf` handles this cleanly |
| **OpenAPI request-level `context: []`** (separate from per-recognizer context) | 🟢 Adopt — already in §A.2 but should be in REST shape |
| **Build-time model bake-in in Dockerfiles** | 🟢 Adopt — `ARG` for model variant, `RUN` to fetch at build time |
| **Non-root user (uid 1001) in all Docker images** | 🟢 Adopt — security hardening default |
| **`limited.yaml` documented-example-config pattern** | 🟢 Adopt — ship `octarine.example.toml` alongside `octarine.default.toml`. Better than just docs |
| **19-entity medical NER label mapping** (PATIENT/STAFF/HOSP/HCW/HOSPITAL/FACILITY/PATORG → Presidio canonical) | 🟢 Adopt — bundle the same mapping for any NER backend octarine supports |
| **Pinned beta dep on AHDS** | ⚠️ Avoid — octarine should NOT pin beta SDK deps without explicit feature-gate |
| **CLI multi-line entity detection** (Presidio CLI is broken: line-by-line) | 🟢 Adopt + DO RIGHT — already in §A.9 |
| **Pydantic-based YAML schema validation with `ConfigurationValidator`** | 🟢 Adopt — `serde` + `figment` validation with structured error messages |
| **`text_replace_builder` end-to-start replacement pattern** (so indices stay valid) | 🟢 Adopt — same algorithm, then re-normalize at end |
| **Comet experiment tracking soft-dep** | 🟡 Adopt later — eval framework can write to Comet/W&B/MLflow via optional adapters |
| **Python upper bound drift across pyproject files** (`<3.14` vs `<4.0`) | ⚠️ Avoid — octarine's MSRV policy should be uniform across the workspace |

### §F.5 Revised priority view

After three audit passes, the priority order for octarine's catch-up + lead has firmed up:

**Tier 1 — must-have parity** (blocks credibility as "PII library"):

1. Country recognizer packs (US, UK, DE, IN, IT — first wave; FR, CA, ES, AU, BR — second wave)
2. Algorithmic validators (Luhn, mod-97, mod-11, Verhoeff, MRZ, ABA, GSTIN)
3. Anonymizer parity (replace, redact, mask, hash, encrypt, decrypt, keep, custom)
4. YAML-driven (TOML in our case) configuration
5. REST API (analyzer + anonymizer)
6. CLI (analyzer scan)
7. Per-call ad-hoc recognizers
8. Context-aware enhancement
9. Confidence scoring + decision-process trace
10. Allow-list + deny-list

**Tier 2 — asymmetric wins** (where octarine genuinely beats Presidio):

11. **LLM integration** (§D′.1) — first-class `LLMRecognizer` + downstream protection proxy + session-stable token vault. The "AI-native" play
12. **Observability** (§D′.2) — OTel SDK redactor adapter, `/metrics` endpoint, correlation-id propagation. octarine's `observe` layer is the asymmetric architectural win
13. **Format-preserving encryption** (§A.3)
14. **Tokenization vault as first-class operator** (§A.3, §F.1)
15. **Generalization operators** (date-shift, age-bucket, ZIP-truncate) (§A.3)
16. **Surrogation as distinct operator archetype** (§F.4)
17. **AEAD encryption** (AES-GCM-SIV or ChaCha20-Poly1305) (§C)
18. **Performance** (Rust + linear-time regex + true parallelism)
19. **Strong-typed identifiers** (compile-time guarantees) (§B.10)
20. **Three-layer architecture composes with security + auth + crypto** (§B.1-9)

**Tier 3 — DICOM and structured data deep play** (§D′.3, §A.5):

21. **DICOM PS3.15 Annex E conformance** with metadata + pixel scrubbing
22. **FHIR / HL7 integration** sharing the identifier registry
23. **Parquet / Arrow / Polars / SQL row iterators / streaming readers**
24. **Sensitive column-name detection**

**Tier 4 — opportunistic** (small wins with disproportionate ROI):

25. **`negative_context` enhancer** (§F.2 PR #1969) — easy add, big FP reduction
26. **Three starter modes** ("fast / balanced / accurate") (§F.2 #1809)
27. **Recipes gallery** (actually fill it) (§F.2 #1687)
28. **Match-group support in PatternRecognizer** (§F.2 #1120)
29. **Build-time model bake-in + non-root container user** (§F.4)
30. **CLI in GitHub Actions format + SARIF** (§A.9)

**Tier 5 — speculative or research**:

31. **AI-generated content labeling** (§F.2 #1923) — EU AI Act compliance
32. **LLM-as-a-judge evaluation** (§F.2 from 2.2.362)
33. **ML-based context awareness** (§F.2 #1686)
34. **Differential-privacy noise** operator (§A.3)
