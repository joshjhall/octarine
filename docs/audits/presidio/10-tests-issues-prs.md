# Presidio — Tests, Open Issues, Recent PRs, Discussions

Audit date: 2026-05-28. Scope: surface things **not yet in the CHANGELOG** (last released entry: 2.2.362, 2026-03-15) — in-flight work, planned features, known bugs, and undocumented behaviors revealed by tests.

## Source files reviewed

### GitHub queries
- `gh issue list --repo microsoft/presidio --state open --limit 100` (52 open issues)
- `gh pr list --repo microsoft/presidio --state merged --limit 100` (filtered to mergedAt > 2026-03-15 → 38 PRs)
- `gh pr list --repo microsoft/presidio --state open --limit 30` (17 open PRs)
- `gh api /repos/microsoft/presidio/discussions` (~50 discussions, mostly 2022-2024)
- `gh issue list --repo microsoft/presidio-research --state open` and merged PRs

### Test directories enumerated
- `presidio-analyzer/tests/` — 126 files (78 recognizer-specific + engine/NLP/registry/chunker tests)
- `presidio-anonymizer/tests/` (incl. `operators/`, `integration/`, `services/`, `mock_operators.py`)
- `presidio-image-redactor/tests/` (incl. `test_dicom_image_*`, `test_tesseract_ocr.py`, `test_document_intelligence_ocr.py`)
- `presidio-structured/tests/` (`test_analysis_builder.py`, `test_tabular_engine.py`)

### Specific test files read in detail
`test_analyzer_engine.py`, `test_pattern_recognizer.py`, `test_context_support.py`, `test_anonymizer_engine.py`, `test_conflict_resolution_strategy.py`, `test_batch_analyzer_engine.py`, `test_dicom_image_redactor_engine.py`, `test_tabular_engine.py`, `test_analysis_builder.py`, `test_date_recognizer.py`, `test_ip_recognizer.py`, `test_credit_card_recognizer.py`, `test_phone_recognizer.py`, `test_gliner_recognizer.py`, `test_basic_langextract_recognizer.py`, `operators/test_mask.py`, `operators/test_hash.py`, `operators/test_encrypt.py`, `operators/test_custom.py`, `test_ahds_surrogate.py`, `test_image_analyzer_engine.py`, `test_azure_ai_language_recognizer.py`, `test_email_recognizer.py`, `test_uk_nhs_recognizer.py`, `test_pl_pesel_recognizer.py`, `test_spacy_nlp_engine.py`, `test_slim_spacy_nlp_engine.py`, `test_huggingface_ner_recognizer.py`, `test_character_based_text_chunker.py`, `test_analyzer_engine_provider.py`, `test_recognizer_registry.py`, `test_entity_mapper.py`, `test_lemma_context_aware_enhancer.py`, `test_prompt_loader.py`, `test_language_validation.py`, `test_ahds_recognizer_credential_selection.py`, `test_stanza_batch_processing.py`.

---

## Tests — capabilities revealed

### `presidio-analyzer/tests/`

#### Directory structure
- `assertions.py` + `test_assertions.py` — shared `assert_result` helper used by ~all recognizer tests (validates entity type, start, end, score together).
- `conf/` and `data/` — YAML fixtures and synthetic input data.
- `mocks/` — mock NER models / pipelines.
- 78 `test_*_recognizer.py` files covering predefined recognizers by country/domain.
- Generic engine tests: `test_analyzer_engine.py` (~31KB, largest), `test_pattern_recognizer.py`, `test_context_support.py`, `test_recognizer_registry.py`, `test_recognizer_registry_provider.py`, `test_recognizers_loader_utils.py`, `test_analyzer_engine_provider.py`.
- NLP engine tests: `test_spacy_nlp_engine.py`, `test_slim_spacy_nlp_engine.py`, `test_stanza_nlp_engine.py`, `test_stanza_batch_processing.py`, `test_transformers_nlp_engine.py`.
- New chunker layer: `test_base_chunker.py`, `test_character_based_text_chunker.py`, `test_text_chunker_provider.py`.
- LLM/LangExtract scaffolding: `test_lm_recognizer.py`, `test_basic_langextract_recognizer.py`, `test_azure_openai_langextract_recognizer.py`, `test_langextract_helper.py`, `test_prompt_loader.py`, `test_examples_loader.py`, `test_entity_mapper.py`.

#### Edge cases revealed

**Conflict resolution / overlapping entities** (`test_analyzer_engine.py`, `test_pattern_recognizer.py`)
- Embedded entities of **different types** are both kept — "John 1234567 Doe" yields 2 results; dedup is per-entity-type only.
- A single recognizer can have **patterns + deny_list simultaneously** — both produce hits in the same call (test_recognizer_registry confirms YAML deny-list silently becomes a pattern, so the recognizer ends up with both `patterns` (length 1) and `deny_list` (length 6)).
- Embedded entity span chosen via `REMOVE_INTERSECTIONS` strategy uses **score-based priority with second-entity tie-break** when scores are equal.

**Allow-list / deny-list interactions**
- Allow-list regex timeout is conservative: on timeout, the **entity is retained** rather than filtered (explicit test comment). This is a security-favoring default but can surprise users.
- Allow-list entries not present in text are **silently ignored** (no error).
- Default literal allow lists are case-sensitive; you must pass `regex_flags=re.IGNORECASE` explicitly.
- Empty deny lists raise `ValueError`; deny-list entries with punctuation/whitespace (`"Mr."`, `"A.,.\\.B"`) must match literally — word boundaries treat `"MMrrrMrs."` as 0 matches.
- Multi-word deny entries can overlap: `"A B"` and `"B C"` both match in `"A B C"` (1 hit) but `"A B B C"` (2 hits).

**Ad-hoc recognizer quirks** (`test_analyzer_engine.py`)
- Ad-hoc recognizers are **ephemeral per call** — not retained across `analyze()` calls.
- Entity-filter (`entities=["PERSON"]`) **overrides** ad-hoc registration — an ad-hoc `MR` recognizer is suppressed when `MR` isn't in the requested entity list.
- Ad-hoc recognizers can be mutated between calls to add context, raising score on the second analysis.

**Regex flag behaviors** (`test_pattern_recognizer.py`)
- `global_regex_flags=0` explicitly disables default flags (case-sensitive).
- Per-call `regex_flags` parameter overrides global setting at analyze time.
- Mid-recognizer-lifetime flag changes trigger regex recompilation.
- `REGEX_TIMEOUT_SECONDS` defaults to 60 but is overridable via env var (requires module reload). Timed-out patterns return `[]` silently — sibling patterns continue.
- Empty matches (e.g. `\d*` against `"abc"`) are **skipped**, not returned as zero-length results.

**Score combinations** (`test_pattern_recognizer.py`)
- `validate_result=True` boosts to `MAX_SCORE` (1.0) regardless of original score.
- `invalidate_result=True` drops below `MIN_SCORE` (filtered out). Invalidation takes precedence when both hooks coexist.
- Context boost is **additive but applied once per result** — not compounded across multiple matches.

**Date recognizer** (`test_date_recognizer.py`)
- Word-boundary enforcement: `"Today is5/21"` → 0 matches; `"Today is,5/21,"` → 1 match.
- ISO-8601 with fractional seconds, microseconds, timezone offsets, minute-precision all tested.
- Partial dates (month/day only, month/year only) detected at very low score (0.05–0.25).
- **Not tested**: ordinals ("May 21st"), bare integers as years, version-number false positives.

**IP recognizer** (`test_ip_recognizer.py`) — substantial IPv6 corpus
- `::ffff:x.x.x.x` IPv4-mapped IPv6 captured as **single span** (intentional — comment: "to avoid leaking the ::ffff: prefix").
- IPv4-compatible (`::192.168.1.1`), IPv4-embedded (`2001:db8::192.168.1.1`, `64:ff9b::192.0.2.1`), zone identifiers (`fe80::1%eth0`), CIDR (`192.168.1.0/24`, `2001:db8::/32`, `fe80::1%eth0/64`) all tested.
- Rejected: multiple `::`, `gggg:...`, `12345:db8::1`, `256.0.0.1`.
- `text::ffff:192.0.2.1` (glued to word) falls back to plain IPv4 match only.
- Explicit non-matches: MAC addresses, timestamps, version strings, CSS colors, `std::cout`, `file:///`.
- Open bug #1476 confirms ipv6 `::` still has real issues (PRs #1940, #1941 partial fix landed).

**Credit-card recognizer** (`test_credit_card_recognizer.py`)
- **Luhn enforced**: invalid-Luhn 16-digit fails even with full context phrase nearby.
- Tests 13/14/15/16-digit formats (Amex, Diners, Visa, MC, Discover, JCB).
- Three formats in one string (no separator, hyphen, space) detected independently.

**Phone recognizer** (`test_phone_recognizer.py`)
- Parametrized `leniency` 0–3 — each level changes detection sensitivity.
- `supported_entity` is configurable (post-#2014) — can override `PHONE_NUMBER` to e.g. `TELEPHONE_OR_FAX`.
- Region-specific textual explanation ("Recognized as US region phone number...") attached to results.
- `DEFAULT_SUPPORTED_REGIONS` excludes JP, CN — must be extended explicitly.

**Email recognizer** (`test_email_recognizer.py`) — **notably shallow**
- Only tests standard `local@domain.tld`.
- **No tests for** IDN/internationalized emails, quoted local parts, sub-addressing, very long emails. False-positive coverage limited to one truncated-TLD case.

**Context-aware enhancer** (`test_context_support.py`, `test_lemma_context_aware_enhancer.py`)
- Lemma matching: `"Drivers license"` lemmatizes to `"driver"` — match is on lemmas, not raw tokens.
- Case-insensitive comparison.
- External context words (passed at analyze-time) are treated "as if in the text itself" and can override which word is selected as supportive.
- Two matching modes: `whole_word` and `substring`. **Default is substring** — preserving backwards compat — so "lic" matches inside "duplicate", "passport" inside "passportnumber". A removed `hybrid` mode raises `ValueError`.
- Score boost is multiplicative-ish: 0.3 → ~0.65; not a clean rounded value.
- Window/prefix-suffix sizes themselves not directly asserted in tests — verified indirectly.
- **All tests use `en` only** — no multilingual context-enhancer coverage.

**Batch analyzer engine** (`test_batch_analyzer_engine.py`)
- Mixed-type inputs: lists with `None`, integers, strings — `[1, 2121551234]` is valid.
- Dict values can be: scalar strings, lists of strings, sets, nested dicts.
- `keys_to_skip` supports dotted paths: `["key_a.key_a1"]`.
- Parametrized `n_process` × `batch_size` combinations: `(1,1), (4,2), (2,1)`.
- Non-primitive types (e.g. `{"data": {"nested": "x"}}` inside a list value) raise `ValueError`.
- **No async or streaming tests** — single `language="en"` throughout.

**Recognizer registry** (`test_recognizer_registry.py`)
- "1 custom + 28 predefined - 11 disabled" — **eleven predefined recognizers are silently disabled by default in the English registry.** This is a load-bearing convention not surfaced in docs.
- `countries=None` ≠ `countries=[]`: `None` is "no filter"; `[]` strips all country-specific but keeps generic (credit-card, email, URL, IBAN, crypto).
- Recognizers without `COUNTRY_CODE` always retained — backwards compat for custom recognizers.
- `COUNTRY_CODE` is resolved once at `__init__` and cached — post-construction reassignment is intentionally a no-op.
- Class-level `COUNTRY_CODE` declaration **wins over** constructor `country_code=` kwarg — but loudly (`ValueError` matching "conflicts with class-level").
- `country_code()` always lowercases; constructor trims whitespace; rejects blank/non-string with explicit error messages.
- `passing countries="us"` (string, not list) raises `TypeError` matching "iterable of strings".
- `global_regex_flags=re.DOTALL` propagates to ALL predefined PatternRecognizers loaded.

**NLP engine quirks**
- `SlimSpacyNlpEngine` (PR #1916, post-CHANGELOG): NER and parser **both disabled**, returns `[]` for entities, intentional design. Falls back to spaCy multilingual `xx_ent_wiki_sm` or blank tokenizer for unsupported languages (e.g. Swahili `sw`). Default models are constrained to `_sm` variants.
- spaCy GPU configuration tested with warning-on-failure path and CPU-detection path.
- HF aggregation_strategy `none` triggers a warning ("may result in fragmented entities"). BILOU prefixes `B-PER`/`I-PER` automatically stripped; `label_prefixes` parameter can override (e.g. `"Tag:"`).
- HF chunking with overlap retains highest-scoring deduped span. Korean-particle test exists — agglutinative language particles are handled cleanly.

**LangExtract / LLM recognizer** (`test_basic_langextract_recognizer.py`, `test_prompt_loader.py`)
- Three alignment-status tiers: `MATCH_EXACT` → 0.95, `MATCH_FUZZY` → 0.80, `NOT_ALIGNED` → 0.60.
- Unknown entity classes can either: (a) become `GENERIC_PII_ENTITY` (consolidation enabled) or (b) be skipped. Original label preserved in `recognition_metadata["original_entity_type"]`.
- Jinja2 prompt templates (`default_pii_phi_prompt.j2`) with filters, conditionals, loops, whitespace-control markers (`{%- ... -%}`) — undefined variables render as empty string by default.
- ConfigUnknown: Provider switching, prompt-file loading, schema-constrained output are NOT tested. Errors propagate; no fallback chain tested.

**Language validation** (`test_language_validation.py`)
- Format-only validation — accepts `"en"`, `"es-ES"`, etc.; rejects `"invalid_lang"`. **No fallback logic** — unsupported languages raise `ValueError`.

**Character chunker** (`test_character_based_text_chunker.py`)
- Defaults: `chunk_size=250`, `chunk_overlap=50`.
- Chunks **extend past `chunk_size`** to reach the next boundary character — not a hard cap.
- CJK text (no spaces) extends to end of input (no boundaries).
- Empty/whitespace input returns `[]`.
- Overlap captures cross-boundary entities (e.g. "John Smith") in at least one chunk.

**Analyzer engine provider** (`test_analyzer_engine_provider.py`)
- Three independent YAML config files: `analyzer_engine_conf_file`, `nlp_engine_conf_file`, `recognizer_registry_conf_file`.
- **Critical precedence rule**: inline sections in the analyzer YAML take priority over separately-provided per-section files — explicitly to prevent "silently overridden by Dockerfile-baked-in default values".
- Default score threshold: `0`.
- Default regex flags: `re.DOTALL | re.MULTILINE | re.IGNORECASE`.
- Invalid YAML → silent fallback to default config (no crash).
- Nonexistent file path → silent default fallback (also no crash).
- Auto-adds a `SpacyRecognizer` per supported language if no NLP recognizer configured.

**Entity mapper** (`test_entity_mapper.py`)
- `GENERIC_PII_ENTITY` constant for unknown labels.
- `filter_results_by_labels` is **case-insensitive**; threshold filtering is **inclusive**.
- `consolidate_generic_entities` vs `skip_unmapped_entities` are two parallel strategies.
- `ensure_generic_entity_support` returns a copy — never mutates caller's list.

### `presidio-anonymizer/tests/`

Top-level files: `test_anonymizer_engine.py`, `test_batch_anonymizer_engine.py`, `test_conflict_resolution_strategy.py`, `test_engine_result.py`, `test_app_entities_convertor.py`, `test_ahds_surrogate.py`, `test_ahds_surrogate_credential_selection.py`, `test_text_replace_builder.py`, `test_recognizer_result.py`, `test_operator_config.py`, `test_operator_result.py`, `test_readme.py`.

Subdirs: `operators/` (test files for hash, encrypt, decrypt, mask, redact, replace, keep, custom, factory), `integration/`, `services/`, `mock_operators.py`.

#### Edge cases revealed
- **Adjacent same-type entities separated by single space are merged by default** (PR #1932, fixes #1925). `merge_entities_with_whitespace=False` opts out.
- **Tabs and newlines are NOT merged** — only spaces. `"a@x.com\tb@y.com\nc@z.com"` produces three separate replacements.
- **Different entity types adjacent are never merged**, even with merging enabled.
- **Multiple spaces between same-type entities still merge**: `"David   Jones"` (3 spaces) → single replacement.
- Available anonymizers: `{hash, mask, redact, replace, custom, keep, encrypt}` + `surrogate_ahds` when AHDS dependency available.
- **Unsorted input is still merged correctly** — order-independence verified.
- Out-of-range spans raise `InvalidParamError` with text-length in message.
- Analyzer results are **not mutated** (verified via deepcopy comparison).

**Mask operator quirks**
- **Negative `chars_to_mask` is silently treated as no-op** (not rejected).
- Overflowing mask count is capped at string length, not error.
- Unicode emoji as masking char (`"😈"`) works per-character.

**Hash operator**
- Default is SHA256; SHA512 also supported.
- Salt minimum 16 bytes (5-byte salt rejected); empty salt also rejected.
- No-salt mode generates random per call → non-deterministic output across calls.

**Encrypt operator** — tests are **shallow**: only key length validation (128/192/256-bit). IV handling, deterministic vs random output (issue #1033 wants opt-out of random IV), unicode plaintext, key rotation — none tested.

**AHDS surrogate** (`test_ahds_surrogate.py`)
- Entity-type aliasing: `PERSON` → `PATIENT`, `PHONE_NUMBER` → `PHONE`, `EMAIL_ADDRESS` → `EMAIL`, `US_SSN` → `SOCIAL_SECURITY`.
- Unknown types fall back to `UNKNOWN`.
- French locale (`fr-FR`) tested in addition to `en-US` — uses `DeidentificationClient` from Azure Health Data Services.
- Skip patterns for forbidden / 500 / `ApiVersionUnsupported` API responses.
- **Length-similarity check loose**: only asserts output length within ±50 chars — no strict format preservation.

**Custom operator regression** (PR #2025)
- `validate()` MUST NOT invoke the lambda — would otherwise corrupt stateful lambdas (e.g. token-counter maps that build de-anonymization mappings).

**Conflict resolution strategy** (`test_conflict_resolution_strategy.py`)
- Two modes: `MERGE_SIMILAR_OR_CONTAINED`, `REMOVE_INTERSECTIONS`.
- `REMOVE_INTERSECTIONS` with equal scores: **second entity gets adjusted** (deterministic tie-break).
- Multi-overlap cascading: out of 4 overlapping entities, only highest-score Ent1 + truncated CC retained.
- **Allowlist-with-overlap is NOT tested** — gap.
- **Pure containment** (one entity inside another) is not isolated as its own test — only via the multi-intersection case.

### `presidio-image-redactor/tests/`

#### DICOM edge cases (`test_dicom_image_redactor_engine.py`)
- File extensions: `.dcm`, `.DCM`, `.dicom`, `.DICOM` all discovered (case-insensitive).
- Color modes: greyscale (mode "L"), RGB. Bit-depth handling tested via varying max pixel values (50, 16383, 32767, 4095).
- `0_ORIGINAL_no_pixels.dcm` → `AttributeError` path tested.
- `0_ORIGINAL_compressed.dcm` → `_check_if_compressed` + `_compress_pixel_data`.
- `0_ORIGINAL_icon_image_sequence.dcm` → multi pixel-data set handling.
- Background colors as both `int` and RGB tuples; invert_flag for inverted colors.
- Nested directories with mixed extensions.
- **NOT tested**: multi-frame DICOM (open issues #1512, #1737 explicitly call this out), specific modalities (CT/MR/US/XA — issue #1731 reports XA modality crash), OCR fallbacks, encrypted DICOM.
- Validation errors for crop ratios (0, negative, >1), `fill` values, padding widths, RGB→greyscale function misuse.

#### OCR backends
- Separate files for Tesseract and Document Intelligence OCR.
- `test_image_analyzer_engine.py` covers: allow-list, bbox handling (PII vs non-PII rendering), threshold filtering parametrized (-1/50/80/100 → 9/7/2/0 results), language param plumbing (recently fixed "got multiple values for keyword argument 'language'" bug).
- **OCR engine swapping and multi-engine setups NOT tested.**

### `presidio-structured/tests/`

#### Strategy edge cases (`test_analysis_builder.py`)
- Three entity selection strategies: `most_common`, `highest_confidence`, `mixed`.
- `most_common` misclassifies email as URL — `highest_confidence` and `mixed` correctly classify as EMAIL_ADDRESS. (This is the bug behind open issue #1316.)
- Invalid strategy → `ValueError` matching "Unsupported entity selection strategy".
- Custom `mixed_strategy_threshold=0.4`; high JSON threshold (0.9) where only email passes.
- Empty DataFrame returns empty mapping.
- JSON with arrays/lists raises `ValueError` — "not supported by BatchAnalyzerEngine".
- Nested JSON keys (`address.city`) handled.
- Multiprocessing tested: `n_process=4, batch_size=2`.
- Sampling: `n=2` works; `n=-1` raises `ValueError`.
- **NOT tested**: multilingual, NaN handling within columns, explicit type inference, numeric ID columns.

#### Tabular engine
- Default operator auto-injected as `"DEFAULT"`; user-supplied `DEFAULT` preserved.
- JsonDataProcessor with DataFrame → `ValueError`; PandasDataProcessor with dict → `ValueError`.
- Tests mostly verify **dispatch logic**, not transformation correctness — substantive strategies are mocked.

---

## Open issues — themes

### Feature requests — most-discussed
- **#1686** (15 comments) — Improved context awareness using ML / embeddings / classifiers. The big "next direction" for context enhancer.
- **#1234** (13 comments) — LLM-based de-identification. Original 2023 issue; partially addressed by LangExtract recognizers in 2025/26.
- **#1506** (8 comments) — Batch analyze API for recognizers. Critical for transformer-recognizer throughput.
- **#1760** (8 comments, "good first issue") — Multiple GLiNERRecognizer instances via YAML. PR #2018 in flight.
- **#1769** (5 comments) — FastAPI implementation for all services. PR #2039 (anonymizer FastAPI) in flight.
- **#2015** (5 comments) — Philippines (PH) country recognizers suite. Partially landed (PH_MOBILE_NUMBER #2038); PRs #2016, #2030, #2028 in flight for TIN, passport, license plate; UMID/SSS/national-ID not started.

### Open bugs (real, reproducible)
- **#1262** (20 comments) — spacy-huggingface-pipelines drops overlapping/unaligned spans, degrading transformer-pipeline accuracy.
- **#1309** (14 comments) — DICOM redaction fails to detect Patient Name on the official tutorial data file.
- **#1603** (11 comments) — Ad-hoc recognizer regexes are always case-insensitive even when caller doesn't want it. Significant footgun.
- **#1063** (6 comments) — US Driver License recognizer false-positives ("INTRODUCTORY", "INTERVENTION" matched as WA driver license).
- **#1444** (5 comments) — Context words used outside the suffix/prefix window (Lemma enhancer bug).
- **#1498** — UrlRecognizer false-positives on code snippets (`os.system`, `rpc.py`, `zeus.mtia.local` all match BASE_URL_REGEX).
- **#1476** — IPv6 `::` handling broken; partial fix via #1941/#1940 but issue still open.
- **#1316** — presidio-structured misidentifies email column as URL (the `most_common` strategy bug confirmed in tests).
- **#1156** — Anonymizing intersecting entities where bigger-span has lower score → anonymizer replaces the bigger one (counterintuitive).
- **#1731** — Image Redactor crashes on XA modality DICOM (`Too many dimensions: 3 > 2`).
- **#1731 / #1737 / #1512** — Multi-frame DICOM support missing across multiple modality types.
- **#1942** — `BasicLangExtractRecognizer` silently drops `provider.language_model_params` (timeout, num_ctx). PR #1943 in flight.

### Customer pain points / UX
- **#1396** — Recent changes broke mypy types (no typed `__init__`). 7 comments. Type-checking story is incomplete.
- **#1090** (12 comments) — Adjacent same-type entities not merged (FIXED post-CHANGELOG via #1932).
- **#1361** — Decision-process output prints offsets but not the entity text. UX friction with long sequences/images.
- **#1525** — Add GLiNER support to Docker image (Docker image story drifting from Python-pkg).
- **#1525 / #1663 / #1615** — Multiple Docker-related issues. #1615 floats deprecating official Docker releases.
- **#1058** — `/supportedentities` REST endpoint only returns English.

### Proposed but not started PII categories
- **#1491** — Presidio Medical Recognizer (MRN, accession numbers, NPI).
- **#2015** — Philippines suite: PH_TIN, PH_PASSPORT, PH_UMID, PH_SSS, PH_NATIONAL_ID (last 3 not started).
- Implied gaps (from in-flight PRs): UPI (#2036), US CLIA (#2029).

### Performance complaints
- **#1262** — transformer pipeline span skipping.
- **#1440** — Multiprocessing for spaCy pipelines (only 1 comment but cited as missing capability).
- **#1506** — Batch analyze for recognizers (transformer-recognizer idle resources).
- **#1639** — Evaluate precision/recall/latency during CI (no precision/recall regression gates today).

### Integration friction
- **#1769** — FastAPI / async services missing.
- **#1882** — DocumentIntelligenceOCR doesn't support `DefaultAzureCredential` / Azure Identity.
- **#1511** — GitHub Action with SARIF export (CI/CD security scanning integration).
- **#1028** — Docker support for Stanza NLP Engine (older).
- **#1617** — Add batch decryption (operator parity gap).

### "Questions" hinting at undocumented behavior
- **#1603** — Why are ad-hoc regexes always case-insensitive? (Undocumented default.)
- **#1444** — Why does context word "Six" in "Sixty" tag erroneously? (Substring-mode default behavior undocumented.)
- **#1711** — Per-entity-type context words? (`LemmaContextAwareEnhancer` expects flat list per recognizer, no per-entity scoping.)
- **#1120** — Use group from matched pattern. (Currently impossible — only full span anonymized; multiple users want capture-group scoping.)

### Aging / abandoned (low-signal)
- **#874** (2022, security: pinned deps) — addressed by 2026 dependabot work but never closed.
- **#1190** (2023) — Revisit NER default score (0.85 hardcoded fallback may be misleading); not actioned.
- **#1033** (2023) — Stable output for encrypt operator (deterministic IV opt-out); not implemented.

---

## Recently merged PRs (post-2.2.362, not yet released)

Filtered to mergedAt > 2026-03-15.

### Features
| PR | Title | Type | Highlights |
|----|-------|------|------------|
| **#1970** | Unified Analyzer Configuration | feat | **Consolidates `default_analyzer.yaml` + `default.yaml` + `default_recognizers.yaml` into a single `analyzer.yaml`.** Old files retained with deprecation banners. Significant config refactor. |
| **#1916** | Slim NLP Engine | feat | New `SlimSpacyNlpEngine` — tokenization + lemmatization only, no NER, no parser. Pairs with `GLiNERRecognizer` as default. Adds `slim.yaml` / `slim_nlp.yaml`. **Default config is now slim** (shift of default behavior). 18-language auto-download. |
| **#2000** | Country filter on `load_predefined_recognizers()` | feat | `countries=[...]` parameter; infers country from module path under `country_specific/`. Case-insensitive. `countries=[]` keeps only locale-agnostic; `countries=None` is backwards-compat. |
| **#1932** | `merge_entities_with_whitespace` param | feat | Anonymizer now merges adjacent same-type entities separated by single spaces (fixes #1925, addresses #1090). Default `True`. |
| **#2014** | Configurable `supported_entity` on PhoneRecognizer | feat | Mirrors PatternRecognizer pattern; can override hardcoded `"PHONE_NUMBER"`. |
| **#2038** | PH_MOBILE_NUMBER recognizer | feat | Phone-recognizer-as-PH-mobile recipe (no subclass, just regions+entity). Filipino+English context words. |
| **#2006** | TR_PHONE_NUMBER recognizer | feat | Same pattern for Turkey. |
| **#1995** | TR_NATIONAL_ID recognizer | feat | Turkish 11-digit identity. |
| **#1999** | TR_LICENSE_PLATE recognizer | feat | Turkish vehicle plate. |
| **#2011** | ES_PASSPORT recognizer | feat | Spanish passport. |
| **#1934** | CA_SIN recognizer | feat | Canadian SIN. |
| **#1918** | SE Organisationsnummer recognizer | feat | Swedish org number. |
| **#1815** | Configurable LangExtract recognizer | feat | Generic LangExtract — supports any provider via `lx.ModelConfig` (e.g. Ollama via LiteLLM OpenAI proxy). |
| **#1924** | Publish sdist alongside wheels | feat | Build/distribution. |

### Fixes
| PR | Highlight |
|----|-----------|
| **#1990** | German recognizers — completed Prüfziffer (check-digit) validation per primary sources for `DE_HEALTH_INSURANCE`, `DE_SOCIAL_SECURITY` (RVNR), `DE_LANR`, added missing `DE_VAT_ID` checksum. Fixes #1972. |
| **#1998** | PESEL checksum was incorrect — fixed. |
| **#2025** | Custom operator `validate()` must NOT invoke the lambda (fixes stateful-lambda corruption). |
| **#2007** | GLiNER config fields preserved through Pydantic validation — was silently dropping `model_name`, `flat_ner`, `threshold`, etc. when loaded from YAML, falling back to hardcoded default model. |
| **#2009** | PhoneRecognizer default region typo `"FE"` → `"FR"`. |
| **#1941 / #1940** | IP recognizer regex updates and IPv6 loopback `::1` test coverage. |
| **#1917** | LangExtract config path resolution for PyPI installs. |
| **#1930** | Stanza model accessibility in Docker conf files. |
| **#1928** | Reverted analyzer Dockerfiles to Python 3.12 (3.13 incompatibility). |
| **#1921** | CI coverage comment skip when not in PR context. |

### Infra / supply chain
- **#1965** — Defensive version ranges in pyproject.toml (`>=min,<next_major`); hardened dependabot.yml.
- **#1929 / #2005 / #1984** — Dependabot grouping + coverage across all `pyproject.toml`. **#2005 consolidates Dependabot into a single multi-ecosystem PR** — same pattern octarine adopted (per MEMORY.md).
- Many digest bumps for python images, codeql-action, github-script, etc.

---

## Open PRs (in flight)

| PR | Theme |
|----|-------|
| **#2041** | Tokenizer-based text chunking for NER recognizers (companion to #1916 slim engine direction). |
| **#2039** | **FastAPI anonymizer server** (addresses #1769). |
| **#2040** | Image-redactor verify bug fix (#1034 dating to 2023). |
| **#2036** | **Indian UPI ID recognizer** for NPCI payment compliance — new payment-system PII category. |
| **#2035** | GSTIN checksum validation (post-detection validity). |
| **#2031** | Country filtering follow-up. |
| **#2030** | PH passport recognizer. |
| **#2029** | **US CLIA recognizer** — Clinical Laboratory Improvement Amendments identifier. New US medical ID category. |
| **#2028** | PH license plate. |
| **#2023** | Custom Docker images docs. |
| **#2018** | Multiple GLiNER YAML configs (#1760). |
| **#2016** | PH TIN. |
| **#1969** | **`negative_context` support** — reduces false positives by penalizing if specific words appear nearby. New axis on context enhancer. |
| **#1943** | Fix BasicLangExtractRecognizer `language_model_params` (#1942). |
| **#1919 / #1890 / #2037** | Custom Docker language images docs. |

---

## Discussions

The GH Discussions tab is largely **dormant** — most active threads are from 2022-2024. No recent (2026) discussions of substance. Notable historical themes:

- **#714** (30 comments, 2024) — "Supporting structured / semi-structured data" — the seed RFC that led to `presidio-structured`. Discusses column-level detection, sampling, multi-strategy selection — features now implemented but with the email-as-URL bug.
- **#669** (12 comments, 2022) — "Using presidio analyzer in pyspark." — still cited as friction point; explains why batch / multi-process work matters.
- **#609** (9 comments, 2024) — "Ability to output the detected text" — same ask as issue #1361.
- **#758** (10 comments, 2024) — Nuget package for .NET — Presidio's .NET ecosystem is desired but unsupported.
- **#726** (9 comments, 2024) — Stanza engine errors — recurring deployment friction.

No "ideas" discussions opened in 2026 that aren't already mirrored as issues.

---

## presidio-research signals

Small but live repo. Recent themes:
- **PR #157, #155, #156, #153, #152, #141** — sustained work on **span-level evaluation** (replacing token-level metrics, handling multi-span overlaps, IoU-based false-positive accounting). Aligns with issue #1639 (CI precision/recall gating) — they're building the evaluation primitives.
- **Issue #98** (open) — Integrate evaluation for **PII column identification in tables/JSONs** with `presidio-structured`. Currently structured evaluation is a gap.
- **Issue #123** (open) — Enforce locale for fake entity generation (Faker locale propagation bug).
- **PR #164** — Migrated CI from Azure Pipelines to GH Actions (Dec 2025).

---

## Inferred state — what's brewing

### Imminent (next release line items, already merged)
1. **Unified `analyzer.yaml` config** — one file replaces three. Breaking-ish for power users with custom configs.
2. **Slim NLP engine is the new default** — significant shift; reduces install footprint but means default behavior no longer gives spaCy NER for free.
3. **`countries=[...]` filter** on registry loading — first-class US-only/EU-only deployments.
4. **Anonymizer whitespace-merge** — adjacent same-type entities now merge by default.
5. **PhoneRecognizer** with configurable `supported_entity` — enables PH/TR/etc. mobile recipes without subclassing.
6. **German + Polish checksum corrections** — wave of recognizer-quality fixes after a primary-source audit.
7. **GLiNER + Pydantic config preservation** fix.

### Mid-term (actively discussed, PRs open or under review)
1. **FastAPI server (#2039)** — anonymizer first, analyzer likely to follow.
2. **Tokenizer-based chunking (#2041)** — next chunker iteration for NER.
3. **`negative_context` (#1969)** — false-positive reduction via anti-context words.
4. **More GLiNER configs in YAML (#2018)** — multiple instances.
5. **Indian payment recognizers (UPI #2036, GSTIN checksum #2035)**.
6. **US CLIA medical recognizer (#2029)**.
7. **PH suite completion** — TIN, passport, license plate in flight.

### Long-term wishes (issues with no PRs)
1. **ML-based context awareness (#1686)** — moving beyond regex+lemma context.
2. **Recognizer-level thresholds (#1572)** — per-recognizer score gating, not just global.
3. **Per-entity-type context words (#1711)** within a single recognizer.
4. **Match-group support in PatternRecognizer (#1120)** — long-standing.
5. **Stable encrypt output / deterministic IV (#1033)** — long-standing.
6. **Recipes gallery (#1687) + 3 starter modes (#1809) + benchmark dataset (#1810)** — UX/onboarding push by maintainers (Omri's own issues).
7. **AI-generated content labeling (#1923)** — EU AI Act Article 50 (Aug 2, 2026) compliance angle. Speculative but interesting expansion of scope.
8. **Medical recognizer suite (#1491)** — MRN, accession numbers, NPI.
9. **Precision/recall/latency CI gates (#1639)** — quality regression prevention.
10. **Multi-frame DICOM + XA modality** (#1512, #1737, #1731).

### Abandoned / stalled
- **#874** (2022, pinned deps) — superseded by dependabot work but unclosed.
- **#1190** (2023, NER default score 0.85) — never actioned.
- **#1028** (2023, Stanza Docker) — eclipsed by Slim engine direction.

---

## Anything notable / unusual

1. **Default behavior shift coming** — Slim NLP engine becomes the default; users who rely on out-of-the-box spaCy NER will lose `PERSON`/`LOCATION`/`ORGANIZATION` unless they also add a NER recognizer (e.g. GLiNER, which is the slim config's pairing). This is a behavioral break worth flagging in any octarine doc comparing Presidio defaults.

2. **Eleven predefined recognizers silently disabled by default in English** — undocumented convention surfaced only by `test_recognizer_registry.py`. Octarine doesn't have this concept and should consider whether quiet-by-default is desired.

3. **`is`-vs-`is not`-confused conflict-resolution tie-breaks** — `REMOVE_INTERSECTIONS` adjusts the second-entity boundary on score ties, deterministic but **undocumented in user docs**. Octarine should make its tie-break policy explicit.

4. **Substring-mode context matching is the historical default** — `"lic" matches inside "duplicate"`. This is intentional for backwards compatibility but is the root cause of issue #1444 (context outside window). Octarine should pick `whole_word` semantics from day one and document.

5. **`::ffff:` IPv4-mapped IPv6 captured as one span** — the explicit comment "to avoid leaking the `::ffff:` prefix" is a security-by-design choice octarine should mirror in IP detection. Currently octarine's IP detection may capture the embedded IPv4 only.

6. **Allow-list regex timeout retains entity** — fail-closed security default. Worth confirming octarine's regex-timeout behavior matches (or explicitly documents the opposite).

7. **Mask operator silently accepts negative `chars_to_mask`** as no-op — sloppy. Octarine should reject invalid inputs explicitly.

8. **Custom operator `validate()` regression (#2025)** — the fact that a "type-check" probe call corrupted stateful lambdas is a non-obvious failure mode. Octarine's analog (if it allows user-provided callbacks for transformation) should never invoke caller code during validation.

9. **PR #2025/#1932/#1990 are all "the obvious thing the test missed"** — Presidio is in a phase of fixing semantics around things their tests previously didn't assert. Octarine's test corpus should specifically include: (a) stateful-callback non-invocation during validation, (b) adjacent-same-type-entity merging policy, (c) per-recognizer-and-language checksum corpus from primary sources.

10. **DICOM multi-frame and XA modality gap is real** — three open issues, no PR. Cross-modality DICOM is a known weakness in Presidio; octarine docs should be honest about not pretending to surpass that without evidence.

11. **No async/streaming tests anywhere** — Presidio is fundamentally sync. FastAPI work (#2039) starting to change this. Octarine being Rust async-native is genuinely differentiating.

12. **Email recognizer test coverage is shallow** (no IDN, no quoted local, no length attack). Likely a real false-negative source. Octarine should test these explicitly.

13. **No language-fallback logic** — unsupported language → `ValueError`. No graceful degradation. Octarine has a chance to do better via locale/script fallback chains.

14. **Recipes/starter-modes/benchmark issues (#1687, #1809, #1810)** are all opened by the project maintainer (Omri) — this is the maintainers' roadmap for 2026 in plain sight. Octarine should consider similar "fast / balanced / accurate" preset modes.

15. **`countries` filter in PR #2000** infers from module path. Octarine's identifier module structure mirrors this — the same pattern could naturally support `with_countries([...])`. Worth adding to the builder API.
