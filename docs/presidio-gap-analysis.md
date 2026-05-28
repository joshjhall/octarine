# Presidio Gap Analysis

_Generated 2026-05-26 from comparison of Microsoft Presidio (83 recognizers across 12 languages, 5 NER entities via spaCy/Stanza/Transformers/GLiNER) against octarine (95 `IdentifierType` variants, 124 `PiiType` variants, 0 NER, English-only context keywords for 13 types plus `ApiKey` in 6 non-Latin scripts)._

## Executive Summary

Octarine already exceeds Presidio across five domains that Presidio does not meaningfully cover: **biometric identifiers** (6 detectors vs 0; GDPR Art. 9 / BIPA / GINA), **cryptographic material** (9 detectors vs 0; PEM / DER / SSH / X.509 / private-key armor with real `pem` / `x509-parser` / `ssh-key` parsing behind the `crypto-validation` feature), **provider tokens / secrets** (~52 detectors across 14 categories vs 1 BTC-only entity), **network security** (RFC-tagged IP classification, cloud-metadata IMDS detection at 169.254.169.254, SSRF allowlists / denylists vs Presidio's shape-only IP/MAC/URL regex), and **algorithmic depth** on shared identifiers (Singapore NRIC with prefix-conditional letter tables, India GSTIN MOD-36, India PAN holder-type validation, Brazil CPF/CNPJ full mod-11 dual check digits, Mexico CURP RENAPO validator, EIN with full IRS campus-prefix allowlist, 10-brand credit card BIN validation with per-brand length enforcement, ISBN-13 false-positive filter, Federal Reserve range filter on ABA routing). Octarine's three-layer detection / validation / sanitization split plus Layer 3 observe instrumentation has no Presidio equivalent.

Octarine is behind on three categorical axes. **NER** is the largest single gap: Presidio's spaCy / Stanza / Transformers / GLiNER pipeline supplies `PERSON`, `LOCATION`, `ORGANIZATION`, `NRP`, and `DATE_TIME` across ~20 languages out of the box; octarine has `ner_entities: []` and a regex-only `is_name()` that admits in its own comment "High false positive rate." **Country coverage** has discrete holes — no `UK_NHS`, no `DE_TAX_ID` / `DE_ID` / `DE_PASSPORT` (and the rest of the 11-recognizer German pack), no `SE_PERSONNUMMER`, no Italian `VAT_CODE` / `DRIVER_LICENSE` / `IDENTITY_CARD` / `PASSPORT`, no `ES_PASSPORT`, no Turkey at all (`TR_NATIONAL_ID` + `TR_LICENSE_PLATE`), no `US_ITIN` as a distinct type, no `US_MBI`. **Algorithmic correctness** has a small set of concrete bugs surfaced by the domain reports: `validate_ssn` accepts 9xx-area numbers as SSNs (those are ITINs), `validate_bank_account` inverts Luhn logic so any Luhn-valid 8-17 digit string is rejected as a bank account (~10% false-reject rate), `AustraliaMedicare` ships with `is_high_risk=false` / `is_hipaa_protected=false` despite being the AU equivalent of US MBI / NHS, Bitcoin address detection is shape-only with no base58check or Bech32 polymod, India Aadhaar lacks the UIDAI palindrome reject, Finland HETU is missing the post-2023 century markers B-F / U-Y, Singapore UEN has no checksum, US Driver License covers only 4 states with a permissive 6-13 alphanumeric fallback, US Passport rejects valid legacy 9-digit numbers, the DEA / state-medical-license entity collides on `IdentifierType::MedicalLicense`. Multilingual context keywords are missing for 14 of 15 keyword-bearing types; 80 of 95 identifiers carry no context keywords at all.

The blockers to claiming "drop-in Presidio replacement" are: NER (cannot match `PERSON` / `LOCATION` / `NRP` / `AGE` against free text), the missing German / Swedish / Turkish / UK NHS / Italian completeness packs, ITIN + MBI for US healthcare, libphonenumber-grade phone parsing, Public Suffix List validation for email / URL, multilingual context keywords for the top 20 identifiers, and the handful of correctness bugs above. **Total focused effort to reach drop-in parity (excluding NER policy decision): 6-8 weeks.** With NER, add 1-2 engineer-months plus a feature-gated ML sub-crate (`candle` / `rust-bert` / ONNX) — or document NER as an explicit non-goal and ship a `NerProvider` trait that lets integrators bring their own.

## Octarine's Competitive Advantages

These are areas where octarine already exceeds Presidio — flag in README, comparison pages, and sales material.

- **Biometric (6 detectors vs 0)** — `Fingerprint`, `FacialRecognition`, `IrisScan`, `VoicePrint`, `DnaSequence`, `BiometricTemplate` in `primitives/identifiers/biometric/detection.rs`. GDPR Art. 9 special-category data, Illinois BIPA ($1,000-$5,000 per violation), GINA, HIPAA 45 CFR 164.514(b)(2)(i). Presidio has no biometric coverage at all.
- **Cryptographic material (9 detectors + KeyType / KeyFormat enums vs 0)** — `is_pem_format`, `is_der_format`, `is_ssh_key_format`, `is_openssh_private_key_format`, `is_rsa_key`, `is_ec_key`, `is_x509_certificate`, `is_private_key`, `is_public_key` in `primitives/identifiers/crypto/detection.rs`. Real cryptographic parsing behind `crypto-validation` feature via `pem`, `x509-parser`, `ssh-key`. Same heuristic GitHub Secret Scanning uses for `-----BEGIN PRIVATE KEY-----` leak prevention.
- **Provider tokens / secrets (~52 detectors across 14 categories vs 0)** — AWS / GCP / Azure / Stripe / Square / Shopify / PayPal / Telegram / Discord / Slack / Twilio / SendGrid / Mailchimp / Mailgun / Resend / Brevo / npm / PyPI / NuGet / Artifactory / Docker Hub / HashiCorp Vault / 1Password / GitHub / GitLab / Bitbucket / Heroku / Linear / Doppler / Netlify / Fly.io / Render / PlanetScale / Supabase / Databricks / Cloudflare / OpenAI / JWT / SSH / Session in `primitives/identifiers/token/detection/api_keys/`. PCI-DSS 3.5/8.3, SOC 2 CC6, GDPR Art. 32 relevance.
- **Network security (RFC-tagged classification + SSRF defences)** — `is_loopback`, `is_private` (RFC 1918 / fc00::/7), `is_link_local` (RFC 3927 / fe80::/10), `is_documentation` (RFC 5737 / 2001:db8::/32), `is_cloud_metadata` (169.254.169.254 IMDS, 169.254.170.2 AWS ECS), `IpAddressList::is_cloud_metadata_present`, SSRF allowlists / denylists / scheme blocking / url-shortener detection in `primitives/security/network/detection/ssrf/`. Presidio has shape-only IP/MAC/URL detection.
- **Algorithmic depth on shared identifiers** — 10-brand credit card BIN validation with per-brand length (Visa / MC inc. 2-series / Amex / Discover 6011 / 644-649 / 65 / Diners / JCB 3528-3589 / UnionPay 62 / Maestro / Verve / RuPay) vs Presidio's single regex; Singapore NRIC mod-11 with prefix-conditional letter tables for S/T (citizens), F/G (PRs), M (post-2022 foreign workers) vs Presidio regex-only; India GSTIN MOD-36 vs Presidio regex-only; India PAN with `VALID_PAN_HOLDER_TYPES` enforcement; Brazil CPF + CNPJ full mod-11 dual check digit; Mexico CURP full RENAPO validator including 33-entry state allowlist; Poland PESEL with century-encoded month decoding spanning 1800s-2200s (Presidio only does regex date + checksum); EIN with full IRS campus-code allowlist `(01-06, 10-16, 20-27, 30-39, 40-48, 50-59, 60-68, 70-79, 80-88, 90-99)` and rejection of gap prefixes `(00, 07-09, 17-19, 28-29, 69, 89)` vs Presidio no EIN at all; DEA with correct registrant-type filtering `VALID_DEA_TYPES = b"ABCDEFGHJKLMPR"` (Presidio's regex permits the full case-insensitive class).
- **Confidence-scoring quality** — graded `High / Medium / Low` confidence levels combining Luhn + BIN + length + context + entropy; ISBN-13 false-positive filter (`978/979` prefixes rejected); test-card filter (Stripe 4242, Visa 4111) flagged as low confidence; RFC 5737 / 555-prefix test-data filter (`is_test_phone`, `is_test_email`, `is_test_ip`, `is_test_url`); per-country test-pattern detection in `finland.rs`, `italy.rs`, `poland.rs`, `spain.rs`; birthdate PII-context gating (`is_date_in_pii_context`) avoids flagging version numbers and ISO timestamps as DOBs.
- **Detection / validation / sanitization three-layer split** — clean separation of `is_*` (lenient detection, false-positives OK), `validate_*` (strict enforcement, no false positives, returns `Problem`), and `redact_*` / `sanitize_*` (transform). Presidio collapses detect + validate into a single recognizer with `invalidate_result`.
- **Layer 3 observability** — every Layer 3 builder is instrumented; audit-trail hooks, metrics, events, PII redaction in event payloads, multi-tenant context capture. Presidio has nothing equivalent.
- **Performance and ReDoS protection** — LRU caches (`LUHN_CACHE`, `ABA_CACHE`, `EMAIL_CACHE`, `PHONE_CACHE`) amortize repeated values; hard input cap (`MAX_INPUT_LENGTH = 10_000`) on all `detect_*_in_text` functions. Presidio recomputes per call and uses a 60s regex timeout on arbitrary-length input.

## Critical Gaps (block "drop-in Presidio replacement" claim or active bugs)

Each gap includes the source domain report reference. Severity rule: blocks a Presidio entity that ships in `default_recognizers.yaml`, or is an active bug producing measurably wrong results.

### CRIT-1. PERSON entity — no NER, only `Capitalized Capitalized` regex

- **Presidio**: `SpacyRecognizer`, `TransformersRecognizer`, `GLiNERRecognizer` extract `PER` / `PERSON` from pre-trained NER (`en_core_web_lg` + `de_core_news_md` + `es_core_news_md` configured in `spacy_multilingual.yaml`); ~0.85 default score from NER; recall ~0.85 on the standard PII test set.
- **Octarine**: `primitives/identifiers/personal/detection/name.rs::detect_names_in_text` matches `[A-Z][a-z]+ [A-Z][a-z]+`-style patterns. Code comment: "High false positive rate. Common words may be detected as names (e.g., 'May June' could be months)." Fails on lowercase first names (`"User john updated record"`), non-Western scripts (CJK, Cyrillic, Arabic), names embedded in sentences, all-caps names. False-positives on every capitalized phrase (`"New York"`, `"Black Friday"`, `"Cargo Workspace"`).
- **Recommendation**: Feature-gated NER. Two viable Rust paths — `rust-bert` v0.23+ (pure Rust + `tch`/libtorch, ships BERT-CoNLL03 PER/LOC/ORG/MISC) or `ort` (ONNX Runtime) + GLiNER ONNX export (smaller, multilingual, same model Presidio's newer recognizer uses). New files `primitives/identifiers/personal/detection/ner.rs`, `primitives/identifiers/personal/builder/ner_methods.rs`. Feature flag `ner` in `Cargo.toml`. Add `Source::Ner` confidence variant. Alternative: ship a `NerProvider` trait in `observe::pii` with `NoopNerProvider` default and feature-gate `octarine-ner-candle` / `octarine-ner-rust-bert` sub-crate. Source: `gap_personal_contact.md` Gap 1, `gap_context_locales.md` C3.
- **Effort**: Large (3-5 days working integration + tests; weeks to harden model loading, GPU/CPU paths, memory limits). NER strategy decision warrants a separate design doc.

### CRIT-2. LOCATION entity — no free-text city / country / region detection

- **Presidio**: spaCy NER `GPE` (geo-political entity) + `LOC` mapped to `LOCATION`. Detects "Berlin", "the Pacific Northwest", "203 Madison Ave". Multilingual via spaCy language models.
- **Octarine**: `primitives/identifiers/location/detection.rs` only detects structured patterns — `is_street_address` (US-leaning numeric+street-suffix regex), `is_postal_code` (10 countries: US/CA/UK/DE/FR/AU/JP/IN/NL/BR), `is_gps_coordinate`. No detection of city, country, region, neighborhood, landmark, building names.
- **Impact**: HIPAA Safe Harbor requires removing geographic subdivisions smaller than a state. Cannot redact "Patient lives in Phoenix" or "I'm visiting Japan".
- **Recommendation**: Same NER feature flag as CRIT-1 (BERT-CoNLL03 emits `LOC`, GLiNER supports custom `LOCATION` label). Add `IdentifierType::Location` + `PiiType::Location` (run `octarine-pii-bridge` skill). New `primitives/identifiers/location/detection/ner.rs`. **Fallback without ML**: bundle a gazetteer (~250 countries + ~5,000 major cities) and match via `aho-corasick` v1.1 — lower quality than NER but adds value with zero ML. Source: `gap_personal_contact.md` Gap 2.
- **Effort**: Large (NER path); Medium (gazetteer-only ~1 day).

### CRIT-3. NRP entity (nationality / religion / political) — entirely absent

- **Presidio**: spaCy NER `NORP` label → `NRP`. Detects "American", "Catholic", "Democrat", "Hispanic". GDPR Article 9 special-category data (racial origin, religious belief, political opinion).
- **Octarine**: No `IdentifierType` variant. No `PiiType::Nrp`. No detection.
- **Impact**: Cannot claim GDPR Article 9 special-category coverage without NRP. Major liability for LLM proxies — political affiliation in prompts/completions is the precise failure mode that drove GDPR.
- **Recommendation**: Lexicon-only path is feasible without ML. Add `IdentifierType::Nationality`, `IdentifierType::Religion`, `IdentifierType::PoliticalAffiliation` (run `octarine-pii-bridge` skill to sync `PiiType` + scanner domains). New `primitives/identifiers/personal/detection/nrp.rs` with embedded `&[&str]` lexicons (~200 nationalities, ~50 religions, ~30 political parties), matched via `aho-corasick`. Mark `is_gdpr_protected: true` and `is_high_risk: true`. Source: `gap_personal_contact.md` Gap 3.
- **Effort**: Medium (1-2 days lexicon path; large if pursuing NER).

### CRIT-4. AGE entity — no detection

- **Presidio**: `TransformersRecognizer` emits `AGE` entity. Detects "42-year-old", "age 65", "in his thirties".
- **Octarine**: No `IdentifierType::Age`. No detection function.
- **Impact**: HIPAA Safe Harbor §164.514(b)(2)(i)(B) requires removing ages >89. GDPR considers age sensitive when combined with other identifiers. Without `AGE`, octarine cannot serve healthcare or insurance redaction.
- **Recommendation**: Pattern-based detection is feasible (high precision, no ML required). New `primitives/identifiers/personal/detection/age.rs` with patterns `r"\b(\d{1,3})[- ]year[- ]old\b"`, `r"\bage[d]?\s*[:=]?\s*(\d{1,3})\b"`, `r"\b(\d{1,3})\s*(?:y\.?o\.?|yrs?\.?)\b"`, `r"\bin (?:his|her|their) (twenties|thirties|...)\b"`. Add `IdentifierType::Age` + `PiiType::Age`. Add `is_age_over_89(age_str) -> bool` HIPAA Safe Harbor helper. Source: `gap_personal_contact.md` Gap 4.
- **Effort**: Small (~half day; pure regex + lexicon).

### CRIT-5. US ITIN missing as distinct type; `validate_ssn` accepts 9xx-area numbers

- **Presidio** (`us_itin_recognizer.py`): Three weighted regexes enforcing IRS structural constraint — ITINs begin `9XX` with middle group restricted to `5X | 6[0-5] | 7X | 8[0-8] | 9[0-2|4-9]` (IRS allocates only these ranges; `93`, `00` excluded).
- **Octarine**: No `is_itin` or `validate_itin`. `primitives/identifiers/government/common.rs:21 is_itin_area()` only returns true for `9xx` area without IRS middle-group validation. `primitives/identifiers/government/validation/ssn.rs:99 validate_ssn` explicitly leaves `9xx` area numbers as `Ok` ("ITIN in lenient mode"); the test `test_ssn_itin_area` asserts `912-34-5678` validates **as an SSN**. No `IdentifierType::Itin` variant — `tax_id.rs:374` comments "ITINs continue to be TaxId".
- **Impact**: ITIN is HIPAA, IRS, and state-tax sensitive. Conflating ITINs with generic `TaxId` loses entity-specific classification. Missing middle-group constraint produces false positives on any 9-digit value starting with `9`. Direct regression for Presidio replacement.
- **Recommendation**: Add `IdentifierType::Itin` + `PiiType::Itin` (via `octarine-pii-bridge`). New `primitives/identifiers/government/validation/itin.rs::validate_itin` enforcing IRS middle-group rule. New `primitives/identifiers/government/detection/itin.rs::is_itin` + `find_itins_in_text`. Update `validate_ssn` to reject `9xx`-area numbers (route to `validate_itin`). Layer 3 `GovernmentBuilder::is_itin / validate_itin / redact_itin`. Source: `gap_government_americas.md` C1 + M4.
- **Effort**: Medium (1-2 days incl. tests, bridge, builder, shortcut).

### CRIT-6. US MBI (Medicare Beneficiary Identifier) entirely missing

- **Presidio** (`us_mbi_recognizer.py`): Full CMS structural validator — 11-char layout `C A AN N A AN N A A N N` with letter alphabet excluding `S, L, O, I, B, Z` (valid: `ACDEFGHJKMNPQRTUVWXY`). Two patterns: bare 11-char (weak 0.3) and dash form `XXXX-XXX-XXXX` (medium 0.5). Context: `medicare, mbi, beneficiary, cms, medicaid, hic, hicn`.
- **Octarine**: No `IdentifierType::Mbi`, no `PiiType::Mbi`, no validation, no detection. `grep -rn "MBI\|Mbi\|medicare.*benef"` in `src/` returns nothing.
- **Impact**: MBIs replaced SSN-based Health Insurance Claim Numbers in 2018 and are now the primary Medicare identifier on every claim, prescription, and EHR field. HIPAA + CMS controlled. Hard regression for any healthcare deployment swapping from Presidio.
- **Recommendation**: Add `IdentifierType::Mbi` + `PiiType::Mbi`. New `primitives/identifiers/government/validation/us_mbi.rs::validate_us_mbi` enforcing position rules + excluded-letter alphabet. New `primitives/identifiers/government/detection/us_mbi.rs::is_us_mbi` + `find_us_mbis_in_text`. HIPAA classification: `is_hipaa_protected = true`, `is_high_risk = true`. `GovernmentBuilder` shortcut + scanner registration. Source: `gap_government_americas.md` C2.
- **Effort**: Medium (1 day — structural regex + tests).

### CRIT-7. Bitcoin address — no checksum validation (shape-match only)

- **Status**: ✅ Closed in #431. `is_bitcoin_checksum_valid()` lives in
  `primitives/identifiers/financial/detection/crypto.rs` using `bs58 = "0.5"`
  (Base58Check for P2PKH/P2SH) and `bech32 = "0.11"` (`bech32::segwit::decode`
  for Bech32/Bech32m, witness-version aware). `BTC_CHECKSUM_CACHE` mirrors
  `LUHN_CACHE`. Exposed via `FinancialBuilder::is_bitcoin_checksum_valid`
  and `validate_crypto_address` (returns `CryptoAddressType` per chain
  flavor).
- **Presidio** (`crypto_recognizer.py:54-141`): Real cryptographic validation. P2PKH/P2SH (`1`/`3` prefix): Base58 decode → `SHA256(SHA256(payload))[:4] == last_4_bytes`. Bech32/Bech32m (`bc1` prefix): Full BIP-173/BIP-350 — HRP expand, polymod, constant check (`1` Bech32, `0x2BC830A3` Bech32m), charset validation, separator position.
- **Octarine** (`financial/detection/crypto.rs:18-30`, `common/patterns/financial.rs:192-211`): Pure regex shape match. No checksum function anywhere in `primitives/identifiers/financial/`. Catalog records `"validation": null` for `CryptoAddress`.
- **Impact**: Order-of-magnitude more false positives than Presidio on the one currency Presidio supports. Single-character typos in otherwise-valid addresses still match. Any 34-char Base58 string starting with `1` or `3` is flagged.
- **Recommendation**: Add `is_bitcoin_checksum_valid()` in `financial/detection/crypto.rs` using `bs58 = "0.5"` with `check` feature (`bs58::decode(addr).with_check(None).into_vec()` does Base58 + double-SHA256 in one call) and `bech32 = "0.11"` (`bech32::decode(addr)` validates polymod constant). Mirror `LUHN_CACHE` / `ABA_CACHE` pattern with `BTC_CHECKSUM_CACHE`. Source: `gap_financial.md` C1, `gap_security_extensions.md` L-1.
- **Effort**: Small (4-6h). Pure-function add, no public API change.

### CRIT-8. Multilingual context keywords — only `ApiKey` has non-English coverage

- **Presidio**: 12 languages (`de, en, es, fi, fr, it, ko, kr, pl, sv, th, tr`). 35 of 83 recognizers (≈42%) have multilingual context. 72 of 83 (≈87%) have any context words.
- **Octarine** (`primitives/identifiers/confidence/keywords.rs`): Multilingual coverage applies **only** to `IdentifierType::ApiKey` per `context_keyword_notes`. 14 of 95 identifiers (≈15%) have any English keywords; 80 of 95 have empty arrays. Per-arm `context_keywords()` returns `&'static [&'static str]` — no language dimension in the type signature. Korean RRN/FRN/BRN/DriverLicense/Passport, Thai TNIN, Italian FiscalCode, Spanish NIF/NIE, Polish PESEL, Finnish HETU, Aussie TFN/ABN/Medicare/ACN, Indian Aadhaar/PAN/GSTIN, Singaporean NRIC/UEN all return `&[]` despite having native-language keywords in Presidio (`사업자등록번호`, `codice fiscale`, `henkilötunnus`, `เลขประจำตัวประชาชน`, `tarjeta`, `Führerschein`, `patente`).
- **Impact**: Context keyword boosting is the standard PII pipeline trick to lift weak regex matches above threshold. Without per-language keywords, octarine in French, German, Italian, Korean, Thai, or Hindi log streams operates at materially lower precision. The `context_keyword_languages` catalog field claims 7 languages but only `ApiKey` uses 6 of them — external consumers will overestimate locale fitness by ~17×.
- **Recommendation**: Refactor `keywords.rs` to `(IdentifierType, KeywordLanguage) -> &[&str]` registry — either `phf` perfect-hash map or `static TABLE: &[(IdentifierType, KeywordLanguage, &[&str])]` linear scan. Per-language files under `primitives/identifiers/common/keywords/{en,de,es,fi,fr,it,ja,ko,pl,sv,th,tr,ar,hi,zh_hans,zh_hant}.rs`. Translate top-20 identifiers into all 12 Presidio languages (data is MIT-licensed in Presidio's `country_specific/{lang}/*.py` files). Update `confidence/context.rs::ContextWindow` to accept `KeywordLanguage` or `LanguageHint`. Source: `gap_context_locales.md` C1, C2, H1, H2, H3; `gap_government_americas.md` L1; `gap_government_apac.md` H1; `gap_financial.md` L3; `gap_personal_contact.md` Gap 8.
- **Effort**: Medium (1-2 weeks: refactor 1-2d + per-language files 2-3d + translations 1-2w).

### CRIT-9. German identifier suite — zero coverage vs 11 Presidio recognizers

- **Presidio**: 11 default-enabled or default-available German recognizers — `DE_TAX_ID` (Steuer-IdNr, ISO 7064 mod-11,10 + 3-repeat rule), `DE_ID_CARD` (Personalausweis nPA, ICAO Doc 9303 weights 7-3-1 with excluded alphabet `ABDEIOQSU`), `DE_PASSPORT` (Reisepass, same ICAO Doc 9303), `DE_FUEHRERSCHEIN` (regex), `DE_VAT_ID` (USt-IdNr mod-11), `DE_TAX_NUMBER` (Steuernummer), `DE_SOCIAL_SECURITY` (Sozialversicherungsnummer), `DE_HEALTH_INSURANCE` (KVNR Luhn-style), `DE_BSNR`/`DE_LANR` (provider numbers), `DE_HANDELSREGISTER` (HRB/HRA), `DE_KFZ` (vehicle plate). German recognizers ship ~190 unique German context keywords total.
- **Octarine**: Zero German government identifiers. Only "Germany" hits in the codebase are phone region (`+49`) and 5-digit postal code (Postleitzahl).
- **Impact**: German `Steuer-IdNr` is the lifelong personal tax ID assigned to every resident, protected under §§ 139a-139e AO + DSGVO. BDSG Art. 22 treats unlawful processing as a regulatory violation. KVNR (health insurance) is health data under GDPR Art. 9. Cannot operate in the German market without these.
- **Recommendation**: Create `primitives/identifiers/government/detection/germany.rs` and `validation/germany.rs`. Implement a shared `icao_doc_9303::check_digit` helper in `primitives/identifiers/government/common.rs` for nPA + Reisepass + any future ICAO-compliant national passport (Netherlands, France, etc. become cheap to add). Add `IdentifierType::GermanyTaxId / GermanyIdCard / GermanyPassport / GermanyDriverLicense / GermanyVatId / GermanyTaxNumber / GermanySocialSecurity / GermanyHealthInsurance / GermanyBsnr / GermanyLanr / GermanyHandelsregister / GermanyKfz`. Split across multiple files to stay under the 500-LOC warning. Source: `gap_government_eu.md` G-EU-2, G-EU-6, G-EU-10, G-EU-11.
- **Effort**: Large (1 week for core 3 — TaxId + IdCard + Passport via shared ICAO helper; 3-5 days for the remainder).

### CRIT-10. UK NHS Number missing

- **Presidio** (`NhsRecognizer`): mod-11 weighted checksum. 10 digits, multiply first 9 by weights `10, 9, 8, 7, 6, 5, 4, 3, 2`, require `total % 11 == 0`. Strips `-` and space via `replacement_pairs`. Default-enabled, English language.
- **Octarine**: No `UkNhs` variant, no NHS function. `grep -ri "nhs" primitives/identifiers/` returns nothing.
- **Impact**: NHS numbers are special-category health data under GDPR Art. 9. UK Data Protection Act 2018 Schedule 3 imposes additional safeguards. SAR or breach involving NHS numbers triggers ICO notification. Cannot ship to UK healthcare workloads.
- **Recommendation**: Add `IdentifierType::UkNhs` + `PiiType::UkNhs`. Create `primitives/identifiers/government/detection/uk.rs` and `validation/uk.rs` with `is_uk_nhs`, `find_uk_nhs_in_text`, `validate_uk_nhs`, `validate_uk_nhs_with_checksum`. Wire through PII bridge, scanner domain, builder, shortcuts per `octarine-identifier-checklist`. Add HIPAA + GDPR flags in `classification`. Source: `gap_government_eu.md` G-EU-1.
- **Effort**: Medium (1 day).

### CRIT-11. Swedish Personnummer + Organisationsnummer missing

- **Presidio**: `SePersonnummerRecognizer` (Luhn over 10 digits + date sanity, includes samordningsnummer where day ≥ 61 means day - 60; accepts `YYMMDDXXXX` and `YYYYMMDDXXXX`, optional `-`/`+` separator where `+` marks 100+ years). `SeOrganisationsnummerRecognizer` (10 digits, third digit ≥ 2 to distinguish from personnummer, Luhn).
- **Octarine**: Neither identifier exists. No Swedish anything in `government/`.
- **Impact**: Personnummer is the unique Swedish national ID, universally used for healthcare / banking / government. Considered the most sensitive non-credential PII in Sweden; identity theft via leaked personnummer is endemic.
- **Recommendation**: Add `IdentifierType::SwedenPersonnummer / SwedenOrgnummer`. Create `validation/sweden.rs` reusing `national_id.rs::luhn_check`. Validate month 1-12, day 1-31 or 61-91 (samordningsnummer), then Luhn over the 10 digits. Source: `gap_government_eu.md` G-EU-3, G-EU-7.
- **Effort**: Medium (1 day for both).

### CRIT-12. Italian completeness — IT_VAT_CODE / IT_DRIVER_LICENSE / IT_IDENTITY_CARD / IT_PASSPORT missing

- **Presidio**: All four default-enabled. `IT_VAT_CODE` (11-digit partita IVA, Luhn-style mod-10 with sum-of-digit-doubling on positions 2,4,6,8,10), `IT_PASSPORT` (`(?i)\b[A-Z]{2}\d{7}\b`), `IT_IDENTITY_CARD` (three patterns — paper `[A-Z]{2}\s?\d{7}`, CIE 2.0 `\d{7}[A-Z]{2}`, CIE 3.0 `[A-Z]{2}\d{5}[A-Z]{2}`), `IT_DRIVER_LICENSE` (`\b([A-Z]{2}\d{7}[A-Z])|(U1[BCDEFGHLJKMNPRSTUWYXZ0-9]{7}[A-Z])\b`).
- **Octarine**: Only `ItalyFiscalCode` exists; no VAT, no driver license, no identity card, no passport. `DriverLicense` covers US/CA/KR/IN only.
- **Impact**: All three identity documents are Member-State national IDs under GDPR Art. 87, requiring Member-State-specific safeguards. Italian Garante considers them among the most sensitive non-health identifiers.
- **Recommendation**: Add `IdentifierType::ItalyVat / ItalyPassport / ItalyIdentityCard / ItalyDriverLicense`. Extend `validation/italy.rs`. VAT is the only one with a checksum; the rest are regex + context keywords. Source: `gap_government_eu.md` G-EU-4, G-EU-5.
- **Effort**: Medium (1-2 days for all four).

### CRIT-13. Turkey missing entirely — TR_NATIONAL_ID + TR_LICENSE_PLATE

- **Status**: ✅ Closed in #434. `TurkeyTckn` (NVI mod-10 dual check) and
  `TurkeyLicensePlate` (province 01-81 + `[A-PR-VY-Z]` letter class)
  implemented in `primitives/identifiers/government/{detection,validation,
  builder}/turkey.rs`, wired through the Layer 3 `GovernmentBuilder`,
  shortcut module, PII bridge (`PiiType::TurkeyTckn`,
  `PiiType::TurkeyLicensePlate`), and `scan_government()`. Classification:
  `is_high_risk = true`; not `is_gdpr_protected` (Turkey is governed by
  KVKK, not GDPR).
- **Presidio**: `TrNationalIdRecognizer` (11-digit NVI mod-10: `10th digit = (odd_sum * 7 - even_sum) % 10`, `11th = sum of first 10 mod 10`). `TR_LICENSE_PLATE` (province codes 01-81, letters `[A-PR-VY-Z]` excluding Q/W/X). Turkish context: `tc kimlik, kimlik no, tckn, nüfus cüzdanı, türk kimlik, plaka`.
- **Octarine**: No `TurkeyTckn` identifier, no `validation/turkey.rs`, no patterns.
- **Impact**: Turkey's KVKK (Kişisel Verilerin Korunması Kanunu, Law 6698) is the local GDPR. TCKN is the most-cited personal identifier in KVKK enforcement actions. Cannot serve Turkish customers.
- **Recommendation**: Add `IdentifierType::TurkeyTckn / TurkeyLicensePlate`. NVI checksum is ~10 lines. Follows the existing `ThailandTnin` template. Add Turkish context keywords. Source: `gap_government_apac.md` C1, `gap_context_locales.md` C2.
- **Effort**: Medium (small — checksum + two patterns).

### CRIT-14. Phone number — bare regex vs libphonenumber

- **Presidio**: `PhoneRecognizer` uses `phonenumbers` (Python port of Google's libphonenumber). 8 default regions (`US, UK, DE, FR, IL, IN, CA, BR`). Validates against carrier prefixes, regional formats, possible/valid length per region, country-code routing tables, short codes.
- **Octarine** (`primitives/identifiers/personal/detection/phone.rs`): Hand-rolled E.164 regex + digit-count heuristic (`digit_count >= 7`). 13 hand-rolled country prefix regexes. False-positive filter rejects sequential / repeated / date-like / SSN-like strings. Missing Israel (`+972`) which is a Presidio default region, Korea (`+82`), Mexico (`+52`), Turkey (`+90`), and the entire African continent. No per-region length validation; `+44 1` is accepted by octarine but rejected by libphonenumber (UK numbers need 10+ digits after country code). No carrier prefix validation; `+1 555 023 4567` accepted but rejected by libphonenumber.
- **Impact**: For log-scrubbing / LLM proxy use cases, false positives on arbitrary-looking digit strings (order numbers, customer IDs, hashes) is the single largest pain point. libphonenumber's per-region prefix tables drop these to near-zero.
- **Recommendation**: Add `phonenumber = "0.3"` crate (Rust port of libphonenumber, currently 0.3.9+9.0.21 wrapping libphonenumber 9.0.21 metadata). Refactor `phone.rs` to call `parse(Some(region), value).map(|n| phonenumber::is_valid(&n))`. `find_phone_region` becomes a thin wrapper over `phonenumber::country()`. Drop most of the hand-rolled false-positive filter (libphonenumber handles those via possible-length tables). Delete UK/DE/FR per-country regexes in `patterns::network::contact_patterns`. Source: `gap_personal_contact.md` Gap 5 + Gap 9, `gap_context_locales.md` L2.
- **Effort**: Medium (1-2 days incl. test migration).

### CRIT-15. Email + URL — no Public Suffix List validation

- **Presidio**: `EmailRecognizer.validate_result` calls `tldextract.extract(pattern_text)` and rejects matches where `result.fqdn == ""`. Consults Mozilla Public Suffix List, so `user@foo.bar` (no real TLD) is rejected even though regex matches. `UrlRecognizer.BASE_URL_REGEX` embeds a hand-curated list of ~1,500 TLDs (gTLDs + ccTLDs); 4 patterns including bare hostname.
- **Octarine** (`primitives/identifiers/personal/detection/email.rs`): TLD validation is "any 2+ ASCII letters." Accepts `user@example.notatld`, `admin@foo.zz`. `URL_HTTP = r"https?://[^\s]+"` matches anything after `https://` to whitespace; `URL_GENERIC = r"[a-z][a-z0-9+.-]*://[^\s]+"` matches any protocol. Over-matches (eats subsequent prose), under-matches (misses bare URLs like `www.example.com`).
- **Impact**: For LLM proxy redaction of chat content, false-positive rates on filenames / made-up TLDs / version strings are unacceptable. Bare URLs in user messages silently leak.
- **Recommendation**: Add `addr = "0.15"` (wraps `publicsuffix`, closest analog to Python's `tldextract`) — `parse_email_address(s).is_ok()` and `parse_dns_name(host).is_ok()`. Add `linkify = "0.10"` for bare URL detection (designed for this; handles IDN + parentheses-balancing inside paths). Pipe `linkify` matches through `url::Url::parse` (already a workspace dependency) for structural validity. Optional `email-strict` feature flag if the ~250KB PSL data is a concern. Source: `gap_personal_contact.md` Gap 6 + Gap 7 + Gap 10, `gap_security_extensions.md` M-1.
- **Effort**: Small (1 day total).

## High Gaps (algorithmic depth or correctness bugs)

### HIGH-1. `validate_bank_account` inverts Luhn logic — ~10% false-reject rate

- **Octarine** (`primitives/identifiers/financial/detection/bank_account.rs:113-121`): `digits.len() >= 8 && digits.len() <= 17 && !is_luhn_checksum_valid(&digits_only)`. Treats Luhn-valid 8-17 digit strings as **not** bank accounts. Real US bank account numbers rarely use Luhn but it is not forbidden; some institutions issue them with checksum digits, and ~10% of 8-digit account numbers Luhn-validate by chance.
- **Impact**: Medium-high false-negative rate on US bank accounts that happen to Luhn-validate. The same numbers also pass through as credit cards, creating a domain confusion.
- **Recommendation**: Drop the `!is_luhn_checksum_valid` exclusion. Replace with positive context-keyword check using `confidence/keywords.rs::context_keywords(&IdentifierType::BankAccount)`. If no context, return `DetectionConfidence::Low` instead of `false` — let the caller decide. Source: `gap_financial.md` H4.
- **Effort**: Small (3-4h incl. test rewrites for the inverted assumption).

### HIGH-2. `AustraliaMedicare` classification — `is_high_risk=false`, `is_hipaa_protected=false`

- **Octarine catalog**: `AustraliaMedicare` shows `is_high_risk=False, is_hipaa_protected=False`.
- **Reality**: Medicare numbers are health-payer identifiers protected under Australia's Privacy Act 1988, *My Health Records Act*, *Healthcare Identifiers Act*. AU equivalent of US MBI / UK NHS.
- **Recommendation**: Set `is_high_risk=true` for `AustraliaMedicare`. Consider adding `is_app_protected` (Australia Privacy Principles) and flipping on for `AustraliaTfn`, `AustraliaMedicare`, `AustraliaAbn` (when linked to sole trader). Source: `gap_government_apac.md` C3 (also surfaced in earlier audit).
- **Effort**: Trivial (one-line classification edit + tests).

### HIGH-3. US Driver License — 4 states only + permissive fallback

- **Presidio**: Single regex with ~20 state alternatives + fallback digits-only pattern.
- **Octarine**: `state_patterns()` in `common/patterns/personal/us_identifiers.rs:105` returns only `CA, TX, NY, FL`. `LicenseValidator` impls for `CA, FL, NE, WA`. `validate_driver_license` falls through to generic "6-13 alphanumeric" — far too permissive, false-positives on any customer/order ID.
- **Recommendation**: Port Presidio's full state-alternation regex as stopgap. Build per-state `LicenseValidator` for top 20 states. Replace generic 6-13 fallback with explicit "unknown jurisdiction" `Problem::Validation`. Source: `gap_government_americas.md` H1.
- **Effort**: Medium (1 week full; 1 day stopgap).

### HIGH-4. US Passport rejects valid legacy 9-digit numbers

- **Presidio**: Two patterns — `\b[0-9]{9}\b` (legacy, weak 0.05) and `\b[A-Z][0-9]{8}\b` (Next Generation, weak 0.1).
- **Octarine** (`primitives/identifiers/government/validation/passport.rs:73`): `validate_passport` requires "alphabetic series letter + digits"; bare 9-digit fails. Also rejects test patterns including `A12345678` (sequential), `A98765432` (descending) — silently drops valid (but unfortunate) real-world numbers.
- **Recommendation**: Add `validate_us_passport` accepting both `[0-9]{9}` and `[A-Z][0-9]{8}`. Move test-pattern rejection behind opt-in `validate_passport_strict`. Distinguish `IdentifierType::UsPassport` from generic `Passport`. Source: `gap_government_americas.md` H2.
- **Effort**: Medium (half-day).

### HIGH-5. IBAN — only 25 country lengths checked, no per-country BBAN structural validation

- **Presidio** (`iban_recognizer.py:210-243`, `iban_patterns.py`): After mod-97, runs per-country structural regex for **70 countries** distinguishing alphabetic / numeric / alphanumeric BBAN segments. France example: `(FR) CK + N4 + N4 + N2 + C2 + C4 + C4 + C + N2` — bank code digits, branch code alphanumeric, 2-digit national check at end.
- **Octarine** (`financial/detection/iban.rs:11-38`): Length check for 25 countries only (AL, AT, BE, CH, CZ, DE, DK, ES, FI, FR, GB, GR, HR, HU, IE, IT, LU, NL, NO, PL, PT, RO, SE, SI, SK). Missing 45 countries from ISO 13616 registry; countries not in table accepted with any length 15-34 as long as mod-97 passes.
- **Impact**: Mod-97 has ~1% collision rate. Without structural backing, octarine detects ~1% of arbitrary 15-34 char alphanumeric strings starting with two letters + two digits as valid IBANs from non-listed countries.
- **Recommendation**: **Quick win**: Extend `COUNTRY_LENGTHS` to all 70 ISO 13616 countries (1h, pure data). **Full parity**: swap to `iban_validator = "0.1"` crate which encodes the full 70-country BBAN layout and runs mod-97 — `iban_validator::IbanLike::validate()` — tracks upstream registry changes via `cargo update`. Source: `gap_financial.md` H1, `gap_security_extensions.md` extension 12.
- **Effort**: Small for data extension (1h); Medium for crate swap (4h).

### HIGH-6. Singapore UEN — no checksum validation

- **Presidio**: Three-layout UEN with per-layout weighted mod-11 checksum (`XMKECAWLJDB`, `ZKCMDNERGWH`, alphanumeric for format C). Format C validates entity-type whitelist of 39 codes (LP, LL, FC, ...). Format B rejects future registration years.
- **Octarine** (`singapore.rs:199-217`): Layout matching only. `validate_singapore_uen` accepts any 8/9-digit+letter or `T NN AA NNNN A` shape. No check letter verification, no entity-type whitelist.
- **Impact**: PDPA — UEN is a business identifier often colocated with NRICs and bank info. False positives on every 9-char-with-trailing-letter string dilute the redaction signal.
- **Recommendation**: Port Presidio's three checksum tables + entity-type whitelist to `validation/singapore.rs`. Add `validate_singapore_uen_with_checksum` keeping `validate_singapore_uen` as format-only variant. Source: `gap_government_apac.md` C2.
- **Effort**: Medium (three weight arrays + three alphabets, ~80 lines).

### HIGH-7. India Aadhaar — missing palindrome rejection

- **Presidio**: `__check_aadhaar` rejects values where the string equals its reverse — UIDAI convention for filtering Verhoeff-valid but obviously-test numbers.
- **Octarine** (`india.rs:98-108`): `validate_india_aadhaar_with_checksum` validates Verhoeff but doesn't reject palindromes. `is_test_india_aadhaar` catches all-same-digit but not palindromes.
- **Recommendation**: Add `is_palindrome_aadhaar()` helper, reject in both `validate_india_aadhaar_with_checksum` and `is_test_india_aadhaar`. Source: `gap_government_apac.md` H2.
- **Effort**: Trivial (5-line check).

### HIGH-8. Finland HETU — missing post-2023 century markers B-F / U-Y

- **Octarine** `VALID_CENTURY_MARKERS = ['-', '+', 'A']`. Finland introduced new markers in 2023 (`B, C, D, E, F` for 2000s; `Y, X, W, V, U` for 1900s) per DVV revised specification after exhausting the legacy 30,000/day allocation.
- **Impact**: Octarine rejects valid HETUs issued after 2023-01-01.
- **Recommendation**: Update `VALID_CENTURY_MARKERS` to include the post-2023 extended set. Source: `gap_government_eu.md` S-EU-2 (action item).
- **Effort**: Trivial (one-line change).

### HIGH-9. `IdentifierType::MedicalLicense` collides with DEA-only detection

- **Octarine catalog**: `MedicalLicense` octarine_type maps to `PiiType::DeaNumber`. `IdentifierType::MedicalLicense` is emitted only by `is_dea_number` / `find_dea_numbers_in_text` (`primitives/identifiers/medical/detection.rs:635, 659`). Type name suggests broader scope.
- **Recommendation**: Rename `IdentifierType::MedicalLicense` → `IdentifierType::DeaNumber` (matches `PiiType`); reserve `MedicalLicense` for future state-license work. Per `octarine-release` skill, pre-1.0 do directly without `#[deprecated]` aliases (consistent with `feedback_pre_1_0_breaking_changes` memory). Source: `gap_government_americas.md` M3, `gap_security_extensions.md` H-1.
- **Effort**: Low (rename + bridge update + scanner registration).

### HIGH-10. State medical license numbers not covered

- **Presidio** (`medical_license_recognizer.py`): Single DEA-format regex; the entity is conceptually `MEDICAL_LICENSE` but in practice DEA-only.
- **Octarine**: DEA fully covered (with correct registrant-type filtering — see CRIT comparison). No state medical board license number coverage (CA MD `A12345`, NY MD `123456-1`, TX MD `A1234`, nursing, pharmacy, dental).
- **Impact**: For HIPAA / credentialing pipelines, state medical license numbers appear in provider directories, credentialing audits, license verification logs.
- **Recommendation**: Add `primitives/identifiers/medical/state_license.rs` with per-state formats analogous to driver-license pattern table. New `IdentifierType::StateMedicalLicense` (after HIGH-9 rename). Coordinate with `octarine-architecture` and `octarine-pii-bridge`. Source: `gap_government_americas.md` H3, `gap_security_extensions.md` extension 6.
- **Effort**: High (1 week incl. per-state patterns; Medium scoped to top 10).

### HIGH-11. UK Driving Licence + UK Passport missing

- **Presidio**: `UkDrivingLicenceRecognizer` validates DVLA 16-char structural shape and rejects all-9 surnames (DVLA check digit algorithm is not public). `UkPassportRecognizer` is regex-only `[A-Z]{2}\d{7}`.
- **Octarine**: Both missing. `DriverLicense` does not include UK variants; `Passport` does not include a UK-specific shape.
- **Recommendation**: Add to `validation/uk.rs` next to NHS — DVLA shape validator with surname check, plus UK passport regex. Tag both as GDPR-protected. Source: `gap_government_eu.md` G-EU-8.
- **Effort**: Small (4h per identifier, bundled with CRIT-10).

### HIGH-12. ES Passport missing; CA SIN missing first-digit `[1-79]` check

- **Spain**: `ES_PASSPORT` (`EsPassportRecognizer`, regex `\b[A-Z]{3}[0-9]{6}\b`) missing. Octarine has SpainNif + SpainNie but no passport.
- **Canada**: `CaSinRecognizer` constrains first digit to `[1-79]` (excludes 0 and 8 — reserved per ESDC). Luhn over 9 digits. Octarine's `validate_canada_sin` (`national_id.rs:217-241`) validates 9 digits + Luhn + test patterns but **does not enforce first-digit `[1-79]`** — `012345674` (starts with 0, Luhn-valid) validates today.
- **Recommendation**: Add `IdentifierType::SpainPassport`. Add first-digit check before Luhn in `validate_canada_sin` (~5 lines). Source: `gap_government_eu.md` G-EU-9, `gap_government_americas.md` M1.
- **Effort**: Trivial (Spain ~2h; Canada ~5 lines).

### HIGH-13. Korea Passport prefix narrower than Presidio

- **Presidio**: Accepts first letter `[MmSsRrOoDd]` (M=multiple, S=single, R=resident, O=official, D=diplomatic) — all five MOFA passport types.
- **Octarine** (`korea_passport.rs:14`): `VALID_TYPE_PREFIXES = &['M', 'R', 'S']` only. Official and diplomatic Korean passports rejected.
- **Recommendation**: Extend `VALID_TYPE_PREFIXES` to `['M', 'R', 'S', 'O', 'D']`. Source: `gap_government_apac.md` H3.
- **Effort**: Trivial (one-line + tests).

### HIGH-14. SSN strict-mode parity — missing 8-digit prefix invalidation + mixed-delimiter check

- **Presidio** (`us_ssn_recognizer.py invalidate_result`): Hard rejections include `98765432`-prefix check (matches any 9-digit starting with these 8 digits, not just exact `987654321`), explicit mixed-delimiter rejection (`"123-45 6789"` rejected because dash and space mix).
- **Octarine** (`primitives/identifiers/government/validation/ssn.rs`): Covers `000`/`666`, group-`00`, serial-`0000`, all-same-digit, sequential `123456789`/`987654321`, Woolworth's `078051120`, plus extras (`219099999`, `457555462`, payment-card patterns). Missing the 8-digit prefix and explicit mixed-delimiter checks.
- **Recommendation**: Add `98765432`-prefix and explicit mixed-delimiter checks to `validate_ssn_uncached`. Source: `gap_government_americas.md` C3.
- **Effort**: Low (couple of hours).

## Medium Gaps (coverage breadth, polish, additional regions)

- **MED-1. India Vehicle Registration patterns** — Presidio has 10 patterns (BH-series `21BH1234AB`, diplomatic `CC/CD/UN`, armed forces, foreign-mission); octarine has 3 (no BH-series, no diplomatic, no armed-forces). Source: `gap_government_apac.md` M1.
- **MED-2. India PAN weak-pattern fallback** — Presidio has three patterns at scores 0.5 / 0.1 / 0.01; octarine has only standard + labeled. Reformatted PANs (`ABCDE-1234-F`) missed. Documented as design tradeoff. Source: `gap_government_apac.md` M2.
- **MED-3. India Passport stricter regex** — Presidio uses `[A-Z][1-9]\d\s?\d{4}[1-9]` (rejects passports ending in 0); octarine STANDARD pattern `[A-Z]\d{7}` is broader but text-scan-blacklisted to avoid false positives. Source: `gap_government_apac.md` L1.
- **MED-4. ABA routing range coverage** — Octarine `valid_ranges = [(1,12), (21,32), (61,72), (80,80)]` — should likely extend to `(80,88)` (traveler's cheques + government) and `(90,99)` (Federal Government, sometimes seen in payroll). Verify against current FedACH ABA assignments. Source: `gap_financial.md` H3.
- **MED-5. MAC broadcast / all-zero invalidation** — Presidio's `mac_recognizer.py::invalidate_result` rejects `FF:FF:FF:FF:FF:FF` and `00:00:00:00:00:00`; octarine reports both as hits. Source: `gap_security_extensions.md` M-2.
- **MED-6. Multi-language credit card / bank-account / routing context keywords** — Presidio supports `en, es, it, pl` for credit card; octarine English-only. Source: `gap_financial.md` L3.
- **MED-7. SWIFT/BIC + UK sort code + IFSC + Canadian transit + German BLZ** — Missing in both libraries; octarine extension opportunity. SWIFT (8 or 11 chars, `[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?`, 5th-6th letters must be valid ISO 3166-1 alpha-2) is the highest ROI for AML/KYC/sanctions screening. IFSC (India, 11 chars `[A-Z]{4}0[A-Z0-9]{6}`), UK sort code (6 digits `XX-XX-XX`), Canadian transit (5+3), legacy German BLZ (8 digits). Source: `gap_financial.md` M2.
- **MED-8. Payment processor tokens** — Stripe/PayPal covered; missing Plaid (`access-sandbox-...`, `access-production-...`, `link-sandbox-...`, high security value), Square (`sqsplt_`, `sqLid_`), Adyen, Braintree, Authorize.net (`AnetApiToken_`). `PaymentToken` currently not shortcut-exposed (catalog: `"shortcut_exposed": false`). Source: `gap_financial.md` M3.
- **MED-9. CryptoAddress validation + sanitization** — ✅ Closed in #431.
  `validate_crypto_address` returns `Result<CryptoAddressType, Problem>`,
  `sanitize_crypto_address_strict` trims + validates, and
  `redact_crypto_address_with_strategy` ships with
  `CryptoAddressRedactionStrategy::ShowPrefix` (first 4 + last 4 chars —
  bank-statement convention). Wired through `FinancialBuilder` plus
  `identifiers::shortcuts::financial` (`validate_crypto_address`,
  `sanitize_crypto_address`, `redact_crypto_address`,
  `redact_crypto_addresses`). `TextRedactionPolicy::Partial` /
  `::Complete` now also cover crypto addresses.
- **MED-10. URL detection — bare hostnames missed; over-broad protocol matching** — Covered by CRIT-15 (linkify). All 5 octarine URL patterns require `[scheme]://`; bare URLs (`"visit example.com"`) not detected. `URL_GENERIC` matches any protocol (`jdbc://`, `file://`, made-up schemes). Source: `gap_personal_contact.md` Gap 10.
- **MED-11. IP detection edge cases** — Octarine missing IPv4-mapped (`::ffff:1.2.3.4`), IPv4-embedded (`2001:db8::1.2.3.4`), CIDR notation, IPv6 zone IDs (`%eth0`), `invalidate_result` post-filter via `std::net::IpAddr`. `ipnet = "2.9"` provides CIDR parsing. Source: `gap_personal_contact.md` Gap 11.
- **MED-12. Date detection — no impossible-date filter; `Datetime` vs `Birthdate` conflated** — Octarine's birthdate patterns identical to Presidio's `DATE_TIME` but octarine's `is_date_in_pii_context` keyword gating is actually a strength (Presidio doesn't have it). Add `chrono::NaiveDate::parse_from_str` post-filter to reject `02/30/2024` / `13/01/2024`. Add separate `Datetime` `IdentifierType` distinct from `Birthdate`. Source: `gap_personal_contact.md` Gap 12.

## Low Gaps (nice-to-have)

- **LOW-1. Credit card test-card list** — Expand `TEST_CARDS` (`financial/detection/credit_card.rs:39-48`, currently 6) to match Stripe's published test cards (3DS scenarios `4000002500003155`, `4000002760003184`, Amex test `378282246310005`) and Adyen's. Source: `gap_financial.md` L1.
- **LOW-2. IBAN normalization — NBSP / unicode digits** — `financial/detection/iban.rs:169-176` filters only `is_whitespace`. Copy-paste from PDFs/Excel introduces NBSP, zero-width-space, Arabic-Indic digits (`٠١٢...`). Use `unicode_normalization` NFKC. Source: `gap_financial.md` L2.
- **LOW-3. Context keywords for identifiers currently at `&[]`** — Add basic English keywords to `Iban`, `CryptoAddress`, `MacAddress`, `Url`, `Jwt`, `BearerToken`, `OAuthToken`, `SshKey`, `SessionId`, `Uuid`, `Username`, `Password`, `ConnectionString`, `HighEntropyString`, `OnePasswordToken`, `OnePasswordVaultRef`, `UrlWithCredentials` (17+ identifiers). Source: `gap_context_locales.md` M1.
- **LOW-4. Stop-word / lemmatization gap** — Presidio's `LemmaContextAwareEnhancer` lemmatises before keyword match (`"social_security"` matches `"socials"`); octarine `context::ContextWindow` does substring match. Misses inflected hits in morphologically rich languages (Finnish, Polish, German compounds). Source: `gap_context_locales.md` L1.
- **LOW-5. UEN test-pattern detection too narrow** — Octarine `is_test_singapore_uen` only flags all-zero / all-same digits; entity-type validation (HIGH-6) would naturally reject test garbage. Source: `gap_government_apac.md` L2.
- **LOW-6. Confidence-score mapping doc** — Presidio per-pattern weights (0.05 very weak, 0.3 weak, 0.5 medium) vs octarine's `DetectionConfidence::{Low, Medium, High}`. Callers migrating need a mapping table. Source: `gap_government_americas.md` L2.
- **LOW-7. NPI validator agreement** — Equivalent to Presidio (`Luhn-with-prefix (NPI '80840')`). Verify, no action. Source: `gap_security_extensions.md` L-2.
- **LOW-8. Architectural alignment doc** — Document `MedicalLicense` vs `DeaNumber` distinction across the three-registry bridge (`IdentifierType` / `PiiType` / scanner domains). Source: `gap_security_extensions.md` architectural alignments.

## Extension Opportunities (competitive moat — neither library has)

Pure extension targets where octarine can widen its lead beyond Presidio.

**APAC + extended regions** (regulatory urgency × addressable population, in priority order):

- **China Resident ID (居民身份证)** — PIPL (2021), ISO 7064 MOD 11-2 on 17 digits, check is 0-9 or X, 1.4B population. No competitor coverage.
- **Japan My Number (個人番号)** — APPI (2017), 11-digit weighted mod-11 (weights `[6,5,4,3,2,7,6,5,4,3,2]`), 125M.
- **Indonesia NIK** — UU PDP 2022, 16 digits region(6) + DOB(6) + serial(4), 270M.
- **Vietnam Citizen ID (CCCD)** — LDP 2023, 12 digits province(3) + gender-century(1) + YY(2) + serial(6), 100M.
- **Malaysia MyKad / NRIC** — PDPA 2010, 12 digits YYMMDD + state code + serial, 33M.
- **Hong Kong HKID** — PDPO, mod-11 letter checksum (A-H prefix + 6 digits + 1 check char), 7.5M.
- **Taiwan National ID** — PDPA, mod-10 with letter-to-number conversion (region letter + 9 digits), 23M.
- **Philippines TIN / PhilSys PSN** — Data Privacy Act 2012, 9 digits + 3 check (TIN); PSN is 12 digits, 110M.
- **Israel Teudat Zehut** — PPL 1981, 9 digits Luhn-style mod-10, 9.5M; valuable for cybersecurity vertical.
- **France INSEE / NIR** — CNIL Délibération 2019-001 establishes the "Référentiel NIR" — processing NIR generally requires CNIL authorization. 15 digits (13 base + 2 check), `97 - (number_13 mod 97)`. Single most regulated identifier in France. Presidio has no `fr_*` recognizer; clear competitive opportunity. Source: `gap_government_eu.md` G-EU-12.
- **Netherlands BSN** — Wbsn-bag restricts BSN processing to public authorities and explicitly authorized processors. Autoriteit Persoonsgegevens fines for unauthorized BSN processing. 8 or 9 digits, 11-test (elfproef) weights `9, 8, 7, 6, 5, 4, 3, 2, -1`. Presidio gap. Source: `gap_government_eu.md` G-EU-13.

**Crypto chain expansion** (octarine has 2 chains; market has 20+):

- **Ethereum EIP-55 mixed-case checksum** — ✅ Closed in #431.
  `is_ethereum_eip55_valid()` in
  `primitives/identifiers/financial/detection/crypto.rs` uses
  `tiny-keccak = "2.0"`. All-lowercase and all-uppercase addresses bypass
  EIP-55 (no checksum encoded); mixed case is verified against the
  keccak-256 of the lowercased hex. Cached via `ETH_EIP55_CACHE`. Exposed
  on `FinancialBuilder::is_ethereum_eip55_valid` and threaded into
  `validate_crypto_address` (returns `CryptoAddressType::EthereumChecksum`
  vs `EthereumLowercase`).
- **Solana** (base58 charset, 32-44 chars, no fixed prefix), **Cardano** (`addr1...` Bech32), **Polkadot** (SS58 base58 with prefix bytes via `ss58-registry = "1.40"`), **Tron** (`T` + base58, 34 chars), **Ripple/XRP** (`r` + base58, 25-35), **Litecoin** (`L`/`M`/`3`/`ltc1` prefixes), **Monero** (`4`/`8` + base58, 95 chars), **Cosmos** (`cosmos1...` Bech32). Add `CryptoChain` enum mirroring `CreditCardType` pattern; Ethereum-compatible chains (MATIC/BSC/AVAX/ARB/OP) share `0x` format and currently can't be distinguished. Source: `gap_financial.md` M1.

**AI provider tokens** (`ai.rs` currently OpenAI-only):

- Anthropic (`sk-ant-api03-...`, `sk-ant-...`), Cohere (`cohere_api_key=`), Hugging Face (`hf_[a-zA-Z0-9]{34}`), Replicate (`r8_[A-Za-z0-9]{40}`), OpenRouter (`sk-or-v1-[hex]{64}`), Mistral, Together AI, Perplexity, Groq. Source: `gap_security_extensions.md` extension 9.

**Cloud / infra tokens**:

- HashiCorp Cloud Platform (`hcp_...`), Cloudflare Workers / R2 / D1 (distinct from Origin CA), Pulumi (`pul-...`), Terraform Cloud (`atlasv1...`), Tailscale (`tskey-...`), Fastly, Vercel deployment tokens, Render deploy hooks. Source: `gap_security_extensions.md` extension 10.

**Quick wins (existing dependencies, <1 day each)**:

- OUI vendor lookup for MAC addresses via `oui` crate (250 KB embedded IEEE registry). Annotate `IdentifierMatch` with vendor; detect known-virtual OUIs (VMware `00:50:56`, VirtualBox `08:00:27`, Docker `02:42:*`) for env-fingerprinting suppression. Source: `gap_security_extensions.md` M-2 + extension 1.
- JWT signature validation (not just structure) — octarine already depends on `jsonwebtoken` v10.2 (feature-gated). Promote `detect_jwt_algorithm` to `validate_jwt_signature` returning `Result<Claims, Problem>`. Source: `gap_security_extensions.md` extension 2.
- PEM curve / key-size enrichment — octarine depends on `x509-parser` and `ssh-key`. Promote `detect_key_type_from_pem` to surface bit-size and curve OID in `IdentifierMatch` metadata for key-rotation tooling. Source: `gap_security_extensions.md` extension 3.

**Larger investments**:

- **HIBP-style password breach lookup** — Octarine already has `is_weak_password` + `credentials/`; add offline `is_breached_password(sha1_prefix)` API. Source: `gap_security_extensions.md` extension 11.
- **Per-state US medical-licence validators** — closes HIGH-10. 50 state medical boards publish format specs; many use state-letter prefix + 5-8 digits (CA `A-`, FL `ME`, NY `XX######`, TX `K`/`J`/`G` prefixes). Source: `gap_security_extensions.md` extension 6.

## Implementation Roadmap

### Phase 1: Bug fixes + classification (1-2 days)

- HIGH-1: Fix `validate_bank_account` inverted Luhn logic (`financial/detection/bank_account.rs:120`).
- CRIT-5 partial: Fix `validate_ssn` to reject 9xx-area numbers (route to future `validate_itin`).
- HIGH-2: Set `AustraliaMedicare` `is_high_risk=true` + revisit `is_hipaa_protected` / add `is_app_protected`.
- HIGH-7: Add palindrome reject to India Aadhaar (`india.rs:98-108`).
- HIGH-8: Extend Finland HETU `VALID_CENTURY_MARKERS` to post-2023 B-F / U-Y.
- HIGH-13: Extend Korea Passport `VALID_TYPE_PREFIXES` to include `O`, `D`.
- HIGH-12 partial: Add Canada SIN first-digit `[1-79]` check (`national_id.rs:217-241`).
- HIGH-14: Add SSN `98765432`-prefix + mixed-delimiter checks.
- HIGH-9: Rename `IdentifierType::MedicalLicense` → `IdentifierType::DeaNumber` (pre-1.0 direct rename per `feedback_pre_1_0_breaking_changes`).
- MED-5: Mirror Presidio MAC broadcast / all-zero invalidation in `is_mac_address`.

### Phase 2: BTC checksum + URL/email PSL + Ethereum EIP-55 (3-5 days)

- CRIT-7: Add `bs58` + `bech32` crates for BTC base58check / Bech32m (`financial/detection/crypto.rs`).
- CRIT-15: Add `addr` (PSL email+URL TLD validation) + `linkify` (bare URL detection) crates.
- Extension: Add EIP-55 mixed-case Ethereum via `tiny-keccak`.
- MED-9: Add `validate_crypto_address` + sanitization + redaction strategy.

### Phase 3: Multilingual context keywords (1-2 weeks)

- CRIT-8 step 1 (1-2d): Refactor `keywords.rs` to `(IdentifierType, KeywordLanguage) -> &[&str]` via `phf` or static table.
- CRIT-8 step 2 (2-3d): Per-language files under `primitives/identifiers/common/keywords/{en,de,es,fi,fr,it,ja,ko,pl,sv,th,tr,ar,hi,zh_hans,zh_hant}.rs`.
- CRIT-8 step 3 (1-2w): Translate top-20 identifiers into all 12 Presidio languages (data MIT-licensed in Presidio's `country_specific/{lang}/*.py`).
- Step 4 (1w): Update `confidence/context.rs::ContextWindow` for language scoping; Layer 3 builders gain `with_language` / `with_language_hint`.
- LOW-3: Add English context keywords to the 17+ identifiers currently at `&[]`.

### Phase 4: Missing country packs (2-4 weeks)

- **US** (CRIT-5, CRIT-6, HIGH-3, HIGH-4, HIGH-10): ITIN, MBI, per-state Driver License (top 20), state Medical License, US Passport 9-digit acceptance.
- **UK** (CRIT-10, HIGH-11): NHS, Driving Licence, Passport in `validation/uk.rs`.
- **Germany** (CRIT-9): Implement `icao_doc_9303::check_digit` helper, then `DE_TAX_ID` + `DE_ID_CARD` + `DE_PASSPORT` first, then the German pack remainder (`DE_FUEHRERSCHEIN`, `DE_VAT_ID`, `DE_SOCIAL_SECURITY`, `DE_HEALTH_INSURANCE`, `DE_BSNR`, `DE_LANR`, `DE_HANDELSREGISTER`, `DE_KFZ`).
- **Sweden** (CRIT-11): `SE_PERSONNUMMER` (Luhn + samordningsnummer day≥61) + `SE_ORGANISATIONSNUMMER`.
- **Italy** (CRIT-12): `IT_VAT_CODE` (Luhn-style mod-10) + `IT_PASSPORT` + `IT_IDENTITY_CARD` (3 patterns) + `IT_DRIVER_LICENSE`.
- **Spain** (HIGH-12): `ES_PASSPORT`.
- **Turkey** (CRIT-13): `TR_NATIONAL_ID` (NVI mod-10) + `TR_LICENSE_PLATE`.
- **Singapore** (HIGH-6): UEN three-layout weighted mod-11 checksum + entity-type whitelist.
- **France** (extension): `FR_INSEE` (15-digit NIR with Corsica 2A→19/2B→18 edge case).
- **Netherlands** (extension): `NL_BSN` (8 or 9 digits, elfproef weights `9..2,-1`).
- **HIGH-5**: Extend IBAN `COUNTRY_LENGTHS` to all 70 ISO 13616 entries (quick win), then consider `iban_validator` crate swap.
- MED-7: SWIFT/BIC (highest ROI international bank ID, ~6h).

### Phase 5: International phone (1 week)

- CRIT-14: Integrate `phonenumber = "0.3"` crate. Replace bare regex in `primitives/identifiers/personal/detection/phone.rs`. Delete per-country regexes in `patterns::network::contact_patterns`. Map `PhoneRegion` enum onto `phonenumber::country::Id`.

### Phase 6: NER strategy decision (separate design doc)

- Decide whether octarine ships NER, defers to caller via `NerProvider` trait, or explicitly does not match `PERSON` / `LOCATION` / `ORG`.
- **CRIT-3 (NRP) and CRIT-4 (AGE) can be done WITHOUT ML** — lexicon + regex respectively — and should ship in earlier phases.
- If shipping NER: feature-gated `octarine-ner-candle` (`candle`, pure Rust + quantised XLM-R) or `octarine-ner-rust-bert` (`rust-bert` + `tch`/libtorch, heavier but battle-tested) sub-crate.
- Minimum viable: `NerProvider` trait in `observe::pii` with `NoopNerProvider` default — unblocks integrators without taking on heavy ML deps.

### Phase 7: Competitive moat extensions (ongoing)

- APAC country IDs: China Resident ID, Japan My Number, Indonesia NIK + Vietnam CCCD + Malaysia MyKad (batched, share format families), HKID + Taiwan ID, Philippines TIN/PSN, Israel Teudat Zehut.
- Additional AI provider tokens (Anthropic, OpenRouter, Cohere, Replicate, HuggingFace, Mistral, Together, Perplexity, Groq).
- Additional cloud provider tokens (HCP, Pulumi, Terraform Cloud, Tailscale, Fastly, Vercel, Render).
- Additional crypto chains (Solana, Cardano, Polkadot, Tron, XRP, Litecoin, Monero, Cosmos) via `bs58`, `bech32`, `ss58-registry`.
- OUI vendor lookup, JWT signature validation, PEM curve/key-size enrichment, HIBP-style breach lookup.
- Per-state US medical-licence validators.

## Effort Summary

| Phase | Effort | Outcome |
|---|---|---|
| 1 | 1-2 days | All identified bugs fixed; classification correct; HETU 2023 markers; Korea/Canada/SSN polish |
| 2 | 3-5 days | BTC checksum parity; URL/email PSL parity; Ethereum EIP-55; CryptoAddress validation+sanitization |
| 3 | 1-2 weeks | Multilingual context for top 20 identifiers in 12 languages; per-language registry; language-aware `ContextWindow` |
| 4 | 2-4 weeks | Drop-in Presidio replacement for all country packs (US ITIN/MBI/states, UK NHS+DL+Passport, German suite, Sweden, Italy, Spain, Turkey, SG UEN checksum, IBAN 70 countries, SWIFT/BIC, FR INSEE, NL BSN) |
| 5 | 1 week | Phone parity via libphonenumber |
| 6 | TBD | NER policy resolved; AGE + NRP shipped via pattern/lexicon paths (do not block on ML) |
| 7 | Ongoing | Competitive moat — APAC countries, AI/cloud tokens, crypto chains, OUI, JWT signing, HIBP |

**Total to claim "drop-in Presidio replacement" (excluding NER policy decision): ~6-8 weeks of focused work.**

With NER policy resolved and a working `NerProvider` trait + at least one feature-gated impl: add 1-2 engineer-months.

## Appendix: Source Catalogs

- **Presidio catalog**: 83 recognizers across 12 languages (`de, en, es, fi, fr, it, ko, kr, pl, sv, th, tr`); 5 NER entities (`PERSON, LOCATION, ORGANIZATION, DATE_TIME, NRP`) via spaCy / Stanza / Transformers / GLiNER / HuggingFaceNer; 35 of 83 recognizers with multilingual context keywords; 72 of 83 with any context words; ~190 German keywords across 13 German recognizers alone.
- **Octarine catalog**: 95 `IdentifierType` variants (commit `49ef786`), 124 `PiiType` variants, 0 NER (`ner_entities: []`, `ner_notes` confirms intentional no-ML posture), 1 identifier (`ApiKey`) with multilingual context keywords in 6 non-Latin scripts (`ja, zh-Hans, zh-Hant, ko, ar, hi`) plus English; 13 identifier types with any English context keywords; 80 of 95 with empty keyword arrays.
- **Domain checksum counts** (octarine): personal 0, financial 2 (Luhn, ISO 7064 mod-97), government 18 (Verhoeff, multiple mod-11 variants, mod-10 weighted, Luhn, MOD-36, mod-26 letter check, VIN NHTSA-49), medical 2 (Luhn-with-prefix NPI, DEA odd+2×even mod 10), biometric 0, location 0, network 0, token 0, credentials 0.

## Appendix: Reference

Domain-level reports archived at `/tmp/presidio_compare/gap_*.md`:

- `gap_personal_contact.md` — `EMAIL_ADDRESS`, `URL`, `IP_ADDRESS`, `PHONE_NUMBER`, `PERSON`, `LOCATION`, `DATE_TIME`, `NRP`, `AGE`.
- `gap_financial.md` — `CREDIT_CARD`, `IBAN_CODE`, `CRYPTO`, `US_BANK_NUMBER`, `ABA_ROUTING_NUMBER`.
- `gap_government_americas.md` — US (SSN/ITIN/Passport/Driver License/Bank Number/NPI/MBI/Medical License), Canada (SIN), Brazil, Mexico.
- `gap_government_eu.md` — UK, Spain, Italy, Poland, Finland, Germany, Sweden, France, Netherlands.
- `gap_government_apac.md` — India, Australia, Korea, Singapore, Thailand, Turkey + Japan / China / HK / TW / MY / PH / ID / VN / IL extension targets.
- `gap_security_extensions.md` — medical, network, biometric, crypto, tokens.
- `gap_context_locales.md` — context-word coverage, multilingual breadth, NER strategy.

Catalog JSONs at `/tmp/presidio_compare/presidio_catalog.json` and `/tmp/presidio_compare/octarine_catalog.json`.
