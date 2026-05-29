# Presidio Analyzer — Built-in Recognizers

Catalog of every entity recognizer bundled with `presidio-analyzer`,
sourced directly from the Python class definitions in
`predefined_recognizers/` plus the YAML registry under `conf/`. Compiled
on 2026-05-28 against `microsoft/presidio` `main`.

Counts at a glance:

- **62 recognizer classes** total
- **9 generic** (locale-agnostic)
- **47 country-specific** spanning **16 countries**
- **6 NER / NLP-engine driven** (spaCy, Stanza, Transformers, HuggingFace, GLiNER, MedicalNER)
- **5 third-party / remote** (Azure AI Language, Azure Health De-ID, LangExtract family)
- IBAN recognizer alone covers **70 country IBAN formats**
- Phone recognizer uses `python-phonenumbers` and defaults to 8 regions but can be opened to all `phonenumbers.SUPPORTED_REGIONS`

## Source files reviewed

- <https://github.com/microsoft/presidio/tree/main/presidio-analyzer/presidio_analyzer/predefined_recognizers>
- <https://github.com/microsoft/presidio/tree/main/presidio-analyzer/presidio_analyzer/predefined_recognizers/country_specific>
  (subdirs: `australia`, `canada`, `finland`, `germany`, `india`, `italy`, `korea`, `nigeria`, `poland`, `singapore`, `spain`, `sweden`, `thai`, `turkey`, `uk`, `us`)
- <https://github.com/microsoft/presidio/tree/main/presidio-analyzer/presidio_analyzer/predefined_recognizers/generic>
- <https://github.com/microsoft/presidio/tree/main/presidio-analyzer/presidio_analyzer/predefined_recognizers/ner>
- <https://github.com/microsoft/presidio/tree/main/presidio-analyzer/presidio_analyzer/predefined_recognizers/nlp_engine_recognizers>
- <https://github.com/microsoft/presidio/tree/main/presidio-analyzer/presidio_analyzer/predefined_recognizers/third_party>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/predefined_recognizers/__init__.py>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/conf/default_recognizers.yaml>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/conf/default.yaml> (spaCy NER mapping)
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/conf/default_analyzer_full.yaml>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/conf/slim.yaml>
- <https://github.com/microsoft/presidio/blob/main/presidio-analyzer/presidio_analyzer/predefined_recognizers/generic/iban_patterns.py>
- <https://microsoft.github.io/presidio/supported_entities/> (Mkdocs page)
- <https://raw.githubusercontent.com/microsoft/presidio/main/docs/supported_entities.md> (raw)

## Recognizers by category

### Global / generic

All in `presidio_analyzer/predefined_recognizers/generic/`. All default to
`supported_language="en"`, but `CreditCardRecognizer` is also registered
in `default_recognizers.yaml` for `es`, `it`, and `pl`.

| Entity | Class | Languages | Detection method | Notes |
|---|---|---|---|---|
| `CREDIT_CARD` | `CreditCardRecognizer` | en, es, it, pl | Regex (per-brand) + **Luhn checksum** + context | Patterns cover All cards / Amex / Diners / Discover / JCB / Maestro / Mastercard / Visa / Instapayment |
| `CRYPTO` | `CryptoRecognizer` | en | Regex `(bc1\|[13])[a-zA-HJ-NP-Z0-9]{25,59}` + **double-SHA-256 base58 checksum** for P2PKH/P2SH and **Bech32/Bech32m** for `bc1` | Bitcoin only |
| `DATE_TIME` | `DateRecognizer` | en | 13 regex patterns (ISO 8601, mm/dd/yyyy, dd/mm/yyyy, yyyy-mm-dd, dd.mm.yyyy, dd-MMM-yyyy, MMM-yyyy, mm/yyyy, mm/yy …) + context "date", "birthday" | No checksum |
| `EMAIL_ADDRESS` | `EmailRecognizer` | en | Single regex (RFC-ish) + context | `validate_result` ensures TLD via `tld` library |
| `IBAN_CODE` | `IbanRecognizer` | en | Country-specific regex (**70 ISO IBAN countries**) + **ISO 7064 mod-97 check digit** | Country list in `iban_patterns.py`: AL, AD, AT, AZ, BH, BY, BE, BA, BR, BG, CR, HR, CY, CZ, DK, DO, TL, EE, FO, FI, FR, GE, DE, GI, GR, GL, GT, HU, IS, IE, IL, IT, JO, KZ, XK, KW, LV, LB, LI, LT, LU, MT, MR, MU, MD, MC, ME, NL, MK, NO, PK, PS, PL, PT, QA, RO, SM, SA, RS, SK, SI, ES, SE, CH, TN, TR, AE, GB, VA, VG |
| `IP_ADDRESS` | `IpRecognizer` | en | 5 regex patterns: IPv4, IPv6, IPv4-mapped IPv6, IPv4-embedded IPv6, unspecified `::` | Has `invalidate_result` to drop false positives |
| `MAC_ADDRESS` | `MacAddressRecognizer` | en | Regex (colon-form + dot-form) + context "mac", "ethernet", "hardware address" | Has `invalidate_result` |
| `PHONE_NUMBER` | `PhoneRecognizer` | en | **`python-phonenumbers` library** (`PhoneNumberMatcher`) + region-aware context | Default regions: US, UK, DE, FR, IL, IN, CA, BR. Can be opened to all `phonenumbers.SUPPORTED_REGIONS` (~250). Not a `PatternRecognizer` — direct `LocalRecognizer` |
| `URL` | `UrlRecognizer` | en | 4 regexes: schemed URL, schemeless URL, quoted URL, IPv4/IPv6/IDN host | Custom URL grammar (no `tldextract`) |

### NLP engine / NER recognizers

In `predefined_recognizers/nlp_engine_recognizers/` and
`predefined_recognizers/ner/`. These pull entities from the configured
NLP pipeline rather than running regexes.

| Entity bundle | Class | Engine | Languages | Notes |
|---|---|---|---|---|
| `PERSON`, `LOCATION`, `ORGANIZATION`, `NRP`, `DATE_TIME` | `SpacyRecognizer` | spaCy (default `en_core_web_lg`) | Configurable via `default.yaml` | `NRP` = Nationality / Religious / Political group. Default `labels_to_ignore` drops `ORGANIZATION`, `CARDINAL`, `EVENT`, `LANGUAGE`, `LAW`, `MONEY`, `ORDINAL`, `PERCENT`, `PRODUCT`, `QUANTITY`, `WORK_OF_ART` |
| Same set | `StanzaRecognizer` | Stanford Stanza via `spacy-stanza` | Multilingual (uses Stanza models) | Subclass of `SpacyRecognizer` |
| `PERSON`, `LOCATION`, `ORGANIZATION`, `AGE`, `ID`, `EMAIL`, `DATE_TIME`, `PHONE_NUMBER` | `TransformersRecognizer` | `spacy-huggingface-pipelines` | Any HF NER model | Subclass of `SpacyRecognizer`. Adds `AGE` and `ID` |
| Configurable label mapping (defaults to PERSON, LOCATION, ORGANIZATION, MISC, DATE_TIME) | `HuggingFaceNerRecognizer` | HuggingFace `pipeline("token-classification")` directly (no spaCy) | en + KO/JA via label aliases (`PS`/`LC`/`OG`/`DT`/`TI`) | Standalone — does not require spaCy |
| `MEDICAL_DISEASE_DISORDER`, `MEDICAL_MEDICATION`, `MEDICAL_THERAPEUTIC_PROCEDURE`, `MEDICAL_CLINICAL_EVENT`, `MEDICAL_BIOLOGICAL_ATTRIBUTE`, `MEDICAL_BIOLOGICAL_STRUCTURE`, `MEDICAL_FAMILY_HISTORY`, `MEDICAL_HISTORY` | `MedicalNERRecognizer` | HuggingFace pipeline, default model `blaze999/Medical-NER` | en | Subclass of `HuggingFaceNerRecognizer` |
| Arbitrary labels (zero-shot) | `GLiNERRecognizer` | GLiNER zero-shot NER model | en (configurable) | Labels are user-defined; default uses `NerModelConfiguration.model_to_presidio_entity_mapping` |

### Third-party / remote recognizers

In `predefined_recognizers/third_party/`. These call an external service
(Azure or LLM) instead of using local regexes / models.

| Class | Service | Entities | Notes |
|---|---|---|---|
| `AzureAILanguageRecognizer` | Azure AI Language PII detection | All categories Azure exposes (PERSON, PHONE, ADDRESS, IBAN, etc.) | `RemoteRecognizer`, en default |
| `AzureHealthDeidRecognizer` | Azure Health Data Services De-identification | Health entities (PATIENT, DOCTOR, AGE, DATE, …) | `RemoteRecognizer` |
| `LangExtractRecognizer` (abstract) | Generic LLM-based extraction via `langextract` package | Configurable via prompt YAML | Base class for the two below |
| `BasicLangExtractRecognizer` | Generic LLM (basic config) | Whatever the prompt YAML defines | `conf/langextract_config_basic.yaml` |
| `AzureOpenAILangExtractRecognizer` | Azure OpenAI | Whatever the prompt YAML defines | `conf/langextract_config_azureopenai.yaml` |

### Country-specific — Australia

Country code `au`. All disabled by default in `default_recognizers.yaml`.

| Entity | Class | Languages | Detection method | Notes |
|---|---|---|---|---|
| `AU_ABN` | `AuAbnRecognizer` | en | Regex (weak + medium) + **ABN mod-89 checksum** + context | Australian Business Number, 11 digits |
| `AU_ACN` | `AuAcnRecognizer` | en | Regex + **ACN modulus checksum** + context | Australian Company Number, 9 digits |
| `AU_MEDICARE` | `AuMedicareRecognizer` | en | Regex + **Medicare checksum** + context | 10–11 digit Medicare card |
| `AU_TFN` | `AuTfnRecognizer` | en | Regex + **TFN modulus-11 checksum** + context | Tax File Number |

### Country-specific — Canada

| Entity | Class | Languages | Detection method | Notes |
|---|---|---|---|---|
| `CA_SIN` | `CaSinRecognizer` | en, fr | Regex (weak + medium) + **Luhn** (via `invalidate_result`) + context | Disabled by default. Rejects SINs starting with 0 or 8 (reserved) |

### Country-specific — Finland

| Entity | Class | Languages | Detection method | Notes |
|---|---|---|---|---|
| `FI_PERSONAL_IDENTITY_CODE` | `FiPersonalIdentityCodeRecognizer` | fi | Regex + **HETU mod-31 check character** + context (`hetu`, `henkilötunnus`, `personbeteckningen`) | 11-char Henkilötunnus (date + century marker + serial + checksum). Not registered in default YAML — code-only |

### Country-specific — Germany

Country code `de`. Each recognizer's `supported_language = "de"`. All
disabled by default. German pack is the largest single-country
collection in Presidio.

| Entity | Class | Languages | Detection method | Notes |
|---|---|---|---|---|
| `DE_TAX_ID` | `DeTaxIdRecognizer` | de | Regex + **ISO 7064 mod-11,10 checksum** + context | 11-digit Steuerliche Identifikationsnummer |
| `DE_TAX_NUMBER` | `DeTaxNumberRecognizer` | de | 3 regex patterns (ELSTER 13-digit + per-state slash formats) + context, no checksum | Steuernummer |
| `DE_VAT_ID` | `DeVatIdRecognizer` | de | Regex + **mod-11 checksum** + context | USt-IdNr. (DE + 9 digits) |
| `DE_PASSPORT` | `DePassportRecognizer` | de | Regex + **ICAO Doc 9303 MRZ check digit** + context | 9-char alphanumeric |
| `DE_ID_CARD` | `DeIdCardRecognizer` | de | 2 regexes (nPA 9-char + legacy T+8) + **MRZ check digit** + context | Personalausweisnummer |
| `DE_SOCIAL_SECURITY` | `DeSocialSecurityRecognizer` | de | 2 regexes + **DRV checksum** + context | RVNR (Rentenversicherungsnummer), 12-char |
| `DE_HEALTH_INSURANCE` | `DeHealthInsuranceRecognizer` | de | Regex + **GKV-Spitzenverband checksum** + context | KVNR on eGK, 1 letter + 9 digits |
| `DE_KFZ` | `DeKfzRecognizer` | de | 5 regex patterns (district + identifier + digits + optional E/H) + context | Vehicle plate. No checksum |
| `DE_HANDELSREGISTER` | `DeHandelsregisterRecognizer` | de | Regex (HRA/HRB + 1–6 digits) + context | Commercial register number. No checksum |
| `DE_PLZ` | `DePlzRecognizer` | de | Single 5-digit regex (01001–99998 range) + context | Postal code — **base confidence 0.05**, explicitly tagged high FP risk |
| `DE_LANR` | `DeLanrRecognizer` | de | Regex + **mod-10 checksum** + context | Lebenslange Arztnummer (doctor ID), 9-digit |
| `DE_BSNR` | `DeBsnrRecognizer` | de | Regex + **checksum** + context | Betriebsstättennummer (medical practice ID), 9-digit |
| `DE_FUEHRERSCHEIN` | `DeFuehrerscheinRecognizer` | de | Regex + context (no checksum) | Driver license number |

### Country-specific — India

Country code `in`.

| Entity | Class | Languages | Detection method | Notes |
|---|---|---|---|---|
| `IN_AADHAAR` | `InAadhaarRecognizer` | en | 2 regex patterns + **Verhoeff checksum** + context | 12-digit Aadhaar |
| `IN_PAN` | `InPanRecognizer` | en | 3 regex variants (weak / medium / strict 10-char fixed format) + context | Permanent Account Number. No checksum |
| `IN_PASSPORT` | `InPassportRecognizer` | en | Regex + context | No checksum |
| `IN_VOTER` | `InVoterRecognizer` | en | 2 regex variants + context | EPIC number (10-char alphanumeric). No checksum |
| `IN_GSTIN` | `InGstinRecognizer` | en | 3 regex variants + **GSTIN modulus checksum** + context | GST Identification Number, 15-char |
| `IN_VEHICLE_REGISTRATION` | `InVehicleRegistrationRecognizer` | en | 9 regex patterns (per state RTO format) + **state code validation** + context | Indian vehicle plates |

### Country-specific — Italy

Country code `it`, language `it`.

| Entity | Class | Languages | Detection method | Notes |
|---|---|---|---|---|
| `IT_FISCAL_CODE` | `ItFiscalCodeRecognizer` | it | Regex + **Codice Fiscale alphanumeric checksum** + context (`codice fiscale`, `cf`) | 16-char |
| `IT_VAT_CODE` | `ItVatCodeRecognizer` | it | Regex + **Luhn-style checksum on Partita IVA** + context | 11-digit |
| `IT_PASSPORT` | `ItPassportRecognizer` | it | Regex + context | Recently added (PR #459) |
| `IT_IDENTITY_CARD` | `ItIdentityCardRecognizer` | it | 3 regex patterns (CIE 2 letters + 7 digits + 2 letters; legacy 9-digit) + context | No checksum |
| `IT_DRIVER_LICENSE` | `ItDriverLicenseRecognizer` | it | Regex + context (`patente`, `licenza`) | No checksum |

### Country-specific — Korea

Country code `kr`, language `ko` (Korean) — class names also accept `kr` as a language alias.

| Entity | Class | Languages | Detection method | Notes |
|---|---|---|---|---|
| `KR_RRN` | `KrRrnRecognizer` | ko | Regex + **RRN mod-11 checksum** + birth-date sanity check + context | Resident Registration Number, 13 digits |
| `KR_FRN` | `KrFrnRecognizer` | ko | Inherits from `KrRrnRecognizer` (regex + checksum) + context | Foreigner Registration Number, 13 digits |
| `KR_BRN` | `KrBrnRecognizer` | ko | 2 regex patterns + **BRN checksum** + context | Business Registration Number, 10 digits |
| `KR_PASSPORT` | `KrPassportRecognizer` | kr | 2 regex patterns + context | No checksum |
| `KR_DRIVER_LICENSE` | `KrDriverLicenseRecognizer` | ko | Regex + **license-format check** + context | 12-digit |

### Country-specific — Nigeria

Country code `ng`.

| Entity | Class | Languages | Detection method | Notes |
|---|---|---|---|---|
| `NG_NIN` | `NgNinRecognizer` | en | Regex + **NIN check** + context | National Identification Number, 11 digits |
| `NG_VEHICLE_REGISTRATION` | `NgVehicleRegistrationRecognizer` | en | Regex + context | 2011+ plate format. No checksum |

### Country-specific — Poland

| Entity | Class | Languages | Detection method | Notes |
|---|---|---|---|---|
| `PL_PESEL` | `PlPeselRecognizer` | pl | Regex + **PESEL weighted-sum checksum** + birth-date sanity check + context (`PESEL`) | 11 digits |

### Country-specific — Singapore

Country code `sg`.

| Entity | Class | Languages | Detection method | Notes |
|---|---|---|---|---|
| `SG_NRIC_FIN` | `SgFinRecognizer` | en | 2 regex patterns (`[A-Z]…` weak, `[STFGM]…` medium) + context (`fin`, `nric`) | No checksum in current code |
| `SG_UEN` | `SgUenRecognizer` | en | Regex + **UEN ACRA checksum** + context | Unique Entity Number. Not registered in default YAML — code-only |

### Country-specific — Spain

Country code `es`, language `es`.

| Entity | Class | Languages | Detection method | Notes |
|---|---|---|---|---|
| `ES_NIF` | `EsNifRecognizer` | es | Regex + **NIF mod-23 letter checksum** + context | DNI / NIF |
| `ES_NIE` | `EsNieRecognizer` | es | Regex + **NIE mod-23 checksum** + context | Foreigner ID |
| `ES_PASSPORT` | `EsPassportRecognizer` | es | Regex + context (`pasaporte`) | No checksum. Disabled by default |

### Country-specific — Sweden

Country code `se`, language `sv` (Swedish).

| Entity | Class | Languages | Detection method | Notes |
|---|---|---|---|---|
| `SE_PERSONNUMMER` | `SePersonnummerRecognizer` | sv | 2 regex patterns (10/12 digit) + **Luhn on truncated form** + context | Also recognises Samordningsnummer (coordination numbers for non-residents). Disabled by default |
| `SE_ORGANISATIONSNUMMER` | `SeOrganisationsnummerRecognizer` | sv | 2 regex patterns + **Luhn checksum** + context | 10-digit org number. Disabled by default |

### Country-specific — Thailand

| Entity | Class | Languages | Detection method | Notes |
|---|---|---|---|---|
| `TH_TNIN` | `ThTninRecognizer` | th | Regex + **Thai mod-11 weighted checksum** + context | Thai National ID, 13 digits. Disabled by default |

### Country-specific — Turkey

Country code `tr`, language `tr`. Recently added (PR mentioned in working-tree status).

| Entity | Class | Languages | Detection method | Notes |
|---|---|---|---|---|
| `TR_NATIONAL_ID` | `TrNationalIdRecognizer` | tr | Regex + **TCKN mod-10/mod-11 checksum** + context | 11-digit TCKN |
| `TR_LICENSE_PLATE` | `TrLicensePlateRecognizer` | tr | 2 regex patterns + **province code 01–81 + letter exclusion (no Q/W/X)** + context | Plaka, civilian format only |

### Country-specific — United Kingdom

Country code `uk`.

| Entity | Class | Languages | Detection method | Notes |
|---|---|---|---|---|
| `UK_NHS` | `NhsRecognizer` | en | Regex + **NHS mod-11 checksum** + context | 10-digit. Class is `NhsRecognizer` (note: not prefixed `Uk`) |
| `UK_NINO` | `UkNinoRecognizer` | en | Regex + context (`national insurance`, `ni number`, `nino`) | National Insurance Number. No checksum. Disabled by default |
| `UK_DRIVING_LICENCE` | `UkDrivingLicenceRecognizer` | en | Regex + **DVLA checksum** + context | Disabled by default |
| `UK_PASSPORT` | `UkPassportRecognizer` | en | Regex + context | No checksum. Disabled by default |
| `UK_POSTCODE` | `UkPostcodeRecognizer` | en | Regex + context | Disabled by default. Note: appears twice in `default_recognizers.yaml` (likely a bug) |
| `UK_VEHICLE_REGISTRATION` | `UkVehicleRegistrationRecognizer` | en | 3 regex patterns + **format/age-tag validation** + context | Disabled by default |

### Country-specific — United States

Country code `us`. Most enabled by default.

| Entity | Class | Languages | Detection method | Notes |
|---|---|---|---|---|
| `US_SSN` | `UsSsnRecognizer` | en | 5 regex variants (very weak → medium) + context | Has `invalidate_result` rejecting all-same digits, `000`/`666`/`9xx` area numbers, group `00`, serial `0000`, and well-known fake SSNs (`123456789`, `078051120`, …). No Luhn — SSNs aren't Luhn |
| `US_ITIN` | `UsItinRecognizer` | en | 3 regex variants + context | Individual Taxpayer ID. No checksum |
| `US_PASSPORT` | `UsPassportRecognizer` | en | 2 regex (legacy 9-digit + next-gen letter+8-digit) + context | No checksum |
| `US_DRIVER_LICENSE` | `UsLicenseRecognizer` | en | 2 regex patterns (alphanumeric + numeric) + context | Class is `UsLicenseRecognizer` — note name mismatch |
| `US_BANK_NUMBER` | `UsBankRecognizer` | en | Regex (8–17 digits) + context | No checksum |
| `US_NPI` | `UsNpiRecognizer` | en | 2 regex patterns + **Luhn checksum on NPI** + context. Has both `validate_result` and `invalidate_result` | National Provider Identifier, 10 digits. Disabled by default |
| `US_MBI` | `UsMbiRecognizer` | en | 2 regex patterns + context | Medicare Beneficiary Identifier, 11 alphanumeric. Disabled by default |
| `ABA_ROUTING_NUMBER` | `AbaRoutingRecognizer` | en | 2 regex patterns + **ABA mod-10 weighted checksum (3,7,1,3,7,1,3,7,1)** + context | Not registered in default YAML — code-only. Not on supported_entities doc page |
| `MEDICAL_LICENSE` | `MedicalLicenseRecognizer` | en | Regex + **DEA number checksum** + context (`medical`, `certificate`, `DEA`) | DEA license numbers. Lives under `country_specific/us/` but documented as global. `country_code: us` in YAML |

## Detection mechanisms summary

### Regex-only recognizers (no checksum, no library)

About **24 recognizers** are pure regex + context. Examples (entity →
class):

- `DATE_TIME` → `DateRecognizer`
- `EMAIL_ADDRESS` → `EmailRecognizer` (plus TLD list check)
- `IP_ADDRESS` → `IpRecognizer` (with `invalidate_result` for false-positive trimming)
- `MAC_ADDRESS` → `MacAddressRecognizer`
- `URL` → `UrlRecognizer`
- `DE_TAX_NUMBER`, `DE_KFZ`, `DE_HANDELSREGISTER`, `DE_PLZ`, `DE_FUEHRERSCHEIN`
- `IN_PAN`, `IN_PASSPORT`, `IN_VOTER`
- `IT_DRIVER_LICENSE`, `IT_IDENTITY_CARD`, `IT_PASSPORT`
- `KR_PASSPORT`
- `NG_VEHICLE_REGISTRATION`
- `SG_NRIC_FIN` (despite the name, no checksum in code)
- `ES_PASSPORT`
- `UK_NINO`, `UK_PASSPORT`, `UK_POSTCODE`
- `US_ITIN`, `US_PASSPORT`, `US_DRIVER_LICENSE`, `US_BANK_NUMBER`, `US_MBI`

### Regex + checksum / algorithmic validation

About **27 recognizers** apply a real validation algorithm on regex
matches:

| Algorithm | Recognizers |
|---|---|
| **Luhn (mod-10)** | `CreditCardRecognizer`, `CaSinRecognizer`, `IT_VAT_CODE`, `SE_PERSONNUMMER`, `SE_ORGANISATIONSNUMMER`, `US_NPI`, `ABA_ROUTING_NUMBER` (mod-10 weighted) |
| **ISO 7064 / mod-97** | `IbanRecognizer` |
| **ISO 7064 mod-11,10** | `DE_TAX_ID` |
| **mod-11 weighted** | `DE_VAT_ID`, `DE_LANR`, `DE_BSNR`, `AU_TFN`, `KR_RRN`/`KR_FRN`, `TR_NATIONAL_ID`, `TH_TNIN`, `UK_NHS`, `PL_PESEL`, `FI_PERSONAL_IDENTITY_CODE` (mod-31), `IT_FISCAL_CODE` (custom alphanumeric weighted) |
| **mod-23 letter table** | `ES_NIF`, `ES_NIE` |
| **Verhoeff** | `IN_AADHAAR` |
| **GSTIN modulus** | `IN_GSTIN` |
| **ICAO 9303 MRZ check digit** | `DE_PASSPORT`, `DE_ID_CARD` |
| **DRV / GKV-specific** | `DE_SOCIAL_SECURITY`, `DE_HEALTH_INSURANCE` |
| **DEA number checksum** | `MEDICAL_LICENSE` |
| **Double-SHA256 + base58** / **Bech32(m)** | `CRYPTO` (Bitcoin) |
| **DVLA driver licence checksum** | `UK_DRIVING_LICENCE` |
| **Mod-89 / Mod-10 (custom)** | `AU_ABN`, `AU_ACN`, `AU_MEDICARE` |
| **SG ACRA UEN checksum** | `SG_UEN` |
| **KR BRN checksum** | `KR_BRN` |
| **Format/range validation** (no cryptographic checksum) | `TR_LICENSE_PLATE` (province 01–81), `IN_VEHICLE_REGISTRATION` (state codes), `UK_VEHICLE_REGISTRATION` (age tag), `US_SSN` (area/group/serial rules + denylist via `invalidate_result`) |

### Regex + context words (every PatternRecognizer)

All `PatternRecognizer` subclasses use a `CONTEXT` list of trigger words
processed by the `LemmaContextAwareEnhancer`. Example contexts:

- Generic — `email`, `phone`, `card`, `wallet`, `btc`, `iban`, `bank`
- IT — `codice fiscale`, `cf`, `piva`, `partita iva`, `patente`
- ES — `documento nacional de identidad`, `DNI`, `NIE`, `pasaporte`
- FI — `hetu`, `henkilötunnus`, `personbeteckningen`
- KR — Korean and English context words
- DE — `Steuernummer`, `Personalausweis`, `RVNR`, `KVNR`, etc.
- IN — `RTO`, `vehicle`, `plate`, `Aadhar`, `PAN`

`PhoneRecognizer` uses *regional* context (per region) on top of the base
context list.

### spaCy NER-based

- `SpacyRecognizer` — emits `PERSON`, `LOCATION`, `NRP`, `DATE_TIME`,
  `ORGANIZATION` (the latter is in the ignore list by default).
  Mapping from spaCy labels in `conf/default.yaml`:

  ```yaml
  PER: PERSON
  PERSON: PERSON
  NORP: NRP
  FAC: LOCATION
  LOC: LOCATION
  GPE: LOCATION
  ORG: ORGANIZATION
  DATE: DATE_TIME
  TIME: DATE_TIME
  ```

### Stanza-based

- `StanzaRecognizer` (subclass of `SpacyRecognizer`) — uses
  `spacy-stanza` to drive Stanford Stanza models. Same entity set as
  spaCy.

### Transformers / HuggingFace

- `TransformersRecognizer` (subclass of `SpacyRecognizer`) — uses
  `spacy-huggingface-pipelines`. Adds `AGE`, `ID`, `EMAIL`,
  `PHONE_NUMBER` to the spaCy entity set.
- `HuggingFaceNerRecognizer` — direct `transformers.pipeline`, no spaCy
  layer. Has built-in label maps including Korean (`PS`/`LC`/`OG`/`DT`/`TI`).
- `MedicalNERRecognizer` — HuggingFace pipeline pointing at
  `blaze999/Medical-NER`, emitting 8 `MEDICAL_*` entities.
- `GLiNERRecognizer` — GLiNER zero-shot NER. Entity set is fully
  configurable.

### LLM / remote

- `AzureAILanguageRecognizer` — calls Azure AI Language PII service
  (`RemoteRecognizer`).
- `AzureHealthDeidRecognizer` — calls Azure Health Data Services
  de-identification service.
- `LangExtractRecognizer` + `BasicLangExtractRecognizer` +
  `AzureOpenAILangExtractRecognizer` — LLM-driven extraction via the
  `langextract` package, configured by YAML prompts under
  `conf/langextract_prompts/`.

## Languages supported

Per `default_recognizers.yaml` and per-class `supported_language`
defaults:

| Language | Recognizers |
|---|---|
| `en` (English) | All 9 generic + all `_us` + all `_uk` + all `_in` + all `_au` + all `_ng` + `CA_SIN` + `SG_NRIC_FIN`/`SG_UEN` + `MEDICAL_LICENSE` + `SpacyRecognizer` defaults + `HuggingFaceNerRecognizer` + `MedicalNERRecognizer` + `GLiNERRecognizer` + LangExtract family |
| `es` (Spanish) | `EsNifRecognizer`, `EsNieRecognizer`, `EsPassportRecognizer`, plus a Spanish variant of `CreditCardRecognizer` |
| `it` (Italian) | All 5 IT recognizers, plus an Italian variant of `CreditCardRecognizer` |
| `pl` (Polish) | `PlPeselRecognizer`, plus a Polish variant of `CreditCardRecognizer` |
| `de` (German) | All 13 DE recognizers |
| `fi` (Finnish) | `FiPersonalIdentityCodeRecognizer` |
| `sv` (Swedish) | `SePersonnummerRecognizer`, `SeOrganisationsnummerRecognizer` |
| `ko` (Korean) | `KrRrnRecognizer`, `KrFrnRecognizer`, `KrBrnRecognizer`, `KrDriverLicenseRecognizer` |
| `kr` (Korean alias) | `KrPassportRecognizer` (note: uses `"kr"`, not `"ko"`) |
| `th` (Thai) | `ThTninRecognizer` |
| `tr` (Turkish) | `TrNationalIdRecognizer`, `TrLicensePlateRecognizer` |
| `fr` (French) | `CaSinRecognizer` is registered for both `en` and `fr` |

NER-driven recognizers (`SpacyRecognizer`, `StanzaRecognizer`,
`TransformersRecognizer`, `HuggingFaceNerRecognizer`) support whatever
language the underlying model handles; Presidio ships multilingual
configs (`spacy_multilingual.yaml`, `stanza_multilingual.yaml`).

## Anything Presidio recognises that surprised me / is unusual

- **German pack is huge.** 13 recognizers for Germany alone — including
  oddities like `DE_LANR` (doctor ID), `DE_BSNR` (medical practice ID),
  `DE_HANDELSREGISTER` (commercial register), and `DE_PLZ` (postal code
  with explicit "high false-positive risk" base confidence of 0.05).
  Octarine likely has nothing in this space.
- **`UK_NHS` checksum + Korean `KR_RRN` checksum.** Both have
  algorithmic validation, not just regex — gives them very low FP rates.
  Worth checking whether octarine validates these the same way.
- **`IN_AADHAAR` uses Verhoeff.** Aadhaar's checksum is the Verhoeff
  algorithm (not Luhn). Distinct because most national IDs use mod-11.
- **`CRYPTO` is Bitcoin-only.** No support for Ethereum (0x-prefixed),
  Solana, Monero, etc. Bitcoin validation is real (base58 + SHA256, or
  Bech32 for `bc1`).
- **`IBAN_CODE` covers 70 countries with mod-97 check digits** including
  small jurisdictions like Faroe Islands (`FO`), Vatican (`VA`),
  Greenland (`GL`), and Kosovo (`XK`). This is unusually complete.
- **`PhoneRecognizer` outsources entirely to `python-phonenumbers`** —
  no internal regex. Default region list is just 8 (US/UK/DE/FR/IL/IN/CA/BR),
  but can be set to all ~250 regions.
- **No SWIFT/BIC recognizer.** Surprising given the IBAN coverage.
- **No driver's license recognizer for many countries** (FR, AU don't
  have one, BR not at all). UK and US do; Italy was added recently.
- **`UK_POSTCODE` is duplicated in `default_recognizers.yaml`** —
  appears twice with identical config. Likely a config bug, not a
  semantic difference.
- **`AbaRoutingRecognizer` is fully implemented in code but missing
  from both the YAML registry and the published `supported_entities`
  docs.** Same situation for `SgUenRecognizer` and
  `FiPersonalIdentityCodeRecognizer` (the FI one is in YAML now). To use
  these you must instantiate the class directly.
- **`MEDICAL_LICENSE` lives under `country_specific/us/`** (DEA-number
  validation is US-specific) but is exposed as a *global* entity in the
  docs.
- **Some entity types overlap weirdly** — `DATE_TIME` is produced both
  by the regex `DateRecognizer` *and* by every NER-based recognizer.
- **`US_SSN` does denylist-based validation** rather than checksum
  (since SSNs have no Luhn): rejects `000`/`666`/`9xx` area numbers,
  group `00`, serial `0000`, and famous "advertising" SSNs like
  `078-05-1120` and `123-45-6789`.
- **`TransformersRecognizer` ENTITIES list adds `AGE` and `ID`** —
  generic categories that the regex pipeline doesn't expose.
- **GLiNER zero-shot recognizer is bundled by default** in `slim.yaml`,
  replacing `SpacyRecognizer` for NER. Means Presidio is moving toward
  zero-shot-by-default in slim deployments.
- **`MedicalNERRecognizer` emits 8 medical sub-entities** —
  `MEDICAL_DISEASE_DISORDER`, `MEDICAL_MEDICATION`,
  `MEDICAL_THERAPEUTIC_PROCEDURE`, `MEDICAL_CLINICAL_EVENT`,
  `MEDICAL_BIOLOGICAL_ATTRIBUTE`, `MEDICAL_BIOLOGICAL_STRUCTURE`,
  `MEDICAL_FAMILY_HISTORY`, `MEDICAL_HISTORY`. Big surface area for
  HIPAA workflows.
- **`KrPassportRecognizer` uses `"kr"` as language code**, every other
  Korean recognizer uses `"ko"`. Inconsistency in their own code.
- **Most non-en country packs are `enabled: false` by default** —
  you have to opt them in via YAML. That explains why most users only
  see the en + global set.
