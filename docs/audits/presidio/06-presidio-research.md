# Microsoft presidio-research

The companion repository to `microsoft/presidio`. While `microsoft/presidio` ships
the production analyzer/anonymizer/image/structured stack (already catalogued in
files 01-05), `microsoft/presidio-research` is a *data-science* / *evaluation*
package. It contains: a Faker-based fake-PII sentence generator with
templates, an evaluation framework (token-level and span-level F-beta), wrappers
that let you score Presidio (or any NER model) on PII detection, dataset
formatters for CoNLL-2003 and i2b2-2014, and a single bundled synthetic JSON
dataset.

- Repo: <https://github.com/microsoft/presidio-research>
- PyPI: `presidio-evaluator` (current 0.2.5)
- Python: `^3.10`
- License: MIT
- Stars: ~284 (May 2026)

## Source files reviewed

Top-level:

- README — <https://github.com/microsoft/presidio-research/blob/master/README.md>
- pyproject.toml — <https://github.com/microsoft/presidio-research/blob/master/pyproject.toml>
- CHANGELOG.md — <https://github.com/microsoft/presidio-research/blob/master/CHANGELOG.md>
- LICENSE — MIT

`presidio_evaluator/`:

- `__init__.py`, `data_objects.py`, `span_to_tag.py`, `validation.py`

`presidio_evaluator/data_generator/`:

- `README.md`, `__init__.py`, `presidio_sentence_faker.py`,
  `presidio_data_generator.py` (deprecated), `presidio_pseudonymize.py`
- `faker_extensions/__init__.py`, `providers.py`, `sentences.py`,
  `span_generator.py`, `datasets.py`, `data_objects.py`
- `raw_data/`: `templates.txt`, `FakeNameGenerator.com_3000.csv`,
  `companies_and_organizations.csv`, `nationalities.csv`, `religions.csv`,
  `us_driver_license_format.yaml`, `us_driver_licenses.csv`

`presidio_evaluator/evaluation/`:

- `__init__.py`, `base_evaluator.py`, `token_evaluator.py`, `span_evaluator.py`
- `evaluation_result.py`, `model_error.py`, `plotter.py`, `scorers.py`,
  `skipwords.py`

`presidio_evaluator/models/`:

- `base_model.py`, `presidio_analyzer_wrapper.py`,
  `presidio_recognizer_wrapper.py`, `spacy_model.py`, `stanza_model.py`,
  `flair_model.py`, `text_analytics_wrapper.py`

`presidio_evaluator/dataset_formatters/`:

- `dataset_formatter.py` (ABC), `conll_formatter.py`, `i2b2_formatter.py`

`presidio_evaluator/experiment_tracking/`:

- `experiment_tracker.py`, `local_tracker.py`

Notebooks (5 root + 5 per-model):

- `notebooks/1_Generate_data.ipynb`, `2_PII_EDA.ipynb`,
  `3_Split_by_pattern_number.ipynb`, `4_Evaluate_Presidio_Analyzer.ipynb`,
  `5_Evaluate_Custom_Presidio_Analyzer.ipynb`
- `notebooks/models/Create datasets for Spacy training.ipynb`,
  `Evaluate azure text analytics.ipynb`, `Evaluate flair models.ipynb`,
  `Evaluate spacy models.ipynb`, `Evaluate stanza models.ipynb`,
  `notebook_template.md`

Docs:

- `docs/evaluation.md`, `span_evaluation.md`, `token_evaluation.md`,
  `span_matching_strategies.md`

Data:

- `data/synth_dataset_v2.json` (the only shipped corpus, ~1 MB, 1500 samples)

## Fake data generation

### Faker integration

Built directly on top of `joke2k/faker` (the standard Python Faker package).
The package extends Faker in three layers:

1. **`SpanGenerator`** (`faker_extensions/span_generator.py`) subclasses
   `faker.Generator` and overrides `parse()` so that placeholder substitution
   *also* returns character-level spans for every replaced entity. Output is
   an `InputSample` carrying `(full_text, spans, masked_template)`.
2. **`RecordGenerator`** (`faker_extensions/sentences.py`) subclasses
   `SpanGenerator` and adds a `DynamicProvider` over a DataFrame of records.
   When a template references multiple fields of the same fake person
   (e.g. `{{name}}` + `{{email}}`), all the values are drawn from the *same*
   record so the email actually corresponds to the name. Falls back to
   independent Faker draws for fields not in the record.
3. **`SentenceFaker`** subclasses `faker.Faker` and uses one of the two
   generators above, adds a `lower_case_ratio` knob (default 5% of samples
   are lowercased) and an `add_provider_alias()` method.

### Custom Faker providers (in `faker_extensions/providers.py`)

All inherit from `faker.providers.BaseProvider`:

| Class | Locale data | Output entity name(s) |
|---|---|---|
| `NationalityProvider` | `raw_data/nationalities.csv` (~140 countries) | `country`, `nationality`, `nation_man`, `nation_woman`, `nation_plural` |
| `OrganizationProvider` | `raw_data/companies_and_organizations.csv` (multi-exchange listings: AEX, BSE, CNQ, GER, LSE, NASDAQ, NSE, NYSE, PAR, TYO) | `organization`, `company` |
| `UsDriverLicenseProvider` | `us_driver_license_format.yaml` (faker-ruby derived; per-state format strings for all 50 US states) | `us_driver_license` |
| `ReligionProvider` | `raw_data/religions.csv` (12 major religions x 2) | `religion` |
| `IpAddressProvider` | n/a — wraps `faker.ipv4`/`ipv6` 80/20 | `ip_address` |
| `AgeProvider` | weighted formats `%#`, `%`, `1.%`, `2.%`, `100`, `101`, `104`, `0.%` | `age` (numerified) |
| `AddressProviderNew` | extends `faker.providers.address.en_US.Provider` with weighted multi-line, military APO/FPO/DPO, "corner of X and Y" templates | `address` |
| `PhoneNumberProviderNew` | extends `faker.providers.phone_number.en_US.Provider` with US/UK/India/Switzerland/Sweden formats + extensions | `phone_number` |
| `HospitalProvider` | live SPARQL query against WikiData (`Q16917` hospitals in US, `Q30`); falls back to 4-item default list on network failure | `hospital_name` |

The wider set of standard Faker providers (e.g. credit-card number, IBAN, SSN,
email, URL) is reused unchanged.

### Templates

`raw_data/templates.txt` ships ~280 templates in Jinja2-ish `{{token}}` syntax
(also accepts `<token>` as alias). Examples:

```
I want to increase limit on my card # {{credit_card_number}} ...
My credit card {{credit_card_number}} has been lost ...
I'm originally from {{country}}
Please update the billing address with {{address}} for this card: {{credit_card_number}}
My name appears incorrectly ... could you please correct it to {{prefix_male}} {{name_male}}?
Inject SELECT * FROM Users WHERE client_ip = ?%//!%20\|{{ip_address}}|%20/
```

Each `{{token}}` resolves to either a Faker built-in or one of the custom
providers above, then is mapped to a Presidio entity type via the static
`PresidioSentenceFaker.ENTITY_TYPE_MAPPING` dict (the `faker → Presidio`
glossary, e.g. `ssn → US_SSN`, `iban → IBAN_CODE`, `ip_address → IP_ADDRESS`,
`url → DOMAIN_NAME`, `email → EMAIL_ADDRESS`, `prefix_male → TITLE`, etc.).

### Locale

The high-level `PresidioSentenceFaker(locale=...)` accepts any Faker locale
string (`en_US`, `en`, etc.) and forwards it to the underlying `Faker(locale=)`.
Defaults in the README use `en_US`. The actual locale-specific data
(addresses, phone numbers) comes from Faker proper plus the
`AddressProviderNew`/`PhoneNumberProviderNew` mixes above, which hard-code
US/UK/IN/CH/SE phone formats. There is no explicit support for non-Latin
scripts.

### Records dataset

`load_fake_person_df()` (in `faker_extensions/datasets.py`) reads
`FakeNameGenerator.com_3000.csv` (3000 personas from fakenamegenerator.com,
CC-BY-SA-3.0) and renames columns to Faker conventions (e.g. `GivenName →
first_name`, `EmailAddress → email`, `CCNumber → credit_card_number`). Each
record carries: name, address, city, state, country, email, username,
password, phone, mother's maiden, birthday, age, CC number+type+expiry+CVV2,
national ID, occupation, company, domain. **CC numbers are dropped from the
record and re-sampled from Faker's `credit_card_number`** because Faker
generates valid Luhn-passing credit cards while the static fakenamegenerator
data does not. So yes — fake credit cards conform to Luhn.

### Format-conforming generation

- **Credit cards**: valid Luhn (Faker built-in).
- **IBAN**: valid format (Faker built-in).
- **US SSN**: format-only via Faker `ssn()`; not validated against SSA rules.
- **US driving license**: per-state format mask (e.g. `?############`)
  bothify-substituted, matching real per-state digit/letter patterns.
- **Phone**: format-only, includes UK mobile prefix `07700`, Swiss `+41`,
  Swedish `+46`, Indian `+91`, US `###-###-####` and variants.
- **IP**: real valid IPv4/IPv6.
- **Email/URL/Domain**: Faker built-ins.

### Pseudonymization helper

`PresidioPseudonymization` (in `presidio_pseudonymize.py`) is a thin glue
between Presidio Analyzer's `RecognizerResult` list, Presidio Anonymizer
(`AnonymizerEngine`), and `SentenceFaker`. Workflow: analyze real text →
anonymize to `<ENTITY>` template → swap `<>` for `{{}}` → re-fill with fake
values. It auto-registers aliases like `name → PERSON`, `credit_card_number →
CREDIT_CARD`, `ssn → US_SSN`.

## Evaluation framework

### Class hierarchy

```
BaseEvaluator (abc)
 ├── TokenEvaluator   (alias `Evaluator`, deprecated)
 └── SpanEvaluator
```

Both produce `EvaluationResult` objects. `Plotter` consumes those for
visualization.

### Scoring strategy — token vs span

This is the key dimension. There are **two parallel evaluators**:

#### TokenEvaluator (`token_evaluator.py`)

- Classic per-token NER evaluation (`(annotation_tag, predicted_tag)` Counter
  = confusion matrix).
- All BIO/BILUO schemes collapsed to IO by default (`compare_by_io=True`).
- Computes per-entity precision, recall, F-beta and an aggregate "PII"
  precision/recall/F-beta (PII = "any tag that is not O").
- `Evaluator` is an alias kept for backward compatibility; emits
  `DeprecationWarning` and tells users to switch to `SpanEvaluator`.

#### SpanEvaluator (`span_evaluator.py`)

- Span-level fuzzy matching via character-level (default) or token-level
  Intersection-over-Union (IoU).
- `iou_threshold` defaults to 0.9. Default `char_based=True`.
- Merges adjacent same-type spans that are separated only by skip words /
  punctuation (so `[ORG, of, ORG]` becomes one span).
- Matching rules (codified in `docs/span_matching_strategies.md`):
  - High IoU + same type ⇒ TP
  - High IoU + wrong type ⇒ FN for annotated type, FP for predicted type
  - Low IoU ⇒ both FN and FP (regardless of type)
  - No overlap ⇒ FN for annotation, FP for unmatched prediction
- Per-entity *and* PII-level precision/recall/F-beta.

### Metric definitions (in `BaseEvaluator`)

```python
precision = tp / (tp + fp)         # or tp / num_predicted
recall    = tp / (tp + fn)         # or tp / num_annotated
f_beta    = ((1 + β²) * p * r) / ((β² * p) + r)
```

Default `beta=2.0` (recall-weighted — appropriate for PII where missing one
hurts more than crying wolf). `EvaluationResult` exposes both `to_log()` (dict
of all scalars) and `to_confusion_matrix()` / `to_confusion_df()` for matrix
form.

### Per-entity reporting

`EvaluationResult.per_type: Dict[str, PIIEvaluationMetrics]` where each
`PIIEvaluationMetrics` dataclass holds:

```
precision, recall, f_beta,
num_predicted, num_annotated,
true_positives, false_positives, false_negatives
```

`EvaluationResult.__str__()` renders a per-entity table; `Plotter.plot_scores`
draws per-entity bar charts (precision, recall, F-beta) coloured by count,
and `Plotter.plot_confusion_matrix` does the matrix heatmap.

### Skip words

`evaluation/skipwords.py::get_skip_words()` returns ~100 words/punctuation
tokens that are ignored when matching: all punctuation, all whitespace,
plus a hand-curated list — `'s`, `street`, `st.`, `st`, `de`, `rue`, `via`,
`and`, `the`, `or`, `of`, `address`, `country`, `state`, `city`, `zip`,
`apt`, `unit`, `mr.`, `mrs.`, `miss`, `year(s)`, `y/o`, `month(s)`, `old`,
`morning`, `afternoon`, `night`, `inc`, `ltd`, etc., plus spaCy's
`STOP_WORDS`. Users can override via `SpanEvaluator(skip_words=...)`.

### Confusion matrix

Stored as `Counter[(annotation_tag, predicted_tag)] → count`. Both
`to_confusion_matrix() -> (entities, matrix)` and `to_confusion_df() ->
pandas.DataFrame` (with `O` row/col forced last, precision row appended,
recall column appended) are available.

### Error analysis (`model_error.py`)

```python
class ErrorType(Enum):
    FP = "FP"
    FN = "FN"
    WrongEntity = "WrongEntity"

class ModelError:
    error_type, annotation, prediction, token, full_text,
    sample_id, metadata, explanation
```

Static helpers: `most_common_fp_tokens(n)`, `most_common_fn_tokens(n)`,
`get_fps_dataframe()`, `get_fns_dataframe()`, `get_wrong_entity_dataframe()`.
Each prints the top-N false-positive / false-negative tokens *with one
example sentence each*, which is the typical debugging workflow.

### Generic entities

`GENERIC_ENTITIES = ("PII", "ID", "PHI", "ID_NUM", "NUMBER", "NUM",
"GENERIC_PII")`. If a model predicts a generic tag where a specific tag was
annotated (or vice-versa), `BaseEvaluator.__revert_known_errors` treats it as
a *correct* prediction. This lets you evaluate LLM-based detectors that
return "PII" without forcing them to disambiguate type.

## Model evaluators / comparators

### BaseModel (abstract, `models/base_model.py`)

```python
class BaseModel(ABC):
    def __init__(self,
        labeling_scheme: str = "IO",      # or BIO / BILUO
        entities_to_keep: List[str] = None,
        entity_mapping: Optional[Dict[str, str]] = None,
        verbose: bool = False)

    @abstractmethod
    def predict(self, sample: InputSample, **kwargs) -> List[str]: ...

    @abstractmethod
    def batch_predict(self, dataset: List[InputSample], **kwargs) -> List[List[str]]: ...
```

`entity_mapping` translates between dataset entity names and model entity
names (e.g. `PER ↔ PERSON`, `LOC ↔ LOCATION`).

### Supported models (all wrappers in `models/`)

| Wrapper | Wraps | Notes |
|---|---|---|
| `PresidioAnalyzerWrapper` | `presidio_analyzer.AnalyzerEngine` (+ `BatchAnalyzerEngine` for batch). Accepts ad-hoc recognizers, context lists, allow lists. | Ships a 60-entry `presidio_entities_map` mapping dataset variants (`PER`, `FIRST_NAME`, `STREET_ADDRESS`, `ZIP`, `DOB`, `HCW`, `PATIENT`, `HOSP`, `NORP`, `VENDOR`, etc.) onto canonical Presidio entity types. |
| `PresidioRecognizerWrapper` | A single `EntityRecognizer` (subclass) + `NlpEngine` (e.g. `SpacyNlpEngine`). | Lets you score one custom recognizer in isolation. |
| `SpacyModel` | A `spacy.Language` pipeline. | Uses `PRESIDIO_SPACY_ENTITIES` translator (`PERSON→PERSON, LOCATION→LOC, GPE→GPE, ORGANIZATION→ORG, DATE_TIME→DATE, NRP→NORP`). |
| `StanzaModel(SpacyModel)` | Stanza via `spacy_stanza.load_pipeline`. | Inherits all spaCy plumbing; uses spaCy tokens for span alignment. |
| `FlairModel` | `flair.models.SequenceTagger`. | Lazy-imports `flair`; uses `SpacyTokenizer` to keep tokenization consistent across wrappers; converts Flair's `PER` to `PERSON` automatically. |
| `TextAnalyticsWrapper` | Azure AI Language `TextAnalyticsClient.recognize_pii_entities`. | **Marked deprecated**: README and source steer users to the in-Presidio `TextAnalyticsRecognizer` instead. |

There is **no transformers/HuggingFace wrapper class** in this repo. The
`pyproject.toml` ner-extras group does include
`spacy_huggingface_pipelines = "^0.0.4"`, which means HF models can be plugged
in through a spaCy pipeline and then evaluated via `SpacyModel`.

### Adding a new model

Implement `predict(sample) -> List[str]` and `batch_predict(dataset) ->
List[List[str]]` on a subclass of `BaseModel`, set `labeling_scheme` and
optionally `entity_mapping`. The evaluator handles everything else.

## Datasets shipped

Only **one** bundled corpus and a small set of test fixtures:

| Path | Content | Size |
|---|---|---|
| `data/synth_dataset_v2.json` | 1500 fully-synthetic sentences with annotated spans, produced by `PresidioSentenceFaker` from the bundled templates. Entity coverage: PERSON (857), STREET_ADDRESS (598), GPE (411), ORGANIZATION (250), CREDIT_CARD (136), DATE_TIME (119), TITLE (92), PHONE_NUMBER (92), AGE (74), NRP (55), EMAIL_ADDRESS (49), ZIP_CODE (37), DOMAIN_NAME (37), IBAN_CODE (21), US_SSN (16), IP_ADDRESS (14), US_DRIVER_LICENSE (5). License: MIT (the repo). | ~1 MB |
| `tests/data/generated_large.json` | larger synthetic sample for tests | 1.4 MB |
| `tests/data/generated_small.json` | small synthetic sample | 64 KB |
| `tests/data/mock_input_samples.json` | test fixtures | 732 B |
| `tests/data/FakeNameGenerator.com_100.csv` | 100-row personas sample | 56 KB |
| `presidio_evaluator/data_generator/raw_data/FakeNameGenerator.com_3000.csv` | 3000 personas (CC-BY-SA-3.0, fakenamegenerator.com — copyright Corban Works, LLC) | 817 KB |
| `…/companies_and_organizations.csv` | organization names scraped from multiple stock exchanges + SEC | 530 KB |
| `…/nationalities.csv` | ~140 countries with nationality / man / woman / plural variants | 9.6 KB |
| `…/religions.csv` | 12 religions (adj + noun pairs) | 205 B |
| `…/us_driver_license_format.yaml` | per-state DL formats (50 states, ported from faker-ruby, MIT) | 4 KB |
| `…/us_driver_licenses.csv` | small DL examples | 731 B |
| `…/templates.txt` | ~280 sentence templates | 18 KB |

**External datasets are referenced but not bundled**:

- CoNLL-2003 — downloaded by `CONLL2003Formatter.download()` from
  `glample/tagger` GitHub mirror.
- i2b2-2014 PHI — user must obtain manually; the
  `I2B22014Formatter` parses the XML format (`<deIdi2b2><TEXT>…<TAGS>…`).

## Notebooks / examples

Root `notebooks/`:

1. `1_Generate_data.ipynb` — Walkthrough of `PresidioSentenceFaker`, custom
   providers, custom templates, JSON export.
2. `2_PII_EDA.ipynb` — Exploratory data analysis of `synth_dataset_v2.json`
   (entity counts, distribution plots).
3. `3_Split_by_pattern_number.ipynb` — Train/test/validation split that
   guarantees no template leakage between folds.
4. `4_Evaluate_Presidio_Analyzer.ipynb` — End-to-end evaluation of *vanilla*
   Presidio against the synth dataset; README cautions accuracy is "not very
   good".
5. `5_Evaluate_Custom_Presidio_Analyzer.ipynb` — Demonstrates how to
   configure Presidio with custom recognizers / context / score thresholds
   to boost F-score by ~30%. This is the headline notebook for tuning.

Sub-directory `notebooks/models/`:

- `Create datasets for Spacy training.ipynb` — convert `synth_dataset_v2`
  → `.spacy` `DocBin` for `spacy train`.
- `Evaluate azure text analytics.ipynb` — Score Azure Language PII detector.
- `Evaluate flair models.ipynb` — Score Flair NER models.
- `Evaluate spacy models.ipynb` — Score spaCy pipelines.
- `Evaluate stanza models.ipynb` — Score Stanza pipelines.
- `notebook_template.md` — template for adding a new model evaluator notebook.

## Programmatic API surface

Top-level (`from presidio_evaluator import …`):

```python
InputSample, Span                            # data_objects.py
SPACY_PRESIDIO_ENTITIES                      # mapping dict
PRESIDIO_SPACY_ENTITIES                      # reverse mapping
tokenize, span_to_tag, io_to_scheme          # span_to_tag.py utilities
split_dataset, split_by_template,            # validation.py — pattern-aware split
    get_samples_by_pattern, group_by_template,
    save_to_json
```

Data generation (`from presidio_evaluator.data_generator import …`):

```python
PresidioSentenceFaker            # high-level entrypoint
PresidioPseudonymization         # detect→anonymize→re-fake helper
raw_data_dir                     # Path to bundled CSVs
presidio_templates_file_path     # default templates.txt
presidio_additional_entity_providers   # list of provider classes
```

Faker extensions (`from presidio_evaluator.data_generator.faker_extensions import …`):

```python
SpanGenerator, RecordGenerator, SentenceFaker
NationalityProvider, OrganizationProvider, UsDriverLicenseProvider,
IpAddressProvider, AddressProviderNew, PhoneNumberProviderNew,
AgeProvider, ReligionProvider, HospitalProvider
load_fake_person_df              # in faker_extensions.datasets
```

Evaluation (`from presidio_evaluator.evaluation import …`):

```python
BaseEvaluator, TokenEvaluator, SpanEvaluator
Evaluator                        # deprecated alias for TokenEvaluator
EvaluationResult, PIIEvaluationMetrics
ModelError, ErrorType
Plotter
get_skip_words
```

Models (`from presidio_evaluator.models import …`):

```python
BaseModel
PresidioAnalyzerWrapper, PresidioRecognizerWrapper
SpacyModel, StanzaModel, FlairModel
TextAnalyticsWrapper             # deprecated
```

Dataset formatters (`from presidio_evaluator.dataset_formatters import …`):

```python
DatasetFormatter (ABC)
CONLL2003Formatter
I2B22014Formatter
```

Experiment tracking:

```python
from presidio_evaluator.experiment_tracking import ExperimentTracker
from presidio_evaluator.experiment_tracking.local_tracker import LocalExperimentTracker
```

E2E scoring helpers (in `evaluation/scorers.py`):

```python
score_model(model, entities_to_keep, input_samples, beta=2.5) -> EvaluationResult
score_presidio_recognizer(recognizer, entities_to_keep, ...) -> EvaluationResult
```

## CLI / runnable scripts

There is **no installed CLI entry point**. Several modules can be invoked as
`__main__` scripts:

- `python -m presidio_evaluator.data_generator.presidio_sentence_faker`
  — generates 10000 samples → `data/presidio_data_generator_data.json`.
- `python -m presidio_evaluator.dataset_formatters.conll_formatter`
  — converts CoNLL-2003 train fold to `InputSample` list (after calling
  `CONLL2003Formatter.download()`).
- `python -m presidio_evaluator.dataset_formatters.i2b2_formatter` — converts
  i2b2-2014 XML directory to JSON.
- `python -m presidio_evaluator.experiment_tracking.local_tracker` — toy
  example writing dummy experiment files.

Otherwise interaction is via notebooks and the Python API.

## Licensing

- Repo: MIT (Microsoft Corporation, standard MIT text).
- `FakeNameGenerator.com_3000.csv`: CC-BY-SA-3.0 US; Fake Name Generator
  is a trademark of Corban Works, LLC. Attribution required.
- `us_driver_license_format.yaml`: ported from faker-ruby (MIT).
- `companies_and_organizations.csv`: assembled from public stock-exchange
  listings and `sec.gov` (no explicit per-file license).
- `nationalities.csv`, `religions.csv`, `templates.txt`,
  `synth_dataset_v2.json`: covered by repo MIT.
- `NOTICE` file is ~40 KB of third-party attributions.

## Anything notable / unusual

- **Two evaluators with sharply different philosophy ship in the same
  package.** Choose `SpanEvaluator` for entity-boundary correctness with
  fuzzy character IoU; choose `TokenEvaluator` for classic CoNLL-style
  per-token F1. The default `beta=2.0` reflects the PII bias toward recall.
- **Template-level train/test split** (`split_by_template`) — splits ensure
  the same template never appears in two folds, preventing the model from
  memorising templates rather than learning entities. Worth borrowing for
  any future octarine evaluation harness.
- **Generic-entity tolerance**: predicting `"PII"` where ground truth says
  `"PERSON"` is *not* counted as an error. This is a deliberate accommodation
  for LLM-as-detector setups that don't distinguish PII subtypes.
- **HospitalProvider does a live SPARQL query against WikiData** at import
  time, falling back to a 4-item default list on network failure. This is
  an unusual side-effect for a data generator and a potential test-flakiness
  source.
- **`RecordGenerator` semantic coherence**: by anchoring `{{name}}` and
  `{{email}}` to the same fake person, generated samples are semantically
  coherent in ways pure Faker is not — a person named "Mike" gets an email
  starting with "mike". For our PII test corpora this is the model to copy.
- **`PresidioSentenceFaker.ENTITY_TYPE_MAPPING`** is the canonical
  `faker → Presidio` glossary and worth grepping if we want to align
  octarine's identifier names with Presidio's wire format.
- **CRF and FlairTrainer support was deleted in 0.2.0** (CHANGELOG). The
  repo is now strictly an *evaluation* package, not a *training* package —
  users are pointed at upstream spaCy / Flair training tooling.
- **`PresidioDataGenerator`** (the older, span-only API) and `FakerSpan`,
  `FakerSpansResult` data classes are kept for backward compatibility but
  raise `DeprecationWarning`. All new code should use `PresidioSentenceFaker`
  and `Span`/`InputSample`.
- **No identifier formats unique to presidio-research**: the only
  format-conforming generators come from upstream Faker (CC Luhn, IBAN
  check digits) or are pattern-only (SSN, DL). There is no Israeli ID,
  Indian Aadhaar, UK NHS, or similar custom-checksum generator here —
  this repo lives downstream of presidio's recognizer set.
- **No bundled gold-annotated real-world dataset** — the synth JSON is the
  only corpus; CoNLL-2003 and i2b2 are downloaded/parsed on demand. So if
  octarine wants real-world benchmark numbers, we'd need to procure those
  separately.
