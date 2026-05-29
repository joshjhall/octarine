# Presidio Anonymizer — Operators

A complete catalog of every operator implemented in the
`presidio-anonymizer` Python package (Microsoft Presidio `main` branch).
Used as input to the octarine PII gap analysis for transformation,
redaction, and reversible-anonymization capabilities.

## Source files reviewed

Operator implementations (`presidio-anonymizer/presidio_anonymizer/operators/`):

- [`__init__.py`](https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/operators/__init__.py)
- [`operator.py`](https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/operators/operator.py) — abstract base + `OperatorType` enum
- [`operators_factory.py`](https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/operators/operators_factory.py) — registry, add/remove APIs
- [`replace.py`](https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/operators/replace.py)
- [`redact.py`](https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/operators/redact.py)
- [`mask.py`](https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/operators/mask.py)
- [`hash.py`](https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/operators/hash.py)
- [`encrypt.py`](https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/operators/encrypt.py)
- [`decrypt.py`](https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/operators/decrypt.py)
- [`aes_cipher.py`](https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/operators/aes_cipher.py)
- [`keep.py`](https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/operators/keep.py) — defines `BaseKeep` + `Keep`
- [`deanonymize_keep.py`](https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/operators/deanonymize_keep.py)
- [`custom.py`](https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/operators/custom.py)
- [`ahds_surrogate.py`](https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/operators/ahds_surrogate.py) — Azure Health Data Services surrogate

Engine + conflict handling:

- [`anonymizer_engine.py`](https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/anonymizer_engine.py)
- [`deanonymize_engine.py`](https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/deanonymize_engine.py)
- [`batch_anonymizer_engine.py`](https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/batch_anonymizer_engine.py)
- [`entities/conflict_resolution_strategy.py`](https://github.com/microsoft/presidio/blob/main/presidio-anonymizer/presidio_anonymizer/entities/conflict_resolution_strategy.py)

Docs cross-checked:

- <https://microsoft.github.io/presidio/anonymizer/>
- <https://microsoft.github.io/presidio/tutorial/10_anonymization/>
- <https://microsoft.github.io/presidio/tutorial/11_custom_anonymization/>

## Anonymization operators

`OperatorType.Anonymize`. Predefined set in
`operators_factory.ANONYMIZERS`: `[Custom, Encrypt, Hash, Keep, Mask, Redact,
Replace]` plus `AHDSSurrogate` when `azure-health-deidentification` is
installed.

| Operator name        | Class           | Parameters                                                                                                                                                                                                | Reversible? | Notes                                                                                                                                                                                                                                                                                                              |
|----------------------|-----------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `replace` (default)  | `Replace`       | `new_value: str` — replacement string. If empty/missing, falls back to `<{entity_type}>` (e.g. `<PERSON>`).                                                                                                | No          | Default operator if user supplies no `operators` map (`DEFAULT = "replace"` in `anonymizer_engine.py`). Validation requires `new_value` to be a `str` (but empty string OK, triggers tag fallback).                                                                                                                 |
| `redact`             | `Redact`        | none                                                                                                                                                                                                       | No          | Returns empty string — deletes span entirely. No validation needed.                                                                                                                                                                                                                                                |
| `mask`               | `Mask`          | `masking_char: str` (single char, required), `chars_to_mask: int` (required), `from_end: bool` (required)                                                                                                  | No          | When `chars_to_mask <= 0` masks nothing; clamped to `len(text)`. `from_end=True` masks the trailing N chars (PAN/phone tail-mask pattern). Validation rejects multi-character `masking_char`.                                                                                                                       |
| `hash`               | `Hash`          | `hash_type: "sha256" \| "sha512"` (default `sha256`), `salt: bytes \| str` (optional, must be ≥16 bytes if supplied)                                                                                       | No          | Only **SHA-256** and **SHA-512** are supported. If no salt is provided a per-entity random 32-byte salt (`os.urandom(32)`) is generated, which is **not stored** — meaning hashes are non-deterministic and not joinable across runs unless caller supplies a fixed salt. Output is hex digest. No HMAC/Blake/MD5. |
| `encrypt`            | `Encrypt`       | `key: str \| bytes` (128, 192, or 256 bits — i.e. 16/24/32 bytes)                                                                                                                                          | **Yes**     | AES-CBC, PKCS7 padded, random 16-byte IV prepended to ciphertext, whole blob URL-safe base64-encoded. Key length validated via `AESCipher.is_valid_key_size`. See "Encryption details" below.                                                                                                                       |
| `keep`               | `Keep`          | none                                                                                                                                                                                                       | n/a         | No-op: returns input unchanged. Inherits from `BaseKeep`. Used to mark a span as "tracked but not modified" so it shows up in `EngineResult.items` for audit/telemetry purposes without changing the text.                                                                                                          |
| `custom`             | `Custom`        | `lambda: Callable[[str], str]` — any user function taking the matched text and returning a string                                                                                                          | Caller's responsibility | Validator only checks `callable(...)`; it deliberately does **not** invoke the lambda during validate (to avoid side effects in stateful lambdas, e.g. token-vault lookups for reversible pseudonymization — see [issue #2024](https://github.com/microsoft/presidio/issues/2024)). Return type checked at operate. |
| `surrogate_ahds`     | `AHDSSurrogate` | `endpoint: str` (or `AHDS_ENDPOINT` env var), `entities: List[RecognizerResult]`, `input_locale: str` (default `en-US`), `surrogate_locale: str` (default `en-US`)                                         | No          | Calls Azure Health Data Services de-identification REST API (`api_version="2025-07-15-preview"`) to generate realistic synthetic replacements (e.g. real-looking but fake patient names, dates, addresses). Requires `azure-health-deidentification` and `azure-identity`; only registered when those packages import successfully. Has a ~80-entry Presidio→`PhiCategory` mapping table (PERSON→PATIENT, PHONE_NUMBER→PHONE, US_SSN→SOCIAL_SECURITY, etc.). |

## Deanonymization operators

`OperatorType.Deanonymize`. Predefined set in
`operators_factory.DEANONYMIZERS`: `[Decrypt, DeanonymizeKeep]`. There are
only **two** built-in deanonymizers.

| Operator name       | Class            | Reverses which anonymizer | Notes                                                                                                                                                                                              |
|---------------------|------------------|---------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `decrypt`           | `Decrypt`        | `encrypt`                 | AES-CBC decryption — same key the user passed to `encrypt`. Validation delegates to `Encrypt().validate(params)`, so same 128/192/256-bit key rule. Input must be the URL-safe base64 IV+ciphertext blob. |
| `deanonymize_keep`  | `DeanonymizeKeep`| `keep`                    | No-op mirror of `Keep`. Subclasses `BaseKeep` (shared `operate`/`validate`) and only differs in `operator_type()` returning `Deanonymize`. Lets a deanonymize run keep an entity unchanged while other entities get decrypted. |

Notably **absent**:

- No reverse for `mask`, `redact`, `hash`, `replace`, `custom`, or
  `surrogate_ahds`. Reversibility is only available via `encrypt`/`decrypt`,
  or via a stateful user-supplied `custom` lambda backed by a token vault.
- No format-preserving encryption (FPE) operator.
- No tokenization operator with built-in vault.

## Hashing algorithms supported

- **SHA-256** (`hash_type="sha256"`, default)
- **SHA-512** (`hash_type="sha512"`)

Validated via `validate_parameter_in_range([sha256, sha512], ...)`. Anything
else raises `InvalidParamError`. No SHA-1, SHA-3, BLAKE2/3, HMAC, scrypt,
bcrypt, Argon2, or MD-family hashes.

Salt rules (post a recent hardening change):

- If `salt` is supplied: must be ≥16 bytes (128 bits); shorter or empty
  raises `InvalidParamError`. Strings are UTF-8 encoded.
- If `salt` is omitted: `os.urandom(32)` (256-bit random) is generated **per
  call** and is **not returned to the user**. Consequence: same input
  produces different output every call, so unsalted-by-default hashing is
  not joinable across rows or runs. To get deterministic/joinable hashes,
  the caller must explicitly pass a stable salt.

Output format: `hashlib.<algo>(text + salt).hexdigest()` — hex string,
plain digest, no algorithm prefix or salt embedded.

## Encryption details

Implemented in `aes_cipher.py` (~50 LOC; `Encrypt`/`Decrypt` are thin
wrappers).

- **Algorithm**: AES (Rijndael) in **CBC** mode, via
  `cryptography.hazmat.primitives.ciphers`.
- **Key sizes**: 128, 192, or 256 bits (16/24/32-byte keys). Enforced by
  `AESCipher.is_valid_key_size`.
- **Key format**: `bytes` directly, or `str` UTF-8-encoded by `Encrypt`/
  `Decrypt` before passing to `AESCipher`. No KDF — the raw key bytes are
  used as-is, so passing a string key effectively requires a key whose
  UTF-8 byte length is 16/24/32. No PBKDF2/Argon2/scrypt key derivation
  step is built in.
- **IV**: 16-byte random IV from `os.urandom(16)`, generated per encryption
  call.
- **Padding**: PKCS#7 against the AES block size (128 bits).
- **Wire format**: `urlsafe_base64(IV ‖ ciphertext)` — IV is prepended to
  the ciphertext, the whole blob is URL-safe base64-encoded, no version
  byte, no MAC, no associated data, no algorithm tag.
- **Authentication**: **None.** AES-CBC without HMAC means ciphertext is
  malleable and not authenticated — no GCM/CCM/ChaCha20-Poly1305 option.
  This is a notable gap for any "tamper-evident" anonymization use case.

## Custom operator extension model

Two distinct extension paths:

1. **Per-call `Custom` operator** — pass `OperatorConfig("custom", {"lambda":
   fn})` for an entity type. The lambda gets the matched span text and must
   return a `str`. Mainly used for one-off transformations and for
   **stateful pseudonymization**: a closure can keep a `dict[str, str]`
   mapping original→token so that callers later reverse it with a paired
   custom deanonymizer. Validator avoids invoking the lambda so this
   side-effecting pattern is safe.
2. **Register a new `Operator` subclass globally** — via the engine API:
   - `AnonymizerEngine.add_anonymizer(cls)` /
     `AnonymizerEngine.remove_anonymizer(cls)`
   - `DeanonymizeEngine.add_deanonymizer(cls)` /
     `DeanonymizeEngine.remove_deanonymizer(cls)`
   - These delegate to `OperatorsFactory.add_anonymize_operator` /
     `add_deanonymize_operator`, which is a dict keyed by
     `operator_name()`. Add/remove are instance-scoped (per engine), not
     process-global.

   Implementing a subclass requires four abstract methods on
   `Operator`: `operate(text, params) -> str`, `validate(params) -> None`,
   `operator_name() -> str`, and `operator_type() -> OperatorType`.

The custom-deanonymizer pattern (registering both an anonymizer and a
deanonymizer that share state) is how the docs recommend implementing
reversible tokenization without using AES (see
<https://microsoft.github.io/presidio/tutorial/11_custom_anonymization/>).

## Engine-level features

### Batch anonymization

`BatchAnonymizerEngine` (`batch_anonymizer_engine.py`) wraps a single
`AnonymizerEngine` and exposes:

- `anonymize_list(texts, recognizer_results_list, **kwargs)` — sequential
  loop, no parallelism. Items whose type is not in
  `(str, bool, int, float)` are passed through unchanged; numbers/bools
  get `str(...)`-coerced before anonymizing.
- `anonymize_dict(analyzer_results: Iterable[DictRecognizerResult])` —
  recursive: walks nested dicts, anonymizes string leaves, recurses into
  child dicts, delegates lists to `anonymize_list`, and passes other
  types through.

There is **no batch deanonymization engine** — `DeanonymizeEngine` only
operates on a single text + list of `OperatorResult`s.

### Conflict resolution between overlapping detections

`AnonymizerEngine.anonymize` takes a `conflict_resolution:
ConflictResolutionStrategy` argument with three values (enum in
`entities/conflict_resolution_strategy.py`):

- **`MERGE_SIMILAR_OR_CONTAINED` (default)** — two-phase reduction in
  `_remove_conflicts_and_get_text_manipulation_data`:
  1. **Same-type merge**: any two results with the same `entity_type`
     whose spans intersect are merged into the union span, keeping the
     max score.
  2. **Conflict drop**: among the survivors, results that "have a
     conflict" with another (one fully contains the other, or equal
     indices) are dropped in favor of the surrounding/higher-scoring
     one. Implemented via `RecognizerResult.has_conflict`.
- **`REMOVE_INTERSECTIONS`** — runs the default reduction first, then
  walks the sorted list and resolves any remaining partial overlap by
  **shrinking the lower-scoring span**: if `current.score >=
  next.score`, push `next.start` to `current.end`; otherwise pull
  `current.end` back to `next.start`. Empty spans (`start > end`) are
  filtered out. No detection is fully dropped, only trimmed.
- **`NONE`** — documented in the enum's docstring as "No conflict
  resolution", but the enum class itself does **not** define a `NONE`
  member in the current source. Passing `None` / not the default
  effectively just skips `REMOVE_INTERSECTIONS`. (Bug-ish discrepancy
  between docstring and code.)

### Adjacent-span merging

Independently of conflict resolution, `anonymize(..., merge_entities_with_spaces=True)`
(default `True`) runs `_merge_entities_with_spaces_between`: any two
adjacent same-type entities separated only by whitespace
(`re.search(r"^( )+$", gap)`) are merged into a single span. This is
useful for multi-token names like `"John   Smith"`. Set
`merge_entities_with_spaces=False` to disable.

### Default operator fallback

If `operators` dict has no entry for a detected entity type, the
`"DEFAULT"` key is consulted; if that's missing too, the engine inserts a
default `OperatorConfig("replace")` which yields `<ENTITY_TYPE>`-style
tags. So calling `engine.anonymize(text, results)` with no operators map
at all still works and produces tagged output.

### Sort + copy invariants

`anonymize` deep-copies `analyzer_results` (so the caller's list is not
mutated) and sorts by `(start, end)` before any processing — downstream
merge logic assumes sorted input.

## Anything notable / unusual

- **Only `encrypt`/`decrypt` is intrinsically reversible.** Hash, mask,
  redact, replace, surrogate_ahds, and keep are all irreversible
  (well — `keep` is a no-op so reversibility is moot). Pseudonymization
  with a reversible token vault is left to the user via the `custom`
  operator + a paired registered custom deanonymizer, with the validator
  intentionally avoiding lambda-invocation so stateful closures survive
  validation.
- **AES-CBC without authentication.** No GCM/CCM/SIV option; no
  associated-data binding; no HMAC over the IV+ciphertext. Ciphertexts
  are malleable. No KDF — raw key bytes used directly.
- **Hash output is non-joinable by default.** Without an explicit salt,
  every call generates a new 32-byte random salt that's discarded after
  use, so identical inputs produce different hashes. Joinable
  pseudonymous hashing requires the caller to manage and pass a stable
  salt.
- **Salt minimum length (16 bytes)** is enforced — a recent hardening.
  Comment in code: "to prevent brute-force attacks."
- **`mask` is single-character only** — `masking_char` is validated to
  be a string of length 1, so you cannot use `"**"` as a unit.
  `from_end=True` is the canonical PAN/phone tail-mask switch.
- **`replace` empty-value fallback** silently substitutes
  `<{entity_type}>` (e.g. `<PHONE_NUMBER>`) when `new_value` is not
  provided, even though the validator requires `new_value` to be a
  `str`. This is also the engine-wide default behavior.
- **AHDS surrogate is the only "format-preserving" / realistic-fake
  output mechanism** — and it's a remote call to an Azure REST API, not
  a local algorithm. There is no built-in local Faker-style synthetic
  generator. The class also embeds a hardcoded ~80-entry mapping from
  Presidio entity types (US/UK/ES/IT/PL/SG/AU/IN/FI/KR) to AHDS
  `PhiCategory` values.
- **Two-operator deanonymization set.** Only `decrypt` and
  `deanonymize_keep` are built-in; everything else reversible has to be
  built and registered manually.
- **No HMAC/keyed-hash operator**, no format-preserving encryption, no
  k-anonymity / generalization operators (no date-shift, no
  age-bucket, no zip-truncate), no differential-privacy noise operator —
  all of these are noted gaps versus libraries like
  `microsoft/presidio-research`, ARX, or Privacy Dynamics.
- **`ConflictResolutionStrategy.NONE` is documented but not declared** in
  the enum body — minor source inconsistency worth flagging in our
  comparison doc.
- **Batch is sequential**, no async or thread/process parallelism.
  `BatchAnonymizerEngine.anonymize_list` is a plain `for` loop.
