# Anonymization Operators

The **anonymize** module is octarine's Layer 3 parity surface for Presidio's
`AnonymizerEngine`. It takes detector output and applies a configurable
transformation — an **operator** — per entity type, producing anonymized text
plus a per-entity audit trail.

Detection answers *"what is in this text, and where?"*. Anonymization answers
*"what should replace it?"*. This page covers the second half. For reversible
pseudonymization backed by the token vault, see
[Token Vault](./token-vault.md).

## The shape of a run

An anonymization run is a pure function of three inputs:

| Input | Type | Meaning |
|-------|------|---------|
| `text` | `&str` | The source text |
| `results` | `Vec<RecognizerResult>` | Detected spans (entity type, offsets, score) |
| `operators` | `&HashMap<String, OperatorConfig>` | Entity type → how to transform it |

It returns an `EngineResult`:

```rust
pub struct EngineResult {
    pub text: Option<String>,        // the transformed output
    pub items: Vec<OperatorResult>,  // per-entity audit record, in output order
}
```

Each `OperatorResult` carries the entity type, the `start`/`end` offsets **in
the output text**, the replacement text, and the name of the operator that
produced it. That last field is what makes the result auditable: you can prove
which transformation was applied to which entity.

Two invariants hold throughout:

- **Spans are half-open** — `start` inclusive, `end` exclusive. The `PiiSpan`
  algebra (`intersects`, `contains`, …) is the shared span type, so detection
  offsets and operator offsets mean the same thing.
- **The caller's results list is never mutated.** The engine sorts and resolves
  a copy, so passing the same `Vec` to two engines is safe.

## Quick start

The `anonymize` shortcut runs a default engine, which is enough for most uses:

```rust
use std::collections::HashMap;
use octarine::anonymize::{anonymize, OperatorConfig, RecognizerResult};

let mut ops = HashMap::new();
ops.insert("EMAIL_ADDRESS".to_string(), OperatorConfig::new("redact")?);

let results = vec![RecognizerResult::new("EMAIL_ADDRESS", 3, 14, 0.95)?];
let out = anonymize("a: foo@bar.com", results, &ops)?;
assert_eq!(out.text.as_deref(), Some("a: "));
# Ok::<(), octarine_problem::Problem>(())
```

`redact_all` is a second shortcut that deletes every detected span regardless
of entity type.

Build an `AnonymizerEngine` directly when you need a custom operator, a
non-default conflict strategy, or silent mode:

```rust
use octarine::anonymize::AnonymizerEngine;

let engine = AnonymizerEngine::new();
```

## Operator resolution

You do **not** have to supply an operator for every entity type. The engine
resolves each span's operator in three steps:

1. An explicit entry in the `operators` map keyed by the entity type.
2. Failing that, an entry under the reserved `DEFAULT` key.
3. Failing that, a synthesized `replace` config.

Step 3 is why an empty map still produces useful output — the default `replace`
emits an `<ENTITY_TYPE>` tag:

```rust
use std::collections::HashMap;
use octarine::anonymize::{AnonymizerEngine, RecognizerResult};

let engine = AnonymizerEngine::new();
let text = "Contact John at john@example.com";
let results = vec![
    RecognizerResult::new("PERSON", 8, 12, 0.9)?,
    RecognizerResult::new("EMAIL_ADDRESS", 16, 32, 0.95)?,
];

// No operator map → everything uses the default Replace.
let out = engine.anonymize(text, results, &HashMap::new())?;
assert_eq!(out.text.as_deref(), Some("Contact <PERSON> at <EMAIL_ADDRESS>"));
assert_eq!(out.items.len(), 2);
# Ok::<(), octarine_problem::Problem>(())
```

Setting a `DEFAULT` entry changes the fallback for every unlisted entity — this
is how `redact_all` is implemented.

## Operator reference

The registry is **instance-scoped**: each engine owns its own operator map,
keyed by the operator's name string. There is no process-global registry, so
two engines in the same program can disagree about what `"mask"` means without
interfering.

`AnonymizerEngine::new()` seeds seven operators. The rest are real operators
that ship in the module but must be registered explicitly — they need
constructor arguments (a closure, a store) that the engine cannot invent.

### Auto-registered by `AnonymizerEngine::new()`

| Name | Effect | Key params |
|------|--------|------------|
| `replace` | Substitutes a fixed string; defaults to `<ENTITY_TYPE>` | `new_value` |
| `redact` | Deletes the span entirely | — |
| `mask` | Positionally masks characters | `masking_char`, `chars_to_mask`, `from_end` |
| `hash` | Salted one-way digest, prefixed with an algorithm tag | `algo`, `salt`, `hmac_key`, `kdf_ikm`, `kdf_info` |
| `encrypt` | Seals the span with authenticated encryption | `key` or `password`, `algo`, `mode`, `aad`, `salt` |
| `decrypt` | Opens an `encrypt` output | `key` or `password`, `algo`, `aad`, `salt` |
| `keep` | Leaves the span verbatim, but still records it in `items` | — |

### Registered explicitly

| Name | Constructor | Registered via | Notes |
|------|-------------|----------------|-------|
| `custom` | `Custom::new(closure)` | `with_operator` | Anonymize direction |
| `custom_deanonymize` | `Custom::deanonymizer(closure)` | `with_operator` | Reverse direction; distinct name so both can coexist |
| `keep_deanonymize` | `DeanonymizeKeep` | `with_operator` | Deanonymize-direction counterpart to `keep` |
| `instance_counter` | `InstanceCounterAnonymizer` / `InstanceCounterDeanonymizer` | `with_async_operator` + `with_store` | Vault-backed; async only |

Registering an operator whose name matches a built-in **replaces** it. This is
the supported way to swap in your own `mask` semantics.

### Notes on individual operators

`keep` exists so that an allow-listed entity stays on the audit record instead
of being indistinguishable from one the detector never found:

```rust
let out = engine.anonymize(text, results, &ops)?;

// The email survives verbatim; the phone is replaced.
assert_eq!(out.text.as_deref(), Some("Contact dev@acme.com or call <PHONE>"));

// ...but the kept email is still on the record for the audit trail.
let kept = out.items.iter().find(|i| i.entity_type == "EMAIL").expect("kept item");
assert_eq!(kept.operator.as_deref(), Some("keep"));
assert_eq!(kept.text.as_deref(), Some("dev@acme.com"));
```

`hash` enforces an explicit salt-determinism contract: a keyless algorithm
requires a salt of adequate length, and reusing a salt is what makes digests
joinable across runs. The output is prefixed with an algorithm tag, so
`sha256:…` and `blake3:…` are never confusable. Supported `algo` values are
`sha256` (the default), `sha512`, `blake3`, `hmac` (HMAC-SHA3-256), and
`argon2`. Anything else — including MD5 and SHA-1 — is rejected rather than
merely discouraged, and `argon2` is further gated to secret-bearing entity
types such as `PASSWORD` or `API_KEY`.

`encrypt` binds the ciphertext to the entity type via AAD, so a `PERSON`
ciphertext will not open as an `EMAIL`. Its `mode` param selects `aead`
(random nonce, the default) or `deterministic` (joinable output — opt in
deliberately, since it leaks equality).

## Conflict resolution

Detectors overlap. Two recognizers may both claim the same substring, or one
span may contain another. `ConflictResolutionStrategy` selects the policy:

| Strategy | Behavior |
|----------|----------|
| `MergeSimilarOrContained` | Merge same-type similar or contained spans, drop conflicts. **Default.** |
| `RemoveIntersections` | Additionally trim partial overlaps, shrinking the lower-scoring span |
| `None` | Pass results through untouched |

Set it with `AnonymizerEngine::with_conflict_strategy`.

## Writing a custom operator

Implement the `Operator` trait — four methods, one of which has a default:

```rust
pub trait Operator {
    fn operate(&self, text: &str, entity_type: &str, config: &OperatorConfig) -> Result<String>;
    fn validate(&self, config: &OperatorConfig) -> Result<()> { Ok(()) }
    fn operator_name(&self) -> &'static str;
    fn operator_type(&self) -> OperatorType;
}
```

`operator_name` must match the string callers put in their `OperatorConfig`.
`operator_type` reports the **direction** — `OperatorType::Anonymize` or
`OperatorType::Deanonymize`. It is not a per-operator kind enum; operator
identity is the name string.

Two rules matter:

- **`validate` must never invoke the caller's transform.** Validating a
  closure-backed operator by probe-calling it corrupts stateful closures —
  Presidio carried exactly this bug. Check the config's shape only.
- **Register under a distinct name per direction.** The registry is keyed by
  name alone, so an anonymize/deanonymize pair sharing one name means the
  second registration silently evicts the first. This is why `Custom` splits
  into `custom` / `custom_deanonymize` and `Keep` into `keep` /
  `keep_deanonymize`.

For one-off transforms, `Custom` wraps a `Fn(&str) -> Result<String>` closure
without requiring a new type.

## The sync/async boundary

Vault-backed operators implement `AsyncOperator` rather than `Operator`, and
are reachable only through `anonymize_async` / `deanonymize_async`. The
synchronous `anonymize` path never touches the vault — that is an invariant of
the module, not an implementation detail. On the async path, an async operator
shadows a sync operator of the same name.

Most store-backed operators also need a store injected via `with_store`. See
[Token Vault](./token-vault.md) for the full reversible-pseudonymization story.

## Batch engines

`BatchAnonymizerEngine` and `BatchDeanonymizeEngine` process many texts in
parallel via rayon. Both report per-item results, and the deanonymize engine
offers a non-strict mode that records a per-item failure rather than aborting
the batch.

## Observability

The engine is instrumented per octarine's Layer 3 conventions:

| Metric | Source |
|--------|--------|
| `anonymize.engine.anonymize_ms` | Single-text engine |
| `anonymize.engine.spans_operated` | Single-text engine |
| `anonymize.engine.errors` | Single-text engine |
| `anonymize.batch.anonymize_total` | Batch engine |
| `anonymize.batch.duration_ms` | Batch engine |
| `anonymize.batch.items_total` | Batch engine |
| `anonymize.batch.deanonymize_total` | Batch engine |
| `anonymize.batch.deanonymize_duration_ms` | Batch engine |
| `anonymize.batch.deanonymize_items_total` | Batch engine |

Event emission can be suppressed for hot paths via the engine's silent mode.

## Differences from Presidio

Where octarine's surface intentionally exceeds the Presidio original:

- **Authenticated encryption by default.** The `encrypt` operator uses
  ChaCha20-Poly1305 or AES-256-GCM with AAD binding. Presidio's operator uses
  plain AES-CBC — unauthenticated, and without a KDF for password-derived keys.
- **Multi-character masking units.** `masking_char` accepts a multi-character
  unit; Presidio's mask is single-character only.
- **Parallel batches.** The batch engines fan out across cores with rayon;
  Presidio's batch anonymizer is a sequential Python loop.
- **Thread-safe instance counters.** `InstanceCounterAnonymizer` mints tokens
  through the store's atomic mint and is thread-safe by construction.
  Presidio ships its instance counter as sample code documented as *not*
  thread-safe.
- **One error class.** Operator configuration errors are a single
  `Problem::Validation` variant rather than two parallel exception classes.

## Roadmap

Shipped: the engine, conflict resolution, the operators listed above, the
token vault with its in-memory backend, and the batch engines.

Tracked as follow-up work:

- FPE (FF1/FF3) operator for shape-preserving anonymization — issue 510
- Generalization operators: date-shift, age-bucket, ZIP-truncate,
  geo-truncate, numeric-round — issue 511
- Redis and Postgres vault backends — see [Token Vault](./token-vault.md)
- Convergence of the `observe/pii` redactor onto this engine, so detection and
  span transformation each live in exactly one place — epic 604
