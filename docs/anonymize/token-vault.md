# Token Vault — Reversible Pseudonymization

The **token vault** is octarine's persistence layer for reversible
pseudonymization: replacing detected PII with stable tokens
(`<PERSON_0>`, `<EMAIL_0>`, …) that can later be reversed back to the original
values within the same session.

This is the headline pattern for protecting LLM prompts — anonymize a prompt
before sending it to a model, then rehydrate the model's response with the
original identities.

> **Status**: the foundational surface (`StateStore` + `SessionId` + `EntityKey`),
> the default `InMemoryStore` backend, the session-lifecycle API
> (`SessionManager` + TTL expiry), the async, session-aware engine path that
> consumes it (`anonymize_async` / `deanonymize_async` + the `AsyncOperator`
> trait), and the `InstanceCounterAnonymizer` / `InstanceCounterDeanonymizer`
> operators that mint and reverse stable tokens have all landed. The
> Redis/Postgres backends are tracked as follow-up work (see
> [Roadmap](#roadmap)).

## Surface

The surface lives under `octarine::anonymize` and consists of two value types
and one trait.

### `SessionId`

An opaque, caller-chosen handle that scopes a single run of pseudonymization.
Every mapping in the vault belongs to exactly one session, and the same
`SessionId` must be presented to reverse those mappings later. Unlike an
authentication session token, it carries no entropy requirement — it is a
routing label, not a credential.

```rust
use octarine::anonymize::SessionId;

let session = SessionId::new("chat-42");
assert_eq!(session.as_str(), "chat-42");
```

**The handle must not be PII.** Use a synthetic identifier — `"chat-42"`, or
the UUID-v7 `SessionManager::open` mints when given no `id_hint` — never a
user's email, account name, or a JWT `sub` claim. `SessionId::new` is
infallible and cannot reject one (PII detection is heuristic, and a false
positive would break a legitimate label), so the vault limits the blast radius
structurally instead: its observe events log `SessionId::digest()`, a truncated
BLAKE3 hash, rather than the handle (#629). `Display`, `Debug`, and `as_str`
still yield the raw value by design — if your own code logs a `SessionId`, log
`digest()`.

### `EntityKey`

The composite key a single original value is stored under: the detected
`entity_type` (e.g. `"PERSON"`, `"EMAIL"`) paired with the `original` value.
Keeping the type alongside the value lets a backend allocate per-type token
indices and enumerate every mapping for a given type.

```rust
use octarine::anonymize::EntityKey;

let key = EntityKey::new("PERSON", "Jane Doe");
assert_eq!(key.entity_type, "PERSON");
```

### `StateStore`

The backend-agnostic `async` trait that records each `(session, key) → token`
mapping. Implementations own their concurrency control so that concurrent
callers never mint divergent tokens for the same original.

| Method  | Contract                                                           |
| ------- | ------------------------------------------------------------------ |
| `get`   | Returns the stored token for a key, or `None`.                     |
| `put`   | Stores a token for a key; idempotent, overwrites; atomic.          |
| `list`  | Returns every `(original, token)` pair for an `entity_type`.       |
| `flush` | Drops all state for a session (session-close / TTL expiry).        |

A store is shared across threads as `Arc<dyn StateStore>`.

## Session lifecycle & TTL

A bare `StateStore` records mappings but has no notion of a session *beginning*
or *ending* — a `SessionId` is just a label the caller invents, and abandoned
sessions accumulate in the backend forever. `SessionManager` adds the missing
lifecycle on top of any store:

```rust
use std::sync::Arc;
use std::time::Duration;
use octarine::anonymize::{InMemoryStore, SessionManager, SessionOptions};

# tokio_test::block_on(async {
let store = Arc::new(InMemoryStore::new());
let sessions = SessionManager::new(Arc::clone(&store));

// Open a 30-minute session; `id` is a fresh, time-ordered UUID-v7.
let id = sessions.open(SessionOptions::with_ttl(Duration::from_secs(1800)));

// On every interaction, reset the TTL so an active conversation stays alive:
sessions.touch(&id).await?;

// End it explicitly — flushes the session's mappings from the store:
sessions.close(&id).await?;
# Ok::<(), octarine_problem::Problem>(())
# });
```

| Method        | Contract                                                              |
| ------------- | -------------------------------------------------------------------- |
| `open`        | Mints a UUID-v7 `SessionId` (or uses `id_hint`); optional TTL. Sync. |
| `close`       | Flushes the session's store state and untracks it. Idempotent.       |
| `touch`       | Resets the TTL clock; `NotFound` if the session is not open.         |
| `sweep_now`   | Runs one expiry pass immediately; returns the count reclaimed.       |
| `start_sweep` | Spawns the background expiry task (aborted on `stop_sweep` / drop).  |

`SessionOptions` carries `ttl: Option<Duration>` (`None` = never expires) and
`id_hint: Option<String>` (a deterministic id for tests or for adopting an
externally-issued identifier). `open` returns a **UUID-v7** — time-ordered, so
session ids sort by creation time when a caller holds or stores them. Note the
ordering does *not* survive into logs: observe events carry the digest, which
is a hash and therefore unordered. Correlate log lines by digest equality, and
use the event timestamp for ordering.

### Why TTL is first-class (compliance)

Presidio's `InstanceCounterAnonymizer` keeps its mapping in a plain Python dict
that lives as long as the process — there is no concept of expiry. Octarine
ships TTL by default because compliance regimes require pseudonymized state to
be purged on a bounded schedule, and the TTL *is* that retention control:

- **HIPAA** minimum-necessary / retention-limitation — re-identification keys
  must not outlive the operational need.
- **GDPR** storage limitation (Art. 5(1)(e)) — personal data kept no longer
  than necessary.

Set the TTL to your retention window and abandoned sessions are reclaimed
automatically — no out-of-band cron job, no manual cleanup.

### TTL enforcement strategy per backend

TTL is enforced **manager-side** by default: a tokio interval task calls
`StateStore::flush` on each expired session. This is backend-agnostic and is the
strategy the `InMemoryStore` uses. Stateful backends that land later additionally
push expiry *into* the store so the database reclaims space even when no manager
process is running:

| Backend        | Strategy                                                       |
| -------------- | ------------------------------------------------------------- |
| **InMemory**   | Manager-side `tokio::time::interval` sweep calls `flush`.     |
| **Redis**      | Native `EXPIRE` on the session hash; `touch` re-issues it.    |
| **Postgres**   | `expires_at` column + a periodic SQL sweep (cadence config).  |

The sweep cadence is configurable via `SessionManager::with_sweep_interval`; the
default is `DEFAULT_SWEEP_INTERVAL` (60 s). A session with TTL `T` is purged at
most one sweep interval after `T` elapses. Observe events on `open`/`close`/
`expire` carry a **truncated BLAKE3 digest of the session id** and nothing else
— no original, no token, and not the handle itself. Logging the handle verbatim
would leak whatever a caller happened to put in it (#629); the digest is stable
per session, so events still correlate.

## Async execution model

Reversible pseudonymization is inherently asynchronous: minting a stable token
or reversing one is `StateStore` I/O. But the engine is **not** async-first.
Epic #604 converges the synchronous `observe/pii/redactor` onto the same
`AnonymizerEngine` ("redaction == anonymization by construction"), and that hot
per-log-line path must never `block_on(..)` a store inside a tokio runtime — a
panic/deadlock footgun. So the engine is split **sans-IO**: one shared
synchronous rewrite core, with a sync shell and an async shell over it.

```text
        ┌─────────────────────────────┐
        │  sync rewrite CORE           │  ← the shared primitive
        │  (conflict res, offsets,     │     pure CPU, no I/O, no async
        │   span splicing)             │
        └─────────────────────────────┘
            ▲                    ▲
   sync shell                async shell
   (logs/redactor:           (LLM prompt / stream filter:
    no store, fixed           await StateStore to resolve
    transforms)               tokens, then call the core)
```

- **Sync shell** — `AnonymizerEngine::anonymize(text, results, operators)`
  applies synchronous [`Operator`]s (fixed transforms: `replace`, `redact`,
  `mask`, pure `custom`). No store, no session, unchanged from before.
- **Async shell** — `anonymize_async(text, results, operators, &session)` and
  `deanonymize_async(..)` are handed an injected `Arc<dyn StateStore>` (via
  `with_store(..)`). For each applied span they prefer a registered
  `AsyncOperator` (via `with_async_operator(..)`), handing it the store and
  `SessionId` so it can `get`/`put` a stable token, and fall back to a
  synchronous fixed transform when no async operator is configured for that
  entity. Both shells then delegate to the **same** sync core for offset
  tracking and splicing, so a replacement of any length stays aligned.

`AsyncOperator` is the session-aware counterpart to `Operator`; the two coexist.
Store-backed operators (the `InstanceCounter` family, #543) implement the async
one — pure operators stay sync.

### The load-bearing invariant

> **The synchronous path only ever applies fixed transforms; vault
> (`StateStore`) access is async-only.**

This is a deliberate, documented assumption — not an accident — confirmed with
the maintainer. Its rationale:

- keeps the redactor (#604) fully synchronous, so the hot path never blocks on a
  store;
- avoids the `block_on(..)` panic/deadlock footgun inside a tokio runtime; and
- avoids dual-colouring every pure primitive (detection, format, classification,
  the redactor's fixed transforms do no I/O and are already callable from async
  contexts for free).

There is no foreseen requirement for a synchronous caller to read from the
vault. **Revisit trigger:** if such a requirement ever appears, `StateStore`
itself would need a synchronous face — at which point this split must be
reconsidered *deliberately*, not broken silently. The same invariant is
documented in the `anonymize::operator` and `anonymize::engine` module docs.

## Worked example — the InstanceCounter round trip

`InstanceCounterAnonymizer` mints stable `<{entity_type}_{index}>` tokens and
`InstanceCounterDeanonymizer` reverses them. Register the forward operator on an
anonymize engine and the reverse operator on a deanonymize engine, both sharing
one `Arc<dyn StateStore>` and `SessionId`:

```rust
use std::collections::HashMap;
use std::sync::Arc;
use octarine::anonymize::{
    AnonymizerEngine, InstanceCounterAnonymizer, InstanceCounterDeanonymizer,
    InMemoryStore, OperatorConfig, RecognizerResult, SessionId, StateStore,
};

# tokio_test::block_on(async {
let store: Arc<dyn StateStore> = Arc::new(InMemoryStore::new());
let session = SessionId::new("chat-42");

// Route every entity type to the instance_counter operator via DEFAULT.
let mut operators = HashMap::new();
operators.insert("DEFAULT".to_string(), OperatorConfig::new("instance_counter")?);

// 1. Anonymize a prompt. Repeated values reuse their token (stability).
let anon_engine = AnonymizerEngine::new()
    .with_async_operator(Box::new(InstanceCounterAnonymizer::new()))
    .with_store(Arc::clone(&store));
let prompt = "Jane and Jane and Bob";
let results = vec![
    RecognizerResult::new("PERSON", 0, 4, 0.9)?,
    RecognizerResult::new("PERSON", 9, 13, 0.9)?,
    RecognizerResult::new("PERSON", 18, 21, 0.9)?,
];
let anon = anon_engine.anonymize_async(prompt, results, &operators, &session).await?;
assert_eq!(anon.text.as_deref(), Some("<PERSON_0> and <PERSON_0> and <PERSON_1>"));

// 2. Send the anonymized prompt to the model; it replies referencing tokens.
// 3. Deanonymize the reply against the same store + session.
let deanon_engine = AnonymizerEngine::new()
    .with_async_operator(Box::new(InstanceCounterDeanonymizer::new()))
    .with_store(Arc::clone(&store));
let reply = "<PERSON_1> greeted <PERSON_0>";
let reply_spans = vec![
    RecognizerResult::new("PERSON", 0, 10, 1.0)?,
    RecognizerResult::new("PERSON", 19, 29, 1.0)?,
];
let restored = deanon_engine.deanonymize_async(reply, reply_spans, &operators, &session).await?;
assert_eq!(restored.text.as_deref(), Some("Bob greeted Jane"));

// 4. Conversation over: drop the session's mappings.
store.flush(&session).await?;
# Ok::<(), octarine_problem::Problem>(())
# });
```

### Token format and strictness

The anonymizer's default token format is `<{entity_type}_{index}>`. Override it
per operator with `InstanceCounterAnonymizer::with_format("[{entity_type}:{index}]")`
or per entity via a `format` config parameter; any format must contain both the
`{entity_type}` and `{index}` placeholders or the operator's `validate` rejects
it up front.

The deanonymizer is **lenient** by default — a token with no mapping in the
session (one the model invented or mangled) passes through unchanged. Call
`InstanceCounterDeanonymizer::new().with_strict(true)` to instead surface an
unknown token as an error, catching a broken round trip loudly.

### Thread safety

The mint goes through `StateStore::get_or_put`, the backend's atomic
compare-and-set: two callers racing on the same new original converge on one
token instead of minting divergent ones. This is the footgun Presidio's sample
`InstanceCounterAnonymizer` carries ("NOT thread-safe") and octarine closes by
construction. Index *sequencing* across distinct concurrent originals is
best-effort (see the operator's rustdoc), but per-value stability and round-trip
correctness hold under concurrency.

## Why octarine over Presidio

Presidio's `InstanceCounterAnonymizer` lives in a sample notebook with a
hand-rolled dictionary that explicitly disclaims thread safety. Octarine
promotes it to a first-class, backend-agnostic trait where each backend
(in-memory, Redis, Postgres) is thread-safe by construction.

## Roadmap

| Capability                       | Issue | Status      |
| -------------------------------- | ----- | ----------- |
| `StateStore` trait + value types | #539  | landed      |
| Async session-aware engine path  | #609  | landed      |
| In-memory backend (default)      | #540  | landed      |
| Session lifecycle API (TTL)      | #544  | landed      |
| InstanceCounter operators        | #543  | landed      |
| Redis backend (`redis` feature)  | #541  | follow-up   |
| Postgres backend                 | #542  | follow-up   |
| Concurrency tests                | #545  | landed      |
