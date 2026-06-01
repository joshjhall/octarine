# Token Vault — Reversible Pseudonymization

The **token vault** is octarine's persistence layer for reversible
pseudonymization: replacing detected PII with stable tokens
(`<PERSON_0>`, `<EMAIL_0>`, …) that can later be reversed back to the original
values within the same session.

This is the headline pattern for protecting LLM prompts — anonymize a prompt
before sending it to a model, then rehydrate the model's response with the
original identities.

> **Status**: the foundational surface (`StateStore` + `SessionId` + `EntityKey`)
> and the async, session-aware engine path that consumes it (`anonymize_async` /
> `deanonymize_async` + the `AsyncOperator` trait) have landed. Concrete store
> backends and the InstanceCounter operators are tracked as follow-up work (see
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

## Worked example (planned)

The async engine path and the `AsyncOperator` trait have landed (#609); once an
in-memory backend (#540) and the InstanceCounter operators (#543) land, the full
round trip looks like this:

```text
let store: Arc<dyn StateStore> = Arc::new(InMemoryStore::new());
let engine = AnonymizerEngine::new()
    .with_async_operator(Box::new(InstanceCounter::new()))
    .with_store(Arc::clone(&store));
let session = SessionId::new("chat-42");

// 1. Anonymize: "Email Jane Doe at jane@acme.com"
//    engine.anonymize_async(prompt, results, &operators, &session).await
//             -> "Email <PERSON_0> at <EMAIL_0>"
// 2. Send the anonymized prompt to the model.
// 3. Deanonymize the reply, reversing tokens back to originals:
//    engine.deanonymize_async(reply, results, &operators, &session).await
// 4. store.flush(&session) when the conversation ends.
```

The injected `Arc<dyn StateStore>` and the `anonymize_async` / `deanonymize_async`
shells exist today (see [Async execution model](#async-execution-model)); only
the concrete store backend and operator are still follow-up work.

## Why octarine over Presidio

Presidio's `InstanceCounterAnonymizer` lives in a sample notebook with a
hand-rolled dictionary that explicitly disclaims thread safety. Octarine
promotes it to a first-class, backend-agnostic trait where each backend
(in-memory, Redis, Postgres) is thread-safe by construction.

## Roadmap

| Capability                       | Issue |
| -------------------------------- | ----- |
| `StateStore` trait + value types | #539  |
| Async session-aware engine path  | #609  |
| In-memory backend (default)      | #540  |
| Redis backend (`redis` feature)  | #541  |
| Postgres backend                 | #542  |
| Session lifecycle API (TTL)      | #544  |
| InstanceCounter operators        | #543  |
| Concurrency tests                | #545  |
