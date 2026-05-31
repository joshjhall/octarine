# Token Vault — Reversible Pseudonymization

The **token vault** is octarine's persistence layer for reversible
pseudonymization: replacing detected PII with stable tokens
(`<PERSON_0>`, `<EMAIL_0>`, …) that can later be reversed back to the original
values within the same session.

This is the headline pattern for protecting LLM prompts — anonymize a prompt
before sending it to a model, then rehydrate the model's response with the
original identities.

> **Status**: this page documents the foundational surface
> (`StateStore` + `SessionId` + `EntityKey`). Backends and the InstanceCounter
> operators that consume it are tracked as follow-up work (see
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

## Worked example (planned)

Once an in-memory backend and the InstanceCounter operators land, the full
round trip looks like this:

```text
let store: Arc<dyn StateStore> = Arc::new(InMemoryStore::new());
let session = SessionId::new("chat-42");

// 1. Anonymize: "Email Jane Doe at jane@acme.com"
//             -> "Email <PERSON_0> at <EMAIL_0>"
// 2. Send the anonymized prompt to the model.
// 3. Deanonymize the reply, reversing tokens back to originals.
// 4. flush(&session) when the conversation ends.
```

## Why octarine over Presidio

Presidio's `InstanceCounterAnonymizer` lives in a sample notebook with a
hand-rolled dictionary that explicitly disclaims thread safety. Octarine
promotes it to a first-class, backend-agnostic trait where each backend
(in-memory, Redis, Postgres) is thread-safe by construction.

## Roadmap

| Capability                       | Issue |
| -------------------------------- | ----- |
| `StateStore` trait + value types | #539  |
| In-memory backend (default)      | #540  |
| Redis backend (`redis` feature)  | #541  |
| Postgres backend                 | #542  |
| Session lifecycle API (TTL)      | #544  |
| InstanceCounter operators        | #543  |
| Concurrency tests                | #545  |
