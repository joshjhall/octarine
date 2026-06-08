---
name: project-anonymize-sans-io-split
description: anonymize engine has a sans-IO split — sync splice core shared by sync + async shells; vault access is async-only by invariant
metadata:
  node_type: memory
  type: project
  originSessionId: 7a1a4a43-92f6-4436-83b4-587c07a70043
---

The `crates/octarine/src/anonymize/` engine uses a **sans-IO split** (landed #609): a private sync `splice()` core (gap-copy, length-based offsets, audit) plus a pure `dedupe_overlaps()` span selector, shared by both the sync `anonymize()` shell and the async `anonymize_async()`/`deanonymize_async()` shells. Two operator traits coexist: sync `Operator` (4 built-ins, fixed transforms) and `#[async_trait] AsyncOperator` (session+store aware, for store-backed token minting). Store injected via `with_store(Arc<dyn StateStore>)`, async ops via `with_async_operator(..)`.

**Load-bearing invariant:** the sync path applies *fixed transforms only*; vault (`StateStore`) access is *async-only*. Rationale: keeps the [[project-redactor-engine-convergence]] #604 redactor sync, avoids the `block_on` footgun in tokio. Documented in operator/engine module docs + `docs/anonymize/token-vault.md`. Revisit trigger: if a sync caller ever needs the vault, `StateStore` needs a sync face — change deliberately.

**Why:** #543 (InstanceCounter operators) needs this async path; it was un-implementable against the merged sync engine + async StateStore. #609 delivers path+trait only (in-test mock); concrete operators = #543, backend = #540.

**How to apply:** when adding store-backed operators, implement `AsyncOperator`, register on the async path; never add `block_on` to the sync path. When resolving replacements on the async path, only iterate `dedupe_overlaps` output so tokens mint once per applied span.
