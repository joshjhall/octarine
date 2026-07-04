---
name: project_crypto_secrets_mlock_stub
description: crypto::secrets mlock is a no-op stub; SecureMap logs keys in cleartext — pick the right secure-memory primitive
metadata:
  node_type: memory
  type: project
  originSessionId: be4c0f99-cc78-4bb4-865d-4b260440466d
---

Two non-obvious facts about `crates/octarine/src/crypto/secrets` that gate any "store this in secure memory" work (learned wiring the anonymize vault, #656):

1. **mlock is a documented no-op stub crate-wide.** `try_mlock`/`is_mlock_supported()`/`max_lockable_memory()` never call a syscall (`is_mlock_supported()` returns `false`, `try_new` *fails* on non-empty data). There is zero `unsafe` because the workspace is `unsafe_code = "forbid"`. Real locking needs `memsec`/`region` + unsafe and does not exist yet. So "mlock the pages" is currently just graceful-degradation-to-zeroization; don't promise real anti-swap.

2. **`SecureMap` only zeroizes VALUES and logs KEYS in cleartext** to observe on insert/remove/drop (`map.rs:132,153,191`). Never key it by PII. The Layer-3 `LockedSecret`/`SecureMap` also emit an observe event on every construction, which breaks any `silent()` contract.

**How to apply:** For zeroize-on-drop secret bytes with no logging and the mlock seam, use the Layer 1 `PrimitiveLockedSecret` (`crate::primitives::crypto::secrets::PrimitiveLockedSecret`), not the Layer 3 wrappers. If PII must be a map key, hash it first — `crate::primitives::crypto::hash::blake3_hex` exists. A byte-level post-free zeroization *witness test* is impossible here (needs unsafe); mirror the `crypto::secrets` type-level + behavioral assertion technique instead. See [[feedback_pre_1_0_breaking_changes]].
