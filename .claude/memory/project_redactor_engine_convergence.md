---
name: project_redactor_engine_convergence
description: Epic #604 — converge observe/pii redactor onto the anonymize engine so detection and transformation are each single-sourced
metadata:
  node_type: memory
  type: project
  originSessionId: 93cf9d72-01f2-4ef4-8fb5-4855e26c48c1
---

Two PII surfaces exist and are NOT redundant: `observe/pii/redactor/`
("scrub string to String", built-in detection, fixed per-profile transform) and
the Layer 3 `anonymize/` engine ("findings + per-entity operators to
EngineResult with audit trail", caller-supplied detection, reversible).
Detection is already single-sourced in `primitives/identifiers/{domain}/`; the
redactor already delegates to it (e.g. redact_ssns to GovernmentIdentifierBuilder
strategy).

The drift risk is span transformation. Engine operators with a redactor
counterpart (Mask, Hash, and partial/token strategies) MUST delegate to the
existing `primitives/identifiers/{domain}/redaction.rs` strategies rather than
re-implement, so "mask an SSN" has one implementation. Replace/Redact have no
counterpart, so no drift risk.

Epic #604 (research-first, `type/refactor`) is native-blocked-by the umbrella
issue 462 plus operators 481/482/483/484/485/486; it tracks rewiring the
redactor onto the engine so redaction equals anonymization by construction. Do
the design note first, then file child stories. Cross-reference notes were added
to issues 462/483/484, and 604 carries native GitHub dependency links.

Engine numbering: there is NO separate "engine core" issue — it lives under the
umbrella #462. The Philippines identifier pack is #480 (unrelated; do not touch
it). The additive first slice (Operator trait + AnonymizerEngine + Replace/Redact)
closes #481 and #482 and advances #462. Token vault #474 is the
reversible-pseudonymization path.
