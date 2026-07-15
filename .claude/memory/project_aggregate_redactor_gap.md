---
name: project_aggregate_redactor_gap
description: Most country government IDs are detected+classified but NOT scrubbed by the aggregate text redactor (silent PHI/PII leak)
metadata:
  node_type: memory
  type: project
  originSessionId: d90d4459-28c5-4539-ad54-bc7fc9743c3a
---

`redact_all_government_ids_in_text_with_policy`
(`primitives/identifiers/government/sanitization/text.rs`) only wires ~8 of the
~72 detected government identifier families into actual text redaction. The
scanner (`observe/pii/scanner/domains.rs`) detects & classifies all of them, and
the redactor dispatch (`observe/pii/redactor/mod.rs`) groups them into one arm
that *looks* handled — but for any type lacking a `redact_<type>_in_text_with_strategy` +
`TextRedactionPolicy::to_<type>_strategy` mapper, `redact_pii` passes the raw
identifier through unchanged.

Wired (scrubbed): SSN, tax_id, MBI (#428), driver_license, passport, uk_ni,
national_id, vehicle_id. NOT scrubbed (silent leak): UkNhs (HIPAA-equiv), all
Korea/India/Australia/Brazil/Mexico/Nigeria/Thailand/Turkey/Singapore/Finland/
Poland/Italy/Spain/Sweden IDs.

**Why:** discovered by `audit-octarine-pii-sync` during #428. Detection ≠
redaction — the bridge-sync skills only check detection/classification, not that
the redactor actually replaces characters. Adding a new identifier is NOT
complete until it is in the aggregate redactor (see
[[feedback_complete_provider_integration]]).

**How to apply:** MBI in #428 is the template — `redact_us_mbis_in_text_with_strategy` +
`MbiRedactionStrategy` + `to_mbi_strategy` + a call in the aggregate + a
`test_redact_all_government_ids_includes_<type>` regression test. Systemic
follow-up for all unwired types tracked in **issue #672**.
