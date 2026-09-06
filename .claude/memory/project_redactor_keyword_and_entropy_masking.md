---
name: project_redactor_keyword_and_entropy_masking
description: The observe PII redactor masks by message KEYWORD and by token ENTROPY — both silently rewrite log messages you thought you controlled
metadata:
  node_type: memory
  type: project
---

The observe PII redactor rewrites event messages in two ways that are easy to
mistake for "my logging works" or "my logging is safe" (found fixing #735):

1. **Keyword masking.** Everything following a `secret:` / `password:` style
   prefix is replaced (`[PASSWORD]` under production profiles, `[REDACTED]`
   under Development). This is a substring rule on the *message text*, not on
   the value's content.

2. **Entropy masking.** Any whitespace-delimited token of **20+ chars** with
   >50% unique characters is replaced with `[SESSION]`
   (`primitives/identifiers/token/detection/session.rs::is_likely_session_id`,
   reached via `redact_session_ids_in_text`, which splits on whitespace).

Three consequences, all measured:

- **Keyword masking is NOT a safety guarantee.** It depends on the wording of
  your message string. `"Inserting secret: {key}"` masks the key, but
  `"Inserting entry: {key}"` and even `"Inserting secret for {key}"` leak it in
  **full** under `ProductionStrict`. Never rely on the redactor to keep
  sensitive data out of a log line — keep it out of the message.

- **It also masks things you WANT logged.** A hash/digest/correlation ID placed
  after a `secret:` prefix is replaced too, so the identifier silently stops
  working while the code looks correct.

- **Digest length is bounded from above by rule 2.** `(key=<16 hex>)` is 22
  chars → whole message becomes `[SESSION]`. `(key=<12 hex>)` is 18 chars and
  survives. Keep a rendered high-entropy token under 20 chars.

**How to apply:** when adding or editing an `observe::*` call that includes any
identifier, assert on the *post-redaction* output, not the format string —
`redact_pii_with_profile(&msg, profile)` across all four `RedactionProfile`
variants. A test that only checks the raw `format!` proves nothing about what
reaches a writer. Note also that `RedactionProfile::Testing` redacts **nothing**,
so a leak invisible in production is fully exposed there.

Related: [[project_crypto_secrets_mlock_stub]] (SecureMap key logging, the case
that surfaced this), [[project_aggregate_redactor_gap]],
[[project_redactor_engine_convergence]].
