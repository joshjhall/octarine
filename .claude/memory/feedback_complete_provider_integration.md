---
name: Complete provider integration across all layers
description: Adding token detection primitives alone is insufficient — must also add builder methods, sanitization, and Layer 3 public API wrapping
type: feedback
---

Detection-only changes to primitives don't create user value. New API key providers must be integrated across all layers:

1. **Layer 1 detection** — `is_*()`, regex patterns, `detect_api_key_provider()`, `TokenType` enum
2. **Layer 1 builder** — `TokenIdentifierBuilder` delegation methods
3. **Layer 1 sanitization** — provider-specific `mask_*()` functions with sensible prefix masking
4. **Layer 3 TokenBuilder** — public API wrappers with observe events
5. **Layer 3 RedactionToken** — provider-specific `[PROVIDER_TOKEN]` placeholders (if warranted)

**Why:** Detection alone is internal plumbing. Users interact via the public builder API and need redaction/masking to function. The PII scanner works generically but provider-specific masking (showing prefix, structured masking) requires explicit integration.

**How to apply:** When implementing Cloud Keys or similar identifier additions, plan the full stack from detection through public API. Don't ship detection-only PRs as "complete" for provider issues.
