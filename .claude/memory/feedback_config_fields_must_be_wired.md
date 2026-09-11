---
name: feedback-config-fields-must-be-wired
description: A config field that is parsed, validated and documented but reaches no consumer is a silent no-op — wire it, or document it as unwired
metadata:
  type: feedback
---

When adding a config schema, every field must reach a consumer — or say plainly
that it does not. On #521 five fields (`top_p`, `json_schema`,
`language_model_params`, `country_code`, `supported_languages`) were declared,
range-validated, documented as working, and consumed by **nothing**. Validation
and round-trip tests all passed, which is exactly what made it invisible: the
tests proved the field *deserialized*, never that it *did* anything.

`supported_languages` was the sharpest case — documented as scoping the
recognizer, with `supports_language()` called only by its own unit tests, while
`analyze` still took an ignored `_language` parameter.

**Why:** an operator who sets a field reasonably believes it took effect. For a
PII detector that means believing coverage is scoped or determinism is pinned
when neither is true — the same silent-coverage-loss class as
[[project_aggregate_redactor_gap]]. This is the config-side twin of
[[feedback_complete_provider_integration]]: there, detection without public API;
here, schema without consumer.

**How to apply:** after writing a config struct, grep each field name across the
crate excluding its own declaration, validation, and tests. A field with no other
hit is dead. Either wire it (with a test that fails when the wiring is reverted —
[[feedback_tests_must_fail_when_inverted]]) or mark it not-yet-wired in the field
doc, the user-facing docs, AND the example config. An ignored `_param` on a trait
impl is the same smell.
