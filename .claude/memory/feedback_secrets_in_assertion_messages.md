---
name: feedback-secrets-in-assertion-messages
description: "CodeQL flags assert! messages that interpolate a secret- or PII-derived value; state the property, omit the value"
metadata:
  node_type: memory
  type: feedback
---

Never interpolate a secret- or PII-derived string into an `assert!` failure
message, even in a test whose whole point is that the value stays hidden:

```rust
// flagged by CodeQL as cleartext logging, and rightly so
assert!(!rendered.contains(secret), "must not print the credential, got: {rendered}");

// correct
assert!(!rendered.contains(secret), "must not print the credential");
```

**Why:** the message is a logging sink whether or not the test passes. If the
property were ever violated, the failure output would put the credential into
CI logs — precisely when you least want it there. CodeQL reports these as
**high severity**, and this repo's token cannot dismiss alerts (403), so a
false-positive-looking alert still has to be fixed in code.

Hit on #520 (PR #756): two alerts, one of them in the test asserting an API key
is never printed. The same anti-pattern was present across the PII-redaction
and error-body tests — `got: {rendered}` is the tell. When a failure genuinely
needs context, print a length, a category, or a boolean, never the bytes.

Hit again on #427 (PR #759), which extends the rule in three ways:

- It fires on **synthetic government-ID fixtures**, not just real secrets:
  `for ssn in [...] { assert!(.., "{ssn} should be rejected") }` was flagged
  even though every value was a made-up test constant in `#[cfg(test)]`.
- For a loop over fixtures, interpolate the **index**:
  `for (i, ssn) in [...].iter().enumerate()` + `"fixture #{i} should be
  rejected"` keeps the failure diagnosable without the bytes.
- **Single-character** interpolation is not flagged (a Finland HETU century
  marker `'{marker}'` passed clean) — the rule keys on identifier-shaped
  values.

CodeQL reported only ONE of the two sites present in that PR, so sweep sibling
tests for the same pattern in the same commit rather than fixing just the
reported line.

Related: [[project_codeql_hardcoded_crypto_fp]],
[[feedback_tests_must_fail_when_inverted]]
