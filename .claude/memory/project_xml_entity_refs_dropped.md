---
name: project_xml_entity_refs_dropped
description: "parse_xml silently drops XML entity references and the text before them; pre-existing, tracked in #728"
metadata:
  node_type: memory
  type: project
  originSessionId: 5d2337d9-008e-449d-b373-9b64ecb12fe8
  modified: 2026-09-06T18:39:26.229Z
---

`primitives::data::formats::xml::parse_xml` returns `Ok(..)` with corrupted
text when the input contains an entity reference:
`parse_xml("<root>a &amp; b</root>")` yields `Some("b")` — both the `&` and the
text preceding it (`a`, with its trailing space) are lost.

Two causes compounding:

1. quick-xml emits `&amp;` as its own `Event::GeneralRef`, never as part of an
   `Event::Text`. `parse_xml` has no `GeneralRef` arm, so `Ok(_) => {}` eats it.
2. The `Event::Text` arm *overwrites* `current.text` instead of appending, so
   the entity splitting the run into two Text events discards the first half.

**Why:** this is NOT from the quick-xml 0.42 bump (#720, merged as `e763261`).
`Event::GeneralRef` exists in 0.41 too, and a 0.41 sandbox driven through the
old `BytesText::decode()` path produces the identical `Some("b")` — `decode()`
was `decoder.decode_cow`, charset decoding only, never entity unescaping.
Anyone re-reading that migration will be tempted to blame it; don't.

**How to apply:** `test_parse_entity_reference_is_dropped_preexisting` in
`parsing.rs` asserts the *broken* value on purpose, so the gap is visible rather
than silent — inverting it is part of fixing #728, not a test failure. When
fixing, watch the XXE surface: entity expansion must not become a new
amplification vector past `primitives/security/formats/xml`.

Related: [[feedback_flaky_timing_verify_first]] — same rule applied to a review
finding rather than a flaky test: reproduce before accepting or dismissing.
