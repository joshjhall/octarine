---
name: feedback_unicode_range_tests_vacuous
description: A test for a newly-added Unicode range must use a code point IN that range and assert both bounds — representative chars silently re-verify old ranges
metadata:
  type: feedback
---

When adding a Unicode codepoint range to a `matches!` guard, a test that picks a
"representative" character of the script usually exercises a **different,
already-covered range** and passes with the new arm deleted. Twice in #667:
a Korean test used precomposed hangul syllables (U+AC00-D7AF) while claiming to
pin the new compatibility-jamo range (U+3130-318F); a fullwidth test used
fullwidth *punctuation*, which is already non-alphanumeric and so passed either
way.

**Why:** scripts span several blocks, and the natural character to type is
rarely in the block you just added. The assertion still passes, so the gap is
invisible.

**How to apply:** test the guard function *directly* (not only through its
caller — some ranges are unreachable via real data), assert **both** bounds of
each inclusive range plus the code point just outside each one, and verify by
shrinking a bound by one and watching the test fail. Print the code points
(`python3 -c "print([hex(ord(c)) for c in s])"`) rather than trusting that a
character "is Korean". Related: [[feedback_tests_must_fail_when_inverted]].
