---
name: Bug report
about: Report something that worked before and is now broken
title: ""
labels: ["type/bug", "severity/medium"]
assignees: []
---

<!--
Triage hints (these comments disappear after you submit):
- Adjust the severity/* label if this is not severity/medium
  (critical / high / medium / low — see CLAUDE.md or .claude/skills/file-issue/label-guide.md).
- Add an effort/* label once the affected files are known
  (trivial / small / medium / large).
- Add a component/* label if one already exists for the affected area.
-->

## Summary

<!-- 1-3 sentences: what is broken and the impact. -->

## Problem

<!-- Describe the incorrect current behavior. Include error output, stack
traces, or screenshots if useful. -->

## Steps to Reproduce

1. <!-- Step 1 -->
2. <!-- Step 2 -->
3. <!-- Observed: description of incorrect behavior -->

## Expected Behavior

<!-- What should happen instead. -->

## Proposed Solution

<!-- Optional. If you have a fix in mind, sketch it here so the implementer
can plan without further clarification. -->

## Acceptance Criteria

- [ ] <!-- Concrete, testable criterion -->
- [ ] <!-- Each checkbox = one verifiable behavior or state -->

## Affected Files

- `path/to/file.rs` — <!-- what is wrong here -->

## Context

<!-- Environment (OS, rustc version, octarine version, feature flags),
related issues (#N), and anything else useful. -->
