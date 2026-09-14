---
name: project_observe_capture_writer_eviction
description: A registered test capture writer receives EVERY event in the binary — filter by marker at write time or the suite-wide flood evicts your event
metadata:
  type: project
---

`observe::writers::dispatch_to_writers` hands **every** event dispatched
anywhere in the test binary to **every** registered writer — the only filter is
a severity check in `should_write`. A capture writer built on a bounded
`MemoryWriter::with_capacity(N)` therefore has its ring rolled by the whole
suite's event flood, evicting the test's own marker before the poll reads it
back.

Filter on the marker **inside the capture writer's `write`** (pattern in
`identifiers/builder/layer_isolation.rs` and `observe/writers/protected.rs`,
#793). Raising the capacity only moves the threshold.

The filter must also admit the markers whose **absence** is asserted, or a
"silent() must not emit" check passes merely because the event was filtered
out — vacuous, per [[feedback_tests_must_fail_when_inverted]].

**Why:** the symptom masquerades as flush timing. The panic message said
`fast-flush config installed: false`, but `POLL_DEADLINE` was already 30s — the
dispatcher config was never the problem, so widening the deadline would not have
helped. See [[feedback_flaky_timing_verify_first]].

**How to apply:** when a marker-based event assertion fails only under
`cargo test`/coverage and not nextest, suspect eviction before timing.
