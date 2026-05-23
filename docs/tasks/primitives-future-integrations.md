# Future Primitives Integrations

Ideas for leveraging `primitives/common` (RingBuffer, LruCache) that require more design work.

## 1. Metrics Snapshot Caching (LruCache)

**Status:** Implemented in #4 (single-slot TTL cache rather than LruCache —
the registry only ever produces one global snapshot, so an LRU key dimension
adds no value). Default TTL 1s, invalidated by `Registry::clear()` and
`flush_for_testing()`. See `src/observe/metrics/aggregation/mod.rs`.

______________________________________________________________________

## 2. Correlation ID Caching (LruCache + Task-Local Storage)

**Location:** `src/observe/context/capture.rs:96-100`

**Current Issue:** Generates new `Uuid::new_v4()` per event, which is expensive (allocation + randomness). Code already
notes: "can be expensive, future optimization".

**Proposed Solution:** Cache correlation IDs per request scope using task-local storage + LruCache.

**Design Questions:**

- How to integrate with `runtime::ContextBuilder`?
- What's the lifecycle of a correlation ID? (per request? per span?)
- How to propagate correlation IDs across async boundaries?
- Should correlation IDs be inherited from parent contexts?

**Benefit:** Reduce UUID allocations, enable proper distributed tracing.

**Related Work:** This ties into the broader observability story - may want to design alongside OpenTelemetry
integration.

______________________________________________________________________

## 3. Dynamic Feature Flags (LruCache)

**Location:** `src/observe/context/environment.rs:111-124`

**Current State:** Feature flags are loaded once at startup from environment variables into a static HashMap.

**Why Not Applicable Now:** LruCache only makes sense if flags are dynamically fetched from a service with TTL-based
refresh. Current design is static.

**Future Consideration:** If we add a feature flag service integration:

- LruCache would provide bounded storage
- TTL would allow flag changes without restart
- LRU eviction prevents memory exhaustion from high-cardinality flags

**Design Questions:**

- What feature flag backend? (LaunchDarkly, Split, custom?)
- How to handle flag evaluation during cache miss?
- Should we support flag change notifications (webhooks)?

______________________________________________________________________

## Implementation Notes

These items were identified during Phase 2.1 of the primitives migration. They represent opportunities to leverage the
new `primitives/common` module but require architectural decisions beyond simple refactoring.

When ready to implement:

1. Create a design doc for the specific feature
1. Consider impact on public API
1. Add appropriate tests and benchmarks
1. Update documentation

## Related Files

- `crates/octarine/src/primitives/collections/buffer/ring.rs` - RingBuffer implementation
- `crates/octarine/src/primitives/collections/cache/lru.rs` - LruCache implementation
- `docs/architecture/refactor-plan.md` - Overall migration plan
