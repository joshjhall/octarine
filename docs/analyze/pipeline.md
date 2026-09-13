# Analysis Pipeline — recognize, score, reconcile, explain

`octarine::analyze` is the Layer 3 surface that turns raw detections into a
coherent result set. It is octarine's parity surface for Presidio's
`AnalyzerEngine`: one entry point that applies every configured recognizer,
scores results with context awareness, resolves overlaps, and returns
explanations.

```rust
use octarine::analyze::AnalyzerEngine;

let results = AnalyzerEngine::new()
    .analyze("Contact: alice@example.com", "en")
    .await?;
```

No registration, no configuration. The built-in `IdentifierRecognizer` covers
octarine's whole identifier catalog out of the box.

## Surface

### `AnalyzerEngine`

The pipeline shell. Construct with `new()` (or `silent()` to suppress observe
events and metrics) and configure fluently:

| Method | Effect |
| --- | --- |
| `with_registry` | Replace the recognizer set |
| `with_conflict_resolution` | Choose how overlapping detections are reconciled |
| `with_score_threshold` | Set the engine-wide minimum score |
| `with_events` | Toggle observe emission |

Two entry points: `analyze(text, language)` for the common case, and
`analyze_request(&AnalyzeRequest)` for the full per-call knob set.

### `RecognizerRegistry`

Holds recognizers behind `Arc`, so one expensive instance — an LLM client with
a connection pool — is shared across engines rather than rebuilt.
`with_defaults()` registers the built-in identifier recognizer; `register()`
adds your own.

Filtering goes through `Recognizer::supports`, which encodes the
**empty-means-everything** convention on both sides: an empty request asks for
everything, and a recognizer advertising an empty `supported_entities` handles
everything. A naive set intersection gets this exactly backwards and skips
precisely the general-purpose recognizers.

### `Recognizer`

The pluggable detection interface — an async trait returning
`Vec<RecognizerResult>`. Implement it for a remote PII service, an LLM, or your
own pattern set. Two contracts matter:

- **An unsupported language is an absence of results, not an error.** Return
  `Ok(vec![])`; erroring would fail the whole run over one recognizer's
  narrowness.
- **"I found nothing" and "I could not look" are different answers.** Return
  `Ok(vec![])` for the first and `Err` for the second. The engine counts errors
  and continues; it cannot distinguish the two if you collapse them.

### `ConflictResolution`

Four strategies, applied to the result set after enhancement:

| Strategy | Behavior |
| --- | --- |
| `None` | Pass through, sorted. Zero-width spans retained. |
| `SameTypeContainment` | **Default.** Drop same-type nested spans (Presidio parity). |
| `CrossTypeContainment` | Drop nested spans regardless of type. |
| `RemoveIntersections` | Trim lower-scoring spans off their overlap. |

`SameTypeContainment` can return overlapping spans — a `PHONE_NUMBER` inside a
`URL` keeps both, exactly as Presidio does. Do not feed its output straight
into a splice-based redactor that assumes disjoint ranges; use
`CrossTypeContainment` or `RemoveIntersections` there.

## The pipeline

Each pass is a separate function, individually testable and individually
extensible.

| # | Pass | Notes |
| --- | --- | --- |
| 1 | Resolve recognizers | language + entity set → recognizer list |
| 2 | *NLP artifacts* | **seam** — requires an NER model |
| 3 | Run recognizers | await each, aggregate |
| 4 | Inject metadata | stamp `recognizer_name` provenance |
| 5 | Enhance context | raise scores on nearby keywords |
| 6 | *Allow-list* | **seam** |
| 7 | Deduplicate | reconcile overlapping spans |
| 8 | Apply threshold | drop low-scoring results |
| 9 | Finalize | strip explanations unless requested |

### The order is load-bearing

Enhancement (5) **must** precede thresholding (8), or a result the context
would have rescued is discarded before the rescue runs. Dedup (7) precedes
thresholding so an absorbed span cannot influence the surviving set.

### Seams, not stubs

Steps 2 and 6 are deliberately absent. A knob that parses and validates but
reaches no consumer is a silent no-op: callers set it, nothing happens, and the
only symptom is wrong output in production. Each lands with the pass that reads
it.

### Failure handling

A recognizer returning `Err` is logged, counted, and **skipped** — the run
continues with the others. One unreachable remote service must not fail an
analysis the remaining recognizers could have answered. The failure count feeds
the `analyze.engine.recognizer_errors` metric, so a degraded run is visible
rather than silently thinner.

## Scoring

Octarine's identifier detection reports a three-level `DetectionConfidence`
describing *how* a detection was reached, which the adapter maps onto the
`[0.0, 1.0]` score `RecognizerResult` carries:

| Confidence | Score | Meaning |
| --- | --- | --- |
| `Low` | 0.40 | Heuristic match |
| `Medium` | 0.60 | Pattern match |
| `High` | 0.85 | Pattern match **and** validation (checksum, Luhn, structure) |

`High` stops short of `1.0` deliberately: a passing checksum is strong
evidence, not certainty, and the headroom lets context enhancement raise a
score without saturating.

The default engine threshold is **0.0**, matching Presidio — return everything
and let the caller decide. For a PII detector a false negative is the costlier
error, so the default fails toward reporting.

## Context enhancement

Step 5 does not reimplement Presidio's `LemmaContextAwareEnhancer`. The window
math, the `+0.35` boost, and the `0.95` cap already live in octarine's
confidence primitives, already multilingual. This pass decides *which* results
to ask about and records the outcome.

The language tag is forwarded as a keyword-language hint. An unrecognized tag
leaves the analyzer **unhinted** — scanning every language's keyword table —
rather than matching nothing, so a typo'd tag degrades to the default instead
of silently suppressing every boost.

A result whose entity label does not map to a known `IdentifierType` — a custom
recognizer's bespoke label — passes through untouched. There is no keyword
table to consult, which is an absence of context, not a reason to drop the
detection.

## Async execution model

`analyze` is async because `Recognizer` is: a recognizer may be a network
service or an LLM. There is **no sync shell**. Unlike the anonymizer, whose
core is pure string splicing and therefore splits cleanly into a sans-IO core
plus async shell, every useful analysis run may perform I/O — offering a
blocking variant would only invite it to be called from an async context.

Recognizers run sequentially. Concurrent fan-out is a deliberate non-goal for
now: with the built-in registry there is one recognizer, and parallelism across
a handful of network recognizers is a change whose failure and cancellation
semantics deserve their own design.

## Worked example

```rust
use std::sync::Arc;

use octarine::analyze::{
    AnalyzeRequest, AnalyzerEngine, ConflictResolution, RecognizerRegistry,
};

# tokio_test::block_on(async {
let engine = AnalyzerEngine::new()
    .with_registry(RecognizerRegistry::with_defaults())
    .with_conflict_resolution(ConflictResolution::CrossTypeContainment)
    .with_score_threshold(0.5);

let request = AnalyzeRequest::new("SSN: 123-45-6789, email user@example.com", "en")
    .with_decision_process(true);

let results = engine.analyze_request(&request).await?;

for result in &results {
    // Provenance: which recognizer produced this.
    let recognizer = result
        .recognition_metadata
        .as_ref()
        .and_then(|m| m.get("recognizer_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    println!(
        "{} [{}..{}] score {:.2} via {}",
        result.entity_type, result.start, result.end, result.score, recognizer,
    );

    // Why it scored what it scored — present because we asked for it.
    if let Some(explanation) = &result.analysis_explanation {
        println!("  {explanation}");
    }
}
# assert!(!results.is_empty());
# Ok::<(), octarine::observe::Problem>(())
# }).unwrap();
```

Results flow directly into `octarine::anonymize` — both surfaces share one
`RecognizerResult` type, so nothing is lost in between.

## Why octarine over Presidio

- **One `RecognizerResult`.** Presidio carries separate analyzer and anonymizer
  copies with different ordering semantics; round-tripping between them
  silently drops fields.
- **Cross-type conflict resolution.** Presidio only dedups same-type overlaps.
- **`ConflictResolutionStrategy.NONE` actually exists.** Presidio's docstring
  references a member missing from the enum body.
- **Correlation-id propagation.** `observe`'s correlation ids and
  tenant-scoped audit writers supersede Presidio's `AppTracer`, with no
  separate tracer to configure.
- **Zero-score handling.** Presidio silently drops detections scoring exactly
  `0`, conflating a recognizer's "definitely not PII" sentinel with a weak hit.
  Octarine drops only the degenerate case it actually has — the zero-width
  span, which covers no text and cannot be redacted.

## Metrics

Emitted unless the engine is `silent()`:

| Metric | Meaning |
| --- | --- |
| `analyze.engine.analyze_ms` | Wall time per run |
| `analyze.engine.results_returned` | Results surviving the full pipeline |
| `analyze.engine.results_filtered` | Results dropped by dedup and thresholding |
| `analyze.engine.recognizer_errors` | Recognizers that failed and were skipped |

## Roadmap

The pipeline's extension seams, each tracked separately:

| Area | Issue |
| --- | --- |
| Per-call + per-entity score thresholds | #488 |
| Ad-hoc recognizer injection | #489 |
| Allow-list (exact + regex modes) | #490 |
| Deny-list at recognizer level | #491 |
| Structured `AnalysisExplanation` record | #492 |
| `validate_result` / `invalidate_result` hooks + regex timeout | #494 |
| Registry `enabled` toggle + country filter | #495 |
| Layered TOML configuration | #496 |
| `analyze_dict` / `analyze_batch` | #497 |
| Adjacent same-type span merging | #498 |
| Negative-context enhancer | #514 |
| Substring / whole-word context matching | #515 |
| Starter modes (fast / balanced / accurate) | #516 |
| Performance budget benchmark + CI gate | #517 |
| `RemoteRecognizer` trait | #518 |
| Tokenizer-based chunking for long inputs | #519 |

Tracked under [#464](https://github.com/joshjhall/octarine/issues/464).

## Related

- [Token vault](../anonymize/token-vault.md) — reversible anonymization
- [Layer architecture](../architecture/layer-architecture.md) — where
  `analyze/` sits
