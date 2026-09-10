# NER Strategy

Does octarine ship named-entity recognition for free-text `PERSON`,
`LOCATION`, `ORGANIZATION`, and `NRP`?

This document records the decision made in
[#441](https://github.com/joshjhall/octarine/issues/441) and gives the rule to
apply to the next detection capability that wants a model behind it. It is the
companion to [crate-layout.md](./crate-layout.md), which decides *where* an
integration lives; this one decides *whether* a model-backed one belongs in
octarine at all.

## The decision

**Octarine ships a `Recognizer` trait, not a model.**

Detection that can be done deterministically — regex, lexicon, gazetteer,
checksum — lands in `primitives/identifiers/` as it always has. Detection that
needs a statistical model is reached through the `Recognizer` extension point,
implemented by a sibling crate or by caller code. `octarine-core` takes on no
ML runtime, no model files, and no model-lifecycle burden.

Concretely:

```text
octarine-core
  primitives/identifiers/    regex + checksum + lexicon + gazetteer
  analyze/                   trait Recognizer  ← the extension point

sibling crates / caller code
  octarine-llm               LLM-backed recognizer      (#520)
  RemoteRecognizer impls     Azure, AWS, in-house HTTP  (#518)
  octarine-ner-*             local ONNX / libtorch NER  (speculative, #592)
```

This is Option B of the three canvassed in #441. Options A (ship a
feature-gated ML dependency) and C (declare NER a non-goal) were both
considered and rejected; see [Alternatives](#alternatives-considered).

> **Status of the trait.** The `Recognizer` trait is *planned, not shipped*.
> It is defined by [#520](https://github.com/joshjhall/octarine/issues/520),
> which owns its signature and its home at `analyze/recognizer.rs`. At the time
> this decision was recorded, `grep 'trait Recognizer'` over the tree returns
> nothing. This document commits to the shape of the answer, not to an existing
> API.

## What is actually uncovered

The issue was filed against a four-entity gap. Three of the four have since
been closed by no-ML work that the issue itself had deferred, so the decision
governs a much narrower surface than its title suggests.

| Presidio entity | Octarine today | Status |
|---|---|---|
| `NRP` (nationality / religion / political) | `primitives/identifiers/personal/detection/nrp.rs` — Aho-Corasick over ~200 nationalities, ~50 religions, ~30 political affiliations | **Shipped** (was CRIT-3) |
| `AGE` | `primitives/identifiers/personal/detection/age.rs` — numeric (`"42-year-old"`, `"age 65"`) and lexical (`"in his thirties"`) forms, with HIPAA Safe Harbor >89 support | **Shipped** (was CRIT-4) |
| `LOCATION` | `primitives/identifiers/location/detection/named.rs` + `common/patterns/location/gazetteer.rs` — ~280 countries, ~1,500 major cities, ambiguous-name downgrading; surfaced as `IdentifierType::NamedLocation` | **Shipped, gazetteer-quality** (was CRIT-2) |
| `PERSON` | `primitives/identifiers/personal/detection/name.rs` — `[A-Z][a-z]+ [A-Z][a-z]+`-style patterns | **Not covered** (CRIT-1) |
| `ORGANIZATION` | `primitives/identifiers/organizational/` detects structured IDs (employee, student, badge) only — no free-text company names | **Not covered** |

So the live gap is **free-text `PERSON` and `ORGANIZATION`**, and octarine does
not close it in-tree.

Two honest caveats about what "shipped" means above:

- The `LOCATION` gazetteer is a **recall-bounded** answer. It matches names on
  its list; it does not generalize to neighborhoods, landmarks, or regions
  ("the Pacific Northwest"), and it does not do multilingual place names beyond
  the transliterations bundled. It is a real improvement over nothing, not
  parity with spaCy `GPE`/`LOC`.
- `name.rs` is not a `PERSON` recognizer and should not be described as one. Its
  own doc comment concedes a high false-positive rate: it fires on any
  capitalized bigram (`"New York"`, `"Black Friday"`) and misses lowercase,
  all-caps, and non-Latin-script names. It stays as a cheap heuristic; the
  `Recognizer` point is where a real answer plugs in.

## Why

**The packaging question was already settled.** [crate-layout.md](./crate-layout.md)
R2 sends anything that links a non-Rust runtime — ONNX Runtime, libtorch — to a
sibling crate, because a system-native toolchain dependency cannot be expressed
as a Cargo feature without breaking the build for everyone who lacks the system
libraries. R3 adds the same verdict for dep families with independent release
cadence and MSRV pressure. A core `ner` feature flag of the kind CRIT-1
originally proposed was never actually available under our own rules.

**A trait is what the already-filed work assumes.** #520 (`LLMRecognizer`), #518
(`RemoteRecognizer`), and #592 (GLiNER via ONNX, currently `status/on-hold`) all
presuppose a pluggable recognizer and none of them can proceed without one. One
extension point unblocks all three, plus every integrator with an in-house NER
service, at the cost of one trait definition.

**It keeps the deterministic guarantees that distinguish octarine.** Regex,
lexicon, and checksum detection is reproducible, auditable, allocation-bounded,
and has no cold start — properties that matter for a library whose output feeds
compliance audit trails. Bringing a model in-tree would make "what did the
redactor do and why" a question with a probabilistic answer for every caller,
including the ones who never wanted NER.

## Alternatives considered

### Option A — ship feature-gated ML NER

Build `octarine-ner-candle` / `-rust-bert` / `-ort` and close `PERSON`/`ORG`
properly, at roughly Presidio's ~0.85 recall.

Rejected for this decision, **not forever**. It carries model download and
distribution, RAM and cold-start budgets, GPU/CPU path divergence, multi-arch
CI, and per-release model-compatibility drift — weeks-to-months of work and a
permanent maintenance surface, taken on speculatively before any caller has
asked. It would also pre-empt #592, which exists precisely to hold this choice
until (a) the strategy resolves toward local NER or (b) a customer asks for a
zero-LLM-cost zero-shot path. Option B does not foreclose Option A: a future
`octarine-ner-*` sibling crate implementing `Recognizer` is exactly how Option A
would land, and it can land without touching `octarine-core`.

### Option C — declare NER a non-goal

Document octarine as regex-and-heuristics only and point NER-heavy callers at
Presidio or a commercial service.

Rejected. It would require closing #520, #518, and #592 — work that is filed,
wanted, and independently justified — and it overstates the ceiling of the
no-ML path, which the NRP, AGE, and gazetteer work has just demonstrated is
higher than assumed. Option B gets Option C's benefit (no ML maintenance
burden in core) without giving up the integration story.

## The rule going forward

Apply in order; first match wins.

1. **Can it be decided deterministically?** Regex, checksum, lexicon,
   gazetteer, or a bounded table → it belongs in `primitives/identifiers/`,
   under the concern rules in [layer-architecture.md](./layer-architecture.md).
   Prefer this. The NRP and AGE work shows how far it reaches.
1. **Does it need a statistical model?** Then it goes behind `Recognizer`, in a
   sibling crate or caller code — never as a Cargo feature on `octarine-core`.
   [crate-layout.md](./crate-layout.md) R2/R3 governs the crate boundary.
1. **Is it a hosted service?** Same answer, via `RemoteRecognizer` (#518) — the
   transport reuses the Layer 3 HTTP builder, so no new transport code.
1. **Never widen `octarine-core` to feed a recognizer.** If an implementation
   needs `pub(crate)` internals, that is a signal the seam is in the wrong
   place, not a licence to widen visibility.

## Answers to #441's decision questions

| Question | Answer |
|---|---|
| Willing to ship a feature-gated ML dependency story? | **No** — not in `octarine-core`. A sibling crate behind `Recognizer` is the supported shape. |
| If yes, which runtime — `candle`, `tch`, `ort`? | **Not decided here.** Deliberately deferred to whichever sibling crate is built first; #592 tracks the `ort`/GLiNER candidate. |
| Ship a `NerProvider` trait or document a non-goal? | **Trait** — named `Recognizer`, generalized beyond NER, owned by #520. The `NerProvider` name from the original proposal is dropped: one extension point serves NER, LLM, and remote-service recognizers alike. |
| Acceptable model size on disk + RAM? | **The caller's budget, not octarine's.** Core carries no model; a sibling crate documents its own footprint. |
| Acceptable cold-start latency for first call? | **Not applicable to core**, which has none. A recognizer implementation owns and documents its warm-up cost. |

## Consequences

- **`PERSON` and `ORGANIZATION` free-text detection remain uncovered**, and this
  must be stated plainly in user-facing docs rather than left to be discovered.
  Filed as [#750](https://github.com/joshjhall/octarine/issues/750).
- **#520 and #518 are unblocked** and are the path by which this decision
  becomes real API.
- **A local-NER sibling crate stays open as an option**, filed speculatively and
  on hold as [#751](https://github.com/joshjhall/octarine/issues/751). The
  runtime (`ort` / `candle` / `rust-bert`) is deliberately not chosen here.
- **#592 stays `status/on-hold`.** This decision satisfies only part of its
  un-hold criterion (a): the strategy now permits a local-NER sibling crate, but
  does not commit to building one. It un-holds when a caller asks, and should be
  reconciled with #751 rather than worked alongside it.
- **`docs/presidio-gap-analysis.md` Phase 6 is resolved** by this document; its
  CRIT-1/CRIT-2 recommendations to add a core `ner` Cargo feature are
  superseded.

## References

- [#441](https://github.com/joshjhall/octarine/issues/441) — the decision issue
- [#520](https://github.com/joshjhall/octarine/issues/520) — `Recognizer` trait + LLM recognizer (owns the trait definition)
- [#518](https://github.com/joshjhall/octarine/issues/518) — `RemoteRecognizer` for hosted services
- [#750](https://github.com/joshjhall/octarine/issues/750) — document the `PERSON` / `ORGANIZATION` limitation
- [#751](https://github.com/joshjhall/octarine/issues/751) — `octarine-ner-*` sibling crate (speculative, on hold)
- [#592](https://github.com/joshjhall/octarine/issues/592) — GLiNER ONNX backend (on hold)
- [crate-layout.md](./crate-layout.md) — feature flag vs sibling crate
- [layer-architecture.md](./layer-architecture.md) — layer boundaries
- [`../presidio-gap-analysis.md`](../presidio-gap-analysis.md) — CRIT-1 … CRIT-4, Phase 6
