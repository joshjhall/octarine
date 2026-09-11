# LLM Recognizer Configuration

A declarative TOML schema for LLM-backed PII recognizers. One file describes one
recognizer completely — provider, model, prompt, few-shot examples, entity
mapping, and confidence policy — and the loader picks up edits without a
restart.

## Quick start

Put one file per recognizer in a directory:

```text
conf/recognizers/
├── person_finder_openai.toml
└── person_finder_ollama.toml
```

Load them:

```rust,no_run
use octarine_llm::recognizer::loader;

# fn main() -> Result<(), octarine_problem::Problem> {
let (configs, handle) = loader::from_toml_dir("conf/recognizers")?;
let recognizers = loader::build_all(&configs)?;
# let _ = (recognizers, handle);
# Ok(())
# }
```

Working examples ship in
[`crates/octarine-llm/examples/`](../../crates/octarine-llm/examples/) and are
covered by a test, so they cannot rot.

## Schema

The whole document is one `[recognizer]` table.

### `[recognizer]`

| Field | Type | Required | Default | Meaning |
|---|---|---|---|---|
| `class_name` | string | yes | — | Instance name, unique within the directory. Becomes the recognizer's identity in metrics and audit records. |
| `provider` | string | yes | — | `openai`, `anthropic`, `azure_openai`, `ollama`, or `openai_compatible`. |
| `model` | string | yes | — | Model id in the provider's own namespace. |
| `max_tokens` | integer | no | `2048` | Generated-token ceiling. Must be > 0. |
| `temperature` | float | no | `0.0` | Sampling temperature, `[0.0, 2.0]`. Detection wants determinism. |
| `top_p` | float | no | `1.0` | Nucleus sampling, `[0.0, 1.0]`. **Validated but not yet forwarded** — see [Not yet wired](#not-yet-wired). |
| `enabled` | bool | no | `true` | `false` parks a config without deleting it. It is still validated. |
| `supported_languages` | array | no | `[]` | BCP 47 tags. **Empty means every language**, not none. Enforced: a language outside the set returns no results without calling the provider. |
| `country_code` | string | no | — | ISO 3166-1 alpha-2 scope. **Advisory metadata only** — see [Not yet wired](#not-yet-wired). |
| `api_key_env` | string | no | per provider | **Name** of the env var holding the credential. See [Credentials](#credentials). |
| `base_url` | string | no | — | Required for `openai_compatible`; optional for a remote `ollama`. |
| `endpoint` | string | conditional | — | Required when `provider = "azure_openai"`. |
| `api_version` | string | no | provider default | Azure API version. |

### `[recognizer.prompt]`

| Field | Type | Required | Meaning |
|---|---|---|---|
| `system` | string | yes | The system prompt. **Replaces** the built-in detection prompt entirely. |
| `json_schema` | table | no | **Validated but not yet forwarded** — see [Not yet wired](#not-yet-wired). |

A custom `system` prompt must still ask for the JSON envelope the parser
expects — one `entities` key holding objects with `type`, `text`, and `score`.
A prompt that elicits prose produces a parse error, not a silent empty result.

Ask for the matched **text**, never for character offsets. Octarine recovers
offsets locally by searching the input, which is what makes a hallucinated value
cost recall instead of redacting an unrelated span.

### `[[recognizer.few_shot_examples]]`

Appended to the system prompt in declaration order, rendered as the same JSON
envelope the prompt asks for.

```toml
[[recognizer.few_shot_examples]]
input = "Alice met Bob in NYC"
output = [
  { entity_type = "PERSON", text = "Alice", start = 0, end = 5 },
  { entity_type = "NAMED_LOCATION", text = "NYC", start = 17, end = 20 },
]
```

| Field | Required | Rules |
|---|---|---|
| `input` | yes | Must not be empty. |
| `output[].entity_type` | yes | Must name a known identifier type (see below). |
| `output[].text` | yes | Must appear **verbatim** in `input`. |
| `output[].start` / `.end` | no | Checked as a pair when present; must select exactly `text`. |

`text` is required to appear in `input` because an example quoting absent text
teaches the model that inventing spans is correct.

### `[recognizer.entity_mapping]`

Maps the model's labels onto octarine identifier types. Keys are whatever the
model emits; values must name a known type.

```toml
[recognizer.entity_mapping]
PERSON = "PERSON"
LOCATION = "NAMED_LOCATION"
```

A label with **no** entry passes through unchanged. The mapping narrows
vocabulary differences; it is not an allow-list, so an unmapped label is not
dropped.

### `[recognizer.confidence]`

| `mode` | `value` | Behavior |
|---|---|---|
| `from_model` (default) | must be absent | Keeps the score the model reported. |
| `constant` | required, `[0.0, 1.0]` | Pins every detection to `value`. |

Setting `value` under `from_model` is an **error**, not a no-op: silently
ignoring it would leave you believing the score was pinned when it is not.

### `[recognizer.language_model_params]`

Free-form provider-specific knobs (`seed`, `stop`, …).

**Validated but not yet forwarded** — see [Not yet wired](#not-yet-wired).

## Not yet wired

Three fields are accepted and validated by the schema but do **not** reach the
provider request yet: `top_p`, `prompt.json_schema`, and
`language_model_params`. Each needs a new field on `LlmRequest` plus
serialization in all five provider wire formats, which is its own change.

`country_code` is advisory metadata: nothing filters on it, because
country-aware dispatch belongs to the analyzer registry
([#464](https://github.com/joshjhall/octarine/issues/464)).

They are documented, validated, and range-checked so a config written today
stays correct once they are honored — but **setting one today has no effect on
the request**. `temperature` and `supported_languages`, by contrast, are fully
wired: temperature reaches the provider, and a language outside
`supported_languages` short-circuits before any call.

## Entity type names

`entity_type` strings resolve to octarine's `IdentifierType`. Names are
SCREAMING_SNAKE_CASE, matched case-insensitively. Presidio's spellings are used
where one exists, so a config written against Presidio transfers unchanged:

| TOML name | `IdentifierType` |
|---|---|
| `EMAIL_ADDRESS` | `Email` |
| `PERSON` | `PersonalName` |
| `PHONE_NUMBER` | `PhoneNumber` |
| `US_SSN` | `Ssn` |
| `CREDIT_CARD` | `CreditCard` |
| `IBAN_CODE` | `Iban` |
| `US_BANK_NUMBER` | `BankAccount` |
| `IP_ADDRESS` | `IpAddress` |
| `NAMED_LOCATION` | `NamedLocation` |
| `STREET_ADDRESS` | `StreetAddress` |
| `DATE_TIME` → use `BIRTHDATE` | `Birthdate` |

That table is an excerpt; every `IdentifierType` variant has a label, and
`IdentifierType::as_str` is the authority. Programmatically:

```rust
use std::str::FromStr;
use octarine::identifiers::IdentifierType;

assert_eq!(IdentifierType::from_str("PERSON"), Ok(IdentifierType::PersonalName));
assert_eq!(IdentifierType::PersonalName.as_str(), "PERSON");
```

**Resolution is strict.** An unrecognized name is a load-time error, never a
silent degrade to `Unknown`:

```text
recognizer.few_shot_examples[2].output[0].entity_type: unknown IdentifierType "PERSEN"
```

A typo that loaded clean and then detected nothing would be the worst available
outcome — the config looks healthy while coverage has silently dropped.

## Credentials

A config names the **environment variable** holding its credential; it never
contains the credential. Config files get committed, diffed, and pasted into
issues, so a schema accepting an inline secret guarantees one eventually gets
checked in.

| Provider | Default variable |
|---|---|
| `openai` | `OPENAI_API_KEY` |
| `anthropic` | `ANTHROPIC_API_KEY` |
| `azure_openai` | `AZURE_OPENAI_API_KEY` |
| `ollama` | none — authenticates nothing |
| `openai_compatible` | **none — `api_key_env` is required** |

Override with `api_key_env`. An unset or empty variable fails at construction
with a message naming it, rather than as a 401 several seconds later. A value
with surrounding whitespace (a key piped from a file keeps its trailing newline)
is trimmed rather than sent verbatim.

`openai_compatible` deliberately has **no** default. Its `base_url` points at an
operator-chosen third-party host, so defaulting to `OPENAI_API_KEY` would mean
that forgetting one optional field silently sends a real OpenAI credential to an
unrelated endpoint. Naming the variable is required for that provider, and a
config omitting it fails to load.

## Hot reload

`from_toml_dir` returns the loaded configs plus a `ReloadHandle` that publishes
a fresh set whenever the directory changes:

```rust,no_run
# async fn run(handle: octarine_llm::recognizer::loader::ReloadHandle) {
let mut changes = handle.subscribe();
while changes.changed().await.is_ok() {
    let fresh = changes.borrow_and_update().clone();
    // rebuild and re-register
    # let _ = fresh;
}
# }
```

Behavior worth knowing:

- **Startup is strict.** A broken config at load time is an error — there is no
  previous good state to fall back on, and starting with silently-reduced
  coverage is worse than not starting.
- **Reload is fail-safe.** A reload that does not validate is logged at `warn`
  and **discarded**; the last good configs stay live. Config files are edited in
  place, and an editor's intermediate save is routinely a half-written file —
  swapping that in would disarm a live detector mid-keystroke.
- **Events are debounced** (250 ms). One save is often a write-truncate-write
  burst, which would otherwise be several full reloads.
- **Dropping the handle stops the watcher.**

Reload emits `observe` events under `llm.recognizer.reload`, so a reload — and a
rejected one — is visible in the audit trail.

## Relationship to the analyzer registry

The loader hands back recognizers and a change channel; it does not own a
registry. Octarine's analyzer registry is still unbuilt scope under the
`analyze/` umbrella ([#464](https://github.com/joshjhall/octarine/issues/464)),
and a competing registry in this sibling crate would only have to be migrated
off later. Wiring the handle to a registry is the caller's job today, and #464 is
the intended consumer.

## See also

- [`crates/octarine-llm/examples/`](../../crates/octarine-llm/examples/) — working configs
- [Crate layout](../architecture/crate-layout.md) — why `octarine-llm` is a sibling crate
