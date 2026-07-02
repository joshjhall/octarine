//! InstanceCounter operators — reversible pseudonymization with stable,
//! per-session index tokens.
//!
//! This is octarine's first-class replacement for Presidio's sample-only
//! `InstanceCounterAnonymizer`/`InstanceCounterDeanonymizer` (which live in a
//! notebook and are explicitly documented as **NOT thread-safe**). The pair
//! here mints tokens of the form `<{entity_type}_{index}>` — `<PERSON_0>`,
//! `<PERSON_1>`, `<EMAIL_0>` — that are:
//!
//! - **stable within a session**: the same original value always maps to the
//!   same token, so a name repeated across a prompt (and across turns of a
//!   conversation) reads consistently;
//! - **reversible**: a later deanonymize call rehydrates the model's response
//!   by reversing the session's mappings back to the originals;
//! - **thread-safe by construction**: minting goes through
//!   [`StateStore::get_or_put`](crate::anonymize::StateStore::get_or_put), the
//!   backend's atomic compare-and-set, so two callers racing on the same new
//!   original converge on one token rather than minting divergent ones.
//!
//! Both operators implement [`AsyncOperator`](crate::anonymize::AsyncOperator),
//! not [`Operator`](crate::anonymize::Operator): resolving a token is
//! [`StateStore`](crate::anonymize::StateStore) I/O, and vault access is
//! async-only by the module's load-bearing invariant (see the
//! [`operator`](crate::anonymize) module docs). They are stateless — the store
//! carries all memory, and the store + session are passed per call — so one
//! operator instance serves every session and backend.
//!
//! # Round trip
//!
//! Anonymize a prompt through an [`AnonymizerEngine`](crate::anonymize::AnonymizerEngine)
//! registered with the anonymizer, then reverse the model's reply through a
//! second engine registered with the deanonymizer, both sharing one store and
//! `SessionId`:
//!
//! ```
//! use std::collections::HashMap;
//! use std::sync::Arc;
//! use octarine::anonymize::{
//!     AnonymizerEngine, InstanceCounterAnonymizer, InstanceCounterDeanonymizer,
//!     InMemoryStore, OperatorConfig, RecognizerResult, SessionId, StateStore,
//! };
//!
//! # tokio_test::block_on(async {
//! let store: Arc<dyn StateStore> = Arc::new(InMemoryStore::silent());
//! let session = SessionId::new("chat-42");
//!
//! // Route every entity to the instance_counter operator via the DEFAULT key.
//! let mut ops = HashMap::new();
//! ops.insert(
//!     "DEFAULT".to_string(),
//!     OperatorConfig::new("instance_counter")?,
//! );
//!
//! // 1. Anonymize: "Jane" repeats (same token), "Bob" gets the next index.
//! let anon_engine = AnonymizerEngine::new()
//!     .with_async_operator(Box::new(InstanceCounterAnonymizer::new()))
//!     .with_store(Arc::clone(&store));
//! let text = "Jane and Jane and Bob";
//! let results = vec![
//!     RecognizerResult::new("PERSON", 0, 4, 0.9)?,
//!     RecognizerResult::new("PERSON", 9, 13, 0.9)?,
//!     RecognizerResult::new("PERSON", 18, 21, 0.9)?,
//! ];
//! let anon = anon_engine.anonymize_async(text, results, &ops, &session).await?;
//! assert_eq!(
//!     anon.text.as_deref(),
//!     Some("<PERSON_0> and <PERSON_0> and <PERSON_1>"),
//! );
//!
//! // 2. Deanonymize the (token-bearing) reply against the same store + session.
//! let deanon_engine = AnonymizerEngine::new()
//!     .with_async_operator(Box::new(InstanceCounterDeanonymizer::new()))
//!     .with_store(Arc::clone(&store));
//! let reply = "<PERSON_1> greeted <PERSON_0>";
//! let reply_spans = vec![
//!     RecognizerResult::new("PERSON", 0, 10, 1.0)?,   // <PERSON_1>
//!     RecognizerResult::new("PERSON", 19, 29, 1.0)?,  // <PERSON_0>
//! ];
//! let restored = deanon_engine
//!     .deanonymize_async(reply, reply_spans, &ops, &session)
//!     .await?;
//! assert_eq!(restored.text.as_deref(), Some("Bob greeted Jane"));
//! # Ok::<(), octarine_problem::Problem>(())
//! # });
//! ```

use async_trait::async_trait;
use octarine_problem::{Problem, Result};

use crate::anonymize::{
    AsyncOperator, EntityKey, OperatorConfig, OperatorType, SessionId, StateStore,
};

/// The operator name both InstanceCounter operators register under.
///
/// The pair share one name because they never coexist in a single engine: the
/// forward operator is registered on the anonymize engine, the reverse on a
/// separate deanonymize engine (mirroring the
/// [`Custom`](crate::anonymize::Custom) / [`Custom::deanonymizer`] split). The
/// direction is carried by [`operator_type`](AsyncOperator::operator_type), not
/// the name.
const OPERATOR_NAME: &str = "instance_counter";

/// The `OperatorConfig` parameter key that overrides the default token format.
const FORMAT_PARAM: &str = "format";

/// The default token format: `<{entity_type}_{index}>` → `<PERSON_0>`.
const DEFAULT_FORMAT: &str = "<{entity_type}_{index}>";

/// The `{entity_type}` placeholder a valid format must contain.
const ENTITY_TYPE_PLACEHOLDER: &str = "{entity_type}";

/// The `{index}` placeholder a valid format must contain.
const INDEX_PLACEHOLDER: &str = "{index}";

/// Renders a token from `format` by substituting the entity type and index.
///
/// Both placeholders (`{entity_type}`, `{index}`) are replaced wherever they
/// appear; a format lacking one is rejected up front by
/// [`validate_format`], so a rendered token always reflects both values.
fn render_token(format: &str, entity_type: &str, index: usize) -> String {
    format
        .replace(ENTITY_TYPE_PLACEHOLDER, entity_type)
        .replace(INDEX_PLACEHOLDER, &index.to_string())
}

/// Checks that `format` carries both placeholders a token needs.
///
/// A format missing `{entity_type}` would collide every type's tokens; one
/// missing `{index}` would collide every value's tokens — either silently
/// breaks stability and reversibility, so both are rejected before any span is
/// processed.
fn validate_format(format: &str) -> Result<()> {
    if !format.contains(ENTITY_TYPE_PLACEHOLDER) {
        return Err(Problem::Validation(format!(
            "instance_counter format must contain the '{ENTITY_TYPE_PLACEHOLDER}' placeholder"
        )));
    }
    if !format.contains(INDEX_PLACEHOLDER) {
        return Err(Problem::Validation(format!(
            "instance_counter format must contain the '{INDEX_PLACEHOLDER}' placeholder"
        )));
    }
    Ok(())
}

/// Mints stable per-session tokens (`<PERSON_0>`, `<PERSON_1>`, …) for detected
/// spans, reversible by [`InstanceCounterDeanonymizer`].
///
/// On each span the operator looks the original value up in the
/// [`StateStore`](crate::anonymize::StateStore) for the session: a hit reuses
/// the existing token (stability), and a miss allocates the next index for the
/// entity type and mints a fresh token through the store's **atomic**
/// [`get_or_put`](crate::anonymize::StateStore::get_or_put).
///
/// # Token format
///
/// The default format is `<{entity_type}_{index}>`. Override it per config with
/// a `format` parameter, or per operator with [`with_format`](Self::with_format);
/// a config `format` takes precedence over the operator default. Any format must
/// contain both `{entity_type}` and `{index}` placeholders or
/// [`validate`](AsyncOperator::validate) rejects it.
///
/// # Concurrency
///
/// The mint itself is atomic per key: concurrent callers racing on the **same**
/// new original all observe the one winning token, and the store holds exactly
/// one mapping for it. The *index* is derived from
/// [`list`](crate::anonymize::StateStore::list)`.len()` and is therefore
/// best-effort under a race between two **distinct** new originals of the same
/// type — they may briefly compute the same index. This never corrupts a round
/// trip (each original keeps its own stored token, and reversal is by token
/// value, not by index), and it never loses a mapping; it only means index
/// *sequencing* is not guaranteed gap-free under heavy concurrent distinct-value
/// load. Strict monotonic indexing would need a store-side atomic counter, which
/// the [`StateStore`](crate::anonymize::StateStore) trait deliberately does not
/// expose.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use octarine::anonymize::{
///     AsyncOperator, InMemoryStore, InstanceCounterAnonymizer, OperatorConfig,
///     SessionId, StateStore,
/// };
///
/// # tokio_test::block_on(async {
/// let store: Arc<dyn StateStore> = Arc::new(InMemoryStore::silent());
/// let session = SessionId::new("s1");
/// let op = InstanceCounterAnonymizer::new();
/// let config = OperatorConfig::new("instance_counter")?;
///
/// // First sighting mints index 0; a re-sighting reuses the same token.
/// let a = op.operate_async("Jane", "PERSON", &config, store.as_ref(), &session).await?;
/// let b = op.operate_async("Jane", "PERSON", &config, store.as_ref(), &session).await?;
/// assert_eq!(a, "<PERSON_0>");
/// assert_eq!(b, "<PERSON_0>");
/// # Ok::<(), octarine_problem::Problem>(())
/// # });
/// ```
#[derive(Debug, Clone)]
pub struct InstanceCounterAnonymizer {
    /// The token format used when a config carries no `format` parameter.
    format: String,
}

impl InstanceCounterAnonymizer {
    /// Creates an anonymizer using the default `<{entity_type}_{index}>` format.
    #[must_use]
    pub fn new() -> Self {
        Self {
            format: DEFAULT_FORMAT.to_string(),
        }
    }

    /// Creates an anonymizer with a custom default token `format`.
    ///
    /// The format must contain both `{entity_type}` and `{index}` placeholders;
    /// an invalid one is rejected later by
    /// [`validate`](AsyncOperator::validate), not here, so construction stays
    /// infallible and consistent with the config-supplied path.
    #[must_use]
    pub fn with_format(format: impl Into<String>) -> Self {
        Self {
            format: format.into(),
        }
    }

    /// Resolves the effective format for a call: the config's `format` parameter
    /// if present, otherwise this operator's default.
    fn effective_format<'a>(&'a self, config: &'a OperatorConfig) -> &'a str {
        config.param_str(FORMAT_PARAM).unwrap_or(&self.format)
    }
}

impl Default for InstanceCounterAnonymizer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AsyncOperator for InstanceCounterAnonymizer {
    async fn operate_async(
        &self,
        text: &str,
        entity_type: &str,
        config: &OperatorConfig,
        store: &dyn StateStore,
        session: &SessionId,
    ) -> Result<String> {
        let key = EntityKey::new(entity_type, text);

        // Stability: a value already seen in this session reuses its token.
        if let Some(existing) = store.get(session, &key).await? {
            return Ok(existing);
        }

        // First sighting: allocate the next index for this type, then mint
        // through the atomic get_or_put so a concurrent caller racing on the
        // same original converges on one token instead of minting a divergent
        // one. The returned token is authoritative — it is the value now in the
        // store, which is `candidate` iff this call won the race.
        let index = store.list(session, entity_type).await?.len();
        let candidate = render_token(self.effective_format(config), entity_type, index);
        store.get_or_put(session, &key, candidate).await
    }

    fn validate(&self, config: &OperatorConfig) -> Result<()> {
        validate_format(self.effective_format(config))
    }

    fn operator_name(&self) -> &'static str {
        OPERATOR_NAME
    }

    fn operator_type(&self) -> OperatorType {
        OperatorType::Anonymize
    }
}

/// Reverses [`InstanceCounterAnonymizer`] tokens back to their originals by
/// reading the session's mappings out of the [`StateStore`](crate::anonymize::StateStore).
///
/// For each token span the deanonymizer scans the session's mappings for the
/// entity type and returns the original whose token matches. An **unknown**
/// token (never minted in this session, or from a different one) is handled by
/// the strictness mode:
///
/// - **lenient** (default): the token is returned unchanged, leaving the text
///   as-is. This is the forgiving choice for reversing an LLM reply that may
///   contain tokens the model invented or mangled.
/// - **strict** ([`with_strict`](Self::with_strict)): an unknown token is a
///   [`Problem::Validation`] error, surfacing a broken round trip loudly rather
///   than silently passing a token through.
///
/// It registers under the same `"instance_counter"` name as the anonymizer but
/// reports [`OperatorType::Deanonymize`], and is used on a separate
/// deanonymize engine via
/// [`deanonymize_async`](crate::anonymize::AnonymizerEngine::deanonymize_async).
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use octarine::anonymize::{
///     AsyncOperator, EntityKey, InMemoryStore, InstanceCounterDeanonymizer,
///     OperatorConfig, SessionId, StateStore,
/// };
///
/// # tokio_test::block_on(async {
/// let store: Arc<dyn StateStore> = Arc::new(InMemoryStore::silent());
/// let session = SessionId::new("s1");
/// // Seed a mapping as the anonymizer would have.
/// store.put(&session, &EntityKey::new("PERSON", "Jane"), "<PERSON_0>".to_string()).await?;
///
/// let op = InstanceCounterDeanonymizer::new();
/// let config = OperatorConfig::new("instance_counter")?;
/// let original = op
///     .operate_async("<PERSON_0>", "PERSON", &config, store.as_ref(), &session)
///     .await?;
/// assert_eq!(original, "Jane");
///
/// // Lenient by default: an unknown token passes through unchanged.
/// let unknown = op
///     .operate_async("<PERSON_9>", "PERSON", &config, store.as_ref(), &session)
///     .await?;
/// assert_eq!(unknown, "<PERSON_9>");
/// # Ok::<(), octarine_problem::Problem>(())
/// # });
/// ```
#[derive(Debug, Clone)]
pub struct InstanceCounterDeanonymizer {
    /// When true, an unknown token is an error rather than passed through.
    strict: bool,
}

impl InstanceCounterDeanonymizer {
    /// Creates a lenient deanonymizer: unknown tokens pass through unchanged.
    #[must_use]
    pub fn new() -> Self {
        Self { strict: false }
    }

    /// Sets whether an unknown token is a hard error (`true`) or passes through
    /// unchanged (`false`, the default), returning `self` for chaining.
    #[must_use]
    pub fn with_strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }
}

impl Default for InstanceCounterDeanonymizer {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AsyncOperator for InstanceCounterDeanonymizer {
    async fn operate_async(
        &self,
        text: &str,
        entity_type: &str,
        _config: &OperatorConfig,
        store: &dyn StateStore,
        session: &SessionId,
    ) -> Result<String> {
        for (original, token) in store.list(session, entity_type).await? {
            if token == text {
                return Ok(original);
            }
        }

        if self.strict {
            return Err(Problem::Validation(format!(
                "instance_counter: no mapping for token '{text}' of type '{entity_type}' in this session"
            )));
        }
        // Lenient: leave an unrecognized token in place.
        Ok(text.to_string())
    }

    fn operator_name(&self) -> &'static str {
        OPERATOR_NAME
    }

    fn operator_type(&self) -> OperatorType {
        OperatorType::Deanonymize
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use std::collections::HashMap;
    use std::sync::Arc;

    use serde_json::json;

    use super::*;
    use crate::anonymize::{AnonymizerEngine, InMemoryStore, RecognizerResult};

    fn store() -> Arc<dyn StateStore> {
        Arc::new(InMemoryStore::silent())
    }

    fn cfg() -> OperatorConfig {
        OperatorConfig::new(OPERATOR_NAME).expect("valid config")
    }

    fn rr(entity: &str, start: usize, end: usize) -> RecognizerResult {
        RecognizerResult::new(entity, start, end, 0.9).expect("valid result")
    }

    fn default_ops() -> HashMap<String, OperatorConfig> {
        let mut ops = HashMap::new();
        ops.insert("DEFAULT".to_string(), cfg());
        ops
    }

    #[tokio::test]
    async fn mints_indexed_tokens_and_reuses_them() {
        let store = store();
        let session = SessionId::new("s1");
        let op = InstanceCounterAnonymizer::new();

        // Distinct originals get successive indices...
        let jane = op
            .operate_async("Jane", "PERSON", &cfg(), store.as_ref(), &session)
            .await
            .expect("mint jane");
        let bob = op
            .operate_async("Bob", "PERSON", &cfg(), store.as_ref(), &session)
            .await
            .expect("mint bob");
        assert_eq!(jane, "<PERSON_0>");
        assert_eq!(bob, "<PERSON_1>");

        // ...and a re-sighting of Jane is stable (same token, no new index).
        let jane_again = op
            .operate_async("Jane", "PERSON", &cfg(), store.as_ref(), &session)
            .await
            .expect("re-mint jane");
        assert_eq!(jane_again, "<PERSON_0>");
    }

    #[tokio::test]
    async fn indices_are_per_entity_type() {
        let store = store();
        let session = SessionId::new("s1");
        let op = InstanceCounterAnonymizer::new();

        let person = op
            .operate_async("Jane", "PERSON", &cfg(), store.as_ref(), &session)
            .await
            .expect("mint person");
        let email = op
            .operate_async("jane@acme.com", "EMAIL", &cfg(), store.as_ref(), &session)
            .await
            .expect("mint email");
        // Each type has its own index space, both starting at 0.
        assert_eq!(person, "<PERSON_0>");
        assert_eq!(email, "<EMAIL_0>");
    }

    #[tokio::test]
    async fn tokens_are_scoped_per_session() {
        let store = store();
        let op = InstanceCounterAnonymizer::new();
        let s1 = SessionId::new("s1");
        let s2 = SessionId::new("s2");

        let in_s1 = op
            .operate_async("Jane", "PERSON", &cfg(), store.as_ref(), &s1)
            .await
            .expect("mint s1");
        // A fresh session restarts the index space from 0.
        let in_s2 = op
            .operate_async("Bob", "PERSON", &cfg(), store.as_ref(), &s2)
            .await
            .expect("mint s2");
        assert_eq!(in_s1, "<PERSON_0>");
        assert_eq!(in_s2, "<PERSON_0>");
    }

    #[tokio::test]
    async fn custom_format_via_operator_and_config() {
        let store = store();
        let session = SessionId::new("s1");

        // Operator-level default format.
        let op = InstanceCounterAnonymizer::with_format("[{entity_type}:{index}]");
        let a = op
            .operate_async("Jane", "PERSON", &cfg(), store.as_ref(), &session)
            .await
            .expect("mint");
        assert_eq!(a, "[PERSON:0]");

        // Config-level format overrides the operator default.
        let mut params = HashMap::new();
        params.insert("format".to_string(), json!("{entity_type}#{index}"));
        let config = OperatorConfig::with_params(OPERATOR_NAME, params).expect("cfg");
        let b = op
            .operate_async("Bob", "PERSON", &config, store.as_ref(), &session)
            .await
            .expect("mint override");
        assert_eq!(b, "PERSON#1");
    }

    #[test]
    fn validate_rejects_format_missing_placeholders() {
        let op = InstanceCounterAnonymizer::with_format("<{entity_type}>"); // no {index}
        assert!(op.validate(&cfg()).is_err());

        let op2 = InstanceCounterAnonymizer::with_format("<{index}>"); // no {entity_type}
        assert!(op2.validate(&cfg()).is_err());

        // A valid default and a valid config both pass.
        assert!(InstanceCounterAnonymizer::new().validate(&cfg()).is_ok());
    }

    #[test]
    fn validate_rejects_bad_config_format_even_with_valid_default() {
        let op = InstanceCounterAnonymizer::new(); // valid default
        let mut params = HashMap::new();
        params.insert("format".to_string(), json!("no-placeholders"));
        let config = OperatorConfig::with_params(OPERATOR_NAME, params).expect("cfg");
        assert!(op.validate(&config).is_err());
    }

    #[test]
    fn operator_identity() {
        let anon = InstanceCounterAnonymizer::new();
        assert_eq!(anon.operator_name(), "instance_counter");
        assert_eq!(anon.operator_type(), OperatorType::Anonymize);

        let deanon = InstanceCounterDeanonymizer::new();
        assert_eq!(deanon.operator_name(), "instance_counter");
        assert_eq!(deanon.operator_type(), OperatorType::Deanonymize);
    }

    #[tokio::test]
    async fn deanonymizer_lenient_passes_unknown_token_through() {
        let store = store();
        let session = SessionId::new("s1");
        let deanon = InstanceCounterDeanonymizer::new();
        let out = deanon
            .operate_async("<PERSON_7>", "PERSON", &cfg(), store.as_ref(), &session)
            .await
            .expect("lenient miss");
        assert_eq!(out, "<PERSON_7>");
    }

    #[tokio::test]
    async fn deanonymizer_strict_errors_on_unknown_token() {
        let store = store();
        let session = SessionId::new("s1");
        let deanon = InstanceCounterDeanonymizer::new().with_strict(true);
        let err = deanon
            .operate_async("<PERSON_7>", "PERSON", &cfg(), store.as_ref(), &session)
            .await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn round_trip_restores_originals_through_the_engine() {
        // The headline property: deanonymize(anonymize(text)) == text.
        let store = store();
        let session = SessionId::new("chat-1");
        let text = "Jane emailed Bob about Jane";
        let results = vec![
            rr("PERSON", 0, 4),   // Jane
            rr("PERSON", 13, 16), // Bob
            rr("PERSON", 23, 27), // Jane
        ];

        let anon_engine = AnonymizerEngine::new()
            .with_async_operator(Box::new(InstanceCounterAnonymizer::new()))
            .with_store(Arc::clone(&store));
        let anon = anon_engine
            .anonymize_async(text, results, &default_ops(), &session)
            .await
            .expect("anonymize");
        let anon_text = anon.text.clone().expect("text");
        assert_eq!(anon_text, "<PERSON_0> emailed <PERSON_1> about <PERSON_0>");

        // Reverse using the produced token spans against the same store.
        let reverse_spans: Vec<RecognizerResult> = anon
            .items
            .iter()
            .map(|item| {
                RecognizerResult::new(&item.entity_type, item.start, item.end, 1.0)
                    .expect("valid span")
            })
            .collect();
        let deanon_engine = AnonymizerEngine::new()
            .with_async_operator(Box::new(InstanceCounterDeanonymizer::new()))
            .with_store(Arc::clone(&store));
        let restored = deanon_engine
            .deanonymize_async(&anon_text, reverse_spans, &default_ops(), &session)
            .await
            .expect("deanonymize");
        assert_eq!(restored.text.as_deref(), Some(text));
    }

    #[tokio::test]
    async fn engine_reports_operator_name_on_applied_spans() {
        let store = store();
        let session = SessionId::new("s1");
        let engine = AnonymizerEngine::new()
            .with_async_operator(Box::new(InstanceCounterAnonymizer::new()))
            .with_store(store);
        let out = engine
            .anonymize_async("Bob", vec![rr("PERSON", 0, 3)], &default_ops(), &session)
            .await
            .expect("anonymize");
        assert_eq!(out.text.as_deref(), Some("<PERSON_0>"));
        assert_eq!(
            out.items.first().expect("item").operator.as_deref(),
            Some("instance_counter"),
        );
    }
}
