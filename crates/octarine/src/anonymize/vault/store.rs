//! The [`StateStore`] trait — the backend-agnostic persistence contract behind
//! octarine's reversible pseudonymization.
//!
//! Reversible pseudonymization needs durable per-session state: the mapping
//! from an original PII value (`"Jane Doe"`) to a stable token (`<PERSON_0>`)
//! must survive across multiple anonymize/deanonymize calls in one session and,
//! in multi-replica deployments, across processes. `StateStore` abstracts that
//! storage so the InstanceCounter operators can swap between an in-memory map
//! (tests, single process), Redis (multi-process), or Postgres (durable,
//! auditable) without changing a line of operator code.

use async_trait::async_trait;
use octarine_problem::Result;

use super::types::{EntityKey, SessionId};

/// Backend-agnostic persistence for reversible pseudonymization state.
///
/// A `StateStore` records, per [`SessionId`], the mapping from each
/// [`EntityKey`] (entity type + original value) to the stable token that
/// replaces it. Implementations are responsible for their own concurrency
/// control — an in-memory store guards a map with a lock, Redis relies on its
/// single-threaded-per-key model, Postgres uses `SELECT ... FOR UPDATE` — so
/// that concurrent callers never observe a torn or duplicated mapping. Because
/// the trait is `Send + Sync`, a store is shared across threads as
/// `Arc<dyn StateStore>`.
///
/// All methods are `async`: backends perform network or disk I/O, and even the
/// in-memory store keeps the signature uniform so callers are backend-agnostic.
///
/// # Worked example: protecting an LLM prompt
///
/// The store is the durable half of the round trip. An InstanceCounter
/// anonymizer mints stable tokens through [`get`](StateStore::get) /
/// [`put`](StateStore::put), and a deanonymizer reverses them on the model's
/// response — all keyed off the same [`SessionId`]:
///
/// ```text
/// let store: Arc<dyn StateStore> = Arc::new(InMemoryStore::new()); // #540
/// let session = SessionId::new("chat-42");
///
/// // 1. Anonymize the user's prompt: "Email Jane Doe at jane@acme.com"
/// //    -> "Email <PERSON_0> at <EMAIL_0>"
/// //    Each original is stored once via put(); a repeat of the same value
/// //    re-reads the existing token via get() (stability).
///
/// // 2. Send the anonymized prompt to the model; it replies referencing the
/// //    tokens, e.g. "I drafted a note to <PERSON_0>."
///
/// // 3. Deanonymize the reply by reversing the session's mappings back to the
/// //    originals: "I drafted a note to Jane Doe."
///
/// // 4. When the conversation ends, flush(&session) drops all of its state.
/// ```
///
/// The runnable form of this example arrives with the in-memory backend
/// (#540) and the InstanceCounter operators (#543); see
/// `docs/anonymize/token-vault.md`.
#[async_trait]
pub trait StateStore: Send + Sync {
    /// Returns the stored token for `key` within `session`, or `None` if no
    /// mapping exists yet.
    ///
    /// This is the stability check an anonymizer performs first: a hit means
    /// the original has already been seen in this session and must reuse its
    /// existing token.
    ///
    /// # Errors
    ///
    /// Returns a [`Problem`](octarine_problem::Problem) if the backend cannot
    /// be reached or the lookup fails.
    async fn get(&self, session: &SessionId, key: &EntityKey) -> Result<Option<String>>;

    /// Stores `value` as the token for `key` within `session`.
    ///
    /// Idempotent: storing the same `(session, key)` again overwrites the
    /// previous token. Implementations must apply this atomically with respect
    /// to concurrent [`get`](StateStore::get)/`put` calls so that two callers
    /// racing on a new original never mint divergent tokens.
    ///
    /// # Errors
    ///
    /// Returns a [`Problem`](octarine_problem::Problem) if the backend cannot
    /// be reached or the write fails.
    async fn put(&self, session: &SessionId, key: &EntityKey, value: String) -> Result<()>;

    /// Returns every `(original, token)` pair stored under `entity_type` within
    /// `session`.
    ///
    /// Used to enumerate a session's mappings — for example to build the
    /// reverse lookup a deanonymizer needs, or to count the indices already
    /// allocated for a type. The order of the returned pairs is unspecified.
    ///
    /// # Errors
    ///
    /// Returns a [`Problem`](octarine_problem::Problem) if the backend cannot
    /// be reached or the scan fails.
    async fn list(&self, session: &SessionId, entity_type: &str) -> Result<Vec<(String, String)>>;

    /// Drops all stored state for `session`.
    ///
    /// Called when a session ends (explicit close or TTL expiry). After
    /// flushing, a subsequent [`get`](StateStore::get) for any key in the
    /// session returns `None`. Flushing an unknown session is a no-op success.
    ///
    /// # Errors
    ///
    /// Returns a [`Problem`](octarine_problem::Problem) if the backend cannot
    /// be reached or the delete fails.
    async fn flush(&self, session: &SessionId) -> Result<()>;

    /// Atomically returns the token already stored for `key`, or stores `value`
    /// and returns it if no mapping exists yet.
    ///
    /// This is the **token-minting** primitive an anonymizer must use on the
    /// hot path. A separate [`get`](StateStore::get)-then-[`put`](StateStore::put)
    /// leaves a check-then-act window in which two callers racing on the same
    /// new original each observe `None` and mint *divergent* tokens
    /// (`<PERSON_0>` vs `<PERSON_1>`); the loser's token is then overwritten in
    /// the store while it still lives in an already-anonymized document, so
    /// deanonymization later recovers the wrong original. `get_or_put` closes
    /// that window: the returned `String` is always the single token now in
    /// force for `key` — the caller's `value` if it won the race, or the
    /// previously-stored token otherwise.
    ///
    /// The provided default is **not** atomic — it performs `get` then `put`
    /// and is correct only when callers never race on the same key. Backends
    /// that can offer a true compare-and-set (the in-memory store under its
    /// write lock, Redis `SETNX`, Postgres `INSERT … ON CONFLICT`) **override**
    /// this method to deliver the atomicity the trait contract promises.
    ///
    /// # Errors
    ///
    /// Returns a [`Problem`](octarine_problem::Problem) if the backend cannot
    /// be reached or the operation fails.
    async fn get_or_put(
        &self,
        session: &SessionId,
        key: &EntityKey,
        value: String,
    ) -> Result<String> {
        if let Some(existing) = self.get(session, key).await? {
            return Ok(existing);
        }
        self.put(session, key, value.clone()).await?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, RwLock};

    /// A minimal in-test backend proving the trait is object-safe behind
    /// `Arc<dyn StateStore>` and that its methods are awaitable. This is not
    /// the production in-memory backend (that ships in #540) — it exists only
    /// to exercise the contract declared here.
    #[derive(Default)]
    struct MockStore {
        // (session, entity_type, original) -> token
        inner: RwLock<HashMap<(String, String, String), String>>,
    }

    #[async_trait]
    impl StateStore for MockStore {
        async fn get(&self, session: &SessionId, key: &EntityKey) -> Result<Option<String>> {
            let guard = self
                .inner
                .read()
                .map_err(|e| octarine_problem::Problem::Runtime(format!("lock poisoned: {e}")))?;
            Ok(guard
                .get(&(
                    session.as_str().to_string(),
                    key.entity_type.clone(),
                    key.original.clone(),
                ))
                .cloned())
        }

        async fn put(&self, session: &SessionId, key: &EntityKey, value: String) -> Result<()> {
            let mut guard = self
                .inner
                .write()
                .map_err(|e| octarine_problem::Problem::Runtime(format!("lock poisoned: {e}")))?;
            guard.insert(
                (
                    session.as_str().to_string(),
                    key.entity_type.clone(),
                    key.original.clone(),
                ),
                value,
            );
            Ok(())
        }

        async fn list(
            &self,
            session: &SessionId,
            entity_type: &str,
        ) -> Result<Vec<(String, String)>> {
            let guard = self
                .inner
                .read()
                .map_err(|e| octarine_problem::Problem::Runtime(format!("lock poisoned: {e}")))?;
            Ok(guard
                .iter()
                .filter(|((sess, etype, _), _)| sess == session.as_str() && etype == entity_type)
                .map(|((_, _, original), token)| (original.clone(), token.clone()))
                .collect())
        }

        async fn flush(&self, session: &SessionId) -> Result<()> {
            let mut guard = self
                .inner
                .write()
                .map_err(|e| octarine_problem::Problem::Runtime(format!("lock poisoned: {e}")))?;
            guard.retain(|(sess, _, _), _| sess != session.as_str());
            Ok(())
        }
    }

    #[tokio::test]
    async fn put_then_get_returns_stored_token() {
        let store = MockStore::default();
        let session = SessionId::new("s1");
        let key = EntityKey::new("PERSON", "Jane Doe");

        assert_eq!(store.get(&session, &key).await.expect("get"), None);
        store
            .put(&session, &key, "<PERSON_0>".to_string())
            .await
            .expect("put");
        assert_eq!(
            store.get(&session, &key).await.expect("get"),
            Some("<PERSON_0>".to_string())
        );
    }

    #[tokio::test]
    async fn put_is_idempotent_and_overwrites() {
        let store = MockStore::default();
        let session = SessionId::new("s1");
        let key = EntityKey::new("PERSON", "Jane Doe");

        store
            .put(&session, &key, "<PERSON_0>".to_string())
            .await
            .expect("put");
        store
            .put(&session, &key, "<PERSON_1>".to_string())
            .await
            .expect("put again");
        assert_eq!(
            store.get(&session, &key).await.expect("get"),
            Some("<PERSON_1>".to_string())
        );
    }

    #[tokio::test]
    async fn list_filters_by_entity_type_within_session() {
        let store = MockStore::default();
        let session = SessionId::new("s1");
        store
            .put(
                &session,
                &EntityKey::new("PERSON", "Jane"),
                "<PERSON_0>".to_string(),
            )
            .await
            .expect("put");
        store
            .put(
                &session,
                &EntityKey::new("EMAIL", "jane@acme.com"),
                "<EMAIL_0>".to_string(),
            )
            .await
            .expect("put");

        let persons = store.list(&session, "PERSON").await.expect("list");
        assert_eq!(
            persons,
            vec![("Jane".to_string(), "<PERSON_0>".to_string())]
        );
    }

    #[tokio::test]
    async fn flush_drops_only_the_named_session() {
        let store = MockStore::default();
        let key = EntityKey::new("PERSON", "Jane");
        let s1 = SessionId::new("s1");
        let s2 = SessionId::new("s2");
        store
            .put(&s1, &key, "<PERSON_0>".to_string())
            .await
            .expect("put");
        store
            .put(&s2, &key, "<PERSON_0>".to_string())
            .await
            .expect("put");

        store.flush(&s1).await.expect("flush");
        assert_eq!(store.get(&s1, &key).await.expect("get"), None);
        assert_eq!(
            store.get(&s2, &key).await.expect("get"),
            Some("<PERSON_0>".to_string())
        );
    }

    #[tokio::test]
    async fn usable_as_trait_object_behind_arc() {
        // Guards the `Send + Sync` + object-safety acceptance criterion.
        let store: Arc<dyn StateStore> = Arc::new(MockStore::default());
        let session = SessionId::new("s1");
        let key = EntityKey::new("PERSON", "Jane");
        store
            .put(&session, &key, "<PERSON_0>".to_string())
            .await
            .expect("put");
        assert_eq!(
            store.get(&session, &key).await.expect("get"),
            Some("<PERSON_0>".to_string())
        );
        // Confirm it crosses a task/thread boundary (Send + Sync).
        let moved = Arc::clone(&store);
        tokio::spawn(async move {
            let _ = moved.flush(&SessionId::new("s1")).await;
        })
        .await
        .expect("join");
    }
}
