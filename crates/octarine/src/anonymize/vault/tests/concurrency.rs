//! Backend-generic concurrency conformance for the vault [`StateStore`].
//!
//! Presidio's `InstanceCounterAnonymizer` ships in a sample notebook that
//! states outright: *"The following logic is NOT thread-safe."* Its mapping is
//! a plain Python dict mutated without a lock, so concurrent conversations can
//! mint divergent tokens for the same value, skip or reuse counter indices, and
//! leak tokens across sessions. Octarine ships the opposite as a **test-enforced
//! contract**: every [`StateStore`] backend must hold the thread-safety
//! invariants below under load, or CI fails before the regression lands.
//!
//! The five scenarios are written once as backend-agnostic harness functions
//! over `Arc<dyn StateStore>` and instantiated per backend by
//! [`vault_concurrency_suite!`]. Today only the default [`InMemoryStore`]
//! exists, so the suite runs against it unconditionally. When the Redis and
//! Postgres backends land (follow-up work — they do not exist yet, nor does a
//! `redis`/`postgres` storage feature for them), each earns the entire suite by
//! adding a single `vault_concurrency_suite!(backend, <ctor>)` line under the
//! appropriate `#[cfg(feature = ...)]`; no test logic is duplicated. Issue #545
//! acceptance criteria 3-4 (Redis/Postgres feature-gated runs) are deferred to
//! those backend issues for exactly this reason — the harness is the
//! deliverable that makes them one line each.
//!
//! Resilience: no fixed sleeps. Scheduling pressure comes from
//! [`tokio::task::yield_now`] inside multi-threaded runtimes, and the suite is
//! validated under high-parallelism nextest runs. See
//! `docs/audits/presidio/00-feature-master.md` §V.2 and the disclaimer in
//! `docs/samples/python/pseudonymization.ipynb`.

#![allow(clippy::panic, clippy::expect_used)]

use std::collections::HashSet;
use std::sync::Arc;

use super::super::{EntityKey, InMemoryStore, SessionId, StateStore};

/// Number of concurrent participants in the put/index/session scenarios.
const PARTICIPANTS: usize = 100;
/// Number of operations in the read-during-write scenario.
const RW_OPS: usize = 1000;
/// Number of writes raced against a flush.
const FLUSH_WRITES: usize = 200;

/// Extracts the trailing index `N` from a `<PERSON_N>` token, or `None` if the
/// token is not in that exact shape. Callers turn a `None` into an assertion
/// failure that prints the offending token, so a torn or malformed entry — the
/// very thing these tests hunt — surfaces as a descriptive failure rather than
/// a bare panic inside the helper. Avoids indexing/slicing (both denied by the
/// project clippy config).
fn person_index(token: &str) -> Option<usize> {
    token
        .strip_prefix("<PERSON_")
        .and_then(|rest| rest.strip_suffix('>'))
        .and_then(|digits| digits.parse().ok())
}

/// **Stability under concurrent put.** Disproves the Presidio footgun where two
/// threads racing on the same new value each observe an empty dict and mint
/// divergent tokens. `PARTICIPANTS` tasks all mint a token for the *same*
/// original; the atomic `get_or_put` must collapse them onto one stable token.
async fn stability_under_concurrent_put(store: Arc<dyn StateStore>) {
    let session = SessionId::new("hot-session");
    let key = EntityKey::new("PERSON", "Jane Doe");

    let mut handles = Vec::with_capacity(PARTICIPANTS);
    for i in 0..PARTICIPANTS {
        let store = Arc::clone(&store);
        let session = session.clone();
        let key = key.clone();
        handles.push(tokio::spawn(async move {
            // Yield before the race so participants interleave on the lock.
            tokio::task::yield_now().await;
            store
                .get_or_put(&session, &key, format!("<PERSON_{i}>"))
                .await
                .expect("get_or_put")
        }));
    }

    let mut tokens = Vec::with_capacity(PARTICIPANTS);
    for h in handles {
        tokens.push(h.await.expect("join"));
    }

    let winner = tokens.first().expect("at least one token").clone();
    assert!(
        tokens.iter().all(|t| *t == winner),
        "all racing callers must receive one stable token; got divergent {tokens:?}"
    );
    assert_eq!(
        store.list(&session, "PERSON").await.expect("list").len(),
        1,
        "exactly one mapping may exist for the shared original"
    );
}

/// **No lost writes under index pressure.** Disproves the Presidio footgun where
/// concurrent writes to a shared mapping clobber each other so the counter's
/// index space ends up with holes or collisions. Index *allocation* itself is
/// the InstanceCounter operator's job (it owns the counter); the store's
/// contract is narrower and is what this test pins: `PARTICIPANTS` distinct
/// originals, each carrying its own already-claimed index `i`, written
/// concurrently must *all* survive — no write swallowed by a racing one — so the
/// persisted indices cover `[0..PARTICIPANTS)` exactly. A store that dropped or
/// overwrote a concurrent write would leave a hole the assertion catches. (The
/// earlier shape of this test fed indices from a test-local `AtomicUsize`, which
/// only re-proved that `AtomicUsize` is atomic — a std guarantee, not a store
/// property; the index now comes straight from each task's own `i`.)
async fn no_lost_writes_across_index_space(store: Arc<dyn StateStore>) {
    let session = SessionId::new("index-space");

    let mut handles = Vec::with_capacity(PARTICIPANTS);
    for i in 0..PARTICIPANTS {
        let store = Arc::clone(&store);
        let session = session.clone();
        handles.push(tokio::spawn(async move {
            let key = EntityKey::new("PERSON", format!("person-{i}"));
            tokio::task::yield_now().await;
            store
                .get_or_put(&session, &key, format!("<PERSON_{i}>"))
                .await
                .expect("get_or_put");
        }));
    }
    for h in handles {
        h.await.expect("join");
    }

    let listed = store.list(&session, "PERSON").await.expect("list");
    assert_eq!(
        listed.len(),
        PARTICIPANTS,
        "every distinct concurrent write must persist exactly once"
    );
    let indices: HashSet<usize> = listed
        .iter()
        .map(|(_, token)| {
            person_index(token).unwrap_or_else(|| panic!("malformed token {token:?}"))
        })
        .collect();
    assert_eq!(
        indices,
        (0..PARTICIPANTS).collect::<HashSet<usize>>(),
        "the index space [0..{PARTICIPANTS}) must be fully and uniquely covered"
    );
}

/// **Cross-session isolation under load.** Disproves the Presidio footgun where
/// one global mapping with no session scope lets concurrent conversations share
/// and leak tokens. Ten sessions run 50 ops each in parallel over *identical*
/// originals; every session must end holding exactly its own deterministic
/// token for each original, with none bleeding across a session boundary.
async fn cross_session_isolation(store: Arc<dyn StateStore>) {
    const SESSIONS: usize = 10;
    const OPS_PER_SESSION: usize = 50;

    let mut handles = Vec::with_capacity(SESSIONS);
    for s in 0..SESSIONS {
        let store = Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            let session = SessionId::new(format!("sess-{s}"));
            for j in 0..OPS_PER_SESSION {
                // Same original `orig-{j}` across every session: isolation, not
                // value uniqueness, is what must keep the tokens distinct.
                let key = EntityKey::new("PERSON", format!("orig-{j}"));
                tokio::task::yield_now().await;
                store
                    .get_or_put(&session, &key, format!("<PERSON_{s}_{j}>"))
                    .await
                    .expect("get_or_put");
            }
        }));
    }
    for h in handles {
        h.await.expect("join");
    }

    for s in 0..SESSIONS {
        let session = SessionId::new(format!("sess-{s}"));
        assert_eq!(
            store.list(&session, "PERSON").await.expect("list").len(),
            OPS_PER_SESSION,
            "session {s} must hold exactly its own {OPS_PER_SESSION} mappings"
        );
        // Exact-token equality (not a prefix check, which would be ambiguous
        // once a session index becomes a prefix of another, e.g. 1 vs 10).
        for j in 0..OPS_PER_SESSION {
            let key = EntityKey::new("PERSON", format!("orig-{j}"));
            assert_eq!(
                store.get(&session, &key).await.expect("get"),
                Some(format!("<PERSON_{s}_{j}>")),
                "token for orig-{j} in session {s} bled or was clobbered"
            );
        }
    }
}

/// **Read-during-write.** Disproves the Presidio footgun where listing the dict
/// while another thread writes can surface a half-updated entry. One writer
/// performs `RW_OPS` puts while one reader performs `RW_OPS` lists; the reader
/// must only ever observe fully-written, self-consistent entries (each token is
/// the exact token for its original), never a torn pair.
async fn read_during_write(store: Arc<dyn StateStore>) {
    let session = SessionId::new("read-write");

    let writer = {
        let store = Arc::clone(&store);
        let session = session.clone();
        tokio::spawn(async move {
            for i in 0..RW_OPS {
                let key = EntityKey::new("PERSON", format!("person-{i}"));
                store
                    .put(&session, &key, format!("<PERSON_{i}>"))
                    .await
                    .expect("put");
                tokio::task::yield_now().await;
            }
        })
    };

    let reader = {
        let store = Arc::clone(&store);
        let session = session.clone();
        tokio::spawn(async move {
            for _ in 0..RW_OPS {
                let snapshot = store.list(&session, "PERSON").await.expect("list");
                for (original, token) in snapshot {
                    // A torn entry would pair an original with someone else's
                    // token; a fully-written one always round-trips.
                    let idx = person_index(&token)
                        .unwrap_or_else(|| panic!("reader saw malformed token {token:?}"));
                    assert_eq!(
                        original,
                        format!("person-{idx}"),
                        "reader observed a torn entry: {original:?} -> {token:?}"
                    );
                }
                tokio::task::yield_now().await;
            }
        })
    };

    // join! polls both join handles together, so a reader panic is captured in
    // `r` without first blocking on the writer's full run.
    let (w, r) = tokio::join!(writer, reader);
    w.expect("writer join");
    r.expect("reader join");

    assert_eq!(
        store
            .list(&session, "PERSON")
            .await
            .expect("final list")
            .len(),
        RW_OPS,
        "every write must be durable once the writer completes"
    );
}

/// **Flush during use.** Disproves the Presidio footgun where clearing the dict
/// while another thread mutates it corrupts the map. Two complementary checks:
///
/// 1. *Concurrent safety (race):* a flush runs genuinely concurrently with a
///    burst of `FLUSH_WRITES` puts. Whatever survives must be internally
///    coherent — the flush may drop a prefix of writes, but it must never tear
///    an individual entry or deadlock. (Which writes survive is timing
///    dependent, so per octarine-test-resilience Rule 3 the count is *not*
///    asserted — only the coherence of whatever landed. The multi-threaded
///    runtime plus nextest CI retries exercise the interleaving across runs.)
/// 2. *Flush semantics (deterministic):* with no concurrency, pre-flush entries
///    are all gone after a flush and the cleared session still accepts writes —
///    flush wins, and post-flush puts land in the cleared session.
async fn flush_during_use(store: Arc<dyn StateStore>) {
    let session = SessionId::new("flush-race");

    // Spawn the flusher first so it starts racing from the first yield rather
    // than after the writer has had a head start.
    let flusher = {
        let store = Arc::clone(&store);
        let session = session.clone();
        tokio::spawn(async move {
            // Let a few writes accumulate, then flush mid-stream — no sleep,
            // just a handful of scheduler yields so the flush lands between puts.
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            store.flush(&session).await.expect("flush");
        })
    };

    let writer = {
        let store = Arc::clone(&store);
        let session = session.clone();
        tokio::spawn(async move {
            for i in 0..FLUSH_WRITES {
                let key = EntityKey::new("PERSON", format!("person-{i}"));
                store
                    .put(&session, &key, format!("<PERSON_{i}>"))
                    .await
                    .expect("put");
                tokio::task::yield_now().await;
            }
        })
    };

    let (f, w) = tokio::join!(flusher, writer);
    f.expect("flusher join");
    w.expect("writer join");

    // (1) Whatever survived the concurrent race must be internally coherent: the
    // flush removed a prefix of writes, never tore an individual entry.
    for (original, token) in store.list(&session, "PERSON").await.expect("list") {
        let idx = person_index(&token)
            .unwrap_or_else(|| panic!("flush race left a malformed token {token:?}"));
        assert_eq!(
            original,
            format!("person-{idx}"),
            "flush race left a torn entry: {original:?} -> {token:?}"
        );
    }

    // (2) Deterministic flush semantics on a fresh session: a flush wins over
    // prior writes, and the cleared session still accepts new ones.
    let det = SessionId::new("flush-deterministic");
    for i in 0..FLUSH_WRITES {
        let key = EntityKey::new("PERSON", format!("person-{i}"));
        store
            .put(&det, &key, format!("<PERSON_{i}>"))
            .await
            .expect("pre-flush put");
    }
    store.flush(&det).await.expect("flush");
    assert!(
        store.list(&det, "PERSON").await.expect("list").is_empty(),
        "flush must drop every pre-flush entry"
    );

    let sentinel = EntityKey::new("PERSON", "post-flush-sentinel");
    store
        .put(&det, &sentinel, "<PERSON_sentinel>".to_string())
        .await
        .expect("post-flush put");
    assert_eq!(
        store.get(&det, &sentinel).await.expect("get"),
        Some("<PERSON_sentinel>".to_string()),
        "post-flush puts must go into the cleared session"
    );
}

/// Instantiates the full backend-generic concurrency suite for one
/// [`StateStore`] backend.
///
/// `$backend` names the generated child module; `$ctor` is an expression
/// yielding the `Arc<dyn StateStore>` under test (re-evaluated fresh per test so
/// each starts from an empty store). Adding a backend is one line.
///
/// The example below is `ignore`d (not compiled) because `RedisStore` and the
/// `redis` feature do not exist yet — it documents the future call site:
/// ```ignore
/// // When the Redis backend + feature land (follow-up work):
/// #[cfg(feature = "redis")]
/// vault_concurrency_suite!(redis, Arc::new(RedisStore::connect(test_url())) as Arc<dyn StateStore>);
/// ```
macro_rules! vault_concurrency_suite {
    ($backend:ident, $ctor:expr) => {
        mod $backend {
            use super::*;

            #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
            async fn stability_under_concurrent_put() {
                super::stability_under_concurrent_put($ctor).await;
            }

            #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
            async fn no_lost_writes_across_index_space() {
                super::no_lost_writes_across_index_space($ctor).await;
            }

            #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
            async fn cross_session_isolation() {
                super::cross_session_isolation($ctor).await;
            }

            #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
            async fn read_during_write() {
                super::read_during_write($ctor).await;
            }

            #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
            async fn flush_during_use() {
                super::flush_during_use($ctor).await;
            }
        }
    };
}

// The default, always-present backend. Redis/Postgres add their own line here
// behind a feature gate when those backends exist.
vault_concurrency_suite!(
    in_memory,
    Arc::new(InMemoryStore::silent()) as Arc<dyn StateStore>
);
