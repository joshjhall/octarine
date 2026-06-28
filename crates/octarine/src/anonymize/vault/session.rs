//! [`SessionManager`] — the session-lifecycle API over a [`StateStore`].
//!
//! A bare [`StateStore`] records `(session, key) → token` mappings but has no
//! notion of a session *beginning* or *ending*: a [`SessionId`] is just a label
//! the caller invents, and abandoned sessions accumulate in the backend forever.
//! `SessionManager` adds the missing lifecycle:
//!
//! - [`open`](SessionManager::open) mints a fresh time-ordered [`SessionId`]
//!   (UUID-v7) with an optional TTL.
//! - [`close`](SessionManager::close) ends a session explicitly, flushing its
//!   state from the store.
//! - [`touch`](SessionManager::touch) resets a session's TTL clock — call it on
//!   every interaction to keep an active conversation alive.
//! - A background sweep ([`start_sweep`](SessionManager::start_sweep) /
//!   [`sweep_now`](SessionManager::sweep_now)) purges sessions whose TTL has
//!   elapsed, so abandoned sessions are reclaimed on the schedule a retention
//!   policy mandates without the operator writing a cron job.
//!
//! # Why TTL is first-class
//!
//! Presidio's `InstanceCounterAnonymizer` keeps its mapping in a plain Python
//! dict that lives as long as the process — there is no concept of expiry.
//! Octarine ships TTL by default because compliance regimes (HIPAA's
//! minimum-necessary retention, GDPR storage limitation) require pseudonymized
//! state to be purged on a bounded schedule. The TTL *is* the retention control.
//!
//! # TTL strategy
//!
//! TTL here is enforced **manager-side**: a tokio interval task periodically
//! calls [`StateStore::flush`] on every expired session. This is backend-agnostic
//! and is the strategy the default [`InMemoryStore`](super::InMemoryStore) uses.
//! Stateful backends that land later (Redis, Postgres) can additionally push
//! expiry *into* the store — Redis via native `EXPIRE` on the session hash,
//! Postgres via an `expires_at` column and a SQL sweep — so the database
//! reclaims space even when no manager process is running. See
//! `docs/anonymize/token-vault.md`.
//!
//! # Privacy
//!
//! A session holds no PII: it tracks only a [`SessionId`] (a non-secret routing
//! label) and an expiry deadline. The original values live in the
//! [`StateStore`], which the manager only ever references by session. Observe
//! events therefore carry the session id alone — never an original value or
//! token.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use uuid::Uuid;

use octarine_problem::{Problem, Result};

use super::StateStore;
use super::types::SessionId;
use crate::observe;
use crate::observe::metrics::increment_by;

crate::define_metrics! {
    open_count => "anonymize.vault.session_open_count",
    close_count => "anonymize.vault.session_close_count",
    expire_count => "anonymize.vault.session_expire_count",
}

/// Operation context label for this module's observe events.
const OP: &str = "anonymize.vault.session";

/// Default cadence of the background expiry sweep when none is configured.
///
/// Sixty seconds balances promptness against wakeup overhead: a session with a
/// TTL of `T` is purged at most `DEFAULT_SWEEP_INTERVAL` after `T` elapses.
/// Override with [`SessionManager::with_sweep_interval`] when a tighter
/// retention bound is required.
pub const DEFAULT_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Per-session options supplied to [`SessionManager::open`].
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use octarine::anonymize::SessionOptions;
///
/// // A 30-minute session, server-assigned id.
/// let opts = SessionOptions::with_ttl(Duration::from_secs(1800));
/// assert_eq!(opts.ttl, Some(Duration::from_secs(1800)));
///
/// // A never-expiring session with a caller-chosen, deterministic id.
/// let pinned = SessionOptions::default().id_hint("chat-42");
/// assert_eq!(pinned.ttl, None);
/// assert_eq!(pinned.id_hint.as_deref(), Some("chat-42"));
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionOptions {
    /// Time-to-live for the session. `None` means the session never expires and
    /// the sweep ignores it (the caller must [`close`](SessionManager::close) it
    /// explicitly).
    pub ttl: Option<Duration>,
    /// A caller-supplied id to use verbatim instead of minting a fresh UUID-v7.
    ///
    /// Intended for deterministic tests and for adopting an externally-issued
    /// session identifier. When `None`, [`open`](SessionManager::open) mints a
    /// time-ordered UUID-v7.
    pub id_hint: Option<String>,
}

impl SessionOptions {
    /// Options for a session that expires `ttl` after it is opened (or last
    /// touched), with a server-minted id.
    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            ttl: Some(ttl),
            id_hint: None,
        }
    }

    /// Sets a deterministic id to use instead of a minted UUID-v7.
    #[must_use]
    pub fn id_hint(mut self, hint: impl Into<String>) -> Self {
        self.id_hint = Some(hint.into());
        self
    }
}

/// One session's bookkeeping: its configured TTL and current expiry deadline.
struct Lease {
    /// The configured TTL, retained so [`touch`](SessionManager::touch) can
    /// recompute a fresh deadline. `None` ⇒ the session never expires.
    ttl: Option<Duration>,
    /// The instant at which this session expires, or `None` when it has no TTL.
    deadline: Option<Instant>,
}

impl Lease {
    /// Builds a lease, computing the deadline from `now + ttl`. A pathological
    /// TTL that overflows the clock collapses to "no expiry" rather than
    /// panicking (`checked_add` keeps the denied `arithmetic_side_effects` lint
    /// satisfied).
    fn new(ttl: Option<Duration>) -> Self {
        let deadline = ttl.and_then(|ttl| Instant::now().checked_add(ttl));
        Self { ttl, deadline }
    }
}

/// Session-lifecycle API layered over a [`StateStore`].
///
/// Construct one over an `Arc`-shared store, then [`open`](Self::open) sessions
/// to mint ids and [`close`](Self::close) them to flush state. Enable automatic
/// TTL reclamation with [`start_sweep`](Self::start_sweep); the spawned task is
/// aborted when the manager is dropped.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use std::time::Duration;
/// use octarine::anonymize::{InMemoryStore, SessionManager, SessionOptions};
///
/// # tokio_test::block_on(async {
/// let store = Arc::new(InMemoryStore::silent());
/// let sessions = SessionManager::new(Arc::clone(&store)).silent();
///
/// // Open a 30-minute session; `id` is a fresh UUID-v7.
/// let id = sessions.open(SessionOptions::with_ttl(Duration::from_secs(1800)));
///
/// // ... anonymize/deanonymize through `store` keyed by `id` ...
///
/// // End it explicitly: flushes the session's mappings from the store.
/// sessions.close(&id).await?;
/// # Ok::<(), octarine_problem::Problem>(())
/// # });
/// ```
pub struct SessionManager<S: StateStore> {
    store: Arc<S>,
    leases: Arc<Mutex<HashMap<SessionId, Lease>>>,
    sweep_interval: Duration,
    sweep_handle: Mutex<Option<JoinHandle<()>>>,
    emit_events: bool,
}

impl<S: StateStore> SessionManager<S> {
    /// Creates a manager over `store` with the [`DEFAULT_SWEEP_INTERVAL`] and
    /// audit events enabled.
    #[must_use]
    pub fn new(store: Arc<S>) -> Self {
        Self {
            store,
            leases: Arc::new(Mutex::new(HashMap::new())),
            sweep_interval: DEFAULT_SWEEP_INTERVAL,
            sweep_handle: Mutex::new(None),
            emit_events: true,
        }
    }

    /// Sets the cadence of the background expiry sweep.
    #[must_use]
    pub fn with_sweep_interval(mut self, interval: Duration) -> Self {
        self.sweep_interval = interval;
        self
    }

    /// Suppresses all observe events and metrics from this manager.
    ///
    /// Useful when the manager is a test fixture or a transient helper and the
    /// per-`open`/`close` audit events would only be noise.
    #[must_use]
    pub fn silent(mut self) -> Self {
        self.emit_events = false;
        self
    }

    /// The configured sweep cadence.
    #[must_use]
    pub fn sweep_interval(&self) -> Duration {
        self.sweep_interval
    }

    /// The number of sessions currently tracked (open and not yet closed or
    /// expired).
    #[must_use]
    pub fn tracked_sessions(&self) -> usize {
        self.leases.lock().len()
    }

    /// Whether `id` is currently an open, tracked session.
    #[must_use]
    pub fn is_open(&self, id: &SessionId) -> bool {
        self.leases.lock().contains_key(id)
    }

    /// Opens a new session, returning its [`SessionId`].
    ///
    /// With [`SessionOptions::id_hint`] set the id is that hint verbatim;
    /// otherwise a fresh time-ordered **UUID-v7** is minted (time-ordered so
    /// that session ids sort by creation time for log correlation). A session
    /// opened with a TTL becomes eligible for the expiry sweep; one without a
    /// TTL lives until it is [`close`](Self::close)d.
    ///
    /// Infallible and synchronous: opening only records local bookkeeping, never
    /// touches the store.
    pub fn open(&self, opts: SessionOptions) -> SessionId {
        let id = match opts.id_hint {
            Some(hint) => SessionId::new(hint),
            None => SessionId::new(Uuid::now_v7().to_string()),
        };

        self.leases.lock().insert(id.clone(), Lease::new(opts.ttl));

        if self.emit_events {
            increment_by(metric_names::open_count(), 1);
            observe::debug(OP, format!("opened session {id}"));
        }

        id
    }

    /// Closes `id`, flushing every mapping it owns from the store.
    ///
    /// Removes the session's bookkeeping and calls [`StateStore::flush`]; after
    /// this returns the store holds no state for `id`. Closing a session that is
    /// not tracked (already closed, expired, or never opened) still flushes the
    /// store — [`flush`](StateStore::flush) is a no-op success on an unknown
    /// session — so close is idempotent.
    ///
    /// # Errors
    ///
    /// Returns a [`Problem`] if the backend flush fails.
    pub async fn close(&self, id: &SessionId) -> Result<()> {
        // Drop the lease before awaiting so the (non-async) lock is never held
        // across the store I/O.
        self.leases.lock().remove(id);

        self.store.flush(id).await?;

        if self.emit_events {
            increment_by(metric_names::close_count(), 1);
            observe::debug(OP, format!("closed session {id}"));
        }

        Ok(())
    }

    /// Resets the TTL clock on an open session.
    ///
    /// Recomputes the expiry deadline as `now + ttl`, keeping an actively-used
    /// session from being swept. A session opened without a TTL stays
    /// non-expiring (touch is a successful no-op on its deadline).
    ///
    /// # Errors
    ///
    /// Returns [`Problem::NotFound`] if `id` is not an open session.
    //
    // Async for backend parity even though the in-memory path does no I/O: a
    // Redis-backed manager re-issues `EXPIRE` here, which is a round trip.
    #[allow(clippy::unused_async)]
    pub async fn touch(&self, id: &SessionId) -> Result<()> {
        let mut guard = self.leases.lock();
        let lease = guard
            .get_mut(id)
            .ok_or_else(|| Problem::NotFound(format!("session {id} is not open")))?;
        lease.deadline = lease.ttl.and_then(|ttl| Instant::now().checked_add(ttl));
        Ok(())
    }

    /// Runs one expiry pass synchronously, flushing every session whose TTL has
    /// elapsed, and returns how many were reclaimed.
    ///
    /// This is the same work the background sweep performs each tick, exposed so
    /// callers (and deterministic `start_paused` tests) can force a pass without
    /// waiting on the interval task.
    ///
    /// # Errors
    ///
    /// Returns a [`Problem`] if flushing an expired session fails; sessions
    /// before the failure are already removed.
    pub async fn sweep_now(&self) -> Result<usize> {
        sweep_expired(self.store.as_ref(), &self.leases, self.emit_events).await
    }
}

impl<S: StateStore + 'static> SessionManager<S> {
    /// Starts the background expiry sweep, if not already running.
    ///
    /// Spawns a tokio task that calls [`sweep_now`](Self::sweep_now) every
    /// [`sweep_interval`](Self::sweep_interval). Calling it again while a sweep
    /// is running is a no-op. The task is aborted by
    /// [`stop_sweep`](Self::stop_sweep) or when the manager is dropped.
    ///
    /// # Panics
    ///
    /// Must be called from within a tokio runtime (it uses [`tokio::spawn`]);
    /// calling it outside one panics, per tokio's contract.
    pub fn start_sweep(&self) {
        let mut handle = self.sweep_handle.lock();
        if handle.is_some() {
            return;
        }

        let store = Arc::clone(&self.store);
        let leases = Arc::clone(&self.leases);
        let interval = self.sweep_interval;
        let emit_events = self.emit_events;

        if emit_events {
            observe::info(
                OP,
                format!("starting session expiry sweep (interval: {interval:?})"),
            );
        }

        *handle = Some(tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);
            // The first tick fires immediately; consume it so the first real
            // sweep happens one full interval in, not at t=0.
            timer.tick().await;
            loop {
                timer.tick().await;
                if let Err(e) = sweep_expired(store.as_ref(), &leases, emit_events).await {
                    observe::warn(OP, format!("session expiry sweep failed: {e}"));
                }
            }
        }));
    }

    /// Stops the background expiry sweep if one is running.
    ///
    /// Idempotent: a no-op when no sweep is active. Manual TTL passes via
    /// [`sweep_now`](Self::sweep_now) remain available afterwards.
    pub fn stop_sweep(&self) {
        if let Some(handle) = self.sweep_handle.lock().take() {
            handle.abort();
        }
    }

    /// Whether the background sweep task is currently running.
    #[must_use]
    pub fn is_sweeping(&self) -> bool {
        self.sweep_handle.lock().is_some()
    }
}

/// Flushes every expired session from the store and returns the count reclaimed.
///
/// Shared by [`SessionManager::sweep_now`] and the spawned sweep loop. Expired
/// ids are collected and removed under the lease lock, which is then released
/// **before** any store I/O so the synchronous `parking_lot` guard is never held
/// across an `await`.
async fn sweep_expired<S: StateStore>(
    store: &S,
    leases: &Mutex<HashMap<SessionId, Lease>>,
    emit_events: bool,
) -> Result<usize> {
    let now = Instant::now();
    let expired: Vec<SessionId> = {
        let mut guard = leases.lock();
        let expired: Vec<SessionId> = guard
            .iter()
            .filter(|(_, lease)| lease.deadline.is_some_and(|deadline| deadline <= now))
            .map(|(id, _)| id.clone())
            .collect();
        for id in &expired {
            guard.remove(id);
        }
        expired
    };

    for id in &expired {
        store.flush(id).await?;
        if emit_events {
            increment_by(metric_names::expire_count(), 1);
            observe::debug(OP, format!("expired session {id} (TTL elapsed)"));
        }
    }

    Ok(expired.len())
}

impl<S: StateStore> Drop for SessionManager<S> {
    fn drop(&mut self) {
        if let Some(handle) = self.sweep_handle.lock().take() {
            handle.abort();
        }
    }
}

/// Prints session-lifecycle metadata only — a tracked-session count, the sweep
/// cadence, and whether a sweep is active. Never enumerates session ids.
impl<S: StateStore> fmt::Debug for SessionManager<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Read the sweep handle directly rather than via `is_sweeping()`, whose
        // `impl` block carries a `'static` bound this `Debug` impl does not.
        let sweeping = self.sweep_handle.lock().is_some();
        f.debug_struct("SessionManager")
            .field("tracked_sessions", &self.tracked_sessions())
            .field("sweep_interval", &self.sweep_interval)
            .field("sweeping", &sweeping)
            .field("emit_events", &self.emit_events)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::panic, clippy::expect_used)]
    use super::*;
    use crate::anonymize::{EntityKey, InMemoryStore};

    fn manager() -> SessionManager<InMemoryStore> {
        SessionManager::new(Arc::new(InMemoryStore::silent())).silent()
    }

    fn manager_with_store() -> (SessionManager<InMemoryStore>, Arc<InMemoryStore>) {
        let store = Arc::new(InMemoryStore::silent());
        let mgr = SessionManager::new(Arc::clone(&store)).silent();
        (mgr, store)
    }

    #[tokio::test]
    async fn open_without_hint_mints_uuid_v7() {
        let mgr = manager();
        let id = mgr.open(SessionOptions::default());
        let uuid = Uuid::parse_str(id.as_str()).expect("session id is a valid UUID");
        assert_eq!(uuid.get_version_num(), 7, "must mint a UUID-v7");
        assert!(mgr.is_open(&id));
    }

    #[tokio::test]
    async fn open_mints_distinct_ids() {
        let mgr = manager();
        let a = mgr.open(SessionOptions::default());
        let b = mgr.open(SessionOptions::default());
        assert_ne!(a, b, "each open must mint a fresh id");
        assert_eq!(mgr.tracked_sessions(), 2);
    }

    #[tokio::test]
    async fn open_with_id_hint_is_deterministic() {
        let mgr = manager();
        let id = mgr.open(SessionOptions::default().id_hint("chat-42"));
        assert_eq!(id.as_str(), "chat-42");
    }

    #[tokio::test]
    async fn close_flushes_session_state_from_store() {
        let (mgr, store) = manager_with_store();
        let id = mgr.open(SessionOptions::default());
        let key = EntityKey::new("PERSON", "Jane Doe");
        store
            .put(&id, &key, "<PERSON_0>".to_string())
            .await
            .expect("put");

        mgr.close(&id).await.expect("close");

        assert_eq!(store.get(&id, &key).await.expect("get"), None);
        assert!(!mgr.is_open(&id), "closed session is no longer tracked");
    }

    #[tokio::test]
    async fn close_unknown_session_is_ok() {
        let mgr = manager();
        // Never opened: close still succeeds (flush is a no-op on the store).
        mgr.close(&SessionId::new("never-opened"))
            .await
            .expect("close is idempotent");
    }

    #[tokio::test]
    async fn touch_on_unknown_session_errors() {
        let mgr = manager();
        let err = mgr
            .touch(&SessionId::new("never-opened"))
            .await
            .expect_err("touch must fail for an unknown session");
        assert!(matches!(err, Problem::NotFound(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn ttl_expiry_flushes_session_end_to_end() {
        // The headline acceptance criterion: a session with a TTL is empty after
        // the TTL elapses. Paused clock + sweep_now makes this deterministic.
        let (mgr, store) = manager_with_store();
        let id = mgr.open(SessionOptions::with_ttl(Duration::from_secs(10)));
        let key = EntityKey::new("PERSON", "Jane Doe");
        store
            .put(&id, &key, "<PERSON_0>".to_string())
            .await
            .expect("put");

        // Before the deadline: nothing is reclaimed.
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(mgr.sweep_now().await.expect("sweep"), 0);
        assert!(mgr.is_open(&id));

        // Past the deadline: the session is swept and its store state flushed.
        tokio::time::advance(Duration::from_secs(6)).await;
        assert_eq!(mgr.sweep_now().await.expect("sweep"), 1);
        assert!(!mgr.is_open(&id), "expired session is untracked");
        assert_eq!(
            store.get(&id, &key).await.expect("get"),
            None,
            "expired session's store state is flushed"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn touch_resets_the_ttl_clock() {
        let mgr = manager();
        let id = mgr.open(SessionOptions::with_ttl(Duration::from_secs(10)));

        // 6s in, touch resets the 10s clock.
        tokio::time::advance(Duration::from_secs(6)).await;
        mgr.touch(&id).await.expect("touch");

        // 6s more (12s total, but only 6s since the touch): still alive.
        tokio::time::advance(Duration::from_secs(6)).await;
        assert_eq!(mgr.sweep_now().await.expect("sweep"), 0);
        assert!(mgr.is_open(&id), "touch kept the session alive");

        // 5s more (11s since the touch): now expired.
        tokio::time::advance(Duration::from_secs(5)).await;
        assert_eq!(mgr.sweep_now().await.expect("sweep"), 1);
        assert!(!mgr.is_open(&id));
    }

    #[tokio::test(start_paused = true)]
    async fn session_without_ttl_never_expires() {
        let mgr = manager();
        let id = mgr.open(SessionOptions::default());

        tokio::time::advance(Duration::from_secs(86_400)).await;
        assert_eq!(
            mgr.sweep_now().await.expect("sweep"),
            0,
            "a session without a TTL is never swept"
        );
        assert!(mgr.is_open(&id));
    }

    #[tokio::test(start_paused = true)]
    async fn touch_on_ttl_less_session_stays_non_expiring() {
        let mgr = manager();
        let id = mgr.open(SessionOptions::default());
        mgr.touch(&id).await.expect("touch a ttl-less session");
        tokio::time::advance(Duration::from_secs(86_400)).await;
        assert_eq!(mgr.sweep_now().await.expect("sweep"), 0);
        assert!(mgr.is_open(&id));
    }

    #[tokio::test(start_paused = true)]
    async fn sweep_reclaims_only_expired_sessions() {
        let mgr = manager();
        let short = mgr.open(SessionOptions::with_ttl(Duration::from_secs(10)));
        let long = mgr.open(SessionOptions::with_ttl(Duration::from_secs(100)));
        let eternal = mgr.open(SessionOptions::default());

        tokio::time::advance(Duration::from_secs(11)).await;
        assert_eq!(mgr.sweep_now().await.expect("sweep"), 1);
        assert!(!mgr.is_open(&short));
        assert!(mgr.is_open(&long), "longer TTL survives");
        assert!(mgr.is_open(&eternal), "no-TTL survives");
    }

    #[test]
    fn sweep_interval_is_configurable_and_defaults() {
        let store = Arc::new(InMemoryStore::silent());
        let default_mgr = SessionManager::new(Arc::clone(&store)).silent();
        assert_eq!(default_mgr.sweep_interval(), DEFAULT_SWEEP_INTERVAL);

        let custom = SessionManager::new(store)
            .with_sweep_interval(Duration::from_secs(5))
            .silent();
        assert_eq!(custom.sweep_interval(), Duration::from_secs(5));
    }

    #[tokio::test]
    async fn start_and_stop_sweep_toggle_state() {
        let mgr = manager();
        assert!(!mgr.is_sweeping());

        mgr.start_sweep();
        assert!(mgr.is_sweeping());
        // Second start is a no-op, not a second task.
        mgr.start_sweep();
        assert!(mgr.is_sweeping());

        mgr.stop_sweep();
        assert!(!mgr.is_sweeping());
        // Stopping again is harmless.
        mgr.stop_sweep();
        assert!(!mgr.is_sweeping());
    }

    #[tokio::test(start_paused = true)]
    async fn background_sweep_reclaims_expired_session() {
        // Exercises the spawned interval loop end-to-end (not just sweep_now):
        // the task must fire after one interval and flush the expired session.
        let (mgr, store) = manager_with_store();
        let mgr = mgr.with_sweep_interval(Duration::from_secs(1));
        let id = mgr.open(SessionOptions::with_ttl(Duration::from_secs(2)));
        let key = EntityKey::new("PERSON", "Jane");
        store
            .put(&id, &key, "<PERSON_0>".to_string())
            .await
            .expect("put");
        mgr.start_sweep();

        // Advance past the TTL and several sweep intervals; yield so the spawned
        // task is polled at each fired timer.
        for _ in 0..4 {
            tokio::time::advance(Duration::from_secs(1)).await;
            tokio::task::yield_now().await;
        }

        assert!(!mgr.is_open(&id), "background sweep reclaimed the session");
        assert_eq!(store.get(&id, &key).await.expect("get"), None);
    }

    #[tokio::test]
    async fn drop_aborts_running_sweep() {
        // A manager dropped with an active sweep must not leak the task.
        let mgr = manager();
        mgr.start_sweep();
        assert!(mgr.is_sweeping());
        drop(mgr); // Drop impl aborts the handle; no panic, no leak.
    }

    #[tokio::test]
    async fn event_path_runs_without_error() {
        // Drive the emit_events=true branch of open/close/expire so a regression
        // in metric names or event formatting cannot pass undetected.
        let store = Arc::new(InMemoryStore::silent());
        let mgr = SessionManager::new(store); // events ON
        let id = mgr.open(SessionOptions::default());
        mgr.close(&id).await.expect("close with events");

        // Open an already-expired session and sweep to hit the expire event.
        let expired = mgr.open(SessionOptions::with_ttl(Duration::ZERO));
        assert_eq!(mgr.sweep_now().await.expect("sweep with events"), 1);
        assert!(!mgr.is_open(&expired));
    }

    #[tokio::test]
    async fn debug_reports_counts_not_session_ids() {
        let mgr = manager();
        let id = mgr.open(SessionOptions::default().id_hint("secret-session-label"));
        let dbg = format!("{mgr:?}");
        assert!(dbg.contains("SessionManager"));
        assert!(dbg.contains("tracked_sessions: 1"));
        assert!(
            !dbg.contains("secret-session-label"),
            "Debug must not enumerate session ids"
        );
        let _ = id;
    }
}
