//! Loading recognizers from a directory of TOML files, and reloading them when
//! those files change.
//!
//! # What the loader returns, and why it is not a registry
//!
//! [`from_toml_dir`] returns the built recognizers **and** a [`ReloadHandle`].
//! It deliberately does not own a registry: octarine has no analyzer registry
//! yet (it is scope under the `analyze/` umbrella, issue #464), and inventing a
//! competing one in this sibling crate would only have to be migrated off later.
//!
//! So re-registration is the caller's wiring, and the handle is what makes that
//! possible without polling:
//!
//! ```no_run
//! # async fn run() -> Result<(), octarine_problem::Problem> {
//! use octarine_llm::recognizer::loader;
//!
//! let (recognizers, handle) = loader::from_toml_dir("conf/recognizers")?;
//! # let _ = recognizers;
//!
//! let mut changes = handle.subscribe();
//! while changes.changed().await.is_ok() {
//!     let fresh = changes.borrow_and_update().clone();
//!     // re-register `fresh` with whatever holds the recognizers
//!     # let _ = fresh;
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Reload is fail-safe
//!
//! A reload that does not validate is **logged and discarded** — the previously
//! loaded configs stay live. This is the important half of hot-reload: config
//! files are edited in place, and an editor's intermediate save is routinely a
//! half-written file. Swapping in whatever is on disk at that instant would
//! disarm a running detector because someone was mid-keystroke.
//!
//! Watching is debounced for the same reason: a single save is often a
//! write-truncate-write burst, and each event would otherwise be its own reload.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use figment::Figment;
use figment::providers::{Format, Toml};
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use octarine::observe;
use octarine_problem::{Problem, Result};
use tokio::sync::watch;

use super::config::{RecognizerConfig, RecognizerFile};
use crate::LLMRecognizer;
use crate::provider::{
    AnthropicProvider, AzureOpenAiProvider, OllamaProvider, OpenAiCompatibleProvider,
    OpenAiProvider,
};
use octarine::analyze::Recognizer;

/// How long to wait for the filesystem to go quiet before reloading.
///
/// One editor save can produce several events (truncate, write, rename, chmod).
/// Reloading per event would re-read and re-validate the whole directory
/// several times and publish several identical updates.
const DEBOUNCE: Duration = Duration::from_millis(250);

/// A validated config together with the file it came from.
///
/// The path is retained for error messages: "which file" is the first thing an
/// operator needs when one of twenty configs stops loading.
#[derive(Debug, Clone)]
pub struct LoadedRecognizer {
    /// The file this config was read from.
    pub path: PathBuf,
    /// The validated config.
    pub config: RecognizerConfig,
}

/// A snapshot of every enabled recognizer config in a directory.
pub type ConfigSet = Vec<LoadedRecognizer>;

/// Publishes a fresh [`ConfigSet`] whenever the watched directory changes.
///
/// Dropping the handle stops the watcher — it owns both the `notify` watcher
/// and the thread draining it.
#[derive(Debug)]
pub struct ReloadHandle {
    /// The channel every subscriber reads from.
    tx: watch::Sender<ConfigSet>,
    /// Held so the watcher lives as long as the handle.
    _watcher: RecommendedWatcher,
    /// The directory being watched.
    dir: PathBuf,
}

impl ReloadHandle {
    /// Subscribes to config changes.
    ///
    /// The receiver starts holding the configs current at subscription time;
    /// [`changed`](watch::Receiver::changed) then resolves on each reload.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<ConfigSet> {
        self.tx.subscribe()
    }

    /// The directory this handle watches.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The configs currently live.
    #[must_use]
    pub fn current(&self) -> ConfigSet {
        self.tx.borrow().clone()
    }
}

/// Reads and validates every `*.toml` file in `dir`.
///
/// Files with `enabled = false` are parsed and validated — a parked config that
/// does not load is still a broken config — then excluded from the result.
///
/// # Errors
///
/// Returns [`Problem::Config`] if `dir` is not a readable directory, if any
/// file is not valid TOML, if any config fails validation, or if two files
/// declare the same `class_name`.
pub fn load_dir(dir: impl AsRef<Path>) -> Result<ConfigSet> {
    let dir = dir.as_ref();
    if !dir.is_dir() {
        return Err(Problem::Config(format!(
            "{} is not a directory",
            dir.display()
        )));
    }

    let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("toml"))
        })
        .collect();
    // Directory order is filesystem-dependent; sorting makes a duplicate
    // `class_name` blame the same file every run.
    paths.sort();

    let mut loaded = Vec::new();
    let mut seen: HashMap<String, PathBuf> = HashMap::new();

    for path in paths {
        let config = load_file(&path)?;

        if let Some(first) = seen.get(&config.class_name) {
            return Err(Problem::Config(format!(
                "{}: class_name {:?} is already declared by {}; \
each recognizer needs a unique name because it becomes the recognizer's \
identity in metrics and audit records",
                path.display(),
                config.class_name,
                first.display()
            )));
        }
        seen.insert(config.class_name.clone(), path.clone());

        if !config.enabled {
            observe::debug(
                "llm.recognizer.load",
                format!(
                    "skipping {} — class_name={} is disabled",
                    path.display(),
                    config.class_name
                ),
            );
            continue;
        }
        loaded.push(LoadedRecognizer { path, config });
    }

    Ok(loaded)
}

/// Reads and validates a single recognizer file.
///
/// Every error is prefixed with the file path, so a message keeps both halves
/// of what an operator needs: which file, and which field inside it.
///
/// # Errors
///
/// Returns [`Problem::Config`] when the file is not valid TOML or the config
/// does not validate.
pub fn load_file(path: impl AsRef<Path>) -> Result<RecognizerConfig> {
    let path = path.as_ref();

    // Read through figment, matching `runtime::config`'s file handling, rather
    // than deserializing the bytes directly.
    let file: RecognizerFile = Figment::new()
        .merge(Toml::file(path))
        .extract()
        .map_err(|e| Problem::Config(format!("{}: {}", path.display(), e)))?;

    file.recognizer
        .validate()
        .map_err(|e| Problem::Config(format!("{}: {e}", path.display())))?;

    Ok(file.recognizer)
}

/// Loads every recognizer config in `dir` and starts watching it.
///
/// Returns the configs current at load time plus a [`ReloadHandle`] publishing
/// each subsequent valid state of the directory. The initial load is strict:
/// a broken config at startup is an error, because there is no previous good
/// state to fall back to and starting with silently-reduced coverage is worse
/// than not starting.
///
/// # Errors
///
/// Returns [`Problem::Config`] if the initial load fails, or if the filesystem
/// watcher cannot be established.
pub fn from_toml_dir(dir: impl AsRef<Path>) -> Result<(ConfigSet, ReloadHandle)> {
    let dir = dir.as_ref().to_path_buf();
    let initial = load_dir(&dir)?;

    let (tx, _rx) = watch::channel(initial.clone());
    let watcher = spawn_watcher(dir.clone(), tx.clone())?;

    observe::info(
        "llm.recognizer.load",
        format!(
            "loaded {} recognizer config(s) from {} — watching for changes",
            initial.len(),
            dir.display()
        ),
    );

    Ok((
        initial,
        ReloadHandle {
            tx,
            _watcher: watcher,
            dir,
        },
    ))
}

/// Starts the filesystem watcher and the thread that debounces its events.
///
/// `notify` delivers events on its own thread and the reload is blocking file
/// I/O, so the draining loop runs on a dedicated std thread rather than the
/// async runtime — this keeps the loader usable whether or not a tokio runtime
/// is even present, and never blocks a runtime worker on a directory read.
fn spawn_watcher(dir: PathBuf, tx: watch::Sender<ConfigSet>) -> Result<RecommendedWatcher> {
    let (event_tx, event_rx) = mpsc::channel::<notify::Result<Event>>();

    let mut watcher = notify::recommended_watcher(move |res| {
        // A send failure means the draining thread is gone, which happens
        // only when the handle was dropped. Nothing to report.
        let _ = event_tx.send(res);
    })
    .map_err(|e| Problem::Config(format!("cannot create filesystem watcher: {e}")))?;

    watcher
        .watch(&dir, RecursiveMode::NonRecursive)
        .map_err(|e| Problem::Config(format!("cannot watch {}: {e}", dir.display())))?;

    std::thread::spawn(move || drain_events(&dir, &event_rx, &tx));

    Ok(watcher)
}

/// Consumes watcher events, debounces them, and republishes on each valid load.
///
/// Exits when the event channel closes, which is how dropping the
/// [`ReloadHandle`] stops the thread.
fn drain_events(
    dir: &Path,
    event_rx: &mpsc::Receiver<notify::Result<Event>>,
    tx: &watch::Sender<ConfigSet>,
) {
    while let Ok(first) = event_rx.recv() {
        if !is_content_change(&first) {
            continue;
        }
        // Swallow the rest of the burst: one save is several events, and
        // each would otherwise trigger its own full reload.
        while event_rx.recv_timeout(DEBOUNCE).is_ok() {}

        match load_dir(dir) {
            Ok(configs) => {
                observe::info(
                    "llm.recognizer.reload",
                    format!(
                        "reloaded {} recognizer config(s) from {}",
                        configs.len(),
                        dir.display()
                    ),
                );
                // A send failure means every receiver is gone. The configs are
                // still retained in the channel for a later `subscribe`.
                let _ = tx.send(configs);
            }
            Err(problem) => {
                // The critical branch: keep serving the last good configs.
                // A half-written file mid-edit must not disarm a live detector.
                observe::warn(
                    "llm.recognizer.reload",
                    format!(
                        "keeping the previous configs — reload of {} failed: {problem}",
                        dir.display()
                    ),
                );
            }
        }
    }
}

/// Whether an event could have changed a config's content.
///
/// Access events (a plain read) cannot, and on some platforms they are frequent
/// enough to cause a reload per read.
fn is_content_change(event: &notify::Result<Event>) -> bool {
    match event {
        Ok(event) => matches!(
            event.kind,
            EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_) | EventKind::Any
        ),
        // A watcher error may mean events were dropped, so reload rather than
        // assume nothing changed.
        Err(_) => true,
    }
}

/// Builds a live recognizer from a validated config.
///
/// Credentials are read from the environment variable the config **names**
/// (see [`RecognizerConfig::credential_env`]) — never from the file itself.
///
/// # Errors
///
/// Returns [`Problem::Config`] when the named credential variable is unset or
/// empty, or when the provider rejects a field.
pub fn build_recognizer(config: &RecognizerConfig) -> Result<Box<dyn Recognizer>> {
    let resolved = config.validate()?;

    // Read the credential once, here, so every provider arm below is spared
    // the same lookup and the same error shape.
    let credential = match config.credential_env() {
        Some(var) => Some(read_credential(var)?),
        None => None,
    };
    // `ollama` is the only provider with no credential, and
    // `credential_env` already returned `None` for it — so any other provider
    // reaching the arms below has a `Some` here.
    let key = credential.as_deref().unwrap_or_default();

    let recognizer: Box<dyn Recognizer> = match config.provider.as_str() {
        "openai" => configure(OpenAiProvider::new(key, &config.model)?, config, &resolved),
        "anthropic" => configure(
            AnthropicProvider::new(key, &config.model)?,
            config,
            &resolved,
        ),
        "ollama" => {
            let provider = match config.base_url.as_deref() {
                Some(url) => OllamaProvider::with_base_url(&config.model, url)?,
                None => OllamaProvider::new(&config.model)?,
            };
            configure(provider, config, &resolved)
        }
        "azure_openai" => {
            // `validate_provider_fields` already required this, so the
            // fallback is unreachable in practice; it keeps the code panic-free.
            let endpoint = config.endpoint.as_deref().unwrap_or_default();
            let provider = AzureOpenAiProvider::with_api_key(endpoint, key, &config.model)?;
            let provider = match config.api_version.as_deref() {
                Some(version) => provider.with_api_version(version)?,
                None => provider,
            };
            configure(provider, config, &resolved)
        }
        "openai_compatible" => {
            let base_url = config.base_url.as_deref().unwrap_or_default();
            configure(
                OpenAiCompatibleProvider::new(&config.class_name, base_url, key, &config.model)?,
                config,
                &resolved,
            )
        }
        // `validate` rejects any provider not in `KNOWN_PROVIDERS`, so this is
        // unreachable via `build_recognizer`. Kept as an error rather than an
        // `unreachable!` so a future provider added to the list but not wired
        // up here fails loudly instead of panicking.
        other => {
            return Err(Problem::Config(format!(
                "provider {other:?} validated but has no constructor wired up"
            )));
        }
    };

    Ok(recognizer)
}

/// Applies the config's prompt, mapping, scoring, and name to a recognizer.
///
/// Generic over the provider so all five arms above share one body — the same
/// reason [`LLMRecognizer`] itself is generic.
fn configure<P: crate::LlmProvider + 'static>(
    provider: P,
    config: &RecognizerConfig,
    resolved: &super::config::ResolvedConfig,
) -> Box<dyn Recognizer> {
    let recognizer = LLMRecognizer::new(provider)
        .with_name(&config.class_name)
        .with_system_prompt(super::prompt::with_few_shot_examples(
            &config.prompt.system,
            &config.few_shot_examples,
        ))
        .with_entity_mapping(resolved.entity_mapping.clone())
        .with_confidence(resolved.confidence)
        .with_max_tokens(config.max_tokens);
    Box::new(recognizer)
}

/// Reads a credential from the environment, failing when it is absent or blank.
///
/// A blank value is treated as absent: an unset variable and one exported as
/// the empty string are the same mistake, and both produce a 401 several
/// seconds later if allowed through.
fn read_credential(var: &str) -> Result<String> {
    match std::env::var(var) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(Problem::Config(format!(
            "environment variable {var} is unset or empty; it holds the provider credential for this recognizer"
        ))),
    }
}

/// Builds a recognizer for every config in a set.
///
/// # Errors
///
/// Returns the first [`Problem`] encountered, naming the file it came from —
/// a partially-registered set would leave detection coverage in a state nobody
/// declared.
pub fn build_all(configs: &ConfigSet) -> Result<Vec<Box<dyn Recognizer>>> {
    configs
        .iter()
        .map(|loaded| {
            build_recognizer(&loaded.config)
                .map_err(|e| Problem::Config(format!("{}: {e}", loaded.path.display())))
        })
        .collect()
}
