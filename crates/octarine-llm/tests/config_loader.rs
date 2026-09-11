//! Loading recognizers from TOML, and reloading them when the files change.
//!
//! These run against the real filesystem and the real `notify` watcher — a
//! hot-reload test that stubs the watcher would pass with reload broken, which
//! is the only failure mode worth testing here.

#![allow(clippy::panic, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use octarine_llm::recognizer::loader;
use tokio::sync::watch;

/// How long a reload assertion waits before giving up.
///
/// Generous: a loaded CI runner can take a while to deliver an inotify event
/// and run the debounce. The tests poll, so a fast machine finishes in
/// milliseconds regardless — this bounds the failure case, it is not a sleep.
const RELOAD_TIMEOUT: Duration = Duration::from_secs(10);

/// Interval between polls while waiting for a reload.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Writes a recognizer config whose system prompt carries `marker`.
///
/// The marker is what every reload assertion looks for: it proves the *new*
/// file's content is what arrived, rather than merely that some event fired.
fn write_config(path: &Path, class_name: &str, marker: &str) {
    let body = format!(
        r#"
[recognizer]
class_name = "{class_name}"
provider = "ollama"
model = "llama3"

[recognizer.prompt]
system = "Find PII. {marker}"

[recognizer.entity_mapping]
PERSON = "PERSON"
"#
    );
    std::fs::write(path, body).expect("config must be writable");
}

/// Polls `rx` until a config set satisfying `predicate` is observed.
///
/// Polls rather than sleeping a fixed interval, and rather than awaiting a
/// single `changed()`: an editor save can produce several events, so the
/// arrival that matters is not necessarily the first.
async fn wait_for(
    rx: &mut watch::Receiver<loader::ConfigSet>,
    predicate: impl Fn(&loader::ConfigSet) -> bool,
) -> Option<loader::ConfigSet> {
    let deadline = Instant::now().checked_add(RELOAD_TIMEOUT);
    loop {
        {
            let current = rx.borrow_and_update().clone();
            if predicate(&current) {
                return Some(current);
            }
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return None;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// True when some config in the set carries `marker` in its system prompt.
fn has_marker(configs: &loader::ConfigSet, marker: &str) -> bool {
    configs
        .iter()
        .any(|loaded| loaded.config.prompt.system.contains(marker))
}

/// The repo's shipped example configs.
fn examples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples")
}

// ---- loading ---------------------------------------------------------------

#[test]
fn loads_every_recognizer_in_a_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_config(&dir.path().join("one.toml"), "first", "ALPHA");
    write_config(&dir.path().join("two.toml"), "second", "BETA");

    let configs = loader::load_dir(dir.path()).expect("both configs must load");

    assert_eq!(configs.len(), 2, "one recognizer per file");
    let names: Vec<&str> = configs
        .iter()
        .map(|c| c.config.class_name.as_str())
        .collect();
    assert!(
        names.contains(&"first") && names.contains(&"second"),
        "each file's own class_name must survive the load: {names:?}"
    );
}

#[test]
fn non_toml_files_are_ignored() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_config(&dir.path().join("real.toml"), "real", "ALPHA");
    std::fs::write(dir.path().join("README.md"), "not a config").expect("write");
    std::fs::write(dir.path().join("notes.txt"), "also not a config").expect("write");

    let configs = loader::load_dir(dir.path()).expect("the .toml file must load");
    assert_eq!(configs.len(), 1, "only the .toml file counts");
}

#[test]
fn a_disabled_config_is_validated_then_excluded() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_config(&dir.path().join("on.toml"), "enabled_one", "ALPHA");
    std::fs::write(
        dir.path().join("off.toml"),
        r#"
[recognizer]
class_name = "parked"
provider = "ollama"
model = "llama3"
enabled = false

[recognizer.prompt]
system = "Find PII."
"#,
    )
    .expect("write");

    let configs = loader::load_dir(dir.path()).expect("load");
    assert_eq!(configs.len(), 1, "the disabled config must be excluded");
    assert_eq!(
        configs.first().map(|c| c.config.class_name.as_str()),
        Some("enabled_one")
    );
}

#[test]
fn a_duplicate_class_name_is_rejected_naming_both_files() {
    // Two recognizers sharing a name would be indistinguishable in metrics.
    let dir = tempfile::tempdir().expect("tempdir");
    write_config(&dir.path().join("a.toml"), "same_name", "ALPHA");
    write_config(&dir.path().join("b.toml"), "same_name", "BETA");

    let err = loader::load_dir(dir.path()).expect_err("a duplicate name must fail the load");
    let msg = err.to_string();
    assert!(msg.contains("same_name"), "must name the collision: {msg}");
    assert!(
        msg.contains("a.toml") && msg.contains("b.toml"),
        "must name both files: {msg}"
    );
}

#[test]
fn a_missing_directory_is_an_error_not_an_empty_set() {
    // Returning an empty set would silently start with no detection at all.
    let err =
        loader::load_dir("/nonexistent/recognizer/dir").expect_err("a missing directory must fail");
    assert!(err.to_string().contains("not a directory"), "{err}");
}

// ---- validation errors carry the TOML path ---------------------------------

#[test]
fn an_unknown_entity_type_fails_the_load_naming_the_path_and_the_value() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("typo.toml");
    std::fs::write(
        &path,
        r#"
[recognizer]
class_name = "typo"
provider = "ollama"
model = "llama3"

[recognizer.prompt]
system = "Find PII."

[recognizer.entity_mapping]
PERSON = "PERSEN"
"#,
    )
    .expect("write");

    let err = loader::load_dir(dir.path()).expect_err("PERSEN is not an IdentifierType");
    let msg = err.to_string();

    // Asserting only `is_err()` here would pass against any unrelated failure —
    // a missing file, a TOML syntax error — so assert all three parts.
    assert!(msg.contains("typo.toml"), "must name the file: {msg}");
    assert!(
        msg.contains("recognizer.entity_mapping.PERSON"),
        "must name the TOML field path: {msg}"
    );
    assert!(msg.contains("PERSEN"), "must quote the bad value: {msg}");
}

#[test]
fn a_typo_does_not_silently_degrade_to_the_unknown_type() {
    // The whole point of strict resolution: a config that loads clean but
    // detects nothing is worse than one that refuses to load.
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("typo.toml"),
        r#"
[recognizer]
class_name = "typo"
provider = "ollama"
model = "llama3"

[recognizer.prompt]
system = "Find PII."

[recognizer.entity_mapping]
PERSON = "PERSEN"
"#,
    )
    .expect("write");

    assert!(
        loader::load_dir(dir.path()).is_err(),
        "an unresolvable entity_type must fail rather than load as Unknown"
    );
}

#[test]
fn a_few_shot_typo_names_its_indexed_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("examples.toml"),
        r#"
[recognizer]
class_name = "examples"
provider = "ollama"
model = "llama3"

[recognizer.prompt]
system = "Find PII."

[[recognizer.few_shot_examples]]
input = "Alice waited"
output = [{ entity_type = "PERSON", text = "Alice" }]

[[recognizer.few_shot_examples]]
input = "Bob called"
output = [{ entity_type = "PERSON", text = "Bob" }]

[[recognizer.few_shot_examples]]
input = "Carol left"
output = [{ entity_type = "PERSEN", text = "Carol" }]
"#,
    )
    .expect("write");

    let err = loader::load_dir(dir.path()).expect_err("PERSEN is not a type");
    let msg = err.to_string();
    assert!(
        msg.contains("recognizer.few_shot_examples[2].output[0].entity_type"),
        "the index must point at the third example, not the first: {msg}"
    );
    assert!(msg.contains("PERSEN"), "{msg}");
}

// ---- hot reload ------------------------------------------------------------

#[tokio::test]
async fn a_config_change_publishes_the_new_content() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("watched.toml");
    write_config(&path, "watched", "MARKER_ALPHA");

    let (initial, handle) = loader::from_toml_dir(dir.path()).expect("initial load");
    assert!(
        has_marker(&initial, "MARKER_ALPHA"),
        "the initial load must carry the original content"
    );

    let mut changes = handle.subscribe();
    write_config(&path, "watched", "MARKER_BETA");

    let observed = wait_for(&mut changes, |c| has_marker(c, "MARKER_BETA"))
        .await
        .expect("the reload must deliver MARKER_BETA within the timeout");

    // Asserting the NEW marker specifically is what makes this test fail if
    // reload is a no-op: a test that only checked "an event fired" would pass
    // against a watcher that republished the old configs.
    assert!(
        has_marker(&observed, "MARKER_BETA"),
        "the reloaded config must carry the new prompt"
    );
    assert!(
        !has_marker(&observed, "MARKER_ALPHA"),
        "the old content must be gone, not merely accompanied by the new"
    );
}

#[tokio::test]
async fn a_new_file_is_picked_up_without_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_config(&dir.path().join("first.toml"), "first", "MARKER_ALPHA");

    let (initial, handle) = loader::from_toml_dir(dir.path()).expect("initial load");
    assert_eq!(initial.len(), 1);

    let mut changes = handle.subscribe();
    write_config(&dir.path().join("second.toml"), "second", "MARKER_GAMMA");

    let observed = wait_for(&mut changes, |c| c.len() == 2)
        .await
        .expect("the new file must be picked up within the timeout");
    assert!(
        has_marker(&observed, "MARKER_GAMMA"),
        "the added recognizer's own content must arrive"
    );
}

#[tokio::test]
async fn an_invalid_reload_keeps_the_last_good_configs() {
    // A half-written file mid-edit must not disarm a live detector.
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("watched.toml");
    write_config(&path, "watched", "MARKER_ALPHA");

    let (_initial, handle) = loader::from_toml_dir(dir.path()).expect("initial load");
    let mut changes = handle.subscribe();

    // First a valid change, so there is a known-good state to preserve.
    write_config(&path, "watched", "MARKER_BETA");
    wait_for(&mut changes, |c| has_marker(c, "MARKER_BETA"))
        .await
        .expect("the valid reload must land first");

    // Now break it.
    std::fs::write(&path, "this is not valid TOML [[[").expect("write");

    // Give the watcher time to see the broken file and reject it. There is no
    // event to wait for — the assertion is that nothing changes — so this
    // polls for the absence of a regression rather than for an arrival.
    let deadline = Instant::now().checked_add(Duration::from_secs(2));
    while deadline.is_some_and(|d| Instant::now() < d) {
        let current = handle.current();
        assert!(
            has_marker(&current, "MARKER_BETA"),
            "the last good config must stay live through an invalid reload"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

#[tokio::test]
async fn an_invalid_config_at_startup_is_an_error() {
    // Unlike a reload, there is no previous good state to fall back on —
    // starting with silently-reduced coverage is worse than not starting.
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("broken.toml"), "not valid TOML [[[").expect("write");

    assert!(
        loader::from_toml_dir(dir.path()).is_err(),
        "a broken config at startup must fail loudly"
    );
}

#[tokio::test]
async fn dropping_the_handle_stops_the_watcher() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("watched.toml");
    write_config(&path, "watched", "MARKER_ALPHA");

    let (_initial, handle) = loader::from_toml_dir(dir.path()).expect("initial load");
    let mut changes = handle.subscribe();
    drop(handle);

    write_config(&path, "watched", "MARKER_BETA");

    // With the sender gone, `changed()` resolves with an error rather than
    // hanging or delivering.
    let result = tokio::time::timeout(Duration::from_secs(2), changes.changed()).await;
    match result {
        Ok(Err(_)) => {}
        Ok(Ok(())) => panic!("no update should arrive after the handle is dropped"),
        Err(_) => panic!("changed() must resolve once the sender is dropped, not hang"),
    }
}

// ---- shipped examples ------------------------------------------------------

#[test]
fn the_shipped_example_configs_load() {
    // A shipped example that does not parse is worse than no example.
    let configs = loader::load_dir(examples_dir()).expect("examples/ must load cleanly");

    assert_eq!(configs.len(), 2, "both example configs must load");
    let names: Vec<&str> = configs
        .iter()
        .map(|c| c.config.class_name.as_str())
        .collect();
    assert!(
        names.contains(&"person_finder_openai") && names.contains(&"person_finder_ollama"),
        "both documented examples must be present: {names:?}"
    );
}

#[test]
fn the_openai_example_resolves_its_entity_mapping() {
    let path = examples_dir().join("recognizer_openai.toml");
    let config = loader::load_file(&path).expect("the example must load");
    let resolved = config.validate().expect("the example must validate");

    assert_eq!(
        resolved.entity_mapping.get("LOCATION"),
        Some(&octarine::identifiers::IdentifierType::NamedLocation),
        "the documented mapping must resolve to a real octarine type"
    );
    assert_eq!(
        config.credential_env(),
        Some("OPENAI_API_KEY"),
        "the example reads its credential from the environment, not the file"
    );
}

#[test]
fn the_ollama_example_needs_no_credential() {
    let path = examples_dir().join("recognizer_ollama.toml");
    let config = loader::load_file(&path).expect("the example must load");

    assert_eq!(
        config.credential_env(),
        None,
        "a local model authenticates nothing"
    );
}

// ---- building recognizers --------------------------------------------------

#[test]
fn a_local_config_builds_a_recognizer_named_after_its_class_name() {
    // Ollama needs no credential, so this exercises the whole config →
    // recognizer path without a key or a network call.
    let dir = tempfile::tempdir().expect("tempdir");
    write_config(&dir.path().join("local.toml"), "my_local_finder", "ALPHA");

    let configs = loader::load_dir(dir.path()).expect("load");
    let built = loader::build_all(&configs).expect("a local config must build");

    assert_eq!(built.len(), 1);
    assert_eq!(
        built.first().map(|r| r.name()),
        Some("my_local_finder"),
        "the recognizer must take its identity from class_name, not the provider"
    );
}

#[test]
fn a_missing_credential_fails_with_the_variable_name() {
    // A config naming an unset variable must say which one, rather than
    // surfacing as a 401 several seconds into the first detection.
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("cloud.toml"),
        r#"
[recognizer]
class_name = "cloud"
provider = "openai"
model = "gpt-4o-mini"
api_key_env = "OCTARINE_TEST_DEFINITELY_UNSET_KEY"

[recognizer.prompt]
system = "Find PII."
"#,
    )
    .expect("write");

    let configs = loader::load_dir(dir.path()).expect("the config itself is valid");
    // `Box<dyn Recognizer>` is not Debug, so `expect_err` is unavailable here.
    let msg = match loader::build_all(&configs) {
        Err(err) => err.to_string(),
        Ok(_) => panic!("building with an unset credential must fail"),
    };

    assert!(
        msg.contains("OCTARINE_TEST_DEFINITELY_UNSET_KEY"),
        "the error must name the variable to set: {msg}"
    );
    assert!(
        msg.contains("cloud.toml"),
        "and the file that asked for it: {msg}"
    );
}

#[test]
fn azure_without_an_endpoint_is_rejected_naming_the_field() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("azure.toml"),
        r#"
[recognizer]
class_name = "azure"
provider = "azure_openai"
model = "my-deployment"

[recognizer.prompt]
system = "Find PII."
"#,
    )
    .expect("write");

    let err = loader::load_dir(dir.path()).expect_err("azure requires an endpoint");
    assert!(
        err.to_string().contains("recognizer.endpoint"),
        "must name the missing field: {err}"
    );
}

#[test]
fn a_few_shot_config_reaches_the_recognizers_prompt() {
    // The examples must survive config → prompt → recognizer, not be parsed
    // and then dropped.
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("shots.toml"),
        r#"
[recognizer]
class_name = "shots"
provider = "ollama"
model = "llama3"

[recognizer.prompt]
system = "Find PII."

[[recognizer.few_shot_examples]]
input = "Alice met Bob"
output = [{ entity_type = "PERSON", text = "Alice" }]
"#,
    )
    .expect("write");

    let config = loader::load_file(dir.path().join("shots.toml")).expect("load");
    let rendered = octarine_llm::recognizer::prompt::with_few_shot_examples(
        &config.prompt.system,
        &config.few_shot_examples,
    );

    assert!(
        rendered.contains("Alice met Bob"),
        "the example input must reach the prompt: {rendered}"
    );
    assert!(
        rendered.contains("Find PII."),
        "the configured system prompt must still lead"
    );
}
