//! Integration tests for the `Data` facade
//!
//! Exercises every method on the public `Data` facade through the same
//! re-export paths that downstream consumers use (`octarine::data::Data`
//! and `octarine::prelude::Data`). The audit that produced issue #77
//! observed that no production code constructs `Data` — these tests close
//! that coverage gap from a consumer's perspective, so any future signature
//! change in a sub-builder constructor surfaces at the facade boundary.

#![allow(clippy::panic)]
#![allow(clippy::expect_used)]

use octarine::data::Data;

#[test]
fn facade_paths_chain_classifies_absolute_and_relative() {
    let data = Data::new();
    let paths = data.paths();

    assert!(paths.is_absolute("/home/user"));
    assert!(!paths.is_absolute("relative/path"));
    assert!(paths.is_relative("./config"));
}

#[test]
fn facade_network_chain_normalizes_url_path() {
    let data = Data::new();
    let network = data.network();

    assert_eq!(network.normalize("/api//users/"), "/api/users");
}

#[test]
fn facade_text_chain_sanitizes_for_log() {
    let data = Data::new();

    let sanitized = data
        .text("user\x00input\nwith\tnull")
        .sanitize_for_log()
        .finish();

    assert!(!sanitized.contains('\x00'));
}

// Compile-time guarantee that the public `Data` type retains the derives downstream
// consumers rely on. If anyone removes a derive in `data/facade.rs`, this fails to
// compile rather than the runtime assertions below silently still passing.
const _: fn() = || {
    fn assert_impls<T: Copy + Default + core::fmt::Debug>() {}
    assert_impls::<Data>();
};

#[test]
fn facade_is_copy_at_runtime() {
    let data = Data::new();
    let copy = data;
    assert!(data.paths().is_absolute("/a"));
    assert!(copy.paths().is_absolute("/a"));
}

#[test]
fn facade_reachable_via_prelude_re_export() {
    use octarine::prelude::Data as PreludeData;

    let data = PreludeData::new();
    let sanitized = data.text("input").sanitize_for_log().finish();

    assert!(!sanitized.is_empty());
}

#[cfg(feature = "formats")]
#[test]
fn facade_formats_chain_parses_json() {
    let data = Data::new();
    let formats = data.formats();

    let value: serde_json::Value = formats
        .parse_json(r#"{"key": "value"}"#)
        .expect("valid JSON should parse");
    assert_eq!(value.get("key").and_then(|v| v.as_str()), Some("value"));
}
