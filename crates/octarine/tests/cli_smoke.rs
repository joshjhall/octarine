//! Smoke tests for the `CliApp` entry points (issue #413).
//!
//! `CliApp::run`, `CliApp::run_with_args`, and `run_cli` were never invoked by
//! any test — the inline tests in `src/runtime/cli/app.rs` only check builder
//! field assignment. These functions call `clap`'s `get_matches()`, which
//! parses the **real process argv**, so they cannot be called from inside a
//! test harness: the harness's own argv would fail to parse and abort the
//! runner.
//!
//! These tests therefore drive the real `cli_smoke` binary
//! (`src/bin/cli_smoke.rs`) as a subprocess, using the `CARGO_BIN_EXE_*`
//! environment variable Cargo provides to integration tests. The binary picks
//! its entry point from `OCTARINE_SMOKE_MODE`, leaving the argv entirely under
//! each test's control.

#![cfg(feature = "cli")]
#![allow(clippy::panic, clippy::expect_used)]

use std::process::{Command, Output};

/// Path to the smoke binary, resolved by Cargo at compile time.
const SMOKE_BIN: &str = env!("CARGO_BIN_EXE_cli_smoke");

/// Run the smoke binary in `mode` with the given extra arguments.
fn run_smoke(mode: &str, args: &[&str]) -> Output {
    Command::new(SMOKE_BIN)
        .env("OCTARINE_SMOKE_MODE", mode)
        .args(args)
        .output()
        .expect("the smoke binary should be runnable")
}

/// Combined stdout + stderr, for assertions that do not care which stream.
fn combined(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

// ============================================================================
// CliApp::run
// ============================================================================

/// A succeeding handler yields exit code 0 and the handler actually ran.
#[test]
fn test_cli_app_run_success_exit_code() {
    let output = run_smoke("ok", &[]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "a succeeding handler must exit 0; output was {:?}",
        combined(&output)
    );
    assert!(
        combined(&output).contains("handler ran for cli-smoke"),
        "the handler body must have executed; output was {:?}",
        combined(&output)
    );
}

/// A handler returning `CliError::usage` propagates that error's **specific**
/// exit code (`USAGE_ERROR` == 2), not merely a non-zero one. Asserting the
/// exact value is what proves `CliError::exit_code()` is wired through.
#[test]
fn test_cli_app_run_propagates_specific_error_exit_code() {
    let output = run_smoke("fail", &[]);

    assert_eq!(
        output.status.code(),
        Some(2),
        "CliError::usage maps to ExitCode::USAGE_ERROR (2); output was {:?}",
        combined(&output)
    );
    assert!(
        combined(&output).contains("smoke failure requested"),
        "the error message must reach the user; output was {:?}",
        combined(&output)
    );
}

/// The error path is reached only after the handler runs — the pre-failure
/// output is present, which rules out an early abort before `handler()`.
#[test]
fn test_cli_app_run_failure_still_executes_handler_body() {
    let output = run_smoke("fail", &[]);

    assert!(
        combined(&output).contains("about to fail"),
        "the handler body must run before the error is reported; output was {:?}",
        combined(&output)
    );
}

// ============================================================================
// Generated command surface (build_command)
// ============================================================================

/// `--help` exits successfully and prints the configured description.
#[test]
fn test_cli_app_help_flag() {
    let output = run_smoke("ok", &["--help"]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "--help exits 0; output was {:?}",
        combined(&output)
    );

    let text = combined(&output);
    assert!(
        text.contains("Smoke test application"),
        "help must show the configured description; got {text:?}"
    );
    assert!(
        text.contains("--verbose"),
        "with_verbose(true) must add a --verbose flag to the help; got {text:?}"
    );
    assert!(
        text.contains("--quiet"),
        "with_quiet(true) must add a --quiet flag to the help; got {text:?}"
    );
}

/// `--version` reports the configured version, not a placeholder.
#[test]
fn test_cli_app_version_flag() {
    let output = run_smoke("ok", &["--version"]);

    assert_eq!(output.status.code(), Some(0));
    assert!(
        combined(&output).contains("9.9.9"),
        "--version must print the version passed to .version(); output was {:?}",
        combined(&output)
    );
}

/// An argument the command does not define is a clap usage error (exit 2).
#[test]
fn test_cli_app_rejects_unknown_flag() {
    let output = run_smoke("ok", &["--definitely-not-a-real-flag"]);

    assert_eq!(
        output.status.code(),
        Some(2),
        "an unknown flag is a clap usage error; output was {:?}",
        combined(&output)
    );
}

// ============================================================================
// CliApp::run_with_args
// ============================================================================

/// `run_with_args` parses the custom `clap::Args` struct and hands it to the
/// handler — the echoed value proves the parse happened.
#[test]
fn test_cli_app_run_with_args_parses_custom_arguments() {
    let output = run_smoke("args", &["--label", "from-argv"]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "output was {:?}",
        combined(&output)
    );
    assert!(
        combined(&output).contains("label=from-argv"),
        "the custom argument must reach the handler; output was {:?}",
        combined(&output)
    );
}

/// Omitting the optional argument leaves it unset rather than failing.
#[test]
fn test_cli_app_run_with_args_optional_argument_absent() {
    let output = run_smoke("args", &[]);

    assert_eq!(output.status.code(), Some(0));
    assert!(
        combined(&output).contains("label=none"),
        "an absent optional argument must arrive as None; output was {:?}",
        combined(&output)
    );
}

// ============================================================================
// run_cli
// ============================================================================

/// The `run_cli` free function runs the handler and exits 0.
#[test]
fn test_run_cli_free_function() {
    let output = run_smoke("run_cli", &[]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "output was {:?}",
        combined(&output)
    );
    assert!(
        combined(&output).contains("run_cli handler ran"),
        "the run_cli handler body must have executed; output was {:?}",
        combined(&output)
    );
}
