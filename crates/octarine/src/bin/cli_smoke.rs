//! Smoke-test binary for `octarine::runtime::cli` (issue #413).
//!
//! `CliApp::run` / `run_with_args` / `run_cli` call `clap`'s `get_matches()`,
//! which parses the **real process argv**. A test harness binary's argv is not
//! the application's, so these entry points cannot be driven in-process — the
//! parse would fail and abort the test runner. This binary exists so
//! `tests/cli_smoke.rs` can invoke them as a real subprocess via
//! `CARGO_BIN_EXE_cli_smoke`.
//!
//! It is excluded from the published package (see `exclude` in `Cargo.toml`)
//! and is not part of the library's public API.
//!
//! ## Modes
//!
//! The mode is chosen by the `OCTARINE_SMOKE_MODE` environment variable rather
//! than a positional argument, so that the argv `clap` sees stays entirely
//! under the test's control:
//!
//! | Mode | Entry point exercised | Expected exit |
//! | ---- | --------------------- | ------------- |
//! | `ok` (default) | `CliApp::run` with a succeeding handler | `SUCCESS` |
//! | `fail` | `CliApp::run` with a handler returning `CliError::usage` | `USAGE_ERROR` |
//! | `args` | `CliApp::run_with_args` with a `clap::Args` struct | `SUCCESS` |
//! | `run_cli` | the `run_cli` free function | `SUCCESS` |

use octarine::runtime::cli::{CliApp, CliError, ExitCode, run_cli};

/// Extra arguments used by the `args` mode to exercise `run_with_args`.
#[derive(Debug, clap::Args)]
struct SmokeArgs {
    /// A label echoed back so the test can confirm parsing happened.
    #[arg(long)]
    label: Option<String>,
}

fn main() -> ExitCode {
    let mode = std::env::var("OCTARINE_SMOKE_MODE").unwrap_or_else(|_| "ok".to_string());

    match mode.as_str() {
        "fail" => CliApp::new("cli-smoke", "Smoke test application")
            .version("9.9.9")
            .run(|ctx| {
                ctx.print("about to fail");
                Err(CliError::usage("smoke failure requested"))
            }),
        "args" => CliApp::new("cli-smoke", "Smoke test application")
            .version("9.9.9")
            .run_with_args(|ctx, args: SmokeArgs| {
                ctx.print(&format!(
                    "label={}",
                    args.label.as_deref().unwrap_or("none")
                ));
                Ok(())
            }),
        "run_cli" => run_cli("cli-smoke", "Smoke test application", |ctx| {
            ctx.print("run_cli handler ran");
            Ok(())
        }),
        _ => CliApp::new("cli-smoke", "Smoke test application")
            .version("9.9.9")
            .with_verbose(true)
            .with_quiet(true)
            .run(|ctx| {
                ctx.print(&format!("handler ran for {}", ctx.app_name()));
                Ok(())
            }),
    }
}
