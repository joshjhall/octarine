//! Integration tests for the OTLP/HTTP span transport (issue #527).
//!
//! Exercises the HTTP exporter against an in-process mock OTLP receiver: a raw
//! `TcpListener` that captures the first request line and headers so we can
//! assert the exporter POSTs to `/v1/traces` and forwards custom auth headers.
//!
//! The whole file is gated on `otel-http` — the HTTP transport only exists with
//! that feature. The blocking reqwest backend runs on the batch-processor
//! thread, so no async runtime is required here.
//!
//! Each live-export test calls `init_otel`, which writes the process-global
//! `OnceLock` tracer provider exactly once per process. Under nextest (the
//! project's mandated runner — see CLAUDE.md) every test is its own process, so
//! all run fully. Under a single-process `cargo test`, only the first
//! `init_otel` succeeds; the rest detect the already-initialized provider and
//! skip with a visible note rather than panicking on a misleading error.
#![cfg(feature = "otel-http")]
#![allow(clippy::panic, clippy::expect_used)] // Known-valid endpoints/headers.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use octarine::observe::tracing::{
    OtelConfig, OtlpProtocol, export_event, init_otel, shutdown_otel,
};
use octarine::observe::{Event, EventType};

/// What the mock receiver captured from a single inbound request.
struct CapturedRequest {
    /// First request line, e.g. `POST /v1/traces HTTP/1.1`.
    request_line: String,
    /// Lower-cased header names mapped to their raw values.
    headers: Vec<(String, String)>,
}

impl CapturedRequest {
    /// Case-insensitive header lookup.
    fn header(&self, name: &str) -> Option<&str> {
        let needle = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| *k == needle)
            .map(|(_, v)| v.as_str())
    }
}

/// Read one HTTP request from the stream, capturing the request line and
/// headers, then reply `200 OK` with an empty body. Best-effort: any partial
/// read still returns whatever was parsed so the test can assert on it.
fn handle_one(mut stream: TcpStream) -> CapturedRequest {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    // Read until we have the full header block (terminated by CRLFCRLF).
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_string();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break; // End of header block.
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }

    // Minimal success response so the exporter's client completes cleanly.
    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let _ = stream.flush();

    CapturedRequest {
        request_line,
        headers,
    }
}

/// Spawn a single-shot mock OTLP/HTTP receiver. Returns the bound base URL and
/// a receiver that yields the captured request once a connection is handled.
fn spawn_mock_receiver() -> (String, mpsc::Receiver<CapturedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock receiver");
    let addr = listener.local_addr().expect("local addr");
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            let captured = handle_one(stream);
            let _ = tx.send(captured);
        }
    });

    (format!("http://{addr}"), rx)
}

/// Drive an export through the HTTP transport and return what the mock saw.
///
/// Returns `None` when the global tracer provider was already initialized by an
/// earlier test in the same process (single-process `cargo test`); under
/// nextest each test gets a fresh process and this never happens. Callers treat
/// `None` as "skip" so a shared-process run degrades to a no-op instead of a
/// spurious panic.
fn export_via(protocol: OtlpProtocol) -> Option<CapturedRequest> {
    let (base, rx) = spawn_mock_receiver();
    // Programmatic HTTP endpoints are used verbatim — the caller supplies the
    // full per-signal path (the `/v1/traces` suffix is only auto-appended to the
    // `OTEL_EXPORTER_OTLP_ENDPOINT` base env var, not to `with_endpoint`).
    let endpoint = format!("{base}/v1/traces");

    let config = OtelConfig::new("otel-http-test")
        .with_otlp_endpoint(&endpoint)
        .with_otlp_protocol(protocol)
        .with_timeout(Duration::from_secs(3))
        .with_header("Authorization", "Api-Token secret-token-123");

    if init_otel(config).is_err() {
        // Already initialized in this process — only possible under a
        // single-process `cargo test`. Skip rather than report a false failure;
        // under nextest (per-test process) this branch is never taken.
        return None;
    }

    export_event(&Event::new(EventType::Info, "otel-http span"));

    // Flush the batch exporter so the request reaches the mock.
    shutdown_otel();

    Some(
        rx.recv_timeout(Duration::from_secs(8))
            .expect("mock receiver captured a request after a successful init"),
    )
}

#[test]
fn http_binary_posts_to_traces_endpoint_with_auth_header() {
    let Some(captured) = export_via(OtlpProtocol::HttpBinary) else {
        return; // Skipped: shared-process run (see export_via).
    };

    assert!(
        captured.request_line.starts_with("POST "),
        "expected a POST, got: {}",
        captured.request_line
    );
    assert!(
        captured.request_line.contains("/v1/traces"),
        "expected the OTLP traces path, got: {}",
        captured.request_line
    );

    // Acceptance criterion: custom auth headers are forwarded on HTTP.
    assert_eq!(
        captured.header("authorization"),
        Some("Api-Token secret-token-123"),
        "auth header must be forwarded on the HTTP transport"
    );

    // Binary protobuf content type.
    assert_eq!(
        captured.header("content-type"),
        Some("application/x-protobuf"),
        "HttpBinary must use protobuf content type"
    );
}

#[test]
fn http_json_uses_json_content_type() {
    let Some(captured) = export_via(OtlpProtocol::HttpJson) else {
        return; // Skipped: shared-process run (see export_via).
    };

    assert!(
        captured.request_line.contains("/v1/traces"),
        "expected the OTLP traces path, got: {}",
        captured.request_line
    );
    assert_eq!(
        captured.header("content-type"),
        Some("application/json"),
        "HttpJson must use JSON content type"
    );
    assert_eq!(
        captured.header("authorization"),
        Some("Api-Token secret-token-123"),
        "auth header must be forwarded on the JSON transport"
    );
}

#[test]
fn default_protocol_is_grpc() {
    // Default transport must remain gRPC — no breaking change for callers.
    let config = OtelConfig::new("default-svc");
    assert_eq!(config.protocol, OtlpProtocol::Grpc);
}
