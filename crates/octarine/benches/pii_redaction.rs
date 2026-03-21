//! Performance benchmarks for PII redaction
//!
//! Target: <100μs overhead per event with PII detection
//!
//! Run with: cargo bench --bench pii_redaction

#![allow(clippy::panic, clippy::expect_used, clippy::print_stdout, missing_docs)]

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use octarine::observe::pii::{RedactionProfile, redact_pii_with_profile, scan_for_pii};
use std::hint::black_box;

// Helper function to match original API
fn redact_pii(text: &str) -> String {
    redact_pii_with_profile(text, RedactionProfile::ProductionStrict)
}

// ==========================================
// CLEAN TEXT BENCHMARKS (No PII)
// ==========================================

fn bench_clean_text(c: &mut Criterion) {
    let mut group = c.benchmark_group("clean_text");

    let inputs = vec![
        ("short", "Server started successfully"),
        (
            "medium",
            "User logged in from endpoint /api/v1/users/profile with status 200 OK",
        ),
        (
            "long",
            "Processing payment transaction for order #12345 at 2025-11-17T10:30:00Z with amount $99.99 USD status approved",
        ),
    ];

    for (name, text) in inputs {
        group.throughput(Throughput::Bytes(text.len() as u64));

        group.bench_with_input(BenchmarkId::new("scan", name), &text, |b, text| {
            b.iter(|| scan_for_pii(black_box(text)));
        });

        group.bench_with_input(BenchmarkId::new("redact", name), &text, |b, text| {
            b.iter(|| redact_pii(black_box(text)));
        });
    }

    group.finish();
}

// ==========================================
// SINGLE PII TYPE BENCHMARKS
// ==========================================

fn bench_single_pii_type(c: &mut Criterion) {
    let mut group = c.benchmark_group("single_pii_type");

    let inputs = vec![
        ("ssn", "User SSN: 900-00-0001"),
        ("email", "Contact: user@example.com"),
        ("credit_card", "Card: 4242424242424242"),
        ("phone", "Call: +1-555-123-4567"),
        ("password", "password=secret123"),
        ("ip_address", "Server: 192.168.1.1"),
        ("api_key", "Key: sk_test_123456789"),
    ];

    for (name, text) in &inputs {
        group.throughput(Throughput::Bytes(text.len() as u64));

        group.bench_with_input(BenchmarkId::new("scan", name), text, |b, text| {
            b.iter(|| scan_for_pii(black_box(text)));
        });

        group.bench_with_input(BenchmarkId::new("redact", name), text, |b, text| {
            b.iter(|| redact_pii(black_box(text)));
        });
    }

    group.finish();
}

// ==========================================
// MULTIPLE PII TYPES BENCHMARKS
// ==========================================

fn bench_multiple_pii_types(c: &mut Criterion) {
    let mut group = c.benchmark_group("multiple_pii_types");

    let inputs = vec![
        ("two_types", "Email: user@example.com, SSN: 900-00-0001"),
        (
            "three_types",
            "User: user@example.com, SSN: 900-00-0001, Card: 4242424242424242",
        ),
        (
            "five_types",
            "Contact: user@example.com, SSN: 900-00-0001, Card: 4242424242424242, Phone: +1-555-123-4567, IP: 192.168.1.1",
        ),
    ];

    for (name, text) in &inputs {
        group.throughput(Throughput::Bytes(text.len() as u64));

        group.bench_with_input(BenchmarkId::new("scan", name), text, |b, text| {
            b.iter(|| scan_for_pii(black_box(text)));
        });

        group.bench_with_input(BenchmarkId::new("redact", name), text, |b, text| {
            b.iter(|| redact_pii(black_box(text)));
        });
    }

    group.finish();
}

// ==========================================
// PROFILE COMPARISON BENCHMARKS
// ==========================================

fn bench_redaction_profiles(c: &mut Criterion) {
    let mut group = c.benchmark_group("redaction_profiles");

    let text = "User: user@example.com, SSN: 900-00-0001, IP: 192.168.1.1";
    group.throughput(Throughput::Bytes(text.len() as u64));

    let profiles = vec![
        ("production_strict", RedactionProfile::ProductionStrict),
        ("production_lenient", RedactionProfile::ProductionLenient),
        ("development", RedactionProfile::Development),
        ("testing", RedactionProfile::Testing),
    ];

    for (name, profile) in profiles {
        group.bench_with_input(BenchmarkId::from_parameter(name), &profile, |b, profile| {
            b.iter(|| redact_pii_with_profile(black_box(text), black_box(*profile)));
        });
    }

    group.finish();
}

// ==========================================
// REAL-WORLD SCENARIO BENCHMARKS
// ==========================================

fn bench_real_world_scenarios(c: &mut Criterion) {
    let mut group = c.benchmark_group("real_world_scenarios");

    let scenarios = vec![
        (
            "user_registration",
            "User registered successfully: email=user@example.com, ip=192.168.1.100, timestamp=2025-11-17T10:30:00Z",
        ),
        (
            "payment_processing",
            "Processing payment for card 4242424242424242 amount $99.99 USD status approved transaction_id=txn_123456",
        ),
        (
            "authentication_log",
            "Authentication attempt: user@example.com from 10.0.0.1 user_agent=Mozilla/5.0 status=success",
        ),
        (
            "error_message",
            "Failed to send email to user@example.com: SMTP connection refused at 192.168.1.25:587 retry_count=3",
        ),
        (
            "audit_log",
            "User admin@company.com (SSN: 900-00-0001) accessed patient record PHI_ID=12345 from 10.0.0.5 at 2025-11-17T14:30:00Z",
        ),
    ];

    for (name, text) in &scenarios {
        group.throughput(Throughput::Bytes(text.len() as u64));

        group.bench_with_input(BenchmarkId::new("scan", name), text, |b, text| {
            b.iter(|| scan_for_pii(black_box(text)));
        });

        group.bench_with_input(BenchmarkId::new("redact", name), text, |b, text| {
            b.iter(|| redact_pii(black_box(text)));
        });
    }

    group.finish();
}

// ==========================================
// EDGE CASES AND WORST-CASE BENCHMARKS
// ==========================================

fn bench_edge_cases(c: &mut Criterion) {
    let mut group = c.benchmark_group("edge_cases");

    // Empty string
    group.bench_function("empty_string", |b| {
        b.iter(|| redact_pii(black_box("")));
    });

    // Very long text with no PII (worst case for scanning)
    let long_clean = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(50);
    group.throughput(Throughput::Bytes(long_clean.len() as u64));
    group.bench_function("long_clean_text", |b| {
        b.iter(|| redact_pii(black_box(&long_clean)));
    });

    // Very long text with multiple PII instances
    let long_with_pii = format!(
        "User {} registered from {} with card {} and SSN {} and phone {}. ",
        "user@example.com", "192.168.1.1", "4242424242424242", "900-00-0001", "+1-555-123-4567"
    )
    .repeat(20);
    group.throughput(Throughput::Bytes(long_with_pii.len() as u64));
    group.bench_function("long_text_with_pii", |b| {
        b.iter(|| redact_pii(black_box(&long_with_pii)));
    });

    // Multiple instances of same PII type
    let repeated_emails = "Contacts: user1@example.com, user2@example.com, user3@example.com, user4@example.com, user5@example.com";
    group.throughput(Throughput::Bytes(repeated_emails.len() as u64));
    group.bench_function("repeated_pii_type", |b| {
        b.iter(|| redact_pii(black_box(repeated_emails)));
    });

    group.finish();
}

// ==========================================
// OVERHEAD MEASUREMENT (Target: <100μs)
// ==========================================

fn bench_overhead_target(c: &mut Criterion) {
    let mut group = c.benchmark_group("overhead_target");

    // Typical event message with mixed content
    let typical_event =
        "User user@example.com logged in successfully from 192.168.1.100 at 2025-11-17T10:30:00Z";

    group.throughput(Throughput::Bytes(typical_event.len() as u64));

    // Measure baseline (no PII processing)
    group.bench_function("baseline_no_processing", |b| {
        b.iter(|| {
            let _ = black_box(typical_event);
        });
    });

    // Measure scan only
    group.bench_function("scan_only", |b| {
        b.iter(|| scan_for_pii(black_box(typical_event)));
    });

    // Measure full redaction (scan + redact)
    group.bench_function("full_redaction", |b| {
        b.iter(|| redact_pii(black_box(typical_event)));
    });

    // Target: <100μs overhead for typical event with PII detection and redaction

    group.finish();
}

criterion_group!(
    benches,
    bench_clean_text,
    bench_single_pii_type,
    bench_multiple_pii_types,
    bench_redaction_profiles,
    bench_real_world_scenarios,
    bench_edge_cases,
    bench_overhead_target
);
criterion_main!(benches);
