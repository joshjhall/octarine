//! Compliance-focused observability example
//!
//! This example demonstrates:
//! - PII detection and redaction
//! - Compliance tagging (contains_pii, security_relevant)
//! - Query capabilities for audit reports

#![allow(clippy::expect_used, clippy::print_stdout)]

use octarine::observe::pii::{
    RedactionProfile, is_pii_present, redact_pii_with_profile, scan_for_pii,
};
use octarine::{Result, debug, fail_security, info, warn};

/// Demonstrate PII detection capabilities
fn demonstrate_pii_detection() {
    println!("--- PII Detection ---\n");

    let aws_key_example = format!("AWS key: AKIA{}", "IOSFODNN7EXAMPLE");
    let test_strings = vec![
        ("SSN", "My SSN is 123-45-6789"),
        ("Credit Card", "Card number: 4111-1111-1111-1111"),
        ("Email", "Contact me at user@example.com"),
        ("Phone", "Call me at (555) 123-4567"),
        ("IPv4 Address", "Server IP: 192.168.1.100"),
        ("AWS Key", aws_key_example.as_str()),
        ("No PII", "This is a clean string with no PII"),
    ];

    for (name, text) in &test_strings {
        let pii_types = scan_for_pii(text);
        let has_pii = is_pii_present(text);

        println!("{}: \"{}\"", name, text);
        println!("  Contains PII: {}", has_pii);
        if !pii_types.is_empty() {
            println!(
                "  Detected types: {:?}",
                pii_types
                    .iter()
                    .map(|t| format!("{:?}", t))
                    .collect::<Vec<_>>()
            );
        }
        println!();
    }
}

/// Demonstrate PII redaction with different profiles
fn demonstrate_pii_redaction() {
    println!("--- PII Redaction Profiles ---\n");

    let text = "User John Doe (SSN: 123-45-6789, email: john@example.com) purchased item #12345";

    println!("Original: {}", text);
    println!();

    // Production Strict - maximum redaction
    let strict = redact_pii_with_profile(text, RedactionProfile::ProductionStrict);
    println!("Production Strict:");
    println!("  {}", strict);

    // Production Lenient - preserves some context
    let lenient = redact_pii_with_profile(text, RedactionProfile::ProductionLenient);
    println!("\nProduction Lenient:");
    println!("  {}", lenient);

    // Development - visible for debugging
    let dev = redact_pii_with_profile(text, RedactionProfile::Development);
    println!("\nDevelopment:");
    println!("  {}", dev);

    println!();
}

/// Simulate a compliance-relevant operation
fn process_patient_record(patient_id: &str, action: &str, user: &str) -> Result<()> {
    // Log PHI access (automatically flagged)
    info(
        "phi_access",
        format!(
            "User '{}' performing '{}' on patient record '{}'",
            user, action, patient_id
        ),
    );

    // Simulate authorization check
    let is_authorized = user.starts_with("dr_") || user.starts_with("nurse_");

    if !is_authorized {
        // Security failure creates audit event
        return Err(fail_security(
            "phi_access",
            format!("Unauthorized PHI access attempt by '{}'", user),
        ));
    }

    debug(
        "phi_access",
        format!("Authorization verified for user '{}'", user),
    );

    // Log successful access
    info(
        "phi_access",
        format!(
            "Completed '{}' on patient '{}' by '{}'",
            action, patient_id, user
        ),
    );

    Ok(())
}

/// Simulate GDPR-relevant operations
fn process_user_data(user_email: &str, action: &str) {
    // Auto-redaction in logs
    info(
        "gdpr_operation",
        format!("Processing {} request for user: {}", action, user_email),
    );

    match action {
        "export" => {
            info(
                "data_export",
                "Generating user data export for DSAR request",
            );
        }
        "delete" => {
            warn("data_deletion", "Processing right to erasure request");
        }
        "access" => {
            debug("data_access", "Recording data access for audit trail");
        }
        _ => {
            warn(
                "gdpr_operation",
                format!("Unknown GDPR operation: {}", action),
            );
        }
    }
}

fn main() {
    println!("=== Observe Module Compliance Example ===\n");

    // 1. PII Detection
    demonstrate_pii_detection();

    // 2. PII Redaction
    demonstrate_pii_redaction();

    // 3. HIPAA-style PHI Access Logging
    println!("--- PHI Access Logging (HIPAA) ---\n");

    // Authorized access
    match process_patient_record("PAT-12345", "view", "dr_smith") {
        Ok(()) => println!("PHI access: GRANTED\n"),
        Err(e) => println!("PHI access: DENIED - {}\n", e),
    }

    // Unauthorized access attempt
    match process_patient_record("PAT-12345", "view", "unknown_user") {
        Ok(()) => println!("PHI access: GRANTED\n"),
        Err(e) => println!("PHI access: DENIED - {}\n", e),
    }

    // 4. GDPR Operations
    println!("--- GDPR Operations ---\n");

    process_user_data("user@example.com", "export");
    process_user_data("user@example.com", "delete");
    process_user_data("user@example.com", "access");

    // 5. PCI-DSS Credit Card Handling
    println!("\n--- PCI-DSS Credit Card Handling ---\n");

    let card_number = "4111-1111-1111-1111";
    let redacted = redact_pii_with_profile(card_number, RedactionProfile::ProductionStrict);

    println!("Original card: {}", card_number);
    println!("Logged as: {}", redacted);
    println!("(Last 4 digits preserved per PCI-DSS display requirements)");

    // 6. Audit Trail Summary
    println!("\n--- Audit Trail Features ---\n");
    println!("Each event automatically captures:");
    println!("  - WHO: user_id, tenant_id from context");
    println!("  - WHAT: event_type, message, metadata");
    println!("  - WHEN: timestamp (microsecond precision)");
    println!("  - WHERE: correlation_id, module path");
    println!("  - FLAGS: contains_pii, contains_phi, security_relevant");

    println!("\n=== Example Complete ===");
}
