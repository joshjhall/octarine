//! Basic observability example showing logging and error handling
//!
//! This example demonstrates:
//! - Simple logging with operation context
//! - Error handling with automatic audit trail
//! - Multi-tenant context
//! - PII detection

#![allow(clippy::expect_used, clippy::print_stdout)]

use octarine::observe::{TenantContext, TenantId, clear_tenant, set_tenant, with_tenant};
use octarine::{Result, debug, error, fail_permission, fail_validation, info, success, warn};

/// Simple user validation with logging
fn validate_user(username: &str) -> Result<()> {
    debug("validation", format!("Validating username: {}", username));

    if username.is_empty() {
        return Err(fail_validation("username", "Username cannot be empty"));
    }

    if username.len() < 3 {
        return Err(fail_validation(
            "username",
            "Username must be at least 3 characters",
        ));
    }

    if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(fail_validation("username", "Username must be alphanumeric"));
    }

    success("validation", format!("Username '{}' is valid", username));
    Ok(())
}

/// Resource access with permission checking
fn access_resource(user: &str, resource: &str, has_permission: bool) -> Result<String> {
    info(
        "resource_access",
        format!("User '{}' requesting access to '{}'", user, resource),
    );

    if !has_permission {
        // This creates a security audit event automatically
        return Err(fail_permission("resource_access", user, resource));
    }

    success(
        "resource_access",
        format!("Access granted to '{}' for user '{}'", resource, user),
    );
    Ok(format!("Content of {}", resource))
}

/// Process payment with logging and error handling
fn process_payment(user: &str, amount: f64) -> Result<String> {
    info(
        "payment",
        format!("Processing payment of ${:.2} for user '{}'", amount, user),
    );

    if amount <= 0.0 {
        return Err(fail_validation("amount", "Payment amount must be positive"));
    }

    if amount > 10000.0 {
        warn(
            "payment",
            format!(
                "Large payment detected: ${:.2} - flagging for review",
                amount
            ),
        );
    }

    // Simulate processing
    let transaction_id = format!("TXN-{}", uuid::Uuid::new_v4());

    success(
        "payment",
        format!(
            "Payment of ${:.2} completed - Transaction: {}",
            amount, transaction_id
        ),
    );

    Ok(transaction_id)
}

/// Demonstrate PII detection (SSN will be redacted in logs)
fn log_with_pii() {
    // The observe module automatically detects and redacts PII
    info(
        "pii_demo",
        "User SSN is 123-45-6789 and email is user@example.com",
    );
    // In logs, this will appear with SSN and email redacted
}

fn main() {
    println!("=== Observe Module Basic Example ===\n");

    // 1. Simple logging
    println!("--- Simple Logging ---");
    info("startup", "Application starting");
    debug("config", "Loading configuration from default path");
    warn("config", "Using deprecated configuration format");

    // 2. User validation
    println!("\n--- User Validation ---");
    match validate_user("john_doe") {
        Ok(()) => println!("Valid user"),
        Err(e) => println!("Validation error: {}", e),
    }

    match validate_user("ab") {
        Ok(()) => println!("Valid user"),
        Err(e) => println!("Validation error: {}", e),
    }

    // 3. Resource access with permissions
    println!("\n--- Resource Access ---");
    match access_resource("alice", "/api/data", true) {
        Ok(content) => println!("Got content: {}", content),
        Err(e) => println!("Access denied: {}", e),
    }

    match access_resource("bob", "/api/admin", false) {
        Ok(content) => println!("Got content: {}", content),
        Err(e) => println!("Access denied: {}", e),
    }

    // 4. Payment processing
    println!("\n--- Payment Processing ---");
    match process_payment("customer-123", 99.99) {
        Ok(txn) => println!("Transaction ID: {}", txn),
        Err(e) => println!("Payment failed: {}", e),
    }

    match process_payment("customer-456", -50.0) {
        Ok(txn) => println!("Transaction ID: {}", txn),
        Err(e) => println!("Payment failed: {}", e),
    }

    // 5. Multi-tenant context
    println!("\n--- Multi-Tenant Context ---");

    // Set tenant context for current thread
    let tenant_id = TenantId::new("acme-corp").expect("valid tenant ID");
    let ctx = TenantContext {
        tenant_id,
        tenant_name: Some("ACME Corporation".to_string()),
        tenant_tier: Some("enterprise".to_string()),
    };
    set_tenant(ctx);

    // All events now include tenant context
    info(
        "tenant_demo",
        "This event includes ACME Corp tenant context",
    );

    // Scoped tenant context
    let other_tenant = TenantId::new("other-tenant").expect("valid tenant ID");
    let other_ctx = TenantContext {
        tenant_id: other_tenant,
        tenant_name: None,
        tenant_tier: None,
    };
    with_tenant(other_ctx, || {
        info(
            "tenant_demo",
            "This event includes other-tenant context (scoped)",
        );
    });

    // Back to original context (ACME)
    info(
        "tenant_demo",
        "Back to ACME Corp context after scoped block",
    );

    clear_tenant();
    info("tenant_demo", "This event has no tenant context (cleared)");

    // 6. PII detection demonstration
    println!("\n--- PII Detection ---");
    log_with_pii();
    println!("(Check logs - PII should be redacted)");

    // 7. Error severity levels
    println!("\n--- Error Levels ---");
    debug("levels", "Debug: detailed diagnostic information");
    info("levels", "Info: general operational messages");
    warn("levels", "Warning: potential issues to investigate");
    error("levels", "Error: operation failed but system continues");

    info("shutdown", "Application shutting down cleanly");
    println!("\n=== Example Complete ===");
}
