//! Distributed tracing example
//!
//! This example demonstrates:
//! - Correlation ID propagation across operations
//! - Parent-child span relationships
//! - Cross-service tracing patterns
//! - Context propagation best practices

#![allow(clippy::expect_used, clippy::print_stdout)]

use octarine::observe::{TenantContext, TenantId, set_tenant};
use octarine::{Result, debug, error, fail, info, success, warn};
use std::collections::HashMap;
use uuid::Uuid;

/// Simulated HTTP headers for demonstrating context propagation
type Headers = HashMap<String, String>;

/// Extract correlation ID from incoming request headers
fn extract_correlation_id(headers: &Headers) -> Uuid {
    headers
        .get("x-correlation-id")
        .and_then(|v| Uuid::parse_str(v).ok())
        .unwrap_or_else(|| {
            let new_id = Uuid::new_v4();
            debug(
                "tracing",
                format!("No correlation ID in request, generated: {}", new_id),
            );
            new_id
        })
}

/// Extract parent span ID from incoming request headers
fn extract_parent_span(headers: &Headers) -> Option<Uuid> {
    headers
        .get("x-parent-span-id")
        .and_then(|v| Uuid::parse_str(v).ok())
}

/// Inject tracing context into outgoing request headers
fn inject_tracing_context(headers: &mut Headers, correlation_id: Uuid, span_id: Uuid) {
    headers.insert("x-correlation-id".to_string(), correlation_id.to_string());
    headers.insert("x-parent-span-id".to_string(), span_id.to_string());
}

/// Simulate an API gateway handling an incoming request
fn api_gateway_handler(incoming_headers: &Headers) -> Result<String> {
    let correlation_id = extract_correlation_id(incoming_headers);
    let _parent_span = extract_parent_span(incoming_headers);

    info(
        "api_gateway",
        format!("Received request [correlation_id={}]", correlation_id),
    );

    // Validate request
    debug("api_gateway", "Validating request authentication");

    // Route to appropriate service
    let mut outgoing_headers = Headers::new();
    let gateway_span_id = Uuid::new_v4();
    inject_tracing_context(&mut outgoing_headers, correlation_id, gateway_span_id);

    // Call downstream service
    let result = user_service_handler(&outgoing_headers)?;

    success(
        "api_gateway",
        format!("Request completed [correlation_id={}]", correlation_id),
    );

    Ok(result)
}

/// Simulate a user service processing a request
fn user_service_handler(headers: &Headers) -> Result<String> {
    let correlation_id = extract_correlation_id(headers);
    let parent_span = extract_parent_span(headers);

    info(
        "user_service",
        format!(
            "Processing user request [correlation_id={}, parent_span={:?}]",
            correlation_id, parent_span
        ),
    );

    // Perform user lookup
    debug("user_service", "Looking up user in database");

    // Call another downstream service
    let mut outgoing_headers = Headers::new();
    let service_span_id = Uuid::new_v4();
    inject_tracing_context(&mut outgoing_headers, correlation_id, service_span_id);

    let order_result = order_service_handler(&outgoing_headers)?;

    success(
        "user_service",
        format!("User request processed [correlation_id={}]", correlation_id),
    );

    Ok(format!("User data + {}", order_result))
}

/// Simulate an order service processing a request
fn order_service_handler(headers: &Headers) -> Result<String> {
    let correlation_id = extract_correlation_id(headers);
    let parent_span = extract_parent_span(headers);

    info(
        "order_service",
        format!(
            "Processing order request [correlation_id={}, parent_span={:?}]",
            correlation_id, parent_span
        ),
    );

    // Simulate order lookup
    debug("order_service", "Fetching recent orders from database");

    // Simulate a warning condition
    warn(
        "order_service",
        format!(
            "Order cache miss, fetching from DB [correlation_id={}]",
            correlation_id
        ),
    );

    success(
        "order_service",
        format!(
            "Order request processed [correlation_id={}]",
            correlation_id
        ),
    );

    Ok("Order data".to_string())
}

/// Demonstrate error propagation with tracing context
fn failing_service_handler(headers: &Headers) -> Result<String> {
    let correlation_id = extract_correlation_id(headers);

    info(
        "failing_service",
        format!("Processing request [correlation_id={}]", correlation_id),
    );

    // Simulate an error condition
    error(
        "failing_service",
        format!(
            "Database connection timeout [correlation_id={}]",
            correlation_id
        ),
    );

    // Return error (in real code, would use fail() helpers)
    Err(fail("database", "Connection timeout after 30 seconds"))
}

/// Demonstrate async-like tracing patterns (simulated with closures)
fn with_tracing_context<F, R>(correlation_id: Uuid, operation: &str, f: F) -> R
where
    F: FnOnce() -> R,
{
    info(
        operation,
        format!("Starting operation [correlation_id={}]", correlation_id),
    );

    let result = f();

    success(
        operation,
        format!("Completed operation [correlation_id={}]", correlation_id),
    );

    result
}

fn main() {
    println!("=== Observe Module Distributed Tracing Example ===\n");

    // 1. Basic request flow with correlation ID
    println!("--- Request Flow with Correlation ID ---\n");

    // Simulate incoming request with correlation ID
    let mut incoming = Headers::new();
    let request_correlation_id = Uuid::new_v4();
    incoming.insert(
        "x-correlation-id".to_string(),
        request_correlation_id.to_string(),
    );

    println!(
        "Incoming request with correlation_id: {}\n",
        request_correlation_id
    );

    match api_gateway_handler(&incoming) {
        Ok(result) => println!("Request succeeded: {}\n", result),
        Err(e) => println!("Request failed: {}\n", e),
    }

    // 2. Request without correlation ID (auto-generated)
    println!("--- Request without Correlation ID (auto-generated) ---\n");

    let empty_headers = Headers::new();
    match api_gateway_handler(&empty_headers) {
        Ok(result) => println!("Request succeeded: {}\n", result),
        Err(e) => println!("Request failed: {}\n", e),
    }

    // 3. Multi-tenant tracing
    println!("--- Multi-Tenant Tracing ---\n");

    let tenant_id = TenantId::new("acme-corp").expect("valid tenant");
    let ctx = TenantContext {
        tenant_id,
        tenant_name: Some("ACME Corporation".to_string()),
        tenant_tier: Some("enterprise".to_string()),
    };
    set_tenant(ctx);

    let correlation_id = Uuid::new_v4();
    with_tracing_context(correlation_id, "tenant_operation", || {
        info(
            "business_logic",
            "Processing tenant-specific business logic",
        );
        debug(
            "business_logic",
            "Tenant context automatically included in all events",
        );
    });

    // 4. Error tracing
    println!("\n--- Error Tracing with Context ---\n");

    let mut error_headers = Headers::new();
    let error_correlation_id = Uuid::new_v4();
    error_headers.insert(
        "x-correlation-id".to_string(),
        error_correlation_id.to_string(),
    );

    println!(
        "Simulating error with correlation_id: {}\n",
        error_correlation_id
    );

    match failing_service_handler(&error_headers) {
        Ok(_) => println!("Unexpected success"),
        Err(e) => println!("Error traced: {}\n", e),
    }

    // 5. Span hierarchy demonstration
    println!("--- Span Hierarchy ---\n");

    let root_span = Uuid::new_v4();
    let child_span = Uuid::new_v4();
    let grandchild_span = Uuid::new_v4();

    println!("Root span:       {}", root_span);
    println!("  Child span:    {}", child_span);
    println!("    Grandchild:  {}", grandchild_span);
    println!();

    info(
        "span_demo",
        format!("Root operation [span_id={}]", root_span),
    );
    info(
        "span_demo",
        format!(
            "Child operation [span_id={}, parent={}]",
            child_span, root_span
        ),
    );
    info(
        "span_demo",
        format!(
            "Grandchild operation [span_id={}, parent={}]",
            grandchild_span, child_span
        ),
    );

    // 6. Best practices summary
    println!("\n--- Tracing Best Practices ---\n");
    println!("1. Always extract correlation ID at service boundary");
    println!("2. Generate new ID if not present in incoming request");
    println!("3. Propagate correlation ID to all downstream calls");
    println!("4. Include correlation ID in error messages for debugging");
    println!("5. Use parent span IDs to build trace trees");
    println!("6. Log span transitions (start/end) for timing analysis");

    println!("\n=== Example Complete ===");
}
