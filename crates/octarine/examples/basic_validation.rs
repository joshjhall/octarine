//! Basic validation example showing path and input security checks
//!
//! This example demonstrates:
//! - Path traversal detection with security shortcuts
//! - Path validation with observability
//! - Input validation with error handling
//! - Logging validation results

#![allow(clippy::expect_used, clippy::print_stdout)]

use octarine::data::paths::validate_path;
use octarine::security::paths::is_path_traversal_present;
use octarine::{Result, fail_validation, info, success, warn};

/// Validate a user registration request
fn validate_user_registration(username: &str, path: &str) -> Result<()> {
    // Validate username (alphanumeric + underscores, 3-20 chars)
    if username.len() < 3 || username.len() > 20 {
        return Err(fail_validation(
            "username",
            "Username must be 3-20 characters",
        ));
    }

    if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(fail_validation(
            "username",
            "Username must be alphanumeric or underscores",
        ));
    }

    info("registration", format!("Valid username: {}", username));

    // Check for path traversal attacks (detection — lenient, pattern-based)
    if is_path_traversal_present(path) {
        warn(
            "registration",
            format!("Path traversal detected in: {}", path),
        );
        return Err(fail_validation("path", "Path contains directory traversal"));
    }

    // Validate the path with observability (strict validation)
    validate_path(path)?;

    success(
        "registration",
        format!("All validations passed for user '{}'", username),
    );
    Ok(())
}

fn main() {
    println!("=== Basic Validation Example ===\n");

    // 1. Valid input
    println!("--- Valid Input ---");
    match validate_user_registration("john_doe", "profile/avatar.jpg") {
        Ok(()) => println!("Registration validation successful"),
        Err(e) => println!("Validation failed: {}", e),
    }

    // 2. Path traversal attack
    println!("\n--- Path Traversal Attack ---");
    match validate_user_registration("john_doe", "../../../etc/passwd") {
        Ok(()) => println!("Registration validation successful"),
        Err(e) => println!("Validation failed: {}", e),
    }

    // 3. Invalid username (too short)
    println!("\n--- Invalid Username ---");
    match validate_user_registration("a", "profile/avatar.jpg") {
        Ok(()) => println!("Registration validation successful"),
        Err(e) => println!("Validation failed: {}", e),
    }

    // 4. Invalid username (special characters)
    println!("\n--- Invalid Username Characters ---");
    match validate_user_registration("user@name!", "profile/avatar.jpg") {
        Ok(()) => println!("Registration validation successful"),
        Err(e) => println!("Validation failed: {}", e),
    }

    println!("\n=== Example Complete ===");
}
