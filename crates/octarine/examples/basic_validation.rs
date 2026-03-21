//! Basic validation example showing how to use rust-core security features
//! TODO: Re-enable this example when security module is fixed

fn main() {
    // Examples are disabled during refactoring
    // println!("Security module examples are temporarily disabled during refactoring");
}

// Original code commented out:
/*
use octarine::security::input::validation;
use octarine::{Event, Problem, Result};

fn validate_user_registration(email: &str, username: &str, path: &str) -> Result<()> {
    // Validate email address
    validation::network::validate_email(email)?;
    Event::info("registration", format!("Valid email: {}", email));

    // Validate username (alphanumeric, 3-20 chars)
    if username.len() < 3 || username.len() > 20 {
        return Err(Problem::validation("Username must be 3-20 characters"));
    }
    if !username.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(Problem::validation("Username must be alphanumeric"));
    }
    Event::info("registration", format!("Valid username: {}", username));

    // Validate file path (no traversal)
    if validation::paths::check_has_traversal(path) {
        return Err(Problem::validation("Path contains directory traversal"));
    }
    Event::info("registration", format!("Valid path: {}", path));

    Event::success("registration", "All validations passed!");
    Ok(())
}

fn main() {
    // Set up console output for events
    octarine::observe::functions::init_console();

    println!("=== Testing Valid Input ===");
    match validate_user_registration("user@example.com", "john_doe", "profile/avatar.jpg") {
        Ok(_) => println!("✓ Registration validation successful"),
        Err(e) => println!("✗ Validation failed: {}", e),
    }

    println!("\n=== Testing Invalid Email ===");
    match validate_user_registration("not-an-email", "john_doe", "profile/avatar.jpg") {
        Ok(_) => println!("✓ Registration validation successful"),
        Err(e) => println!("✗ Validation failed: {}", e),
    }

    println!("\n=== Testing Path Traversal ===");
    match validate_user_registration("user@example.com", "john_doe", "../../../etc/passwd") {
        Ok(_) => println!("✓ Registration validation successful"),
        Err(e) => println!("✗ Validation failed: {}", e),
    }

    println!("\n=== Testing Invalid Username ===");
    match validate_user_registration("user@example.com", "a", "profile/avatar.jpg") {
        Ok(_) => println!("✓ Registration validation successful"),
        Err(e) => println!("✗ Validation failed: {}", e),
    }
}
*/
