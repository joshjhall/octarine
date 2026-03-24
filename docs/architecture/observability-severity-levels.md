# Observability Severity Levels

## Overview

The observe module provides a smart logging system with automatic severity assignment based on the type of issue detected. This document explains when to use each severity level.

## Severity Hierarchy

From least to most severe:

### 1. **TRACE** (Development Only)

- **When**: Detailed flow tracking
- **Examples**: Function entry/exit, loop iterations, intermediate values
- **Visibility**: Only when TRACE env var is set
- **Usage**: `Event::trace("Starting validation loop")`

### 2. **DEBUG** (Development)

- **When**: Development information that helps diagnose issues
- **Examples**: Invalid character details, parsing steps, state transitions
- **Visibility**: Development and staging environments
- **Usage**: `Event::debug("Invalid char 'ñ' at position 5")`

### 3. **INFO** (Normal Operations)

- **When**: Normal operational events
- **Examples**: Service started, configuration loaded, metrics recorded
- **Visibility**: All environments
- **Usage**: `Event::info("Service initialized with 4 workers")`

### 4. **SUCCESS** (Positive Outcomes)

- **When**: Operations completed successfully
- **Examples**: User created, payment processed, file uploaded
- **Visibility**: All environments
- **Usage**: `Event::success("User registration completed")`

### 5. **WARN** (Concerning but Not Critical)

- **When**: Invalid input, approaching limits, deprecated usage
- **Examples**: Validation failures, rate limit warnings, reserved keywords
- **Visibility**: All environments
- **Automatic**: `Problem::validation()` logs at this level
- **Usage**: `Event::warn("Rate limit 80% reached")` or `Problem::validation("Invalid email")`

### 6. **ERROR** (Operation Failed)

- **When**: Operations that couldn't complete
- **Examples**: File not found, network timeout, parse errors
- **Visibility**: All environments
- **Automatic**: Most `Problem::*` methods log at this level
- **Usage**: `Problem::not_found("Config file")` or `Event::error("Database connection failed")`

### 7. **CRITICAL** (Immediate Attention Required)

- **When**: Security threats, attacks, system failures
- **Examples**: SQL injection, privilege escalation, data corruption
- **Visibility**: All environments with immediate alerts
- **Automatic**: `Problem::security()` logs at this level
- **Usage**: `Event::critical("SQL injection detected!")` or `Problem::security("Attack blocked")`

## Security-Specific Guidelines

### What's CRITICAL (Security)?

- **SQL Injection Attempts**: Any SQL metacharacters in identifiers
- **Command Injection**: Shell metacharacters in env vars or commands
- **Privilege Escalation**: Attempts to override LD_PRELOAD, PATH, IFS
- **Cardinality Attacks**: Excessive metric labels (DoS attempt)
- **Template Injection**: ${} or {{}} patterns in user input
- **Path Traversal**: ../ patterns attempting to escape boundaries
- **Active Attacks**: Multiple injection attempts from same source

### What's WARNING (Validation)?

- **Invalid Format**: Email doesn't match pattern
- **Reserved Keywords**: Using "SELECT" as table name (likely mistake)
- **Length Exceeded**: Username too long (user error)
- **Invalid Characters**: Spaces in identifiers (formatting issue)
- **Missing Required Fields**: Incomplete form submission

## Code Examples

### Automatic Logging via Problem

```rust
// Validation failure - logs at WARN automatically
if !is_valid_email(input) {
    return Err(Problem::validation("Invalid email format"));
}

// Security issue - logs at CRITICAL automatically
if contains_sql_injection(input) {
    return Err(Problem::security("SQL injection detected"));
}

// Not found - logs at ERROR automatically
if !file.exists() {
    return Err(Problem::not_found("Configuration file"));
}
```

### Manual Logging via Event

```rust
// Log without returning error (e.g., honeypot detection)
if is_honeypot_field_filled(form) {
    Event::critical("Bot detected via honeypot");
    // Continue processing to not reveal detection
}

// Debug info during validation
Event::debug(format!("Validating {} fields", fields.len()));

// Success after operation
Event::success("Payment processed successfully");
```

### Combined Approach

```rust
// Log additional context before returning error
if is_sql_injection(input) {
    Event::critical(format!("SQL injection from IP: {}", ip));
    Event::debug(format!("Payload: {:?}", input));
    return Err(Problem::security("SQL injection blocked"));
}
```

## Best Practices

1. **Don't Log Twice**: `Problem::*` already logs, don't add redundant `Event::*` calls
1. **Add Context with Event**: Use `Event::debug()` for additional details before Problem
1. **Critical = Immediate**: CRITICAL should trigger alerts/pages
1. **Warn ≠ Error**: Warnings are for bad input, errors are for system failures
1. **Security = Critical**: Security issues should always be CRITICAL
1. **Be Specific**: Include relevant details in the message
1. **No Secrets**: Never log passwords, tokens, or sensitive data

## Environment-Specific Behavior

The observe module automatically adjusts based on environment:

- **Development**: Shows all levels including TRACE/DEBUG
- **Staging**: Shows INFO and above, redacts some sensitive data
- **Production**: Shows WARN and above, full redaction, sends to SIEM

## Integration with Monitoring

Different severity levels trigger different responses:

- **TRACE/DEBUG**: Local logs only
- **INFO/SUCCESS**: Metrics and logs
- **WARN**: Logs + dashboard counters
- **ERROR**: Logs + alerts to on-call (business hours)
- **CRITICAL**: Logs + immediate page to on-call + incident creation
