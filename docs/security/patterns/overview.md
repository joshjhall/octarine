# Security Patterns Guide

## OWASP Top 10 Implementation

### 1. Injection Prevention

**Principle**: Validate structure, not patterns. Separate data from commands.

```rust
// SQL Injection Prevention
pub fn validate_sql_identifier(name: &str) -> Result<String> {
    // Whitelist approach - only allow safe characters
    if !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return Err(Problem::validation("Invalid SQL identifier"));
    }

    // Check reserved words
    if SQL_RESERVED_WORDS.contains(&name.to_uppercase().as_str()) {
        return Err(Problem::validation("Reserved SQL keyword"));
    }

    Ok(name.to_string())
}

// Command Injection Prevention
pub fn sanitize_shell_arg(arg: &str) -> String {
    // Use proper escaping, never string concatenation
    shell_escape::escape(arg.into()).to_string()
}
```

### 2. Path Traversal Prevention

**Principle**: Normalize first, validate second, jail third.

```rust
pub fn prevent_traversal(path: &str) -> Result<String> {
    // 1. Normalize first
    let normalized = normalize_path(path);

    // 2. Check after normalization
    if normalized.contains("..") {
        Event::security("traversal_attempt", path);
        return Err(Problem::validation("Path traversal detected"));
    }

    // 3. Jail to safe directory
    let jailed = jail_path(&normalized, "/safe/root")?;

    Ok(jailed)
}
```

### 3. XSS Prevention

**Principle**: Context-aware encoding based on output location.

```rust
pub enum HtmlContext {
    Text,
    Attribute,
    JavaScript,
    Css,
    Url,
}

pub fn encode_for_html(input: &str, context: HtmlContext) -> String {
    match context {
        HtmlContext::Text => html_escape::encode_text(input),
        HtmlContext::Attribute => html_escape::encode_double_quoted_attribute(input),
        HtmlContext::JavaScript => js_escape::escape(input),
        HtmlContext::Css => css_escape::escape(input),
        HtmlContext::Url => percent_encoding::utf8_percent_encode(input, NON_ALPHANUMERIC),
    }
}
```

## Input Validation Strategy

### Size Limits (DoS Prevention)

```rust
pub struct InputLimits {
    pub max_length: usize,
    pub max_depth: usize,      // For nested structures
    pub max_elements: usize,   // For collections
    pub timeout: Duration,     // Processing timeout
}

pub fn validate_with_limits<T>(input: &str, limits: &InputLimits) -> Result<T> {
    // Check size first (cheap)
    if input.len() > limits.max_length {
        return Err(Problem::validation("Input too large"));
    }

    // Parse with timeout
    let result = timeout(limits.timeout, async {
        parse_input(input)
    }).await?;

    // Check complexity
    if count_depth(&result) > limits.max_depth {
        return Err(Problem::validation("Input too complex"));
    }

    Ok(result)
}
```

### Multi-Layer Validation

```rust
pub fn validate_email_comprehensive(email: &str) -> Result<String> {
    // Layer 1: Basic format
    if !email.contains('@') {
        return Err(Problem::validation("Invalid email format"));
    }

    // Layer 2: Length limits
    if email.len() > 254 {  // RFC 5321
        return Err(Problem::validation("Email too long"));
    }

    // Layer 3: Structure validation
    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return Err(Problem::validation("Invalid email structure"));
    }

    // Layer 4: Component validation
    validate_email_local_part(parts[0])?;
    validate_email_domain(parts[1])?;

    // Layer 5: Security checks
    check_for_homograph_attack(email)?;

    Ok(email.to_string())
}
```

## Secure Defaults

### Configuration

```rust
pub struct SecurityConfig {
    pub max_input_size: usize,
    pub enable_debug_logging: bool,
    pub allow_unsafe_operations: bool,
    pub session_timeout: Duration,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_input_size: 1_048_576,        // 1MB - conservative default
            enable_debug_logging: false,       // No debug in production
            allow_unsafe_operations: false,    // Deny by default
            session_timeout: Duration::from_secs(900), // 15 minutes
        }
    }
}
```

### Fail Closed

```rust
pub fn check_permission(user: &User, resource: &str) -> bool {
    match load_permissions(user) {
        Ok(perms) => perms.can_access(resource),
        Err(e) => {
            // On error, deny access (fail closed)
            Event::security("permission_check_failed", e.to_string());
            false  // Deny by default
        }
    }
}
```

## Sensitive Data Handling

### Never Log Sensitive Data

```rust
pub fn log_request(request: &Request) {
    Event::info("request", format!(
        "Method: {}, Path: {}, User: {}",
        request.method,
        request.path,
        request.user_id,  // ID only, not credentials
    ));
    // Never log: passwords, tokens, keys, PII
}
```

### Redaction

```rust
pub fn redact_sensitive(text: &str) -> String {
    let mut result = text.to_string();

    // Redact credit cards
    result = CREDIT_CARD_REGEX.replace_all(&result, "****-****-****-$1").to_string();

    // Redact SSNs
    result = SSN_REGEX.replace_all(&result, "***-**-$1").to_string();

    // Redact API keys
    result = API_KEY_REGEX.replace_all(&result, "$1****").to_string();

    result
}
```

## Rate Limiting

```rust
pub struct RateLimiter {
    limits: HashMap<String, TokenBucket>,
}

impl RateLimiter {
    pub fn check_rate_limit(&self, key: &str, cost: u32) -> Result<()> {
        let bucket = self.limits.get(key)
            .ok_or_else(|| Problem::not_found("No rate limit configured"))?;

        if !bucket.try_consume(cost) {
            Event::security("rate_limit_exceeded", key);
            return Err(Problem::rate_limited(bucket.time_until_refill()));
        }

        Ok(())
    }
}
```

## Security Event Logging

### What to Log

```rust
pub enum SecurityEventType {
    // Always log these
    AuthenticationFailure,
    AuthorizationFailure,
    InputValidationFailure,
    RateLimitExceeded,
    SuspiciousPattern,

    // Log with context
    LoginSuccess,       // Include source IP
    PrivilegedOperation, // Include what was done
    ConfigurationChange, // Include what changed
}

pub fn log_security_event(event_type: SecurityEventType, context: &Context) {
    let event = SecurityEvent {
        event_type,
        timestamp: Utc::now(),
        user_id: context.user_id.clone(),
        session_id: context.session_id.clone(),
        ip_address: context.ip_address.clone(),
        user_agent: context.user_agent.clone(),
        // Never log passwords, tokens, or PII
    };

    Event::security(event_type.as_str(), serde_json::to_string(&event)?);
}
```

## Cryptography Guidelines

### Use High-Level APIs

```rust
// Use high-level crypto libraries, not primitives
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let hash = argon2.hash_password(password.as_bytes(), &salt)
        .map_err(|e| Problem::operation_failed(e.to_string()))?;

    Ok(hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| Problem::parse(e.to_string()))?;

    let argon2 = Argon2::default();
    Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
}
```

### Secure Random

```rust
use rand::rngs::OsRng;
use rand::RngCore;

pub fn generate_session_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    base64::encode_config(bytes, base64::URL_SAFE_NO_PAD)
}
```

## Testing Security

### Security Test Cases

```rust
#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn test_sql_injection_prevention() {
        // Test dangerous inputs
        assert!(validate_sql_identifier("users; DROP TABLE users").is_err());
        assert!(validate_sql_identifier("' OR '1'='1").is_err());
        assert!(validate_sql_identifier("admin'--").is_err());
    }

    #[test]
    fn test_path_traversal_prevention() {
        // Test traversal attempts
        assert!(prevent_traversal("../../../etc/passwd").is_err());
        assert!(prevent_traversal("..\\..\\windows\\system32").is_err());
        assert!(prevent_traversal("/etc/passwd").is_err());
    }

    #[test]
    fn test_rate_limiting() {
        let limiter = RateLimiter::new();

        // Should allow initial requests
        assert!(limiter.check_rate_limit("user1", 1).is_ok());

        // Should block after limit
        for _ in 0..100 {
            let _ = limiter.check_rate_limit("user1", 1);
        }
        assert!(limiter.check_rate_limit("user1", 1).is_err());
    }
}
```

## Security Checklist

Before deploying:

- [ ] All inputs validated and size-limited
- [ ] SQL queries use parameters, not concatenation
- [ ] Paths normalized before validation
- [ ] HTML output properly encoded
- [ ] Sensitive data never logged
- [ ] Rate limiting on all endpoints
- [ ] Security events logged with context
- [ ] Passwords hashed with Argon2/bcrypt
- [ ] HTTPS/TLS enforced
- [ ] Security headers configured

## See Also

- [`../../api/error-handling.md`](../../api/error-handling.md) - Error handling patterns
- [`../../../crates/octarine/src/security/`](../../../crates/octarine/src/security/) - Security module implementation
- [`./detection-validation-sanitization.md`](./detection-validation-sanitization.md) - Layer separation for validation
- [`./input-architecture.md`](./input-architecture.md) - Input validation architecture
