# Zero-Trust and Defense in Depth

## Core Principle

"Never Trust, Always Verify, Assume Breach" - Every input source is untrusted by default, including internal systems and secure vaults.

## Trust Boundaries

### No Implicit Trust

```rust
use octarine::security::TrustLevel;

// Everything starts untrusted - no exceptions
pub enum TrustLevel {
    Untrusted,  // Default for ALL input
    Validated,  // Passed validation checks
    Verified,   // Cryptographically verified
}

// Even "secure" sources are untrusted
let password_from_vault = get_from_1password();  // Still untrusted!
let config_from_file = read_config();            // Untrusted!
let env_variable = std::env::var("API_KEY");     // Untrusted!
```

### Validation Required

All data must be validated before use:

```rust
// Every data source requires validation
pub fn process_api_key(key: String) -> Result<ValidatedApiKey> {
    // Even from environment variables
    validate_api_key_format(&key)?;
    validate_api_key_entropy(&key)?;
    validate_api_key_charset(&key)?;

    Ok(ValidatedApiKey::new(key))
}
```

## Defense Layers

### Layer 1: Perimeter Security

- Input validation at entry points
- Rate limiting on all endpoints
- Authentication required

### Layer 2: Input Processing

- Type validation
- Format verification
- Size and complexity limits

### Layer 3: Business Logic

- Authorization checks
- Business rule validation
- Consistency verification

### Layer 4: Data Access

- Query parameterization
- Output encoding
- Result filtering

### Layer 5: Audit and Monitoring

- Event generation
- Anomaly detection
- Compliance logging

## Implementation Patterns

### Multi-Layer Validation

```rust
use octarine::security::validators::*;

pub struct DefenseInDepthValidator {
    layers: Vec<Box<dyn Validator>>,
}

impl DefenseInDepthValidator {
    pub fn validate(&self, input: &str) -> Result<ValidatedInput> {
        // All layers must pass independently
        for layer in &self.layers {
            layer.validate(input)?;
        }

        Ok(ValidatedInput::new(input))
    }
}

// Usage
let validator = DefenseInDepthValidator::new()
    .add_layer(LengthValidator::new(1, 1000))
    .add_layer(CharsetValidator::ascii_printable())
    .add_layer(InjectionValidator::new())
    .add_layer(BusinessRuleValidator::new());

let validated = validator.validate(untrusted_input)?;
```

### Fail-Safe Defaults

```rust
// Always fail closed, never open
pub fn check_permission(user: &User, resource: &Resource) -> bool {
    // Default deny
    let mut allowed = false;

    // Must explicitly grant access
    if let Some(permissions) = get_permissions(user) {
        if permissions.can_access(resource) {
            if !rate_limit_exceeded(user) {
                if audit_log_available() {
                    allowed = true;
                    audit_access(user, resource);
                }
            }
        }
    }

    allowed  // Defaults to false if any check fails
}
```

### Assume Breach

```rust
// Design assuming attacker has partial access
pub struct SecureProcessor {
    // Encrypt sensitive data at rest
    data: EncryptedStore,

    // Limit blast radius
    rate_limiter: RateLimiter,

    // Detect anomalies
    anomaly_detector: AnomalyDetector,

    // Audit everything
    audit_log: AuditLog,
}

impl SecureProcessor {
    pub fn process(&mut self, request: Request) -> Result<Response> {
        // Check for anomalies
        if self.anomaly_detector.is_anomalous(&request) {
            self.audit_log.security_event("anomaly_detected", &request);
            return Err(Problem::security("Anomaly detected"));
        }

        // Rate limit everything
        self.rate_limiter.check(&request.user_id)?;

        // Process with minimal privilege
        let result = with_limited_scope(|| {
            self.process_internal(request)
        })?;

        // Audit the operation
        self.audit_log.operation("process_complete", &result);

        Ok(result)
    }
}
```

## Practical Examples

### API Endpoint Protection

```rust
// Multiple independent security layers
pub async fn api_endpoint(req: Request) -> Result<Response> {
    // Layer 1: Authentication
    let user = authenticate(&req)?;

    // Layer 2: Authorization
    authorize(&user, &req.resource)?;

    // Layer 3: Rate limiting
    rate_limit(&user, &req)?;

    // Layer 4: Input validation
    let input = validate_input(&req.body)?;

    // Layer 5: Business logic with monitoring
    let result = with_monitoring(|| {
        process_business_logic(input)
    })?;

    // Layer 6: Output filtering
    let filtered = filter_output(&result, &user.permissions)?;

    // Layer 7: Audit logging
    audit_operation(&user, &req, &result);

    Ok(Response::new(filtered))
}
```

### Configuration Loading

```rust
// Even configuration is untrusted
pub fn load_config(path: &str) -> Result<Config> {
    // Validate path
    let safe_path = sanitize_path_strict(path)?;

    // Read with size limit
    let content = read_file_limited(&safe_path, MAX_CONFIG_SIZE)?;

    // Parse with validation
    let parsed: ConfigData = parse_json_safe(&content)?;

    // Validate all values
    validate_config_values(&parsed)?;

    // Check consistency
    verify_config_consistency(&parsed)?;

    // Return validated config
    Ok(Config::from_validated(parsed))
}
```

## Security Boundaries

### Trust Zones

```text
External → DMZ → Application → Data
   ↓        ↓         ↓          ↓
Untrusted  Validated  Verified  Encrypted
```

### Validation Points

- Network boundary (firewall/WAF)
- Application boundary (input validation)
- Service boundary (API validation)
- Data boundary (query validation)

## Monitoring and Detection

### Continuous Validation

```rust
// Re-validate periodically
pub struct ContinuousValidator {
    cache: HashMap<Key, (ValidatedData, Instant)>,
    ttl: Duration,
}

impl ContinuousValidator {
    pub fn get(&mut self, key: &Key) -> Result<ValidatedData> {
        if let Some((data, timestamp)) = self.cache.get(key) {
            if timestamp.elapsed() < self.ttl {
                // Re-validate even cached data
                self.validate(&data)?;
                return Ok(data.clone());
            }
        }

        Err(Problem::not_found("data", &key.to_string()))
    }
}
```

## Best Practices

1. **Never trust any input source** - Validate everything
1. **Layer independent defenses** - Don't rely on single control
1. **Fail secure by default** - Deny unless explicitly allowed
1. **Assume breach** - Design for compromised components
1. **Monitor continuously** - Detect anomalies in real-time
1. **Limit blast radius** - Minimize damage from breaches
1. **Audit comprehensively** - Log all security-relevant events

## Related Documentation

- [Input Architecture](./input-architecture.md)
- [Detection vs Validation vs Sanitization](./detection-validation-sanitization.md)
- [Security Guidelines](../security-guidelines.md)
