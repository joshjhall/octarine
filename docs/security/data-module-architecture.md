# Security Data Module Architecture

## Overview

The `security/data` module provides comprehensive data security operations for Rust applications. It encompasses four major pillars of data security: detection, validation, sanitization, and conversion. This unified approach ensures that all data - whether from user input, files, APIs, or databases - is processed through consistent security controls.

## Why "Data" Instead of "Input"?

The module was renamed from `security/input` to `security/data` to better reflect its comprehensive scope:

- **Broader Application**: Handles data from any source (user input, files, APIs, databases, logs)
- **Unified Pipeline**: All data flows through the same security controls
- **Future-Proof**: Supports data discovery, classification, and compliance scanning
- **Clear Intent**: "Data security" immediately conveys the module's purpose

## Module Structure

```text
security/
└── data/                       # All data security operations
    ├── detection/              # Identify data types and patterns
    │   ├── classifiers/        # Data type detection
    │   ├── patterns/           # Pattern matching (PII, secrets)
    │   └── risk/               # Risk assessment
    │
    ├── validation/             # Verify data correctness and safety
    │   ├── identifiers/        # IDs, tokens, keys
    │   ├── network/            # URLs, IPs, emails
    │   ├── paths/              # File paths, directories
    │   └── formats/            # JSON, XML, dates
    │
    ├── sanitization/           # Make data safe for use
    │   ├── redaction/          # Remove sensitive data
    │   ├── escaping/           # Context-aware escaping
    │   └── normalization/      # Standardize formats
    │
    └── conversion/             # Transform data formats
        ├── encoding/           # Character encoding
        ├── serialization/      # Format conversion
        └── compression/        # Data compression
```

## The Four Pillars

### 1. Detection (What is this data?)

Identifies the type and characteristics of data before processing:

```rust
use security::data::detection;

// Automatic type detection
let data_type = detection::identify("123-45-6789")?;
match data_type {
    DataType::SSN => { /* Handle SSN */ },
    DataType::Phone => { /* Handle phone */ },
    _ => { /* Handle other */ }
}

// Risk assessment
if detection::contains_sensitive_data(text) {
    // Apply additional security controls
}

// Pattern matching
if detection::is_credit_card_likely(input) {
    // PCI DSS compliance required
}
```

### 2. Validation (Is this data valid?)

Ensures data meets security and business requirements:

```rust
use security::data::validation;

// Simple validation
validation::identifiers::validate_ssn("123-45-6789")?;
validation::network::validate_email("user@example.com")?;
validation::paths::validate_no_traversal("/safe/path")?;

// Builder pattern for complex validation
let validator = validation::NetworkValidator::new()
    .with_context(NetworkContext::Email)
    .require_dns_validation()
    .block_disposable_domains()
    .build();

validator.validate(email)?;
```

### 3. Sanitization (Make it safe)

Transforms potentially dangerous data into safe formats:

```rust
use security::data::sanitization;

// Remove sensitive data
let safe_log = sanitization::redact_pii(log_entry);

// Context-aware escaping
let safe_html = sanitization::escape_html(user_input);
let safe_sql = sanitization::escape_sql_identifier(table_name);

// Path normalization
let safe_path = sanitization::normalize_path(user_path);
```

### 4. Conversion (Transform format)

Safely converts between data formats:

```rust
use security::data::conversion;

// Encoding conversion
let utf8 = conversion::to_utf8(bytes)?;
let base64 = conversion::to_base64(data);

// Format conversion
let json = conversion::xml_to_json(xml_data)?;
let yaml = conversion::json_to_yaml(json_data)?;
```

## Data Processing Pipeline

The typical data flow through the security pipeline:

```rust
use security::data::{detection, validation, sanitization};

pub fn process_user_data(input: &str) -> Result<String, SecurityError> {
    // 1. Detect what type of data this is
    let data_type = detection::identify(input)?;

    // 2. Validate based on detected type
    match data_type {
        DataType::Email => validation::network::validate_email(input)?,
        DataType::Path => validation::paths::validate_safe_path(input)?,
        DataType::SSN => validation::identifiers::validate_ssn(input)?,
        _ => validation::text::validate_safe_text(input)?
    }

    // 3. Sanitize for the target context
    let sanitized = match context {
        Context::Database => sanitization::escape_sql(input),
        Context::HTML => sanitization::escape_html(input),
        Context::Log => sanitization::redact_sensitive(input),
        _ => sanitization::basic_sanitize(input)
    };

    // 4. Convert if needed
    let final_data = if needs_encoding {
        conversion::encode_utf8(sanitized)?
    } else {
        sanitized
    };

    Ok(final_data)
}
```

## OWASP Compliance

The module implements OWASP best practices throughout:

### Input Validation (OWASP Top 10 - A03:2021)

- Whitelist validation preferred over blacklist
- Context-specific validation rules
- Length and format restrictions
- Type checking and coercion

### Injection Prevention (OWASP Top 10 - A03:2021)

- SQL injection prevention through parameterization
- XSS prevention through context-aware encoding
- Command injection prevention through safe APIs
- Path traversal prevention through canonicalization

### Sensitive Data Exposure (OWASP Top 10 - A02:2021)

- Automatic PII detection and redaction
- Credit card masking (PCI DSS)
- SSN/ITIN/EIN protection
- API key and token redaction

### Security Logging (OWASP Top 10 - A09:2021)

- Automatic security event generation
- Safe logging with PII redaction
- Audit trail generation
- Compliance reporting

## Usage Patterns

### Simple Functions (80% of use cases)

For common scenarios, use the simple function API:

```rust
use security::data::validation::identifiers;

// Quick validation with defaults
if identifiers::is_valid_credit_card(card_number) {
    process_payment(card_number);
}
```

### Builder Pattern (Complex scenarios)

For advanced configuration, use the builder pattern:

```rust
use security::data::validation::IdentifierValidator;

let validator = IdentifierValidator::new()
    .with_context(IdentifierContext::Payment)
    .require_luhn_check()
    .allow_test_cards(false)
    .with_pci_compliance()
    .build();

validator.validate_credit_card(card_number)?;
```

### Shortcuts (Domain-specific helpers)

Pre-configured validators for specific domains:

```rust
use security::data::validation::shortcuts::payment;

// PCI-compliant credit card validation
payment::validate_for_processing(card_data)?;

// E-commerce validation (more permissive)
payment::validate_for_display(card_data)?;
```

## Integration with Other Modules

The data module integrates seamlessly with other security components:

### With Observe Module

```rust
// Automatic event generation
validation::validate_ssn(ssn)
    .map_err(|e| {
        observe::event::security_warning("Invalid SSN attempt");
        e
    })?;
```

### With Audit Module

```rust
// Automatic audit logging
let safe_data = sanitization::redact_for_audit(sensitive_data);
audit::log_data_access(user, resource, safe_data);
```

### With Access Control

```rust
// Rate limiting on validation failures
if !validation::is_valid_email(email) {
    access_control::increment_failure_count(client_ip);
}
```

## Performance Considerations

The module is designed for high performance:

- **Lazy Compilation**: Regex patterns compiled once and cached
- **Zero-Copy**: Where possible, returns references instead of clones
- **Fast Path**: Common cases optimized with dedicated code paths
- **Batch Processing**: Support for validating multiple items efficiently

## Testing

Comprehensive test coverage ensures reliability:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssn_validation() {
        // Valid SSN
        assert!(validate_ssn("123-45-6789").is_ok());

        // Invalid patterns (OWASP compliance)
        assert!(validate_ssn("000-00-0000").is_err());
        assert!(validate_ssn("666-66-6666").is_err());
        assert!(validate_ssn("123-45-6789").is_err()); // Test SSN
    }
}
```

## Future Enhancements

Planned additions to the module:

1. **Machine Learning Detection**: AI-powered data classification
1. **Format Inference**: Automatic format detection and conversion
1. **Compliance Scanning**: GDPR, CCPA, HIPAA data discovery
1. **Performance Metrics**: Built-in performance monitoring
1. **Custom Validators**: User-defined validation rules
1. **Async Support**: Non-blocking validation for large datasets

## Migration from `security/input`

If you're migrating from the old `security/input` module:

```rust
// Old
use security::input::validation;

// New
use security::data::validation;
```

The API remains largely the same, with these key improvements:

- Broader scope (not limited to "input")
- Better organized submodules
- More consistent naming
- Enhanced detection capabilities

## Best Practices

1. **Always Detect First**: Use detection to identify data types before validation
1. **Validate Early**: Check data at system boundaries
1. **Sanitize for Context**: Apply appropriate escaping for the target context
1. **Log Safely**: Always redact sensitive data in logs
1. **Fail Secure**: Reject suspicious data by default
1. **Use Shortcuts**: Leverage pre-configured validators for common cases
1. **Monitor Failures**: Track validation failures for security monitoring

## Conclusion

The `security/data` module provides a comprehensive, unified approach to data security. By treating all data consistently - regardless of source - it ensures robust security controls throughout your application. The four-pillar approach (detect, validate, sanitize, convert) creates a clear mental model for developers while maintaining the flexibility needed for complex security requirements.
