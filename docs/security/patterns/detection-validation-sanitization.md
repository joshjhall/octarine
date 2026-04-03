# Security Module Philosophy: Detection vs Validation vs Sanitization

## Core Principle: Different Modules, Different Purposes

The security/data modules follow a clear separation of concerns with distinct philosophies for each layer.

______________________________________________________________________

## Module Responsibilities

### Detection Module (`security/data/detection`)

**Purpose**: Pattern recognition and threat identification
**Return Type**: Primarily `bool`
**Philosophy**: **Lenient/Sensitive** - catch everything, false positives acceptable

```rust
// Detection is intentionally sensitive
pub fn is_traversal_present(path: &str) -> bool {
    path.contains("..")  // Will flag "file..txt" - that's OK for detection
}

pub fn is_command_injection_present(path: &str) -> bool {
    path.contains("$(") || path.contains('`')  // Pattern matching
}
```

**Use Detection When**:

- Scanning for potential threats
- Logging suspicious patterns
- Analysis and reporting
- False positives are acceptable
- You want maximum sensitivity

**Examples**:

- Security scanners
- Audit logs
- Threat intelligence
- Pattern analysis

#### Detection Dual API Pattern (Identifiers)

All identifier detection modules provide a **dual API** for flexibility:

| Function | Return Type | Purpose |
|----------|-------------|---------|
| `detect_{category}_identifier(value)` | `Option<IdentifierType>` | Returns WHICH type was detected |
| `is_{category}_identifier(value)` | `bool` | Returns WHETHER any type was detected |

**Contract**: `is_x(value) == detect_x(value).is_some()`

```rust
// Example from government/detection.rs
pub fn detect_government_identifier(value: &str) -> Option<IdentifierType> {
    if is_ssn(value) { Some(IdentifierType::Ssn) }
    else if is_tax_id(value) { Some(IdentifierType::TaxId) }
    else if is_driver_license(value) { Some(IdentifierType::DriverLicense) }
    // ... etc
    else { None }
}

pub fn is_government_identifier(value: &str) -> bool {
    detect_government_identifier(value).is_some()
}
```

**When to Use Each**:

- `detect_*`: When you need to know the specific type for routing, logging, or formatting
- `is_*`: When you only need a yes/no answer for filtering or gating

**All Modules Follow This Pattern**:

| Module | `detect_*` Function | `is_*` Function |
|--------|---------------------|-----------------|
| biometric | `detect_biometric_identifier` | `is_biometric_identifier` |
| financial | `detect_financial_identifier` | `is_financial_identifier` |
| government | `detect_government_identifier` | `is_government_identifier` |
| location | `detect_location_identifier` | `is_location_identifier` |
| medical | `detect_medical_identifier` | `is_medical_identifier` |
| network | `detect_network_identifier` | `is_network_identifier` |
| organizational | `detect_organizational_id` | `is_organizational_id` |
| personal | `detect_personal_identifier` | `is_personal_identifier` |
| token | `detect_token_type` | `is_token` |

______________________________________________________________________

### Validation Module (`security/data/validation`)

**Purpose**: Policy enforcement and strict checking
**Return Type**: Primarily `Result<()>`, with helper `bool` functions
**Philosophy**: **Strict/Precise** - no false positives allowed

```rust
// Validation is precise - uses Path::components()
pub fn is_traversal_attempt_present(path: &str) -> bool {
    // Only flags actual traversal, not "file..txt"
    path.components().any(|c| c == Component::ParentDir)
}

pub fn validate_no_traversal(path: &str) -> Result<()> {
    if is_traversal_attempt_present(path) {
        Err(Problem::validation("Path contains directory traversal"))
    } else {
        Ok(())
    }
}
```

**Why Validation Has Both `bool` and `Result`**:

- `is_*_present` functions: Internal helpers for builder logic
- `validate_*` functions: Public API for enforcement
- Different implementation than detection (stricter)

**Use Validation When**:

- Enforcing security policy
- Rejecting dangerous input
- False positives are NOT acceptable
- You need error messages

**Examples**:

- User input validation
- API parameter checking
- Security gates
- Access control

______________________________________________________________________

### Sanitization Module (`security/data/sanitization`)

**Purpose**: Transform dangerous input to safe output
**Return Type**: `Result<String>` (strict) or `String` (lenient)
**Philosophy**: **Dual mode** - strict (reject) or lenient (fix)

```rust
// Sanitization removes or rejects dangerous content
pub fn sanitize_path_strict(path: &str) -> Result<String> {
    validate_no_traversal(path)?;  // Uses validation first
    Ok(path.to_string())
}

pub fn sanitize_path(path: &str) -> String {
    path.replace("..", "")  // Lenient - fixes instead of rejects
}
```

**Use Sanitization When**:

- Cleaning user input
- Removing dangerous patterns
- Transforming to safe format
- You can't reject (need output)

**Examples**:

- Form input cleaning
- File upload handling
- Path normalization
- User-facing errors

______________________________________________________________________

## Decision Tree: Which Module to Use?

```text
┌─────────────────────────────────────┐
│ What do you need to do?             │
└──────────────┬──────────────────────┘
               │
        ┌──────┴──────┐
        │             │
    Find          Check           Clean
   patterns?     policy?         input?
        │             │             │
        v             v             v
   DETECTION     VALIDATION    SANITIZATION
   (is_*_present) (validate_*) (sanitize_*)
   → bool        → Result<()>  → Result<String>
```

### Examples

**Scenario 1: User Uploads File**

```rust
// Step 1: DETECT potential issues (logging)
if detection::is_traversal_present(path) {
    observe::warn("suspicious_upload", "Potential traversal detected");
}

// Step 2: VALIDATE it's safe (enforcement)
validation::validate_no_traversal(path)?;  // Rejects if unsafe

// Step 3: SANITIZE for storage (optional)
let safe_path = sanitization::sanitize_path_strict(path)?;
```

**Scenario 2: Security Scanner**

```rust
// Use DETECTION only - we want to find everything
let issues = vec![
    detection::is_traversal_present(path),
    detection::is_command_injection_present(path),
    detection::is_null_bytes_present(path),
];

generate_security_report(issues);  // Report includes false positives
```

**Scenario 3: API Endpoint**

```rust
// Use VALIDATION only - strict enforcement
fn create_file(path: &str) -> Result<File> {
    validation::validate_no_traversal(path)?;
    validation::validate_no_command_injection(path)?;
    validation::validate_within_boundary(path, "/app/data")?;

    Ok(File::create(path)?)
}
```

______________________________________________________________________

## Naming Conventions

### Standard Patterns

| Pattern | Return | Module | Example |
|---------|--------|--------|---------|
| `is_*` / `is_*_present` | `bool` | All | `is_absolute`, `is_traversal_present` |
| `detect_*` | `Result<Details>` | Detection | `detect_path_type` |
| `validate_*` | `Result<()>` | Validation | `validate_no_traversal` |
| `sanitize_*` | `Result<String>` | Sanitization | `sanitize_path_strict` |

### Anti-Patterns (Avoid)

❌ `check_*` - Ambiguous, use `is_*_present` or `validate_*` instead
❌ `verify_*` - Ambiguous, use `validate_*` instead
❌ `ensure_*` - Ambiguous, use `validate_*` or `sanitize_*`

______________________________________________________________________

## Implementation Differences

### Same Function Name, Different Philosophy

```rust
// DETECTION - Lenient (string matching)
pub fn is_traversal_present(path: &str) -> bool {
    path.contains("..")  // Simple, sensitive
}

// VALIDATION - Strict (proper parsing)
pub fn is_traversal_attempt_present(path: &str) -> bool {
    path.components().any(|c| c == Component::ParentDir)  // Precise
}
```

**Why Different**:

- Detection: "Might be dangerous" (scan mode)
- Validation: "Is definitely dangerous" (enforcement mode)

______________________________________________________________________

## Common Mistakes

### ❌ Wrong: Using Detection for Enforcement

```rust
// Don't do this!
if detection::is_traversal_present(path) {
    return Err("Traversal detected");  // False positives!
}
```

### ✅ Right: Use Validation for Enforcement

```rust
validation::validate_no_traversal(path)?;  // Precise, no false positives
```

### ❌ Wrong: Using Validation for Scanning

```rust
// Don't do this!
for path in all_paths {
    if validation::validate_no_traversal(path).is_err() {
        log_threat(path);  // Misses patterns validation doesn't check
    }
}
```

### ✅ Right: Use Detection for Scanning

```rust
for path in all_paths {
    if detection::is_traversal_present(path) {
        log_threat(path);  // Catches everything
    }
}
```

______________________________________________________________________

## FAQ

### Q: Why does Validation have both `is_*_present` and `validate_*`?

**A**: Different purposes within the module:

- `is_*_present`: Quick boolean checks for internal builder logic
- `validate_*`: Public API with error messages for enforcement

They use the same strict philosophy (unlike detection's lenient approach).

### Q: Should I move bool functions from Validation to Detection?

**A**: No! They serve different purposes:

- Detection `is_*_present`: Lenient pattern matching
- Validation `is_*_present`: Strict checking (used internally)

Different implementations, different philosophies.

### Q: Can I use Sanitization instead of Validation?

**A**: Only in lenient mode. Strict sanitization USES validation:

```rust
pub fn sanitize_path_strict(path: &str) -> Result<String> {
    validate_no_traversal(path)?;  // Validation first
    // Then sanitization logic
}
```

### Q: Which module should shortcuts use?

**A**: Shortcuts should always use builders, never call domain functions directly.

______________________________________________________________________

## Summary

| Module | Purpose | Return Type | Philosophy | Use For |
|--------|---------|-------------|------------|---------|
| **Detection** | Find patterns | `bool` | Lenient/Sensitive | Scanning, logging, analysis |
| **Validation** | Enforce policy | `Result<()>` | Strict/Precise | Security gates, enforcement |
| **Sanitization** | Clean input | `Result<String>` | Dual (strict/lenient) | Input cleaning, transformation |
| **Conversion** | Transform format | Varies by operation | Best-effort or strict | Format normalization, extraction |

**Golden Rules**:

- Use **detection** to find patterns
- Use **validation** to enforce policy
- Use **sanitization** to clean dangerous input
- Use **conversion** to transform between formats

______________________________________________________________________

## Primitives/Identifiers: Inheritance Arrow Pattern

The `primitives/identifiers/` modules follow a strict **one-way dependency flow** called the "inheritance arrow":

```text
detection.rs  ──→  validation.rs  ──→  sanitization.rs
(pure matching)    (uses detection)    (uses validation + detection)
```

### Rules

| Import | Allowed? | Reason |
|--------|----------|--------|
| validation → detection | ✅ Yes | Validators should check format first |
| sanitization → detection | ✅ Yes | Sanitizers may need format info |
| sanitization → validation | ✅ Yes | Strict sanitizers validate first |
| detection → validation | ❌ **NO** | Creates circular dependency |
| detection → sanitization | ❌ **NO** | Creates circular dependency |
| validation → sanitization | ❌ **NO** | Violates layer separation |

### Why Validators Should Use Detectors

**Principle:** Validators should call detection functions FIRST to confirm input format before applying validation rules.

```rust
// ✅ CORRECT: Validator uses detector first
pub fn validate_email_strict(email: &str) -> Result<(), Problem> {
    // Step 1: Use detection to confirm format
    if !detection::is_email(email) {
        return Err(Problem::validation("Invalid email format"));
    }

    // Step 2: Apply additional validation rules
    validate_email_length(email)?;
    validate_email_domain(email)?;
    Ok(())
}

// ❌ WRONG: Validator reimplements detection logic
pub fn validate_email_strict(email: &str) -> Result<(), Problem> {
    // Don't reimplement pattern matching!
    if !email.contains('@') || !email.contains('.') {
        return Err(Problem::validation("Invalid email format"));
    }
    // ...
}
```

**Benefits:**

1. **DRY Principle** - Pattern logic lives in ONE place (detection layer)
1. **Type Safety** - Fail fast if input doesn't match expected type
1. **Consistency** - Same format checking everywhere
1. **Cache Benefits** - Detection functions may use cached regex

### Gold Standard Example: Network IP Validators

The network module's IP validators show the pattern correctly:

```rust
// From primitives/identifiers/network/validation/ip.rs
pub fn is_private_ipv4(ip: &str) -> bool {
    // ✅ Uses detection first!
    if !is_ipv4(ip) {
        return false;
    }
    // Then applies semantic validation (private range check)
    // ...
}
```

### Documented Exceptions

Some modules have architectural reasons for NOT using detection first:

#### 1. Biometric Validators

**Location:** `primitives/identifiers/biometric/validation.rs`

**Reason:** Detection patterns require labels (e.g., "fingerprint: abc123") to avoid false positives with git commit hashes and other hex strings. Validators work on bare application IDs (e.g., "FP-A1B2C3D4"), so detection would always return false.

```rust
// Detection layer: Requires labeled format
detection::is_fingerprint("fingerprint: a1b2c3d4...")  // ✅ true
detection::is_fingerprint("FP-A1B2C3D4")              // ❌ false (no label)

// Validator: Works on bare IDs
validate_fingerprint_id_strict("FP-A1B2C3D4")  // ✅ validates directly
```

#### 2. Location Validators

**Location:** `primitives/identifiers/location/validation.rs`

**Reason:** Location validators use the **conversion layer** for format detection instead of the detection layer because:

- Conversion layer is case-insensitive (UK postcodes, Canadian postal codes)
- Returns specific format types (`GpsFormat`, `PostalCodeType`) needed for validation
- GPS detection doesn't support range validation (lat/lon bounds checking)
- Street address detection requires specific US formats; validator is intentionally lenient

```rust
// Uses conversion layer's detect function
let format = conversion::detect_gps_format(coordinate)?;
// NOT detection::is_gps_coordinate() which lacks format info
```

### Audit Results (Issue #15)

A comprehensive audit of all 9 identifier modules found:

| Finding | Count | Status |
|---------|-------|--------|
| **Violations** (detection imports validation) | **0** | ✅ Clean |
| Validators not using detection | ~31 | Fixed in #39-#48 |
| Documented exceptions | 2 | Biometric, Location |

**Conclusion:** The inheritance arrow is strictly respected. All modules now follow the "validators use detectors" pattern where architecturally appropriate.

______________________________________________________________________

## Conversion Module Patterns

The conversion layer handles **format transformation** and **metadata extraction**. Unlike sanitization (which cleans dangerous input), conversion transforms valid input between formats.

### Where Conversion Fits in the Inheritance Arrow

```text
detection.rs  ──→  conversion.rs  ──→  validation.rs  ──→  sanitization.rs
(pattern match)    (format transform)   (policy enforce)   (clean input)
```

Conversion sits **between detection and validation**:

| Import | Allowed? | Reason |
|--------|----------|--------|
| conversion → detection | ✅ Yes | Format detection before transformation |
| validation → conversion | ✅ Yes | Validators may need format detection (e.g., GPS) |
| sanitization → conversion | ✅ Yes | Sanitizers may need format info |
| detection → conversion | ❌ **NO** | Creates circular dependency |
| conversion → validation | ❌ **NO** | Creates circular dependency |
| conversion → sanitization | ❌ **NO** | Creates circular dependency |

**Real Example**: Location validators use `conversion::detect_gps_format()` because:

- Detection layer only returns `bool` (is/isn't GPS coordinate)
- Conversion layer returns `Option<GpsFormat>` with specific format info
- Validators need the format type to apply format-specific rules

______________________________________________________________________

### Conversion Return Type Patterns

Unlike validation (which uses `Result<(), Problem>` vs `bool`), conversion uses return types to signal **operation semantics**:

| Return Type | When to Use | Semantics |
|-------------|-------------|-----------|
| `String` | Operation always produces output | Best-effort, never fails |
| `Result<String, Problem>` | Operation can fail | Requires valid input |
| `Option<String>` | Data may not exist | Extraction of optional parts |
| `Option<T>` | Detection/classification | Returns enum variant if recognized |

______________________________________________________________________

### Pattern 1: Normalization Functions

**Purpose**: Produce canonical form from various input formats.

**Naming**: `normalize_{identifier}()`

**Return Type Decision**:

```rust
// ✅ Returns String: Always succeeds (strips non-essential chars)
pub fn normalize_ssn(ssn: &str) -> String {
    masking::digits_only(ssn)  // "123-45-6789" → "123456789"
}

// ✅ Returns Result: Can fail (requires valid format)
pub fn normalize_email(email: &str) -> Result<String, Problem> {
    if !detection::is_email(email) {
        return Err(Problem::conversion("Invalid email format"));
    }
    // ... normalize
}
```

**Rule**: Return `String` when normalization is pure character stripping (digits_only, uppercase, remove separators). Return `Result<String, Problem>` when normalization requires parsing or validation.

______________________________________________________________________

### Pattern 2: Formatting Functions

**Purpose**: Produce human-readable display format.

**Naming**: `format_{identifier}_for_display()` or `format_{identifier}_with_{style}()`

**Return Type**: Always `String` (best-effort, never fails)

```rust
// ✅ Always returns String - best effort formatting
pub fn format_ssn_with_hyphens(ssn: &str) -> String {
    let digits = normalize_ssn(ssn);
    if digits.len() == 9 {
        format!("{}-{}-{}", &digits[0..3], &digits[3..5], &digits[5..9])
    } else {
        digits  // Return as-is if unexpected format
    }
}

pub fn format_card_for_display(card: &str) -> String {
    let (card_type, last4) = extract_card_display_info(card);
    format!("{} ending in {}", card_type, last4)
}
```

**Rule**: Formatting functions NEVER fail. If input is unexpected, return best-effort output or the input unchanged.

______________________________________________________________________

### Pattern 3: Extraction Functions

**Purpose**: Extract specific components from an identifier.

**Naming**: `extract_{identifier}_{component}()`

**Return Type**: `Option<String>` for optional parts, `Result<T, Problem>` for required parts

```rust
// ✅ Returns Option: Component may not exist
pub fn extract_ssn_area(ssn: &str) -> Option<String> {
    let digits = normalize_ssn(ssn);
    if digits.len() >= 3 {
        Some(digits[0..3].to_string())
    } else {
        None  // Not enough digits
    }
}

// ✅ Returns Result: Extraction requires valid format
pub fn extract_jwt_algorithm(token: &str) -> Result<String, Problem> {
    if !detection::is_jwt(token) {
        return Err(Problem::conversion("Invalid JWT format"));
    }
    // ... parse and extract
}
```

**Rule**: Use `Option` when the component may legitimately not exist in valid input. Use `Result` when extraction requires specific format validation.

______________________________________________________________________

### Pattern 4: Detection/Classification Functions

**Purpose**: Identify the format or type of input.

**Naming**: `detect_{identifier}_format()` or `detect_{identifier}_type()`

**Return Type**: `Option<FormatEnum>`

```rust
// ✅ Returns Option<Enum>: Classification may not match any known type
pub fn detect_gps_format(input: &str) -> Option<GpsFormat> {
    // Try each format
    if is_decimal_degrees(input) {
        return Some(GpsFormat::DecimalDegrees);
    }
    if is_dms(input) {
        return Some(GpsFormat::DegreesMinutesSeconds);
    }
    None  // Unknown format
}

pub fn detect_postal_code_type(input: &str) -> Option<PostalCodeType> {
    // ... returns UsZip, UkPostcode, CanadianPostal, etc.
}
```

**Rule**: Detection functions return `Option<Enum>` to allow for unknown formats. They should NOT return `Result` because an unrecognized format is not an error—it's just unclassified.

______________________________________________________________________

### Dual API for Conversion?

**Question**: Should conversion have `_strict()` variants like validation?

**Answer**: **No.** The return type already communicates strictness:

| Validation Pattern | Conversion Equivalent |
|--------------------|----------------------|
| `validate_x() -> bool` | Not applicable |
| `validate_x_strict() -> Result<(), Problem>` | `normalize_x() -> Result<String, Problem>` |

For conversion:

- `String` return = lenient (always succeeds)
- `Result<String, Problem>` return = strict (can fail)

Adding `_strict()` variants would be redundant. The return type IS the API contract.

______________________________________________________________________

### Conversion and the Inheritance Arrow

Conversion functions SHOULD use detection when appropriate:

```rust
// ✅ CORRECT: Uses detection to validate format first
pub fn normalize_email(email: &str) -> Result<String, Problem> {
    if !detection::is_email(email) {
        return Err(Problem::conversion("Invalid email format"));
    }
    // Now safe to parse
    let parts: Vec<&str> = email.split('@').collect();
    // ...
}

// ❌ WRONG: Reimplements detection logic
pub fn normalize_email(email: &str) -> Result<String, Problem> {
    if !email.contains('@') {  // Don't do this!
        return Err(Problem::conversion("Invalid email"));
    }
    // ...
}
```

**Exception**: Format detection functions (`detect_*_format()`) may need more sophisticated logic than simple detection. They can implement their own pattern matching when returning rich type information.

______________________________________________________________________

### Summary: Conversion API Patterns

| Pattern | Naming | Return Type | When to Use |
|---------|--------|-------------|-------------|
| **Normalization** | `normalize_*()` | `String` or `Result<String>` | Canonical form |
| **Formatting** | `format_*_for_display()` | `String` | Human-readable output |
| **Extraction** | `extract_*_component()` | `Option<String>` or `Result<T>` | Get specific parts |
| **Detection** | `detect_*_format()` | `Option<Enum>` | Classify input type |

**Golden Rules**:

1. Formatting functions NEVER fail
1. Return type communicates strictness (no need for `_strict()`)
1. Use detection layer for format validation when possible
1. `Option` = data may not exist, `Result` = operation can fail

______________________________________________________________________

## Caching Pattern

### When to Use Caching

Caching is used for **expensive operations** in the identifier modules:

| Module | Cached Operations | Why Cache? |
|--------|-------------------|------------|
| personal | Email validation, Phone validation | Complex regex patterns |
| financial | Luhn checksum, ABA routing validation | Math computation + checksums |
| government | SSN validation, VIN checksum | Pattern + checksum algorithms |
| location | GPS validation, Postal code validation | Multi-format parsing + range checks |
| medical | NPI validation | Luhn checksum variant |
| **network** | **None** | Operations are cheap (simple regex/parsing) |

### Implementation Pattern

All cached modules use **global transparent caching** with lazy_static:

```rust
// In detection.rs or validation.rs
static EMAIL_CACHE: Lazy<LruCache<String, bool>> =
    Lazy::new(|| LruCache::new(10_000, Duration::from_secs(3600)));

pub fn is_email(value: &str) -> bool {
    // Cache lookup transparent to caller
    if let Some(result) = EMAIL_CACHE.get(&value.to_string()) {
        return result;
    }
    let result = /* expensive validation */;
    EMAIL_CACHE.insert(value.to_string(), result);
    result
}
```

### Builder Cache API (Standardized)

Every builder with caching exposes these methods:

| Method | Return Type | Purpose |
|--------|-------------|---------|
| `cache_stats()` | `CacheStats` | Aggregated stats for all module caches |
| `{identifier}_cache_stats()` | `CacheStats` | Stats for specific cache (debugging) |
| `clear_caches()` | `()` | Clear all caches in module |

```rust
// Example usage
let builder = PersonalIdentifierBuilder::new();

// Monitor overall performance
let stats = builder.cache_stats();
println!("Hit rate: {:.1}%", stats.hit_rate());
println!("Size: {}/{}", stats.size, stats.capacity);

// Debug specific cache
let email_stats = builder.email_cache_stats();

// Clear for testing
builder.clear_caches();
```

### Why Network Has No Caching

The network module does NOT use caching because:

1. **Operations are cheap**: UUID/IP/MAC validation is simple regex or parsing
1. **Simplicity**: No global state, no memory overhead
1. **Predictable memory**: No cache growth over time

If your workload benefits from caching network identifiers, implement application-level caching.

### Security Considerations

**Issue #49** tracks securing cache memory:

- Cached values may contain sensitive data (emails, SSNs, etc.)
- When entries are evicted, memory is not zeroed
- Consider `zeroize` crate for secure memory handling

______________________________________________________________________

## Test Data Detection Pattern

The `is_test_*` functions help identify test/development/sample data that should be excluded from analytics, treated specially in production, or flagged during security audits.

### Purpose

Test data detection serves several important use cases:

1. **Analytics Filtering**: Exclude test data from production metrics
1. **Security Auditing**: Identify potentially insecure test credentials in production
1. **Data Quality**: Flag sample/demo data during data validation
1. **Debugging**: Help developers identify test data during troubleshooting

### Naming Convention

All test data detection functions follow the naming pattern:

```rust
// In detection module
pub fn is_test_{identifier_type}(value: &str) -> bool

// Examples
pub fn is_test_ip(ip: &str) -> bool           // Network module
pub fn is_test_uuid(uuid: &str) -> bool       // Network module
pub fn is_test_jwt(jwt: &str) -> bool         // Token module
pub fn is_test_email(email: &str) -> bool     // Personal module
```

### Builder API

Each builder exposes the same functions:

```rust
let builder = NetworkIdentifierBuilder::new();

// Test data detection
if builder.is_test_ip("127.0.0.1") {
    log::debug!("Skipping test IP in analytics");
}

if builder.is_test_url("http://localhost:8080") {
    log::warn!("Test URL detected in production config!");
}
```

### Module Coverage

| Module | Test Data Functions |
|--------|---------------------|
| **network** | `is_test_ip`, `is_test_mac`, `is_test_url`, `is_test_uuid`, `is_test_domain`, `is_test_hostname` |
| **token** | `is_test_jwt`, `is_test_api_key`, `is_test_session_id`, `is_test_ssh_key` |
| **personal** | `is_test_email`, `is_test_phone` |
| **financial** | `is_test_credit_card`, `is_test_bank_account` |
| **government** | `is_test_ssn`, `is_test_passport` |
| **medical** | `is_test_npi`, `is_test_mrn`, `is_test_dea` |
| **organizational** | `is_test_employee_id`, `is_test_student_id`, `is_test_badge_number` |
| **biometric** | `is_test_dna_sequence`, `is_test_fingerprint_hash` |
| **location** | `is_test_gps`, `is_test_postal_code` |

### What Counts as "Test Data"?

Each module defines test patterns appropriate to its domain:

#### Network Module

- **IPs**: Loopback (127.x.x.x), private ranges (10.x, 192.168.x), TEST-NET (RFC 5737)
- **MACs**: Broadcast, null, VM prefixes (VMware, VirtualBox, etc.)
- **URLs**: localhost, example.com (RFC 2606), .test/.localhost TLDs
- **UUIDs**: Nil, max, repeating patterns (all-zeros, all-f's)

#### Token Module

- **JWTs**: jwt.io example tokens, "none" algorithm, known test signatures
- **API Keys**: sk_test\_\*, EXAMPLE in key, AWS/GitHub documented examples
- **Session IDs**: test- prefix, sequential patterns (123456)
- **SSH Keys**: <test@example.com> comments, known example fingerprints

#### Personal Module

- **Emails**: @example.com, @test.com, test@*, demo@*
- **Phones**: 555-xxxx (North American test range), +1-555-\*

#### Financial Module

- **Credit Cards**: Stripe test cards (4242...), Luhn-valid test numbers
- **Bank Accounts**: Test routing numbers (000000xxx)

### Philosophy

Test data detection is **intentionally broad** (errs on side of flagging):

- Better to flag real data as test than miss actual test data in production
- Use case is filtering/flagging, not validation
- Always returns `bool` (is it test data?)

### Example Use Cases

```rust
// Analytics filtering
let builder = NetworkIdentifierBuilder::new();
for ip in access_logs {
    if !builder.is_test_ip(&ip) {
        metrics.record_access(&ip);  // Only real IPs
    }
}

// Security audit
let token_builder = TokenIdentifierBuilder::new();
for jwt in auth_tokens {
    if token_builder.is_test_jwt(&jwt) {
        security_alerts.push(format!("Test JWT in production: {}", &jwt[..20]));
    }
}

// Data quality validation
let email_builder = PersonalIdentifierBuilder::new();
for email in user_emails {
    if email_builder.is_test_email(&email) {
        validation_warnings.push(format!("Test email: {}", email));
    }
}
```

______________________________________________________________________

**Last Updated**: 2025-11-24
**Status**: Established architectural pattern across all modules
**Related Issues**: #15 (audit), #20 (conversion patterns), #22 (cache standardization), #23 (test data detection), #39-#48 (module fixes), #49 (cache security)
