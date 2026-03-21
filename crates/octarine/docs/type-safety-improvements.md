# Type-Safety Improvements for Observe Module

## Overview

This document tracks opportunities to improve compile-time safety in the observe module by replacing string-based fields with validated newtype wrappers, following the pattern established in the FileWriter refactoring.

**Pattern**: Use newtype wrappers + builder pattern to move validation from runtime to compile-time, preventing invalid configurations from being created in the first place.

**Benefits**:

- ✅ Compile-time validation instead of runtime checks
- ✅ Impossible to forget validation (type system enforces it)
- ✅ Better error messages at construction time
- ✅ Self-documenting API (types show constraints)
- ✅ Reduced runtime overhead (validation happens once)

______________________________________________________________________

## Priority 1: MetricName and Labels

**Status**: ✅ **COMPLETED** (2025-11-17)
**Impact**: High - Prevents cardinality explosion and injection attacks
**Effort**: Actual: 3 hours (including breaking change migration)
**Files**: `src/observe/metrics/types.rs`, `src/observe/metrics/mod.rs`

### MetricName: Current Implementation

```rust
// Runtime validation with raw strings
pub fn metric(name: &str, labels: Vec<(&str, &str)>) {
    // Validation happens at runtime
    if name.is_empty() || name.len() > 200 {
        // Error at runtime - too late!
    }
    // ...
}
```

**Problems**:

- No compile-time guarantee that names are valid
- Easy to create high-cardinality metrics by accident
- Injection attacks through dynamic label values
- Validation repeated on every metric call

### MetricName: Proposed Solution

```rust
/// A validated metric name
/// - 1-200 characters
/// - Alphanumeric + underscore only
/// - No consecutive underscores
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MetricName(String);

impl MetricName {
    pub fn new(name: impl AsRef<str>) -> Result<Self, Problem> {
        let name = name.as_ref();

        if name.is_empty() || name.len() > 200 {
            return Err(Problem::validation("Metric name must be 1-200 characters"));
        }

        if !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(Problem::validation("Metric name must be alphanumeric + underscore"));
        }

        if name.contains("__") {
            return Err(Problem::validation("Metric name cannot have consecutive underscores"));
        }

        Ok(Self(name.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated metric label (key-value pair)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricLabel {
    key: String,
    value: String,
}

impl MetricLabel {
    pub fn new(key: impl AsRef<str>, value: impl AsRef<str>) -> Result<Self, Problem> {
        let key = key.as_ref();
        let value = value.as_ref();

        // Validate key (same rules as metric name)
        if key.is_empty() || key.len() > 100 {
            return Err(Problem::validation("Label key must be 1-100 characters"));
        }

        // Validate value (less strict, but bounded)
        if value.len() > 200 {
            return Err(Problem::validation("Label value must be ≤200 characters"));
        }

        // Prevent high-cardinality patterns
        if value.chars().any(|c| c.is_control()) {
            return Err(Problem::validation("Label value contains control characters"));
        }

        Ok(Self {
            key: key.to_string(),
            value: value.to_string(),
        })
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

/// New type-safe API
pub fn metric(name: MetricName, labels: Vec<MetricLabel>) {
    // No validation needed - types guarantee safety!
    // ...
}
```

### Implementation Approach ✅

**Breaking Change Strategy** (No migration path needed)

1. ✅ Added `MetricName` and `MetricLabel` types to `src/observe/metrics/types.rs`
1. ✅ Changed public API from `fn increment(name: &str)` to `fn increment(name: MetricName)`
1. ✅ Updated all 24 call sites using compiler-driven refactoring
1. ✅ Added `MetricName::from_static_str()` for internal known-valid strings
1. ✅ Added comprehensive tests (15 tests for validation rules)
1. ✅ Single atomic commit - no gradual migration needed

**Key Decision**: No "lenient" or "migration" modes. Single type-safe API.

### Results

- **No Production Panics**: Validation failures handled gracefully (not panics)
- **Security**: Prevents injection through metric names/labels
- **Performance**: Prevents cardinality explosion from unbounded labels
- **Type Safety**: `MetricsBuilder::new(name: MetricName)` - no panic possible
- **All 1489 tests pass**: Compiler-driven migration caught all issues

______________________________________________________________________

## Priority 2: TenantId and UserId

**Status**: 🔴 Not Started
**Impact**: High - Prevents injection through identifiers
**Effort**: Low (1-2 hours)
**Files**: `src/observe/types.rs`, `src/observe/context/mod.rs`

### TenantId/UserId: Current Implementation

```rust
pub struct EventContext {
    pub tenant_id: Option<String>,  // ❌ No validation
    pub user_id: Option<String>,     // ❌ No validation
    // ...
}

// Usage allows anything
let ctx = EventContext {
    tenant_id: Some("tenant_$(whoami)".to_string()),  // ❌ Command injection!
    user_id: Some("../../../etc/passwd".to_string()),  // ❌ Path traversal!
};
```

**Problems**:

- No validation on tenant/user IDs
- Allows command injection, path traversal, SQL injection
- IDs used in file paths and database queries unsafely
- No format constraints

### TenantId/UserId: Proposed Solution

```rust
/// A validated tenant identifier
/// - 1-100 characters
/// - Alphanumeric + dash/underscore only
/// - No path traversal or command injection
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TenantId(String);

impl TenantId {
    pub fn new(id: impl AsRef<str>) -> Result<Self, Problem> {
        let id = id.as_ref();

        if id.is_empty() || id.len() > 100 {
            return Err(Problem::validation("Tenant ID must be 1-100 characters"));
        }

        // Only allow alphanumeric + dash/underscore
        if !id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(Problem::validation("Tenant ID must be alphanumeric + dash/underscore"));
        }

        // Prevent command injection
        if id.contains("$(") || id.contains('`') || id.contains("${") {
            return Err(Problem::validation("Tenant ID contains command injection patterns"));
        }

        // Prevent path traversal
        if id.contains("..") || id.contains('/') || id.contains('\\') {
            return Err(Problem::validation("Tenant ID contains path traversal"));
        }

        Ok(Self(id.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated user identifier (same rules as TenantId)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UserId(String);

impl UserId {
    pub fn new(id: impl AsRef<str>) -> Result<Self, Problem> {
        // Same validation as TenantId
        let id = id.as_ref();

        if id.is_empty() || id.len() > 100 {
            return Err(Problem::validation("User ID must be 1-100 characters"));
        }

        if !id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
            return Err(Problem::validation("User ID must be alphanumeric + dash/underscore"));
        }

        if id.contains("$(") || id.contains('`') || id.contains("${") {
            return Err(Problem::validation("User ID contains command injection patterns"));
        }

        if id.contains("..") || id.contains('/') || id.contains('\\') {
            return Err(Problem::validation("User ID contains path traversal"));
        }

        Ok(Self(id.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Updated EventContext
pub struct EventContext {
    pub tenant_id: Option<TenantId>,  // ✅ Type-safe
    pub user_id: Option<UserId>,      // ✅ Type-safe
    // ...
}
```

### TenantId/UserId: Implementation Strategy

**Breaking Change Approach** (same as MetricName)

1. Add `TenantId` and `UserId` to `observe/types.rs`
1. Change `EventContext` fields from `Option<String>` to `Option<TenantId>`/`Option<UserId>`
1. Update `ContextBuilder` methods to accept/validate IDs
1. Let compiler find all call sites that need updates
1. Single atomic commit - no gradual migration
1. Add comprehensive tests

### TenantId/UserId: Benefits

- **Security**: Prevents injection attacks through identifiers
- **Reliability**: Invalid IDs caught at construction
- **Type Safety**: Compiler prevents mixing tenant/user IDs
- **Documentation**: Types clearly indicate constraints

______________________________________________________________________

## Priority 3: OperationName

**Status**: 🔴 Not Started
**Impact**: Medium - Enforces naming conventions
**Effort**: Low (1 hour)
**Files**: `src/observe/types.rs`

### OperationName: Current Implementation

```rust
pub struct Event {
    pub operation: String,  // ❌ No constraints
    // ...
}

// Usage allows anything
Event {
    operation: "".to_string(),                    // ❌ Empty
    operation: "a".repeat(1000),                  // ❌ Too long
    operation: "user.login.success.attempt.1234", // ❌ High cardinality
}
```

**Problems**:

- No length limits (can create huge events)
- No naming convention enforcement
- Easy to create high-cardinality operations (timestamps, IDs in names)
- No standardization across codebase

### OperationName: Proposed Solution

```rust
/// A validated operation name
/// - 1-100 characters
/// - Format: category.action.result (e.g., "user.login.success")
/// - Alphanumeric + dot/underscore only
/// - Max 4 segments (prevent deep nesting)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationName(String);

impl OperationName {
    pub fn new(name: impl AsRef<str>) -> Result<Self, Problem> {
        let name = name.as_ref();

        if name.is_empty() || name.len() > 100 {
            return Err(Problem::validation("Operation name must be 1-100 characters"));
        }

        // Only allow alphanumeric + dot/underscore
        if !name.chars().all(|c| c.is_alphanumeric() || c == '.' || c == '_') {
            return Err(Problem::validation("Operation name must be alphanumeric + dot/underscore"));
        }

        // Prevent high-cardinality patterns (max 4 segments)
        let segments: Vec<&str> = name.split('.').collect();
        if segments.len() > 4 {
            return Err(Problem::validation("Operation name cannot have >4 segments"));
        }

        // Prevent empty segments
        if segments.iter().any(|s| s.is_empty()) {
            return Err(Problem::validation("Operation name cannot have empty segments"));
        }

        Ok(Self(name.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Updated Event
pub struct Event {
    pub operation: OperationName,  // ✅ Type-safe
    // ...
}
```

### OperationName: Implementation Strategy

**Breaking Change Approach** (same as MetricName)

1. Add `OperationName` to `observe/types.rs`
1. Change `Event::operation` from `String` to `OperationName`
1. Update `EventBuilder::operation()` to construct/validate
1. Compiler-driven refactoring of all event creation sites
1. Single atomic commit
1. Add tests for naming conventions

### OperationName: Benefits

- **Consistency**: Enforces naming conventions across codebase
- **Performance**: Prevents cardinality explosion from dynamic names
- **Reliability**: Invalid operations caught at creation
- **Searchability**: Standardized names improve log queries

______________________________________________________________________

## Priority 4: ResourceType and ResourceId

**Status**: 🔴 Not Started
**Impact**: Medium - Standardizes resource references
**Effort**: Low (1 hour)
**Files**: `src/observe/types.rs`

### ResourceType: Current Implementation

```rust
pub struct Event {
    pub resource_type: Option<String>,  // ❌ No validation
    pub resource_id: Option<String>,    // ❌ No validation
    // ...
}

// Usage allows anything
Event {
    resource_type: Some("".to_string()),              // ❌ Empty
    resource_type: Some("user/admin/$(whoami)"),      // ❌ Injection
    resource_id: Some("../../../etc/passwd"),          // ❌ Path traversal
}
```

**Problems**:

- No validation on resource types or IDs
- Allows injection attacks
- No standardization (same resource referred to different ways)
- No enumeration of valid resource types

### ResourceType: Proposed Solution

```rust
/// A validated resource type
/// - Predefined enum of known types
/// - Custom types allowed with validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceType {
    User,
    Tenant,
    ApiKey,
    Database,
    File,
    Service,
    Custom(String),
}

impl ResourceType {
    pub fn custom(type_name: impl AsRef<str>) -> Result<Self, Problem> {
        let type_name = type_name.as_ref();

        if type_name.is_empty() || type_name.len() > 50 {
            return Err(Problem::validation("Resource type must be 1-50 characters"));
        }

        if !type_name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(Problem::validation("Resource type must be alphanumeric + underscore"));
        }

        Ok(Self::Custom(type_name.to_string()))
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::User => "user",
            Self::Tenant => "tenant",
            Self::ApiKey => "api_key",
            Self::Database => "database",
            Self::File => "file",
            Self::Service => "service",
            Self::Custom(name) => name,
        }
    }
}

/// A validated resource identifier
/// - 1-200 characters
/// - Alphanumeric + dash/underscore/colon only
/// - No injection patterns
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceId(String);

impl ResourceId {
    pub fn new(id: impl AsRef<str>) -> Result<Self, Problem> {
        let id = id.as_ref();

        if id.is_empty() || id.len() > 200 {
            return Err(Problem::validation("Resource ID must be 1-200 characters"));
        }

        // Allow alphanumeric + dash/underscore/colon (for UUIDs, ARNs, etc.)
        if !id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == ':') {
            return Err(Problem::validation("Resource ID contains invalid characters"));
        }

        // Prevent command injection
        if id.contains("$(") || id.contains('`') || id.contains("${") {
            return Err(Problem::validation("Resource ID contains command injection patterns"));
        }

        // Prevent path traversal
        if id.contains("..") || id.contains('/') || id.contains('\\') {
            return Err(Problem::validation("Resource ID contains path traversal"));
        }

        Ok(Self(id.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Updated Event
pub struct Event {
    pub resource_type: Option<ResourceType>,  // ✅ Type-safe
    pub resource_id: Option<ResourceId>,      // ✅ Type-safe
    // ...
}
```

### ResourceType: Implementation Strategy

**Breaking Change Approach** (same as MetricName)

1. Add `ResourceType` (enum) and `ResourceId` to `observe/types.rs`
1. Change `Event` fields from `Option<String>` to typed versions
1. Update `EventBuilder` methods
1. Compiler-driven refactoring
1. Single atomic commit
1. Add tests for resource validation

### ResourceType: Benefits

- **Consistency**: Standardized resource naming across codebase
- **Security**: Prevents injection through resource identifiers
- **Type Safety**: Compiler prevents invalid resource references
- **Enumeration**: Known resource types are self-documenting

______________________________________________________________________

## Implementation Strategy

### Recommended Approach: Breaking Changes (No Migration Paths)

Based on MetricName success, apply same pattern to remaining priorities:

**Week 1: Identity Types**

1. ✅ MetricName, MetricLabel - COMPLETE
1. Implement `TenantId`, `UserId` (Priority 2)
   - Single atomic commit
   - Compiler finds all call sites
   - ~1-2 hours estimated

**Week 2: Event System Types**

1. Implement `OperationName` (Priority 3)
1. Implement `ResourceType`, `ResourceId` (Priority 4)
   - Each as separate atomic commits
   - ~1 hour per type estimated

**Week 3: Testing & Documentation**

1. Add integration tests for all new types
1. Update documentation with examples
1. Security audit of validated types

**Why No Migration Paths:**

- ✅ Internal library - we control all call sites
- ✅ Compiler guides migration automatically
- ✅ Faster overall (hours vs weeks)
- ✅ No technical debt from deprecated APIs
- ✅ Immediate security benefits
- ✅ Proven successful with MetricName (24 files, 3 hours)

______________________________________________________________________

## Success Criteria

- ✅ All new types have comprehensive validation
- ✅ All new types have 100% test coverage
- ✅ No string-based APIs remain in public interface
- ✅ All existing tests pass with new types
- ✅ Documentation updated with type-safe examples
- ✅ Zero injection vulnerabilities through validated types

______________________________________________________________________

## References

- **FileWriter Refactoring**: `src/observe/writers/types.rs`, `builder.rs` (completed example)
- **Security Validation**: `src/security/data/validation/` (reusable validation functions)
- **OWASP Top 10**: Injection prevention patterns
- **Cardinality Best Practices**: Prometheus metric naming conventions
