# Module Quality Scorecard & Evaluation Methodology

**Purpose**: This document provides an objective, reproducible methodology for evaluating the quality of Rust security modules. Use this as a quality gate for new modules and for scoring refactored modules.

**Version**: 1.0
**Date**: 2025-11-10
**Applies to**: All modules in `src/security/data/` (detection, validation, sanitization, conversion, etc.)

______________________________________________________________________

## Scoring Overview

**Total Possible Score**: 100 points

| Category | Max Points | Weight |
|----------|-----------|--------|
| **1. Architecture & Organization** | 15 | Critical |
| **2. Builder Pattern Purity** | 15 | Critical |
| **3. Code Duplication** | 15 | Critical |
| **4. Naming Consistency** | 10 | High |
| **5. Type Organization** | 10 | High |
| **6. API Design & Patterns** | 10 | High |
| **7. Documentation Quality** | 10 | High |
| **8. Test Coverage** | 10 | High |
| **9. Shortcut Patterns** | 5 | Medium |

### Grade Scale

| Score | Grade | Status |
|-------|-------|--------|
| 90-100 | A | Exemplar - use as template |
| 80-89 | B | Good - minor improvements needed |
| 70-79 | C | Acceptable - notable issues to address |
| 60-69 | D | Needs work - significant refactoring required |
| 0-59 | F | Unacceptable - major redesign needed |

______________________________________________________________________

## Category 1: Architecture & Organization (15 points)

### Evaluation Criteria

**File Structure** (5 points):

- [ ] **5 pts**: Perfect structure - mod.rs, types.rs, domain files, builder/ subdirectory
- [ ] **4 pts**: Good structure - missing types.rs but otherwise organized
- [ ] **3 pts**: Acceptable - some organization issues
- [ ] **2 pts**: Poor - files scattered or unclear organization
- [ ] **0-1 pts**: Chaotic - no clear organization

**Expected Structure**:

```text
{module}/paths/
├── mod.rs                  # Public API, re-exports
├── types.rs                # Options, Results, Enums (REQUIRED)
├── core.rs                 # Optional: shared utilities
├── domain1.rs              # Domain logic files
├── domain2.rs              # Keep logically cohesive
└── builder/
    ├── mod.rs              # Main builder struct
    ├── domain1.rs          # Domain-specific builder delegation
    ├── domain1_shortcuts.rs # Shortcuts for domain1
    └── ...
```

**Domain File Cohesion** (5 points):

- [ ] **5 pts**: Each file represents a single, clear logical domain
- [ ] **4 pts**: Most files cohesive, 1-2 with minor overlap
- [ ] **3 pts**: Some files mix concerns or responsibilities unclear
- [ ] **2 pts**: Multiple files with overlapping concerns
- [ ] **0-1 pts**: Files randomly organized, no clear boundaries

**Measurement**: Review each domain file - does it have ONE clear purpose?

**File Size Reasonableness** (5 points):

**Important**: Count only actual code lines (exclude tests, comments, blank lines, imports).

- [ ] **5 pts**: All files under 500 lines of actual code OR longer files are justified by logical cohesion
- [ ] **4 pts**: 1-2 files over 500 lines code with good justification
- [ ] **3 pts**: Several files over 500 lines code, some could split logically
- [ ] **2 pts**: Many oversized files without clear justification
- [ ] **0-1 pts**: Massive files (1000+ lines actual code) with poor organization

**How to Count**:

```bash
# Count non-test, non-comment lines
grep -v "^//" file.rs | grep -v "^\s*$" | grep -v "^#\[cfg(test)\]" | wc -l
```

**Justification for longer files**:

- Comprehensive test suite (tests don't count toward limit)
- Dual function patterns (strict/lenient, bool/Result) in one file
- Extensive documentation (comments don't count toward limit)
- Cohesive domain that would be artificial to split

______________________________________________________________________

## Category 2: Builder Pattern Purity (15 points)

### Category 2: Evaluation Criteria

**Builder mod.rs Purity** (8 points):

Inspect `builder/mod.rs` - does it contain business logic?

- [ ] **8 pts**: ZERO business logic - only input validation (empty/null) and delegation
- [ ] **6 pts**: Minimal logic leaks (1-2 inline checks that should delegate)
- [ ] **4 pts**: Some business logic (policy decisions, inline validation)
- [ ] **2 pts**: Significant business logic (orchestration, string parsing)
- [ ] **0 pts**: Heavy business logic throughout

**Business Logic Examples** (DEDUCT POINTS):

- ❌ Inline string checks: `path.contains('/')`, `path.starts_with("~/")`
- ❌ Policy decisions: `if strict_mode { ... } else { ... }` with complex logic
- ❌ Data transformations: String manipulation, parsing
- ❌ Classification logic: Determining file types, credential classification
- ❌ Magic numbers: Hardcoded limits like `path.len() > 4096`

**Acceptable in Builder** (DON'T DEDUCT):

- ✅ Empty/null input validation
- ✅ Simple delegation: `self.domain_method(input)`
- ✅ Mode switching: `match self.mode { Strict => fn_strict(), Lenient => fn_lenient() }`
- ✅ Configuration: Setting fields, chaining builder methods

**Domain Builder Files** (4 points):

Check `builder/domain.rs` files - do they delegate cleanly?

- [ ] **4 pts**: Pure delegation to `super::super::domain` core functions
- [ ] **3 pts**: Mostly delegation, 1-2 helper functions
- [ ] **2 pts**: Some business logic mixed in
- [ ] **1 pt**: Significant business logic
- [ ] **0 pts**: Heavy business logic, should be in core domain

**Builder Documentation** (3 points):

- [ ] **3 pts**: Clear comment stating "ZERO BUSINESS LOGIC" or equivalent
- [ ] **2 pts**: Good doc comments explaining builder purpose
- [ ] **1 pt**: Minimal documentation
- [ ] **0 pts**: No documentation

**Example - Perfect Score**:

```rust
//! ZERO BUSINESS LOGIC: All logic in domain files.
//! This module provides the builder API and delegates to domain functions.

pub fn main_method(&self, input: &str) -> Result<Output> {
    if input.is_empty() {
        return Err(Problem::module("Input cannot be empty"));
    }
    self.delegate_to_domain(input)  // Pure delegation
}
```

______________________________________________________________________

## Category 3: Code Duplication (15 points)

### Category 3: Evaluation Criteria

**Cross-Module Duplication** (10 points):

Check if module reimplements security checks that exist elsewhere:

- [ ] **10 pts**: Zero duplication - uses shared security_core or imports from single source
- [ ] **8 pts**: Minimal duplication (1-2 simple checks duplicated)
- [ ] **5 pts**: Moderate duplication (3-5 security checks duplicated)
- [ ] **2 pts**: Significant duplication (6+ checks, or complex logic duplicated)
- [ ] **0 pts**: Massive duplication (reimplements entire security domains)

**Common Duplication Targets** (check these):

- Command injection detection (`$(`, `` ` ``, `${`)
- Path traversal detection (`..`, encoded variants)
- Null byte detection (`\0`)
- Control character detection (`\n`, `\r`, `\t`)
- Shell metacharacter detection (`;`, `|`, `&`)
- Encoding attack detection (double-encoding, overlong UTF-8)
- Normalization checks (redundant separators, trailing slashes)
- Boundary validation logic

**How to Check**:

```bash
# Search for security patterns across modules
rg "path\.contains\(\"\$\(\"" src/security/data/*/paths/
rg "path\.contains\(\"\.\.\"" src/security/data/*/paths/
# If same pattern appears in 2+ modules = duplication
```

**Intra-Module Duplication** (5 points):

Check within the module for repeated logic:

- [ ] **5 pts**: No repeated logic - functions are DRY
- [ ] **4 pts**: Minimal repetition (1-2 small helper patterns repeated)
- [ ] **3 pts**: Some repetition (string checks repeated 3-4 times)
- [ ] **2 pts**: Notable repetition (same validation logic in multiple places)
- [ ] **0-1 pts**: Significant repetition throughout

**Example of Intra-Module Duplication**:

```rust
// ❌ Repeated 4 times in sanitization module
if !result.contains('/') && !result.contains('\\') {
    // This is a filename only
}
```

**Should be**:

```rust
// ✅ Helper function used 4 times
fn is_filename_only(path: &str) -> bool {
    !path.contains('/') && !path.contains('\\')
}
```

______________________________________________________________________

## Category 4: Naming Consistency (10 points)

### Category 4: Evaluation Criteria

**Internal Naming Consistency** (5 points):

Within the module, are naming patterns consistent?

- [ ] **5 pts**: Perfect consistency - all functions follow established patterns
- [ ] **4 pts**: Very consistent - 1-2 minor deviations
- [ ] **3 pts**: Mostly consistent - several deviations
- [ ] **2 pts**: Inconsistent - multiple naming styles mixed
- [ ] **0-1 pts**: Chaotic - no clear naming pattern

**Standard Patterns** (must follow):

| Pattern | Usage | Returns | Example |
|---------|-------|---------|---------|
| `is_*` | Identity/type check | `bool` | `is_absolute`, `is_hidden_file` |
| `has_*` | Property check | `bool` | `has_traversal`, `has_command_injection` |
| `detect_*` | Active detection | `Type` or `Result<Type>` | `detect_path_type` |
| `validate_*` | Validation | `Result<()>` | `validate_no_traversal` |
| `sanitize_*` | Sanitization (lenient) | `String` | `sanitize_filename` |
| `sanitize_*_strict` | Sanitization (strict) | `Result<String>` | `sanitize_filename_strict` |
| `convert_*` / `to_*` | Conversion | `Result<String>` | `convert_to_unix`, `to_portable` |
| `normalize_*` | Normalization (lenient) | `String` | `normalize_separators` |
| `normalize_*_strict` | Normalization (strict) | `Result<String>` | `normalize_path_strict` |

**Avoid**:

- ❌ `check_*` - use `has_*` or `validate_*` instead
- ❌ `clean_*` - use `sanitize_*` for consistency
- ❌ `ensure_*` - use `validate_*` instead

**Cross-Module Naming Consistency** (5 points):

Does module follow same naming as sibling modules?

- [ ] **5 pts**: Perfectly aligned with established patterns
- [ ] **4 pts**: Minor deviations (1-2 functions)
- [ ] **3 pts**: Some deviations (3-5 functions use different pattern)
- [ ] **2 pts**: Notable deviations (different approach for same concepts)
- [ ] **0-1 pts**: Completely different naming scheme

**Check**:

- If validation uses `has_traversal`, does detection also use `has_traversal`?
- If validation uses `is_within_boundary`, does sanitization use the same name?
- Are dual patterns maintained? (bool + Result, or strict + lenient)

______________________________________________________________________

## Category 5: Type Organization (10 points)

### Category 5: Evaluation Criteria

**types.rs File Exists** (5 points):

- [ ] **5 pts**: Has dedicated `types.rs` file with all type definitions
- [ ] **3 pts**: Types in builder/mod.rs but well-organized
- [ ] **1 pt**: Types scattered across multiple files
- [ ] **0 pts**: No clear type organization

**Type Organization Quality** (5 points):

If types.rs exists, evaluate its contents:

- [ ] **5 pts**: Clean, focused - Options, Results, Enums with impl blocks
- [ ] **4 pts**: Well-organized, minor improvements possible
- [ ] **3 pts**: Some organization issues
- [ ] **2 pts**: Poorly organized or incomplete
- [ ] **0-1 pts**: Minimal or no type definitions

**Expected Type Patterns**:

```rust
// Enum for variants/formats/modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleFormat { ... }

// Options struct for configuration
#[derive(Debug, Clone)]
pub struct ModuleOptions {
    // Configuration fields
}

impl ModuleOptions {
    // Convenience constructors
    pub fn new() -> Self { ... }
    pub fn variant1() -> Self { ... }
    pub fn variant2() -> Self { ... }
}

// Result struct (if needed)
#[derive(Debug, Clone)]
pub struct ModuleResult {
    // Result fields
}
```

______________________________________________________________________

## Category 6: API Design & Patterns (10 points)

### Category 6: Evaluation Criteria

**Dual Function Patterns** (4 points):

For validation/detection modules - are there paired functions?

- [ ] **4 pts**: Complete dual pattern - every `has_*` has `validate_*`, every `is_*` has validation
- [ ] **3 pts**: Most functions paired, 1-2 missing pairs
- [ ] **2 pts**: Some pairing, many missing
- [ ] **1 pt**: Minimal pairing
- [ ] **0 pts**: No dual pattern

**Example - Perfect**:

```rust
// Boolean check
pub fn has_traversal(path: &str) -> bool { ... }

// Result validation
pub fn validate_no_traversal(path: &str) -> Result<()> { ... }
```

**Strict/Lenient Patterns** (3 points):

For sanitization modules - are there strict/lenient pairs?

- [ ] **3 pts**: Complete pattern - all functions have strict + lenient variants
- [ ] **2 pts**: Most functions paired
- [ ] **1 pt**: Some pairing
- [ ] **0 pts**: No lenient/strict pattern

**Builder API Completeness** (3 points):

Does builder provide convenient configuration?

- [ ] **3 pts**: Full builder API - constructors, with\_\* methods, complete configuration
- [ ] **2 pts**: Good builder API, minor gaps
- [ ] **1 pt**: Basic builder, limited configuration
- [ ] **0 pts**: Minimal or no builder pattern

______________________________________________________________________

## Category 7: Documentation Quality (10 points)

### Category 7: Evaluation Criteria

**Module-Level Documentation** (3 points):

Check mod.rs for module documentation:

- [ ] **3 pts**: Comprehensive module docs with ALL of:
  - Purpose statement (what the module does)
  - List of capabilities (bullet points)
  - Usage examples (at least 2 with code blocks)
  - Security considerations section
  - Architecture overview (three-layer pattern explained)
  - Links to related modules
- [ ] **2 pts**: Good module docs with 4-5 of above elements
- [ ] **1 pt**: Minimal module docs (purpose + 1-2 examples)
- [ ] **0 pts**: No module documentation or only summary line

**Example - Exemplar Level**:

````rust
//! Network identifier detection
//!
//! Detects network-related identifiers including:
//! - **UUIDs**: Universally Unique Identifiers (v4 and other versions)
//! - **IP Addresses**: IPv4 and IPv6 addresses
//! - **MAC Addresses**: Hardware addresses in various formats
//! - **URLs**: Web addresses with protocol schemes
//!
//! # Examples
//!
//! ```ignore
//! use octarine::security::data::detection::identifiers::network;
//!
//! // Detect UUID
//! let result = network::detect_network_identifier("550e8400-...");
//! assert_eq!(result, Some(IdentifierType::UUID));
//! ```
//!
//! # Security Considerations
//!
//! - UUIDs are generally not sensitive but may reveal system information
//! - IP addresses can be PII in some jurisdictions (GDPR)
//! - MAC addresses are hardware identifiers and may need redaction
//!
//! # Architecture
//!
//! Uses three-layer pattern: core domain → builder → shortcuts
````

**Function Documentation** (4 points):

Sample 10-15 public functions across the module. Each function MUST have:

**Required Elements** (all must be present for full points):

- ✅ Summary line (concise, starts with verb)
- ✅ Detailed description (behavior, edge cases, algorithm if complex)
- ✅ `# Arguments` section documenting each parameter
- ✅ `# Returns` section explaining all return variants
- ✅ `# Examples` section with 2-3 code examples
- ✅ `# Security Considerations` (if applicable to security)
- ✅ `# Errors` or `# Panics` sections (if applicable)

**Scoring**:

- [ ] **4 pts**: 90-100% of sampled functions have ALL required elements
- [ ] **3 pts**: 75-89% have all elements OR all have most elements
- [ ] **2 pts**: 50-74% have all elements OR most have basic docs only
- [ ] **1 pt**: \<50% have all elements, basic documentation only
- [ ] **0 pts**: Little to no function documentation

**Example - Exemplar Function Documentation**:

````rust
/// Detect network-related identifiers
///
/// Automatically detects the type of network identifier from the input string.
/// Checks for UUIDs, IP addresses, MAC addresses, and URLs in order of specificity.
///
/// # Arguments
///
/// * `value` - The string to analyze for network identifier patterns
///
/// # Returns
///
/// * `Some(IdentifierType::UUID)` - If the value matches UUID format
/// * `Some(IdentifierType::IPAddress)` - If the value is IPv4 or IPv6
/// * `Some(IdentifierType::MACAddress)` - If the value is a MAC address
/// * `Some(IdentifierType::URL)` - If the value has a protocol scheme
/// * `None` - If no network identifier pattern is detected
///
/// # Examples
///
/// ```ignore
/// // UUID detection
/// let result = detect_network_identifier("550e8400-...");
/// assert_eq!(result, Some(IdentifierType::UUID));
///
/// // IPv4 detection
/// let result = detect_network_identifier("192.168.1.1");
/// assert_eq!(result, Some(IdentifierType::IPAddress));
///
/// // Non-network identifier
/// let result = detect_network_identifier("not-an-id");
/// assert_eq!(result, None);
/// ```
///
/// # Security Considerations
///
/// - IP addresses may be PII under GDPR in certain contexts
/// - MAC addresses are hardware identifiers that should be masked in logs
///
/// # Implementation Notes
///
/// Detection is performed in this order for performance:
/// 1. UUID (most specific pattern with strict format)
/// 2. MAC Address (colon/dash delimited hex)
/// 3. IP Address (IPv4 then IPv6)
/// 4. URL (protocol-based detection)
pub fn detect_network_identifier(value: &str) -> Option<IdentifierType> {
````

**Code Examples Requirements**:

For internal modules (marked `pub(crate)` or `pub(super)`):

- ✅ Use `ignore` flag: ```` ```ignore ```` instead of ```` ```rust ````
- ✅ Still provide complete, realistic examples
- ✅ Show correct usage patterns even if not compilable
- ❌ Never omit examples just because module is internal

**Why**: Documentation is for developers working on the codebase. Internal APIs need documentation as much as public ones.

**Handling Private/Internal Code**:

````rust
// ✅ CORRECT - Internal module with examples
//! Internal network detection (pub(crate))
//!
//! # Examples
//!
//! ```ignore
//! // Example showing correct usage for developers
//! use super::detect_ipv4;
//! assert!(detect_ipv4("192.168.1.1"));
//! ```

// ❌ WRONG - No examples because it's internal
//! Internal network detection (pub(crate))
//!
//! No examples provided since this is internal.
````

**Architecture Documentation** (3 points):

Check for comprehensive architectural documentation:

- [ ] **3 pts**: Complete architecture documentation including:
  - Decision records (why this organization?)
  - Pattern explanations (why three-layer?)
  - Security design rationale
  - Cross-module dependencies
  - Migration notes (if refactored)
  - Example: review.md or ARCHITECTURE.md file
- [ ] **2 pts**: Good architecture docs explaining organization and patterns
- [ ] **1 pt**: Basic structure documentation in comments
- [ ] **0 pts**: No architecture documentation

**Example - Excellent Architecture Doc** (in review.md or similar):

```markdown
# Path Detection Architecture

## Design Decisions

### Why Three Layers?
1. **Domain files** contain pure business logic for testing
2. **Builder** provides configuration API without logic
3. **Shortcuts** offer convenience for common patterns

### Detection Order Rationale
Credentials checked first because:
- Most security-sensitive
- Specific patterns (less false positives)
- Early exit improves performance

### Module Organization
- `credential.rs` - 15 functions, ~300 LOC (cohesive domain)
- `characteristic.rs` - 8 functions, ~200 LOC (path properties)
- Split avoids mixing security checks with general properties
```

______________________________________________________________________

## Category 8: Test Coverage (10 points)

### Category 8: Evaluation Criteria

**Test Existence** (3 points):

- [ ] **3 pts**: All domain files have `#[cfg(test)]` modules
- [ ] **2 pts**: Most domain files have tests (80%+)
- [ ] **1 pt**: Some domain files have tests (50%+)
- [ ] **0 pts**: Minimal or no tests

**Test Comprehensiveness** (4 points):

Sample test modules - do they cover:

- ✅ Happy path cases

- ✅ Edge cases

- ✅ Error cases

- ✅ Security attack patterns

- ✅ OWASP threat scenarios

- [ ] **4 pts**: Comprehensive tests - all categories covered, 20+ tests per major domain

- [ ] **3 pts**: Good tests - most categories, 10-20 tests per domain

- [ ] **2 pts**: Basic tests - happy path + some edge cases, 5-10 tests

- [ ] **1 pt**: Minimal tests - only happy path

- [ ] **0 pts**: No meaningful tests

**Integration Tests** (3 points):

Check for integration tests in mod.rs or tests/ directory:

- [ ] **3 pts**: Comprehensive integration tests - tests cross-domain interactions
- [ ] **2 pts**: Some integration tests
- [ ] **1 pt**: Minimal integration tests
- [ ] **0 pts**: No integration tests

**Test Quality Checklist**:

- [ ] Tests use descriptive names (test_validate_rejects_command_injection)
- [ ] Tests are independent (no shared state)
- [ ] Tests cover both success and failure paths
- [ ] Security tests cover OWASP threats
- [ ] Edge cases documented in test names

______________________________________________________________________

## Category 9: Shortcut Patterns (5 points)

### Category 9: Evaluation Criteria

**Shortcuts Organization** (2 points):

- [ ] **2 pts**: Clean `pub mod shortcuts` organization with domain sub-modules
- [ ] **1 pt**: Shortcuts exist but organization unclear
- [ ] **0 pts**: No shortcuts or poorly organized

**Expected Structure**:

```rust
pub mod shortcuts {
    pub mod domain1 {
        pub use super::super::domain1_shortcuts::*;
    }
    pub mod domain2 {
        pub use super::super::domain2_shortcuts::*;
    }
}
```

**Shortcut Implementation** (3 points):

Review shortcut files - do they:

- ✅ Only use builder (no direct domain imports)

- ✅ Provide pre-configured builders

- ✅ Keep functions simple (1-2 lines)

- [ ] **3 pts**: Perfect shortcuts - all use builder, clean delegation

- [ ] **2 pts**: Good shortcuts, 1-2 bypass builder

- [ ] **1 pt**: Some shortcuts bypass builder

- [ ] **0 pts**: Shortcuts bypass builder or have business logic

**Example - Perfect**:

```rust
pub fn standard_validator() -> PathValidator {
    PathValidator::strict()  // Returns configured builder
}

pub fn validate_path(path: &str) -> Result<()> {
    standard_validator().validate(path)  // Uses builder
}
```

**Example - Wrong**:

```rust
pub fn validate_path(path: &str) -> Result<()> {
    crate::security::data::validation::paths::traversal::validate(path)
    // ❌ Bypasses builder, directly imports domain
}
```

______________________________________________________________________

## Scoring Worksheet

Use this worksheet when evaluating a module:

### Module: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_ Date: \_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

| Category | Points Earned | Max Points | Notes |
|----------|--------------|------------|-------|
| 1. Architecture & Organization | \_\_\_\_\_ / 15 | 15 | |
| 2. Builder Pattern Purity | \_\_\_\_\_ / 15 | 15 | |
| 3. Code Duplication | \_\_\_\_\_ / 15 | 15 | |
| 4. Naming Consistency | \_\_\_\_\_ / 10 | 10 | |
| 5. Type Organization | \_\_\_\_\_ / 10 | 10 | |
| 6. API Design & Patterns | \_\_\_\_\_ / 10 | 10 | |
| 7. Documentation Quality | \_\_\_\_\_ / 10 | 10 | |
| 8. Test Coverage | \_\_\_\_\_ / 10 | 10 | |
| 9. Shortcut Patterns | \_\_\_\_\_ / 5 | 5 | |
| **TOTAL SCORE** | **\_\_\_\_\_ / 100** | **100** | |

**Grade**: \_\_\_\_\_ **Status**: \_\_\_\_\_

______________________________________________________________________

## Using This Scorecard

### As a Quality Gate

**Before merging a new module**:

1. Complete the scorecard evaluation
1. Minimum score: **80/100 (B grade)**
1. Document any deductions and create issues for improvements
1. Get sign-off if score is 70-79 (acceptable but needs improvement plan)
1. Reject if score \<70 (needs refactoring before merge)

### As a Refactoring Guide

**When refactoring an existing module**:

1. Score the current state (baseline)
1. Identify lowest-scoring categories
1. Create improvement plan targeting those categories
1. Set target score (should improve by 10+ points)
1. Re-score after refactoring to measure improvement

### As a Review Prompt

**Use this as a Claude Code prompt**:

```text
Please evaluate the {module_name} module using the Module Quality Scorecard
at /workspace/octarine/src/security/data/MODULE_QUALITY_SCORECARD.md

Provide:
1. Completed scorecard with point values and justification for each category
2. Overall score and grade
3. Top 3 issues to address
4. Specific recommendations for improvement with file:line references
5. Comparison to exemplar modules (conversion/paths = A- grade)
```

______________________________________________________________________

## Example: conversion/paths Scoring

To demonstrate the methodology, here's the scoring for conversion/paths:

| Category | Score | Justification |
|----------|-------|---------------|
| **Architecture** | 14/15 | Perfect structure with types.rs, small focused files. -1 for format.rs having helper function with business logic |
| **Builder Purity** | 15/15 | Perfect - explicit "ZERO BUSINESS LOGIC" comment, pure delegation throughout |
| **Duplication** | 12/15 | Minimal duplication. -3 for security checks that could use shared security_core |
| **Naming** | 10/10 | Perfect consistency - follows all patterns |
| **Types** | 10/10 | Has types.rs with clean organization, impl blocks for convenience constructors |
| **API Design** | 9/10 | Good API, clear patterns. -1 for not having detailed Result types for some operations |
| **Documentation** | 8/10 | Good module and function docs. -2 for missing architecture documentation file |
| **Tests** | 10/10 | 123 tests, 100% passing, comprehensive coverage including security |
| **Shortcuts** | 5/5 | Perfect - clean organization, only uses builder |
| **TOTAL** | **93/100** | **Grade: A** |

**Status**: Exemplar - use as template for other modules

______________________________________________________________________

## Module Comparison Matrix

| Module | Architecture | Builder | Duplication | Naming | Types | API | Docs | Tests | Shortcuts | **Total** | **Grade** |
|--------|-------------|---------|-------------|--------|-------|-----|------|-------|-----------|-----------|-----------|
| **conversion/paths** | 14/15 | 15/15 | 12/15 | 10/10 | 10/10 | 9/10 | 8/10 | 10/10 | 5/5 | **93/100** | **A** |
| **detection/paths** | 12/15 | 11/15 | 5/15 | 8/10 | 7/10 | 8/10 | 7/10 | 9/10 | 5/5 | **72/100** | **C** |
| **validation/paths** | 12/15 | 9/15 | 2/15 | 8/10 | 7/10 | 9/10 | 8/10 | 10/10 | 4/5 | **69/100** | **D** |
| **sanitization/paths** | 12/15 | 9/15 | 2/15 | 8/10 | 7/10 | 9/10 | 8/10 | 10/10 | 5/5 | **70/100** | **C** |

**Key Takeaway**: The duplication issue significantly impacts validation and sanitization scores. Creating security_core would bring both modules to B+ grade.

______________________________________________________________________

## Continuous Improvement

### Rescoring Protocol

**When to rescore**:

- After significant refactoring
- Before and after creating shared modules (like security_core)
- Quarterly reviews of all modules
- When establishing new patterns

**Tracking Progress**:

```text
Module: validation/paths
Initial Score (2025-11-10): 69/100 (D)
After security_core (target): 82/100 (B)
After builder cleanup (target): 87/100 (B+)
```

### Adding New Categories

If new quality dimensions emerge:

1. Document the new category with scoring criteria
1. Update max points (may exceed 100)
1. Rescore all modules with new category
1. Update grade thresholds if total points changed

______________________________________________________________________

**End of Scorecard**
