//! Security types for structured data formats
//!
//! Threat definitions and policy types for XML, JSON, and YAML security.

use std::collections::HashSet;
use std::fmt;

// ============================================================================
// Format Threat Enumeration
// ============================================================================

/// Security threats in structured data formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FormatThreat {
    // XML Threats (CWE-611, CWE-776, CWE-827)
    /// External entity reference (file:// or http://)
    XxeExternalEntity,
    /// Parameter entity reference
    XxeParameterEntity,
    /// Billion laughs / entity expansion attack
    XxeBillionLaughs,
    /// DTD declaration present
    DtdPresent,

    // JSON Threats (CWE-400)
    /// Nesting depth exceeds limit
    JsonDepthExceeded,
    /// Content size exceeds limit
    JsonSizeExceeded,

    // YAML Threats (CWE-502, CWE-94, CWE-776)
    /// Unsafe YAML tag (!!python/exec, etc.)
    YamlUnsafeTag,
    /// Anchor/alias bomb (exponential expansion)
    YamlAnchorBomb,
}

impl FormatThreat {
    /// Get the CWE identifier for this threat
    #[must_use]
    pub const fn cwe(&self) -> &'static str {
        match self {
            Self::XxeExternalEntity | Self::XxeParameterEntity => "CWE-611",
            Self::XxeBillionLaughs | Self::YamlAnchorBomb => "CWE-776",
            Self::DtdPresent => "CWE-827",
            Self::JsonDepthExceeded | Self::JsonSizeExceeded => "CWE-400",
            Self::YamlUnsafeTag => "CWE-502",
        }
    }

    /// Get the severity level (1-5, higher is more severe)
    #[must_use]
    pub const fn severity(&self) -> u8 {
        match self {
            // Critical: Code execution or file access
            Self::XxeExternalEntity | Self::YamlUnsafeTag => 5,
            // High: Potential code execution or DoS
            Self::XxeParameterEntity | Self::XxeBillionLaughs | Self::YamlAnchorBomb => 4,
            // Medium: DoS risk
            Self::JsonDepthExceeded | Self::JsonSizeExceeded => 3,
            // Low: Configuration concern
            Self::DtdPresent => 2,
        }
    }

    /// Get a human-readable description
    #[must_use]
    pub const fn description(&self) -> &'static str {
        match self {
            Self::XxeExternalEntity => "XML external entity (file:// or http://)",
            Self::XxeParameterEntity => "XML parameter entity reference",
            Self::XxeBillionLaughs => "XML entity expansion attack (billion laughs)",
            Self::DtdPresent => "XML DOCTYPE declaration present",
            Self::JsonDepthExceeded => "JSON nesting depth exceeds limit",
            Self::JsonSizeExceeded => "JSON content size exceeds limit",
            Self::YamlUnsafeTag => "Unsafe YAML tag (potential code execution)",
            Self::YamlAnchorBomb => "YAML anchor/alias expansion attack",
        }
    }
}

impl fmt::Display for FormatThreat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.description(), self.cwe())
    }
}

// ============================================================================
// Policy Types
// ============================================================================

/// Security policy for XML parsing
#[derive(Debug, Clone, Default)]
pub struct XmlPolicy {
    /// Allow DOCTYPE declarations (default: false)
    pub allow_dtd: bool,
    /// Allow external entities (default: false)
    pub allow_external_entities: bool,
    /// Maximum entity expansion depth (default: 0 = no expansion)
    pub max_entity_expansions: usize,
}

impl XmlPolicy {
    /// Create a new strict XML policy (no DTD, no entities)
    #[must_use]
    pub fn strict() -> Self {
        Self::default()
    }

    /// Create a permissive policy (allows DTD, no external entities)
    ///
    /// Use with caution - only for trusted input.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            allow_dtd: true,
            allow_external_entities: false,
            max_entity_expansions: 10,
        }
    }
}

/// Security policy for JSON parsing
#[derive(Debug, Clone)]
pub struct JsonPolicy {
    /// Maximum nesting depth (default: 64)
    pub max_depth: usize,
    /// Maximum content size in bytes (default: 10MB)
    pub max_size: usize,
}

impl Default for JsonPolicy {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_size: 10 * 1024 * 1024, // 10MB
        }
    }
}

impl JsonPolicy {
    /// Create a new default JSON policy
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a strict policy for untrusted input
    #[must_use]
    pub fn strict() -> Self {
        Self {
            max_depth: 32,
            max_size: 1024 * 1024, // 1MB
        }
    }
}

/// Security policy for YAML parsing
#[derive(Debug, Clone, Default)]
pub struct YamlPolicy {
    /// Allowed YAML tags (empty = default safe tags only)
    pub allowed_tags: HashSet<String>,
    /// Maximum alias references (default: 0 = no aliases)
    pub max_aliases: usize,
}

impl YamlPolicy {
    /// Create a new strict YAML policy (no custom tags, no aliases)
    #[must_use]
    pub fn strict() -> Self {
        Self::default()
    }

    /// Create a permissive policy (allows aliases, no custom tags)
    ///
    /// Use with caution - only for trusted input.
    #[must_use]
    pub fn permissive() -> Self {
        Self {
            allowed_tags: HashSet::new(),
            max_aliases: 100,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_threat_cwe() {
        assert_eq!(FormatThreat::XxeExternalEntity.cwe(), "CWE-611");
        assert_eq!(FormatThreat::XxeBillionLaughs.cwe(), "CWE-776");
        assert_eq!(FormatThreat::JsonDepthExceeded.cwe(), "CWE-400");
        assert_eq!(FormatThreat::YamlUnsafeTag.cwe(), "CWE-502");
    }

    #[test]
    fn test_format_threat_severity() {
        assert_eq!(FormatThreat::XxeExternalEntity.severity(), 5);
        assert_eq!(FormatThreat::YamlUnsafeTag.severity(), 5);
        assert_eq!(FormatThreat::DtdPresent.severity(), 2);
    }

    #[test]
    fn test_xml_policy_defaults() {
        let policy = XmlPolicy::default();
        assert!(!policy.allow_dtd);
        assert!(!policy.allow_external_entities);
        assert_eq!(policy.max_entity_expansions, 0);
    }

    #[test]
    fn test_json_policy_defaults() {
        let policy = JsonPolicy::default();
        assert_eq!(policy.max_depth, 64);
        assert_eq!(policy.max_size, 10 * 1024 * 1024);
    }

    #[test]
    fn test_yaml_policy_defaults() {
        let policy = YamlPolicy::default();
        assert!(policy.allowed_tags.is_empty());
        assert_eq!(policy.max_aliases, 0);
    }
}
