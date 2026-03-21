//! Network data types with public visibility
//!
//! Wrapper types that expose primitives types at the public API level.

use crate::primitives::data::network::NormalizeUrlPathOptions as PrimitiveOptions;
use crate::primitives::data::network::PathPattern as PrimitivePathPattern;

/// Options for URL path normalization
///
/// Controls which transformations are applied during normalization.
///
/// # Example
///
/// ```ignore
/// use octarine::data::network::NormalizeUrlPathOptions;
///
/// // Strict normalization (default)
/// let strict = NormalizeUrlPathOptions::strict();
///
/// // For metrics collection (adds lowercase)
/// let metrics = NormalizeUrlPathOptions::for_metrics();
///
/// // Minimal normalization
/// let minimal = NormalizeUrlPathOptions::minimal();
/// ```
#[derive(Debug, Clone, Default)]
pub struct NormalizeUrlPathOptions {
    /// Remove trailing slashes (default: true)
    pub remove_trailing_slash: bool,
    /// Collapse multiple consecutive slashes (default: true)
    pub collapse_slashes: bool,
    /// Lowercase the path (default: false, as paths are case-sensitive)
    pub lowercase: bool,
    /// Remove dot segments (. and ..) (default: true)
    pub remove_dot_segments: bool,
}

impl NormalizeUrlPathOptions {
    /// Create options with all normalizations enabled (except lowercase)
    #[must_use]
    pub fn strict() -> Self {
        Self {
            remove_trailing_slash: true,
            collapse_slashes: true,
            lowercase: false,
            remove_dot_segments: true,
        }
    }

    /// Create options for metrics collection (includes lowercase for grouping)
    #[must_use]
    pub fn for_metrics() -> Self {
        Self {
            remove_trailing_slash: true,
            collapse_slashes: true,
            lowercase: true,
            remove_dot_segments: true,
        }
    }

    /// Create minimal normalization options
    #[must_use]
    pub fn minimal() -> Self {
        Self {
            remove_trailing_slash: false,
            collapse_slashes: true,
            lowercase: false,
            remove_dot_segments: false,
        }
    }
}

impl From<NormalizeUrlPathOptions> for PrimitiveOptions {
    fn from(opts: NormalizeUrlPathOptions) -> Self {
        Self {
            remove_trailing_slash: opts.remove_trailing_slash,
            collapse_slashes: opts.collapse_slashes,
            lowercase: opts.lowercase,
            remove_dot_segments: opts.remove_dot_segments,
        }
    }
}

impl From<PrimitiveOptions> for NormalizeUrlPathOptions {
    fn from(opts: PrimitiveOptions) -> Self {
        Self {
            remove_trailing_slash: opts.remove_trailing_slash,
            collapse_slashes: opts.collapse_slashes,
            lowercase: opts.lowercase,
            remove_dot_segments: opts.remove_dot_segments,
        }
    }
}

/// Pattern for matching and normalizing URL path segments
///
/// Used to replace dynamic path segments (like IDs, UUIDs) with placeholders
/// for metrics aggregation and logging.
///
/// # Example
///
/// ```ignore
/// use octarine::data::network::PathPattern;
///
/// // Match user ID paths
/// let pattern = PathPattern::new("/users/{id}");
///
/// // Match order with nested item
/// let pattern = PathPattern::new("/orders/{order_id}/items/{item_id}");
/// ```
#[derive(Debug, Clone)]
pub struct PathPattern(PrimitivePathPattern);

impl PathPattern {
    /// Create a new path pattern from a template string
    ///
    /// Use `{name}` placeholders for dynamic segments.
    ///
    /// # Arguments
    ///
    /// * `template` - Pattern template like "/users/{id}" or "/orders/{order_id}/items/{item_id}"
    ///
    /// # Example
    ///
    /// ```ignore
    /// use octarine::data::network::PathPattern;
    ///
    /// let pattern = PathPattern::new("/api/{version}/users/{user_id}");
    /// ```
    #[must_use]
    pub fn new(template: &str) -> Self {
        Self(PrimitivePathPattern::new(template))
    }
}

impl From<PathPattern> for PrimitivePathPattern {
    fn from(pattern: PathPattern) -> Self {
        pattern.0
    }
}

impl From<PrimitivePathPattern> for PathPattern {
    fn from(pattern: PrimitivePathPattern) -> Self {
        Self(pattern)
    }
}

impl AsRef<PrimitivePathPattern> for PathPattern {
    fn as_ref(&self) -> &PrimitivePathPattern {
        &self.0
    }
}
