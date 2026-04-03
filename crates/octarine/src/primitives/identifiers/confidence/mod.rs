//! Context-aware confidence scoring primitives
//!
//! Keyword dictionaries and configuration for boosting identifier detection
//! confidence based on surrounding text context. When contextual keywords
//! like "social security" appear near a pattern match, confidence increases.

mod builder;
mod context;
mod keywords;
mod types;

pub use self::builder::ConfidenceBuilder;
pub use self::context::ContextAnalyzer;
pub use self::keywords::context_keywords;
pub use self::types::ContextConfig;
