//! Text Primitives
//!
//! Builder-based API for text detection and sanitization operations.
//! Prevents log injection, CRLF injection, control character attacks,
//! and Unicode-based security threats.
//!
//! ## Architecture
//!
//! This is **Layer 1 (primitives)** - `pub(crate)` only:
//! - Pure utilities, no observe dependencies
//! - Used by Layer 2 (observe) for log sanitization
//! - Wrapped by Layer 3 (data/text) for public API
//!
//! ## Security Background
//!
//! Log injection attacks exploit text handling to:
//! - **Forge log entries**: Inject fake log lines via newlines
//! - **Hide attacks**: Use control characters to overwrite or hide content
//! - **Execute commands**: Some terminals interpret ANSI escapes dangerously
//! - **Break protocols**: CRLF injection in HTTP headers and other protocols
//!
//! Unicode attacks exploit visual similarity:
//! - **Homograph attacks**: Cyrillic 'а' looks like Latin 'a'
//! - **Mixed script spoofing**: `аpple.com` looks like `apple.com`
//! - **Invisible manipulation**: Zero-width chars, bidi overrides
//!
//! ## Public API
//!
//! - [`TextBuilder`] - Fluent API for text detection and transformation
//! - [`TextConfig`] - Configuration for sanitization behavior
//!
//! ## Example
//!
//! ```rust,ignore
//! use crate::primitives::data::text::{TextBuilder, TextConfig};
//!
//! // Detection
//! let has_issues = TextBuilder::new("user\x00input")
//!     .is_control_chars_present();
//!
//! // Transform chain
//! let safe = TextBuilder::new("input\nwith\x1B[31mcolors")
//!     .sanitize_for_log()
//!     .strip_ansi()
//!     .truncate(100)
//!     .finish();
//!
//! // Unicode security
//! let safe = TextBuilder::new("аpple.com")  // Cyrillic а
//!     .normalize_nfc()
//!     .strip_format_chars()
//!     .finish();
//!
//! // With custom config
//! let config = TextConfig::strict();
//! let safe = TextBuilder::new(user_input)
//!     .with_config(config)
//!     .sanitize_for_log()
//!     .finish();
//! ```
//!
//! ## Compliance Coverage
//!
//! | Check | OWASP | CWE | Notes |
//! |-------|-------|-----|-------|
//! | Log injection | A03:2021 | CWE-117 | Improper output neutralization |
//! | CRLF injection | A03:2021 | CWE-93 | HTTP response splitting variant |
//! | Control chars | A03:2021 | CWE-116 | Improper encoding |
//! | ANSI escapes | - | CWE-150 | Terminal escape injection |
//! | Homograph | UTS #39 | CWE-1007 | Insufficient visual distinction |
//! | Mixed script | UTS #39 | CWE-1007 | Script mixing detection |

// Private implementation modules
mod builder;
mod control;
mod log;
pub(crate) mod unicode;

// Public API - TextBuilder and TextConfig only
// These may appear unused until the observe module starts using them

/// Fluent builder for text detection and transformation
#[allow(unused_imports)]
pub use builder::TextBuilder;

/// Configuration for TextBuilder sanitization behavior
#[allow(unused_imports)]
pub use log::TextConfig;

// Re-export unicode types for crate-internal use
#[allow(unused_imports)]
pub use unicode::{RestrictionLevel, UnicodeSecurityResult, UnicodeThreat, UnicodeThreatType};
