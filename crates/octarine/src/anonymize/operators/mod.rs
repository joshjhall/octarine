//! Built-in anonymize operators.
//!
//! Each operator is a pure implementation of the
//! [`Operator`](crate::anonymize::Operator) trait. The
//! [`AnonymizerEngine`](crate::anonymize::AnonymizerEngine) seeds its default
//! registry with the operators here; additional operators land as follow-up
//! work under the `anonymize/` umbrella.

mod redact;
mod replace;

pub use redact::Redact;
pub use replace::Replace;
