//! Built-in anonymize operators.
//!
//! Each operator is a pure implementation of the
//! [`Operator`](crate::anonymize::Operator) trait. The
//! [`AnonymizerEngine`](crate::anonymize::AnonymizerEngine) seeds its default
//! registry with the stateless built-ins here ([`Replace`], [`Redact`],
//! [`Mask`], [`Hash`], [`Encrypt`], [`Decrypt`]); [`Custom`] carries a
//! caller-supplied closure and is registered explicitly via
//! [`with_operator`](crate::anonymize::AnonymizerEngine::with_operator).
//! Additional operators land as follow-up work under the `anonymize/` umbrella.

mod custom;
mod decrypt;
mod encrypt;
mod hash;
mod keyed_config;
mod mask;
mod redact;
mod replace;

pub use custom::Custom;
pub use decrypt::Decrypt;
pub use encrypt::Encrypt;
pub use hash::Hash;
pub use mask::Mask;
pub use redact::Redact;
pub use replace::Replace;
