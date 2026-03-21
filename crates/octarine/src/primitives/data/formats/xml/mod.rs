//! XML parsing and serialization primitives
//!
//! Pure XML operations with no security checks or file I/O.
//! For safe parsing with XXE prevention, use `security::formats` or `runtime::formats`.

mod parsing;
mod serialization;

// Types are public since they're part of the API
pub use parsing::XmlDocument;
// XmlNode is exported for full API access when needed
#[allow(unused_imports)]
pub use parsing::XmlNode;

// Functions remain crate-internal (exposed through builder)
pub(crate) use parsing::parse_xml;
pub(crate) use serialization::serialize_xml;
