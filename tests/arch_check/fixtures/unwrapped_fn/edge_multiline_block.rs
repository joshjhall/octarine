// Multi-line `pub use` block — bash arch-check.sh greps line-by-line so it
// only sees the head line `pub use crate::primitives::foo::{`. The inner
// regex `[{,]\s*[a-z]...` does not match that head line, so multi-line
// blocks are silently skipped. This fixture documents the parity bug.
pub use crate::primitives::foo::{
    do_thing,
    AnotherType,
};
