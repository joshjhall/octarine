// Multi-line `pub use` block. The check now collapses the block onto a
// single line via `collapse_use_statements` before iterating, so the inner
// regex `[{,]\s*[a-z]...` sees the full body and fires on the lowercase
// function name. Intentional bare re-exports opt out with the inline
// `// arch-check: allow unwrapped-fn` directive.
pub use crate::primitives::foo::{
    do_thing,
    AnotherType,
};
