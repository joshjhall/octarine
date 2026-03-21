//! Config derive implementation.

mod generate;
mod parse;
mod validate;

use darling::FromDeriveInput;
use proc_macro2::TokenStream;
use syn::DeriveInput;

use parse::ConfigOpts;

/// Expand the Config derive macro.
pub fn expand_config(input: DeriveInput) -> Result<TokenStream, darling::Error> {
    // Parse attributes
    let opts = ConfigOpts::from_derive_input(&input)?;

    // Validate
    validate::validate_config(&opts)?;

    // Generate code
    Ok(generate::generate_impl(&opts))
}
