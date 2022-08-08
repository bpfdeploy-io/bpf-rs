#![doc = include_str!("../README.md")]

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

/// Derive Display based on the impl StaticName trait
#[proc_macro_derive(Display)]
pub fn derive_display_trait(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    let expanded = quote! {
        const _: () = {
            fn assert_static_name<T: StaticName>() {}
            fn assert_traits() {
                assert_static_name::<#name>();
            }
        };

        impl ::std::fmt::Display for #name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                write!(f, "{}", self.name())
            }
        }
    };

    TokenStream::from(expanded)
}

/// Derive Serde's Serialize trait based on Display
///
/// Enabled through the `serde` feature
#[cfg(any(feature = "serde", doc))]
#[proc_macro_derive(SerializeFromDisplay)]
pub fn derive_serialize_from_display_trait(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    let expanded = quote! {
        const _: () = {
            fn assert_display<T: ::std::fmt::Display>() {}
            fn assert_traits() {
                assert_display::<#name>();
            }
        };
        impl serde::ser::Serialize for #name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.collect_str(self)
            }
        }
    };

    TokenStream::from(expanded)
}
