use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput};

// TESTME:
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

// TESTME:
#[cfg(feature = "serde")]
#[proc_macro_derive(Serialize)]
pub fn derive_serialize_trait(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    let expanded = quote! {
        const _: () = {
            fn assert_static_name<T: StaticName>() {}
            fn assert_traits() {
                assert_static_name::<#name>();
            }
        };

        impl serde::ser::Serialize for #name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(self.name())
            }
        }
    };

    TokenStream::from(expanded)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
